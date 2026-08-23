/** ACME(RFC 8555) — JOSE 유닛 + 목 ACME 서버로 dns-01 전체 발급 흐름 + acmeCertSource. */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { createPrivateKey, createPublicKey, createSign, randomBytes, verify as cryptoVerify } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  acmeCertSource,
  asn1,
  b64url,
  distinguishedName,
  generateAccountKey,
  generateCsr,
  generateEcKeyPair,
  generateSelfSigned,
  jwkThumbprint,
  makeJws,
  publicJwk,
  requestCertificate,
  subjectAltNames,
  type DnsProvider,
} from "@ionosphere/tls";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  dirs.length = 0;
});
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "ionosphere-acme-"));
  dirs.push(d);
  return d;
}

describe("JOSE", () => {
  test("publicJwk / thumbprint 안정", () => {
    const key = generateAccountKey();
    const jwk = publicJwk(key);
    expect(jwk).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(typeof jwk.x).toBe("string");
    const tp = jwkThumbprint(jwk);
    expect(tp).toBe(jwkThumbprint(jwk)); // 결정적
  });

  test("makeJws ES256 서명이 공개키로 검증됨(raw R||S)", () => {
    const key = generateAccountKey();
    const jws = JSON.parse(makeJws(key, { alg: "ES256", nonce: "n1", url: "https://a/x", jwk: publicJwk(key) }, { hello: 1 }));
    const signingInput = `${jws.protected}.${jws.payload}`;
    const sig = Buffer.from(jws.signature, "base64url");
    const pub = createPublicKey(createPrivateKey(key));
    const ok = cryptoVerify("sha256", Buffer.from(signingInput), { key: pub, dsaEncoding: "ieee-p1363" }, sig);
    expect(ok).toBe(true);
  });
});

describe("CSR", () => {
  test("generateCsr — 유효 EC 키 + DER SEQUENCE", () => {
    const { keyPem, csrDer } = generateCsr(["mx.test.local", "autoconfig.test.local"]);
    expect(() => createPrivateKey(keyPem)).not.toThrow();
    expect(csrDer[0]).toBe(0x30); // SEQUENCE
    expect(csrDer.length).toBeGreaterThan(100);
  });
});

/**
 * CSR DER에서 P-256 SubjectPublicKeyInfo(고정 91바이트)를 잘라낸다.
 *
 * 왜 필요한가: 진짜 CA는 **CSR의 공개키로** 인증서를 발급한다. 목이 무관한 인증서를 돌려주면
 * cert-key 페어링 검사(감사 H-1 계열)를 통과할 수 없어, 정상 흐름 테스트가 실패 검사와
 * 구분되지 않는다. 전용 DER 파서를 들이는 대신 알려진 SPKI 프리픽스를 찾는다 — P-256 한 곡선만
 * 쓰므로 모양이 고정이다.
 */
function p256SpkiFromCsr(csrDer: Uint8Array): Uint8Array {
  const prefix = Uint8Array.from([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
  for (let i = 0; i + prefix.length <= csrDer.length; i++) {
    if (prefix.every((b, k) => csrDer[i + k] === b)) return csrDer.subarray(i, i + 91);
  }
  throw new Error("목 CA: CSR에서 P-256 SPKI를 못 찾았다");
}

/** 목 CA — 주어진 공개키(=CSR의 것)로 SAN 인증서를 발급한다. 서명 주체는 무관(체인 검증 안 함). */
function mockIssue(csrDer: Uint8Array, sans: string[]): string {
  const ca = generateEcKeyPair();
  const sigAlg = asn1.seq(asn1.oid("1.2.840.10045.4.3.2")); // ecdsaWithSHA256
  const dn = distinguishedName(sans[0]!);
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(notBefore.getTime() + 90 * 86_400_000);
  const tbs = asn1.seq(
    asn1.context(0, true, asn1.int(2)),
    asn1.int(randomBytes(16)),
    sigAlg,
    dn,
    asn1.seq(asn1.time(notBefore), asn1.time(notAfter)),
    dn,
    asn1.raw(p256SpkiFromCsr(csrDer)),
    asn1.context(3, true, asn1.seq(asn1.seq(asn1.oid("2.5.29.17"), asn1.octetString(subjectAltNames(sans))))),
  );
  const sig = createSign("SHA256").update(Buffer.from(tbs)).sign(ca.privateKeyPemForSign);
  return asn1.toPem(asn1.seq(tbs, sigAlg, asn1.bitString(new Uint8Array(sig))), "CERTIFICATE");
}

// ── 목 ACME 서버(stateful fake fetch) ──────────────────────────────────
/** certPem을 주면 그것을 그대로 발급(비정상 응답 시나리오용), 안 주면 CSR에 맞는 인증서를 만든다. */
function mockAcme(certPem?: string, sans: string[] = ["mx.test.local"]): { fetch: typeof fetch; dns: DnsProvider; txt: Map<string, string>; issued: string[] } {
  const BASE = "https://acme.mock";
  let nonce = 0;
  let challengeTriggered = false;
  let finalized = false;
  const issued: string[] = [];
  const txt = new Map<string, string>();
  const headers = (extra: Record<string, string> = {}) => new Headers({ "replay-nonce": `nonce-${nonce++}`, ...extra });
  const json = (status: number, body: unknown, extra?: Record<string, string>) =>
    new Response(JSON.stringify(body), { status, headers: (() => { const h = headers(extra); h.set("content-type", "application/json"); return h; })() });

  const f = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.endsWith("/directory")) return json(200, { newNonce: `${BASE}/nonce`, newAccount: `${BASE}/acct`, newOrder: `${BASE}/order` });
    if (url.endsWith("/nonce")) return new Response(null, { status: 200, headers: headers() });
    if (url.endsWith("/acct")) return json(201, { status: "valid" }, { location: `${BASE}/acct/1` });
    if (url.endsWith("/order") && method === "POST") {
      return json(201, { status: "pending", authorizations: [`${BASE}/authz/1`], finalize: `${BASE}/finalize` }, { location: `${BASE}/order/1` });
    }
    if (url.endsWith("/authz/1")) {
      return json(200, { identifier: { value: "mx.test.local" }, status: challengeTriggered ? "valid" : "pending", challenges: [{ type: "dns-01", url: `${BASE}/chal/1`, token: "tok-123" }] });
    }
    if (url.endsWith("/chal/1")) {
      challengeTriggered = true;
      return json(200, { type: "dns-01", status: "processing", url: `${BASE}/chal/1` });
    }
    if (url.endsWith("/finalize")) {
      finalized = true;
      // 진짜 CA처럼 CSR의 공개키로 발급한다(JWS payload → {csr: b64url(DER)}).
      const payload = JSON.parse(Buffer.from(JSON.parse(String(init?.body ?? "{}")).payload ?? "", "base64url").toString());
      issued.push(certPem ?? mockIssue(new Uint8Array(Buffer.from(String(payload.csr), "base64url")), sans));
      return json(200, { status: "processing" });
    }
    if (url.endsWith("/order/1")) {
      return json(200, finalized ? { status: "valid", certificate: `${BASE}/cert/1` } : { status: "processing" });
    }
    if (url.endsWith("/cert/1")) {
      return new Response(issued.at(-1) ?? "", { status: 200, headers: (() => { const h = headers(); h.set("content-type", "application/pem-certificate-chain"); return h; })() });
    }
    return new Response("not found", { status: 404, headers: headers() });
  }) as unknown as typeof fetch;

  const dns: DnsProvider = {
    setTxt: async (fqdn, value) => void txt.set(fqdn, value),
    removeTxt: async (fqdn) => void txt.delete(fqdn),
  };
  return { fetch: f, dns, txt, issued };
}

describe("requestCertificate (목 ACME dns-01)", () => {
  test("전체 흐름 → 인증서 발급 + TXT 게시/정리", async () => {
    const issued = generateSelfSigned({ commonName: "mx.test.local", sans: ["mx.test.local"] }).certPem;
    const mock = mockAcme(issued);
    let txtDuringChallenge = "";
    const dns: DnsProvider = {
      setTxt: async (fqdn, value) => {
        txtDuringChallenge = value;
        await mock.dns.setTxt(fqdn, value);
      },
      removeTxt: mock.dns.removeTxt,
    };
    const result = await requestCertificate(
      { directoryUrl: "https://acme.mock/directory", accountKeyPem: generateAccountKey(), challenge: { type: "dns-01", dns }, fetch: mock.fetch, contactEmail: "a@x.test", dnsPropagationMs: 0, pollIntervalMs: 5, pollMaxTries: 20 },
      ["mx.test.local"],
    );
    expect(result.certPem).toBe(issued);
    expect(() => createPrivateKey(result.keyPem)).not.toThrow();
    expect(txtDuringChallenge).toMatch(/^[A-Za-z0-9_-]+$/); // dns-01 base64url 값 게시됨
    expect(mock.txt.size).toBe(0); // 정리됨
  });
});

/**
 * 감사 H-1 동일 계열 — ACME는 **응답 본문의 URL을 계속 따라가는** 프로토콜이라,
 * 디렉터리 하나만 잘못 지정되면 임의 주소로 POST를 날리는 SSRF 프리미티브가 된다.
 */
describe("ACME 보안 게이트", () => {
  test("평문 디렉터리는 거부하지 않고 경고한다(스킴 자체가 틀리면 던진다)", () => {
    // 평문은 막지 않고 경고한다(url cert와 같은 정책 — secure-url.ts checkTransportUrl 주석).
    expect(() => acmeCertSource({ domains: ["mx.test.local"], directoryUrl: "http://acme.mock/directory", challenge: { type: "dns-01", dns: mockAcme().dns }, dir: tmp() })).not.toThrow();
    // 스킴 자체가 http(s)가 아니면 여전히 설정 오류로 던진다.
    expect(() => acmeCertSource({ domains: ["mx.test.local"], directoryUrl: "ftp://acme.mock/directory", challenge: { type: "dns-01", dns: mockAcme().dns }, dir: tmp() })).toThrow();
  });

  test("디렉터리가 가리키는 크로스 오리진 URL은 따라가지 않는다", async () => {
    const issued = generateSelfSigned({ commonName: "mx.test.local", sans: ["mx.test.local"] }).certPem;
    const inner = mockAcme(issued);
    const seen: string[] = [];
    const f = (async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      seen.push(url);
      if (url.endsWith("/directory")) {
        // 침해된(또는 오설정된) 디렉터리가 내부망 주소를 찍어준다
        return new Response(JSON.stringify({ newNonce: "https://acme.mock/nonce", newAccount: "https://169.254.169.254/acct", newOrder: "https://acme.mock/order" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return inner.fetch(input, init);
    }) as unknown as typeof fetch;
    await expect(
      requestCertificate({ directoryUrl: "https://acme.mock/directory", accountKeyPem: generateAccountKey(), challenge: { type: "dns-01", dns: inner.dns }, fetch: f, dnsPropagationMs: 0, pollIntervalMs: 5 }, ["mx.test.local"]),
    ).rejects.toThrow(/오리진/);
    expect(seen.some((u) => u.includes("169.254.169.254"))).toBe(false); // 요청 자체가 나가지 않았다
  });

  /** CSR과 쌍은 맞지만 **다른 도메인**용 인증서 — 페어링만 봤다면 통과했을 케이스. */
  test("발급분이 요청한 도메인용이 아니면 디스크에 쓰지 않는다", async () => {
    const dir = tmp();
    const mock = mockAcme(undefined, ["evil.attacker.test"]);
    const s = acmeCertSource({
      domains: ["mx.test.local"],
      directoryUrl: "https://acme.mock/directory",
      challenge: { type: "dns-01", dns: mock.dns },
      dir,
      fetch: mock.fetch,
      dnsPropagationMs: 0,
      pollIntervalMs: 5,
      pollMaxTries: 20,
    });
    await expect(s.resolve()).rejects.toBeTruthy();
    expect(existsSync(join(dir, "acme-cert.pem"))).toBe(false);
    expect(existsSync(join(dir, "acme-key.pem"))).toBe(false);
    s.close?.();
  });

  test("인증서가 아닌 응답(오류 본문 등)은 기존 인증서를 덮어쓰지 못한다", async () => {
    const dir = tmp();
    const mock = mockAcme("서버 오류입니다");
    const s = acmeCertSource({
      domains: ["mx.test.local"],
      directoryUrl: "https://acme.mock/directory",
      challenge: { type: "dns-01", dns: mock.dns },
      dir,
      fetch: mock.fetch,
      dnsPropagationMs: 0,
      pollIntervalMs: 5,
      pollMaxTries: 20,
    });
    await expect(s.resolve()).rejects.toBeTruthy();
    expect(existsSync(join(dir, "acme-cert.pem"))).toBe(false);
    s.close?.();
  });
});

describe("acmeCertSource", () => {
  test("resolve가 발급+영속, 재resolve는 재사용, status/refresh", async () => {
    const dir = tmp();
    const mock = mockAcme(); // CSR 공개키로 발급하는 목 CA(= 페어링 검사를 통과하는 정상 경로)
    const s = acmeCertSource({
      domains: ["mx.test.local"],
      directoryUrl: "https://acme.mock/directory",
      challenge: { type: "dns-01", dns: mock.dns },
      dir,
      fetch: mock.fetch,
      dnsPropagationMs: 0,
      pollIntervalMs: 5,
      pollMaxTries: 20,
    });
    const a = await s.resolve();
    expect(Buffer.from(a!.cert).toString()).toBe(mock.issued[0]!);
    // 계정 키 영속됨
    expect(readFileSync(join(dir, "acme-account.key.pem")).length).toBeGreaterThan(0);
    // 재사용(유효 인증서 → 재발급 안 함): cert 바이트 동일 + 추가 발급 없음
    const b = await s.resolve();
    expect(Buffer.from(b!.cert).toString()).toBe(mock.issued[0]!);
    expect(mock.issued).toHaveLength(1);
    const st = await s.status();
    expect(st).toMatchObject({ mode: "acme", enabled: true });
    s.close?.();
  });
});
