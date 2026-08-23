/**
 * 자체 내장 ACME 클라이언트(RFC 8555) — dns-01/http-01 챌린지로 인증서 발급.
 * zero-dep(node:crypto + jose/csr). 챌린지 응답은 훅으로 주입, fetch도 주입 가능(테스트).
 *
 * 절차: directory → newNonce → newAccount(JWK) → newOrder → authz → 챌린지 게시 → (dns면 전파대기)
 *      → challenge 응답 → authz valid 폴링 → CSR finalize → order valid 폴링 → cert 다운로드.
 */
import { createHash } from "node:crypto";
import { noopLogger, type Logger } from "@ionosphere/core";
import { generateCsr } from "./csr.ts";
import { b64url, generateAccountKey, jwkThumbprint, makeJws, publicJwk } from "./jose.ts";
import { assertSameOrigin, checkTransportUrl, insecureTransportWarning } from "./secure-url.ts";

export interface DnsProvider {
  /** _acme-challenge.<domain> TXT 레코드 생성(전파까지는 클라이언트가 대기). */
  setTxt(fqdn: string, value: string): Promise<void>;
  /** 검증 후 정리(실패해도 무해). */
  removeTxt(fqdn: string, value: string): Promise<void>;
}

/**
 * http-01 응답 훅 — `/.well-known/acme-challenge/<token>`에 keyAuthorization을 그대로 서빙한다
 * (RFC 8555 §8.3: 본문은 key authorization **원문**, dns-01처럼 해시하지 않는다).
 */
export interface HttpChallengeResponder {
  set(token: string, keyAuthorization: string): Promise<void>;
  /** 검증 후 정리(실패해도 무해). */
  remove(token: string): Promise<void>;
}

/**
 * 챌린지 갈래 — **판별 유니온**으로 둔다.
 *
 * ★왜(오픈소스 자립성): 예전엔 `dns: DnsProvider`가 필수 필드였고 구현체가 Cloudflare 전용
 * 하나뿐이라, 다른 DNS를 쓰는 사용자는 `IONOSPHERE_TLS_MODE=acme`를 아예 쓸 수 없었다. http-01은
 * DNS 프로바이더 없이 80포트만으로 성립하므로 외부 의존성 0인 발급 경로가 된다.
 *
 * 유니온이라 갈래를 추가하면 `issue()`의 분기가 컴파일 에러로 드러난다 — 옵션 두 개를 다 optional로
 * 두면 "둘 다 안 넣은 설정"이 런타임에야 터진다.
 */
export type AcmeChallenge =
  | { type: "dns-01"; dns: DnsProvider }
  | {
      type: "http-01";
      http: HttpChallengeResponder;
      /**
       * 발급 전후로 리스너를 열고 닫는 훅(선택). 80포트를 **상시 점유하지 않기 위해** 있다 —
       * 같은 호스트의 다른 웹서버와 충돌하고, 발급은 몇 주에 한 번이다.
       * 이미 떠 있는 리스너에 붙이는 구성(리버스 프록시 뒤 등)이라면 생략한다.
       */
      open?: () => Promise<unknown>;
      close?: () => Promise<unknown>;
    };

export interface AcmeOptions {
  directoryUrl: string;
  accountKeyPem: string;
  challenge: AcmeChallenge;
  contactEmail?: string;
  fetch?: typeof fetch;
  logger?: Logger;
  /** dns-01 TXT 전파 대기(ms). http-01은 게시가 즉시 유효하므로 무시된다. */
  dnsPropagationMs?: number;
  pollIntervalMs?: number;
  pollMaxTries?: number;
  /** 루프백 http: 디렉터리 허용(개발·pebble 전용 opt-out). 원격 평문은 이 플래그로도 안 열린다. */
}

interface Directory {
  newNonce: string;
  newAccount: string;
  newOrder: string;
}

const JOSE_CT = "application/jose+json";

class AcmeSession {
  private readonly f: typeof fetch;
  private readonly log: Logger;
  private nonce = "";
  private dir!: Directory;
  private kid = "";
  private readonly opts: AcmeOptions;
  /** 디렉터리 오리진 — 서버가 본문에 실어준 URL은 전부 여기에 묶어 둔다. */
  private readonly origin: string;

  constructor(opts: AcmeOptions) {
    this.opts = opts;
    this.f = opts.fetch ?? fetch;
    this.log = (opts.logger ?? noopLogger).child({ component: "acme" });
    // cert URL과 같은 정책: 막지 않고 경고한다(secure-url.ts checkTransportUrl 주석).
    const dir = checkTransportUrl("ACME directory URL", opts.directoryUrl);
    if (dir.insecure) this.log.warn(insecureTransportWarning("ACME directory URL", dir.url), { phase: "startup" });
    this.origin = dir.url.origin;
  }

  /**
   * 서버 응답에서 받은 URL을 따라가기 전 오리진을 확인한다.
   *
   * ACME는 directory → newOrder → authz → challenge → finalize → certificate로 **응답 본문의 URL을
   * 계속 따라가는** 프로토콜이라, 검증이 없으면 디렉터리 하나를 잘못 지정하는 것만으로 내부망 임의
   * 주소에 POST를 날리는 SSRF 프리미티브가 된다(감사 H-1 동일 계열). 실제 CA는 전 엔드포인트가
   * 같은 오리진이므로 이 제약으로 정상 발급이 막히지 않는다.
   */
  private checkedUrl(url: string, what: string): string {
    assertSameOrigin(`ACME ${what}`, this.origin, url);
    return url; // 정규화하지 않고 원문 그대로 — JWS protected의 url은 요청 URL과 같아야 한다
  }

  private async loadDirectory(): Promise<void> {
    const res = await this.f(this.opts.directoryUrl);
    if (!res.ok) throw new Error(`ACME directory ${res.status}`);
    this.dir = (await res.json()) as Directory;
  }

  private async freshNonce(): Promise<void> {
    const res = await this.f(this.checkedUrl(this.dir.newNonce, "newNonce"), { method: "HEAD" });
    this.nonce = res.headers.get("replay-nonce") ?? "";
  }

  /** JWS POST(payload=null → POST-as-GET). badNonce 시 1회 재시도. text=true면 본문 문자열 반환. */
  private async post(rawUrl: string, payload: unknown | null, useKid: boolean): Promise<{ res: Response; body: unknown }> {
    // 서버가 준 URL은 전부 이 관문을 지난다(newAccount·newOrder·authz·challenge·finalize·order·cert).
    const url = this.checkedUrl(rawUrl, "endpoint");
    for (let attempt = 0; attempt < 2; attempt++) {
      if (!this.nonce) await this.freshNonce();
      const header = useKid
        ? { alg: "ES256" as const, nonce: this.nonce, url, kid: this.kid }
        : { alg: "ES256" as const, nonce: this.nonce, url, jwk: publicJwk(this.opts.accountKeyPem) };
      const jws = makeJws(this.opts.accountKeyPem, header, payload);
      const res = await this.f(url, { method: "POST", headers: { "content-type": JOSE_CT }, body: jws });
      const next = res.headers.get("replay-nonce");
      if (next) this.nonce = next;
      const ct = res.headers.get("content-type") ?? "";
      const body: unknown = ct.includes("json") ? await res.json() : await res.text();
      if (res.status === 400 && typeof body === "object" && body && (body as { type?: string }).type?.includes("badNonce")) {
        this.nonce = "";
        continue; // 재시도
      }
      return { res, body };
    }
    throw new Error("ACME: badNonce 재시도 실패");
  }

  private async newAccount(): Promise<void> {
    const payload: Record<string, unknown> = { termsOfServiceAgreed: true };
    if (this.opts.contactEmail) payload.contact = [`mailto:${this.opts.contactEmail}`];
    const { res } = await this.post(this.dir.newAccount, payload, false);
    if (res.status !== 200 && res.status !== 201) throw new Error(`ACME newAccount ${res.status}`);
    this.kid = res.headers.get("location") ?? "";
    if (!this.kid) throw new Error("ACME newAccount: kid(Location) 없음");
  }

  private async pollUntil(url: string, want: string, bad: string[]): Promise<Record<string, unknown>> {
    const interval = this.opts.pollIntervalMs ?? 2000;
    const maxTries = this.opts.pollMaxTries ?? 30;
    for (let i = 0; i < maxTries; i++) {
      const { body } = await this.post(url, null, true); // POST-as-GET
      const obj = body as Record<string, unknown>;
      const status = String(obj.status);
      if (status === want) return obj;
      if (bad.includes(status)) throw new Error(`ACME ${url} → ${status}`);
      await new Promise((r) => setTimeout(r, interval));
    }
    throw new Error(`ACME ${url}: '${want}' 폴링 타임아웃`);
  }

  /**
   * http-01 리스너를 발급 동안만 열어 둔다. 열기가 실패하면(EACCES 등) **그대로 올린다** —
   * 여기서 삼키면 CA가 못 닿아 authz invalid로 돌아오고, 진짜 원인(80포트 권한)이 묻힌다.
   */
  async issue(domains: readonly string[]): Promise<{ certPem: string; keyPem: string }> {
    const ch = this.opts.challenge;
    if (ch.type !== "http-01" || !ch.open) return this.issueInner(domains);
    await ch.open();
    try {
      return await this.issueInner(domains);
    } finally {
      await ch.close?.().catch(() => {});
    }
  }

  private async issueInner(domains: readonly string[]): Promise<{ certPem: string; keyPem: string }> {
    await this.loadDirectory();
    await this.freshNonce();
    await this.newAccount();

    // newOrder
    const { res: orderRes, body: orderBody } = await this.post(this.dir.newOrder, { identifiers: domains.map((d) => ({ type: "dns", value: d })) }, true);
    if (orderRes.status !== 201 && orderRes.status !== 200) throw new Error(`ACME newOrder ${orderRes.status}`);
    const orderUrl = orderRes.headers.get("location") ?? "";
    const order = orderBody as { authorizations: string[]; finalize: string };
    const thumbprint = jwkThumbprint(publicJwk(this.opts.accountKeyPem));

    // 각 authz: 챌린지 게시(정리는 finally에서 — 어느 갈래든 되돌려야 한다)
    const ch = this.opts.challenge;
    const published: { challengeUrl: string; undo: () => Promise<void> }[] = [];
    for (const authzUrl of order.authorizations) {
      const { body } = await this.post(authzUrl, null, true);
      const authz = body as { identifier: { value: string }; challenges: { type: string; url: string; token: string }[] };
      const chal = authz.challenges.find((c) => c.type === ch.type);
      if (!chal) throw new Error(`ACME: ${ch.type} 챌린지 없음 (${authz.identifier.value})`);
      const keyAuth = `${chal.token}.${thumbprint}`;
      if (ch.type === "dns-01") {
        // dns-01은 keyAuthorization의 **SHA-256을 base64url**로 올린다(RFC 8555 §8.4).
        const txtValue = b64url(createHash("sha256").update(keyAuth).digest());
        const fqdn = `_acme-challenge.${authz.identifier.value}`;
        await ch.dns.setTxt(fqdn, txtValue);
        published.push({ challengeUrl: chal.url, undo: () => ch.dns.removeTxt(fqdn, txtValue) });
      } else {
        // http-01은 keyAuthorization **원문**을 그대로 서빙한다(RFC 8555 §8.3) — 해시하면 안 된다.
        const token = chal.token;
        await ch.http.set(token, keyAuth);
        published.push({ challengeUrl: chal.url, undo: () => ch.http.remove(token) });
      }
    }

    try {
      /**
       * dns-01만 전파를 기다린다. http-01은 게시가 곧 유효하므로 대기가 순수 낭비다 —
       * 기본 15초를 그대로 두면 발급마다 이유 없이 15초씩 늘어난다.
       */
      if (ch.type === "dns-01") await new Promise((r) => setTimeout(r, this.opts.dnsPropagationMs ?? 15_000));
      for (const p of published) await this.post(p.challengeUrl, {}, true);
      for (const authzUrl of order.authorizations) await this.pollUntil(authzUrl, "valid", ["invalid", "revoked", "deactivated", "expired"]);

      // finalize(CSR) → order valid → cert 다운로드
      const csr = generateCsr(domains);
      const { res: finRes } = await this.post(order.finalize, { csr: b64url(csr.csrDer) }, true);
      if (finRes.status !== 200) throw new Error(`ACME finalize ${finRes.status}`);
      const finalOrder = await this.pollUntil(orderUrl, "valid", ["invalid"]);
      const certUrl = String(finalOrder.certificate);
      const { body: certBody } = await this.post(certUrl, null, true);
      const certPem = typeof certBody === "string" ? certBody : String(certBody);
      this.log.info("acme cert issued", { domains: [...domains] });
      return { certPem, keyPem: csr.keyPem };
    } finally {
      for (const p of published) await p.undo().catch(() => {});
    }
  }
}

/** ACME로 인증서 1회 발급. 계정 키는 호출자가 영속(재사용 권장). */
export async function requestCertificate(opts: AcmeOptions, domains: readonly string[]): Promise<{ certPem: string; keyPem: string }> {
  return new AcmeSession(opts).issue(domains);
}

export { generateAccountKey };
