/**
 * 수신 인증 파이프라인 조립 테스트 — 통제된 리졸버로 실세계 두 모양을 재현:
 *  (1) 카카오 모양: SPF pass, DKIM 없음, DMARC via SPF 정렬
 *  (2) Gmail 모양: DKIM 서명 pass, DMARC via DKIM 정렬
 * 실 DNS 검증은 라이브 서버 배포로 별도 확인.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { DnsNotFoundError, dkimSign, generateDkimKeyPair, type DnsResolver } from "@ionosphere/mail-auth";
import { parseMessage } from "@ionosphere/mime";
import { prependAuthResults, runInboundAuth } from "../src/inbound-auth.ts";

/** Map 기반 통제 리졸버 — 없는 이름은 NotFound. */
function fakeResolver(txt: Record<string, string[]>): DnsResolver {
  const get = (name: string): string[] => {
    const v = txt[name.toLowerCase()];
    if (!v) throw new DnsNotFoundError(name);
    return v;
  };
  const nf = (): never => {
    throw new DnsNotFoundError("none");
  };
  return {
    txt: async (n) => get(n),
    mx: async () => nf(),
    a: async () => nf(),
    aaaa: async () => nf(),
    ptr: async () => nf(),
  };
}

const enc = (s: string) => new TextEncoder().encode(s);

describe("수신 인증 파이프라인", () => {
  test("카카오 모양: SPF pass + DKIM 없음 + DMARC via SPF 정렬", async () => {
    const raw = enc(
      [
        "From: 장효찬 <jang@example.test>",
        "To: you@ionosphere.test",
        "Subject: hi",
        "Message-ID: <1@example.test>",
        "",
        "본문",
      ].join("\r\n"),
    );
    const resolver = fakeResolver({
      "example.test": ["v=spf1 ip4:192.0.2.10 -all"],
      "_dmarc.example.test": ["v=DMARC1; p=quarantine"],
    });
    const auth = await runInboundAuth(
      {
        raw,
        parsed: parseMessage(raw),
        clientIp: "192.0.2.10",
        heloName: "mail.example.test",
        mailFrom: "jang@example.test",
        authservId: "mx.ionosphere.test",
      },
      resolver,
    );
    expect(auth.summary.spf).toBe("pass");
    expect(auth.summary.dkim).toBe("none");
    expect(auth.summary.dmarc).toBe("pass"); // SPF 도메인=From 도메인 정렬
    expect(auth.authResults).toContain("spf=pass");
    expect(auth.authResults).toContain("dmarc=pass");
    // 저장 코드 (SCHEMA §9-3): 1 pass, 0 none
    expect(auth.codes).toEqual({ spf: 1, dkim: 0, dmarc: 1 });
  });

  test("SPF fail (IP 불일치) → DMARC fail", async () => {
    const raw = enc(["From: x@example.test", "To: a@b.c", "", "m"].join("\r\n"));
    const resolver = fakeResolver({
      "example.test": ["v=spf1 ip4:192.0.2.10 -all"],
      "_dmarc.example.test": ["v=DMARC1; p=reject"],
    });
    const auth = await runInboundAuth(
      { raw, parsed: parseMessage(raw), clientIp: "203.0.113.99", heloName: "h", mailFrom: "x@example.test", authservId: "mx.ionosphere.test" },
      resolver,
    );
    expect(auth.summary.spf).toBe("fail");
    expect(auth.summary.dmarc).toBe("fail");
    expect(auth.codes.spf).toBe(2);
  });

  test("Gmail 모양: DKIM 서명 pass + DMARC via DKIM 정렬", async () => {
    const { privateKeyPem, dnsRecord } = generateDkimKeyPair("ed25519-sha256");
    const base = ["From: sender@example.test", "To: you@ionosphere.test", "Subject: signed", "Message-ID: <2@example.test>", "", "signed body"].join("\r\n");
    const sigHeader = dkimSign(enc(base), {
      domain: "example.test",
      selector: "sel1",
      privateKey: privateKeyPem,
      algorithm: "ed25519-sha256",
    });
    const raw = enc(sigHeader + "\r\n" + base);
    const resolver = fakeResolver({
      "sel1._domainkey.example.test": [dnsRecord],
      "_dmarc.example.test": ["v=DMARC1; p=reject"],
      // SPF는 없음(NotFound → none) — DKIM만으로 DMARC 통과해야 함
    });
    const auth = await runInboundAuth(
      { raw, parsed: parseMessage(raw), clientIp: "198.51.100.7", heloName: "h", mailFrom: "sender@example.test", authservId: "mx.ionosphere.test" },
      resolver,
    );
    expect(auth.summary.dkim).toBe("pass");
    expect(auth.summary.dmarc).toBe("pass"); // DKIM d=example.test 정렬
    expect(auth.authResults).toContain("dkim=pass");
    expect(auth.codes.dkim).toBe(1);
  });

  test("prependAuthResults: 헤더가 원문 앞에 붙고 원본 바이트 보존", () => {
    const raw = enc("From: a@b.c\r\n\r\nbody");
    // authResults는 이미 authserv-id로 시작 (buildAuthenticationResults 규약)
    const out = prependAuthResults("mx.ionosphere.test; spf=pass smtp.mailfrom=a@b.c", raw);
    const s = Buffer.from(out).toString("utf8");
    expect(s.startsWith("Authentication-Results: mx.ionosphere.test; spf=pass")).toBe(true);
    expect(s.endsWith("From: a@b.c\r\n\r\nbody")).toBe(true);
    // authserv-id가 한 번만 (중복 접두 방지 회귀 테스트)
    expect(s.match(/mx\.ionosphere\.test/g)?.length).toBe(1);
  });
});
