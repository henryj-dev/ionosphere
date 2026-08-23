/**
 * Received-SPF (RFC 7208 §9.1).
 *
 * A-R과 함께 내는 이유는 §9가 두 방식을 나란히 제시하며 "Both are in common use"라고 하고,
 * §9.2가 A-R은 "provide less information than the Received-SPF field"라고 짚기 때문이다.
 * Received-SPF의 목적은 **판정을 재구성**할 수 있게 하는 것이라 client-ip·helo·envelope-from을 담는다.
 *
 * §9.1의 MUST: "SPF verifiers MUST make sure that the Received-SPF header field does not contain
 * invalid characters, is not excessively long, and does not contain malicious data that has been
 * provided by the sender." — 이 셋이 전부 상대가 정하는 값이라 주입 방어가 이 파일의 중심이다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { buildReceivedSpf } from "../src/inbound-auth.ts";

function base(over: Partial<Parameters<typeof buildReceivedSpf>[0]> = {}) {
  return buildReceivedSpf({
    result: "pass",
    receiver: "mx.ionosphere.test",
    clientIp: "203.0.113.5",
    heloName: "mail.example.com",
    mailFrom: "user@example.com",
    domain: "example.com",
    ...over,
  });
}

/** 언폴딩 — 키-값은 접힌 둘째 줄에 있다. */
function flat(h: string): string {
  return h.replace(/\r\n[ \t]+/g, " ");
}

describe("RFC 7208 §9.1 형식", () => {
  test("결과 + 주석 + 키-값 목록", () => {
    const h = flat(base());
    expect(h.startsWith("Received-SPF: pass (")).toBe(true);
    expect(h).toContain("mx.ionosphere.test: domain of user@example.com designates 203.0.113.5 as permitted sender");
  });

  /** §9.1: "at least client-ip, helo, and, if the MAIL FROM identity was checked, envelope-from". */
  test("재구성에 필요한 키가 모두 있다", () => {
    const h = flat(base());
    expect(h).toContain("receiver=mx.ionosphere.test");
    expect(h).toContain("client-ip=203.0.113.5");
    expect(h).toContain('envelope-from="user@example.com"');
    expect(h).toContain("helo=mail.example.com");
    expect(h).toContain("identity=mailfrom");
  });

  test("결과값 7종 모두 고유한 주석을 낸다", () => {
    const results = ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"] as const;
    const comments = new Set<string>();
    for (const result of results) {
      const h = flat(base({ result }));
      expect(h.startsWith(`Received-SPF: ${result} (`)).toBe(true);
      comments.add(h.slice(h.indexOf("("), h.indexOf(")") + 1));
    }
    // 주석이 겹치면 결과를 구분해 읽을 수 없다
    expect(comments.size).toBe(results.length);
  });

  /** 널 리턴패스(바운스)는 MAIL FROM을 검사할 수 없어 HELO 신원으로 판정한다(§2.3). */
  test("널 리턴패스는 identity=helo, envelope-from=<>", () => {
    const h = flat(base({ mailFrom: "" }));
    expect(h).toContain("identity=helo");
    expect(h).toContain('envelope-from="<>"');
    // 주석의 발신자 자리는 검사한 도메인으로 메운다
    expect(h).toContain("example.com");
  });

  test("접힌 줄은 공백류로 시작한다 — 아니면 새 헤더가 된다", () => {
    for (const line of base().split("\r\n").slice(1)) expect(/^[ \t]/.test(line)).toBe(true);
  });
});

describe("주입 방어 (§9.1 MUST)", () => {
  test("helo의 CRLF는 헤더를 새로 만들지 못한다", () => {
    const h = base({ heloName: "evil\r\nBcc: victim@evil.test" });
    expect(h.toLowerCase()).not.toContain("bcc:");
    expect(h).not.toContain("helo=evil");
  });

  test("envelope-from의 따옴표는 quoted-string을 깨지 못한다", () => {
    const h = base({ mailFrom: 'a"@x.test' });
    // 위험한 값은 버리고 <>로 떨어진다 — 깨진 헤더보다 정보가 없는 헤더가 낫다
    expect(h).toContain('envelope-from="<>"');
    expect(h).not.toContain('a"@x.test');
  });

  test("괄호는 주석 구문을 닫아 버리므로 거부한다", () => {
    const h = base({ heloName: "x) evil=1 (" });
    expect(h).not.toContain("evil=1");
  });

  test("clientIp에도 같은 가드가 걸린다", () => {
    const h = base({ clientIp: "1.2.3.4\r\nX-Injected: 1" });
    expect(h.toLowerCase()).not.toContain("x-injected");
    expect(h).not.toContain("client-ip=1.2.3.4");
  });

  test("과도하게 긴 값은 버린다 — 한 값이 헤더를 밀어내지 못하게", () => {
    const h = base({ heloName: "a".repeat(300) });
    expect(h).not.toContain("aaaa");
  });

  /** 값이 전부 위험해도 형식은 유효해야 한다 — 그래야 파서가 나머지를 읽는다. */
  test("모든 외부 값이 위험해도 유효한 한 줄이 나온다", () => {
    const h = base({ heloName: "a\r\nb", clientIp: "c\r\nd", mailFrom: 'e"f' });
    expect(h.startsWith("Received-SPF: pass (")).toBe(true);
    for (const line of h.split("\r\n").slice(1)) expect(/^[ \t]/.test(line)).toBe(true);
    expect(h).toContain("receiver=mx.ionosphere.test");
  });
});
