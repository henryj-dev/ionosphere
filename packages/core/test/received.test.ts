/**
 * Received 헤더 조립 — RFC 5321 §4.4 / RFC 3848 / §7.6.
 *
 * 이 파일의 중심은 **헤더 주입**이다. heloName은 상대가 EHLO로 주는 값이라 그대로 보간하면
 * 공격자가 헤더를 새로 만든다. 가드가 조립 함수 안에 있어야 호출자가 우회할 수 없다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { buildReceivedHeader, rfc5322Date } from "../src/received.ts";

const AT = new Date(Date.UTC(2026, 6, 28, 6, 12, 3));

function base(over: Partial<Parameters<typeof buildReceivedHeader>[0]> = {}) {
  return buildReceivedHeader({
    transport: "esmtp",
    heloName: "mail.example.com",
    clientIp: "203.0.113.5",
    by: "mx.ionosphere.test",
    id: "01KZ8F3QW2P6VN0R4T7Y9XC5AB",
    authenticated: false,
    date: AT,
    ...over,
  });
}

describe("헤더 주입 방어", () => {
  /**
   * ★이 테스트가 이 파일의 이유다. CRLF가 통과하면 공격자가 Bcc를 심을 수 있다.
   * 가드는 값을 "정제"하지 않고 **통째로 버린다** — 잘라내기는 무엇이 남는지 추론하기 어렵다.
   */
  test("heloName의 CRLF는 헤더를 새로 만들지 못한다", () => {
    const h = base({ heloName: "foo\r\nBcc: victim@evil.test" });
    expect(h.toLowerCase()).not.toContain("bcc:");
    // 위험한 helo는 버려지고 IP만 남는다 — 정보가 줄지언정 형식은 지킨다
    expect(h).toContain("from [203.0.113.5]");
    expect(h).not.toContain("foo");
  });

  test("NUL·제어문자도 막는다 — CR/LF만 막으면 파서가 다른 데서 깨진다", () => {
    for (const bad of [String.fromCharCode(0), String.fromCharCode(1), String.fromCharCode(127)]) {
      const h = base({ heloName: "ok" + bad + "bad" });
      expect(h).not.toContain(bad);
      expect(h).toContain("from [203.0.113.5]");
    }
  });

  test("괄호는 Received 주석 구문을 닫아 버릴 수 있어 거부한다", () => {
    const h = base({ heloName: "evil) by attacker.test (x" });
    expect(h).not.toContain("attacker.test");
  });

  test("clientIp도 같은 가드를 받는다", () => {
    const h = base({ clientIp: "1.2.3.4\r\nX-Injected: 1" });
    expect(h.toLowerCase()).not.toContain("x-injected");
    expect(h).toContain("from mail.example.com");
    expect(h).not.toContain("[1.2.3.4");
  });

  test("수신자 주소로도 주입할 수 없다", () => {
    const h = base({ forRecipient: "a@b.test>\r\nBcc: victim@evil.test" });
    expect(h.toLowerCase()).not.toContain("bcc:");
  });

  test("둘 다 위험하면 from 절을 통째로 생략한다 — 깨진 헤더보다 낫다", () => {
    const h = base({ heloName: "a\r\nb", clientIp: "c\r\nd" });
    expect(h).not.toContain("from ");
    expect(h).toContain("by mx.ionosphere.test");
    // 여전히 유효한 한 줄이어야 한다: CRLF는 폴딩(뒤에 공백)으로만 등장
    for (const line of h.split("\r\n").slice(1)) expect(line.startsWith("\t")).toBe(true);
  });

  test("과도하게 긴 값은 버린다 — 한 값이 헤더 전체를 밀어내지 못하게", () => {
    const h = base({ heloName: "a".repeat(300) });
    expect(h).not.toContain("aaaa");
    expect(h).toContain("from [203.0.113.5]");
  });
});

describe("RFC 3848 with 키워드", () => {
  const cases: [string, { tls?: { protocol: string }; authenticated: boolean }][] = [
    ["ESMTP", { authenticated: false }],
    ["ESMTPA", { authenticated: true }],
    ["ESMTPS", { tls: { protocol: "TLSv1.3" }, authenticated: false }],
    ["ESMTPSA", { tls: { protocol: "TLSv1.3" }, authenticated: true }],
  ];
  for (const [expected, over] of cases) {
    test(`${expected}`, () => {
      // 절은 CRLF+TAB으로 접히므로 뒤에 공백이 아니라 접힘(또는 세미콜론)이 온다.
      expect(base(over)).toMatch(new RegExp(`with ${expected}(\\r\\n|;)`));
    });
  }

  test("LMTP 계열", () => {
    expect(base({ transport: "lmtp", authenticated: false })).toMatch(/with LMTP(\r\n|;)/);
    expect(base({ transport: "lmtp", tls: { protocol: "TLSv1.3" }, authenticated: false })).toMatch(/with LMTPS(\r\n|;)/);
  });
});

describe("RFC 5321 §4.4 / §7.6 — for 절", () => {
  /**
   * §4.4: "If the FOR clause appears, it MUST contain exactly one <path>".
   * §7.6이 이유를 적어 뒀다 — 여러 명일 때 적으면 BCC 수신자 신원이 노출된다.
   * 호출자가 1명일 때만 넘기는 계약이고, 여기서는 넘겼을 때 형식이 맞는지만 본다.
   */
  test("수신자를 주면 <>로 감싸 정확히 하나만 적는다", () => {
    const h = base({ forRecipient: "you@ionosphere.test" });
    expect(h).toContain("for <you@ionosphere.test>");
    expect(h.match(/for </g)).toHaveLength(1);
  });

  test("수신자를 주지 않으면 for 절이 아예 없다", () => {
    expect(base({ forRecipient: undefined })).not.toContain("for <");
  });
});

describe("형식", () => {
  test("전체 모양이 RFC 5321 §4.4 순서를 따른다", () => {
    const h = base({ tls: { protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384" }, forRecipient: "you@ionosphere.test" });
    expect(h).toBe(
      "Received: from mail.example.com ([203.0.113.5])\r\n" +
        "\tby mx.ionosphere.test\r\n" +
        "\twith ESMTPS\r\n" +
        "\tid 01KZ8F3QW2P6VN0R4T7Y9XC5AB\r\n" +
        "\t(version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384)\r\n" +
        "\tfor <you@ionosphere.test>;\r\n" +
        "\t" +
        rfc5322Date(AT),
    );
  });

  test("헤더는 항상 Received: 로 시작하고 세미콜론 뒤에 날짜가 온다", () => {
    const h = base();
    expect(h.startsWith("Received: ")).toBe(true);
    expect(h).toContain(";\r\n\t");
  });

  test("접힌 줄은 모두 공백류로 시작한다 — 아니면 새 헤더가 된다", () => {
    const lines = base({ tls: { protocol: "TLSv1.3" }, forRecipient: "a@b.test" }).split("\r\n");
    for (const line of lines.slice(1)) expect(/^[ \t]/.test(line)).toBe(true);
  });
});

describe("rfc5322Date", () => {
  test("RFC 5322 date-time 형식", () => {
    // TZ에 따라 오프셋이 달라지므로 구조만 검사한다(§4.4는 로컬시각+오프셋을 SHOULD로 둔다)
    expect(rfc5322Date(AT)).toMatch(/^[A-Z][a-z]{2}, \d{1,2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} [+-]\d{4}$/);
  });

  test("UTC 환경에서는 +0000", () => {
    if (new Date().getTimezoneOffset() === 0) expect(rfc5322Date(AT)).toBe("Tue, 28 Jul 2026 06:12:03 +0000");
  });
});
