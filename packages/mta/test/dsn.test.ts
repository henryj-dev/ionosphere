/**
 * DSN 생성 (RFC 3464) — 구조·필드·안전성.
 *
 * 왕복으로 검증한다: 만든 DSN을 우리 MIME 파서로 다시 읽어 구조가 성립하는지 본다.
 * 문자열 비교만 하면 "우리가 만든 것을 우리가 못 읽는" 경우를 놓친다.
 */
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { parseMessage } from "@ionosphere/mime";
import { buildDsn, DSN_ACTION, enhancedStatusFor } from "@ionosphere/mta";

const ORIGINAL = new Uint8Array(
  Buffer.from(
    "From: sender@x.test\r\nTo: nobody@remote.test\r\nSubject: hello\r\n" +
      "Message-ID: <orig@x.test>\r\n\r\nbody line 1\r\nbody line 2\r\n",
  ),
);

const BASE = {
  originalEnvelopeFrom: "sender@x.test",
  reportingMta: "mx.x.test",
  originalMessage: ORIGINAL,
  originalMessageId: "<orig@x.test>",
  now: new Date(Date.UTC(2026, 7, 23, 12, 0, 0)),
  boundary: "BOUND",
};

function text(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("latin1");
}

describe("buildDsn", () => {
  test("영구 실패 — multipart/report 3파트 구조", () => {
    const dsn = buildDsn({
      ...BASE,
      recipients: [
        {
          rcpt: "nobody@remote.test",
          action: DSN_ACTION.failed,
          status: "5.1.1",
          diagnostic: "550 5.1.1 no such user",
          remoteMta: "mx.remote.test",
        },
      ],
    })!;
    const s = text(dsn);

    expect(s).toContain("Content-Type: multipart/report; report-type=delivery-status");
    expect(s).toContain("Content-Type: message/delivery-status");
    expect(s).toContain("Content-Type: message/rfc822-headers");
    expect(s).toContain("Reporting-MTA: dns; mx.x.test");
    expect(s).toContain("Final-Recipient: rfc822; nobody@remote.test");
    expect(s).toContain("Action: failed");
    expect(s).toContain("Status: 5.1.1");
    expect(s).toContain("Diagnostic-Code: smtp; 550 5.1.1 no such user");
    expect(s).toContain("Remote-MTA: dns; mx.remote.test");
    expect(s).toContain("--BOUND--"); // 종료 바운더리
  });

  test("우리 파서로 다시 읽힌다(왕복)", () => {
    const dsn = buildDsn({
      ...BASE,
      recipients: [{ rcpt: "nobody@remote.test", action: DSN_ACTION.failed, status: "5.1.1" }],
    })!;
    const p = parseMessage(dsn);
    expect(p.subject).toBe("Undelivered Mail Returned to Sender");
    expect(p.to[0]!.email).toBe("sender@x.test");
    // 파서는 주소를 소문자로 정규화한다(SCHEMA §2) — 그게 맞는 동작이다.
    expect(p.from[0]!.email).toBe("mailer-daemon@mx.x.test");
    // 스레딩 — 클라이언트가 원 메일과 묶어 보여 줄 수 있어야 한다.
    expect(p.references).toContain("orig@x.test");
  });

  /**
   * ★원문 **전체**가 아니라 헤더만 동봉한다. 25MB 메시지가 실패하면 바운스도 25MB가 되고,
   * 그것이 다시 실패하면 큐가 원문 두 벌을 붙든다.
   */
  test("원문은 헤더만 동봉한다 — 본문은 싣지 않는다", () => {
    const dsn = buildDsn({
      ...BASE,
      recipients: [{ rcpt: "nobody@remote.test", action: DSN_ACTION.failed, status: "5.1.1" }],
    })!;
    const s = text(dsn);
    expect(s).toContain("Subject: hello"); // 원 헤더는 있고
    expect(s).not.toContain("body line 1"); // 본문은 없다
  });

  test("지연 통보는 제목과 Action이 다르다", () => {
    const dsn = buildDsn({
      ...BASE,
      recipients: [{ rcpt: "slow@remote.test", action: DSN_ACTION.delayed, status: "4.3.0" }],
    })!;
    const s = text(dsn);
    expect(s).toContain("Subject: Delivery Status Notification (Delayed)");
    expect(s).toContain("Action: delayed");
    expect(s).toContain("You do not need to resend");
  });

  /**
   * ★이중 바운스 차단의 마지막 겹. 봉투 발신자가 null(`<>`)이면 DSN을 만들지 않는다 —
   * 호출자가 먼저 끊어야 하지만, 실수로 와도 여기서 막는다.
   */
  test("null 발신자에는 DSN을 만들지 않는다", () => {
    expect(buildDsn({ ...BASE, originalEnvelopeFrom: "", recipients: [{ rcpt: "a@b.test", action: DSN_ACTION.failed, status: "5.0.0" }] })).toBe(null);
    expect(buildDsn({ ...BASE, originalEnvelopeFrom: "   ", recipients: [{ rcpt: "a@b.test", action: DSN_ACTION.failed, status: "5.0.0" }] })).toBe(null);
  });

  test("수신자가 없으면 만들지 않는다", () => {
    expect(buildDsn({ ...BASE, recipients: [] })).toBe(null);
  });

  /**
   * ★수신자 주소와 원격 응답 문구는 **공격자가 정하는 값**이다. CR/LF가 그대로 헤더에
   * 들어가면 우리가 만든 메시지가 우리 파서를 속이는 헤더 주입이 된다.
   */
  test("CR/LF 주입을 막는다", () => {
    const dsn = buildDsn({
      ...BASE,
      recipients: [
        {
          rcpt: "evil@x.test\r\nBcc: victim@y.test",
          action: DSN_ACTION.failed,
          status: "5.1.1",
          diagnostic: "550 bad\r\nX-Injected: yes",
        },
      ],
    })!;
    const s = text(dsn);
    /**
     * 지켜야 하는 성질은 "그 문자열이 안 보인다"가 아니라 **"헤더 줄이 되지 않는다"** 다.
     * CR/LF를 공백으로 치환하므로 텍스트는 한 줄 안에 남지만, 줄 선두에 오지 못하면
     * 파서에게 헤더가 아니다. 문자열 부재를 요구하면 정상 진단 문구까지 못 싣는다.
     */
    expect(s.split("\r\n").some((l) => l.startsWith("Bcc:"))).toBe(false);
    expect(s.split("\r\n").some((l) => l.startsWith("X-Injected:"))).toBe(false);
    // 파서가 봐도 주입 헤더가 없어야 한다 — 이것이 최종 판정이다.
    const parsed = parseMessage(dsn);
    expect(parsed.headers.has("x-injected")).toBe(false);
    expect(parsed.headers.has("bcc")).toBe(false);
  });

  test("수신자 여러 명을 한 리포트에 담는다", () => {
    const dsn = buildDsn({
      ...BASE,
      recipients: [
        { rcpt: "a@remote.test", action: DSN_ACTION.failed, status: "5.1.1" },
        { rcpt: "b@remote.test", action: DSN_ACTION.failed, status: "5.2.2" },
      ],
    })!;
    const s = text(dsn);
    expect(s).toContain("Final-Recipient: rfc822; a@remote.test");
    expect(s).toContain("Final-Recipient: rfc822; b@remote.test");
  });
});

describe("enhancedStatusFor", () => {
  test("흔한 코드는 세부까지 매핑한다", () => {
    expect(enhancedStatusFor(550, DSN_ACTION.failed)).toBe("5.1.1");
    expect(enhancedStatusFor(552, DSN_ACTION.failed)).toBe("5.2.2");
    expect(enhancedStatusFor(553, DSN_ACTION.failed)).toBe("5.1.3");
  });

  test("모르는 코드는 클래스만 맞춘다 — 틀린 세부보다 일반값이 낫다", () => {
    expect(enhancedStatusFor(571, DSN_ACTION.failed)).toBe("5.0.0");
    expect(enhancedStatusFor(451, DSN_ACTION.delayed)).toBe("4.3.0");
  });

  test("지연은 코드와 무관하게 4.x다", () => {
    expect(enhancedStatusFor(550, DSN_ACTION.delayed)).toBe("4.1.1");
  });
});
