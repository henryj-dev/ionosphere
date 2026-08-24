/**
 * DSN 확장 파라미터 (RFC 3461) — **`NOTIFY=NEVER`를 실제로 존중하는가.**
 *
 * ★파라미터를 받아 놓고 버리면 우리는 사실상 그 요청을 무시하는 서버다. 특히 `NEVER`를
 * 무시하면 메일링리스트가 자기 실패 알림을 되받아 **폭풍**이 된다 — 리스트 소프트웨어가
 * 이 파라미터를 쓰는 이유가 정확히 그것이다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { dsnWanted } from "../src/worker.ts";
import { buildDsn, DSN_ACTION } from "../src/dsn.ts";

describe("dsnWanted (RFC 3461 §4.1)", () => {
  /** ★말하지 않았으면 기본은 `FAILURE,DELAY`다 — 성공 통보는 **요청해야** 간다. */
  test("파라미터가 없으면 실패·지연만 보낸다", () => {
    expect(dsnWanted(null, "failure")).toBe(true);
    expect(dsnWanted(null, "delay")).toBe(true);
    expect(dsnWanted(null, "success")).toBe(false);
    expect(dsnWanted("", "failure")).toBe(true);
  });

  /** ★`NEVER`면 무엇도 보내지 않는다. 이 한 줄이 이 배선의 존재 이유다. */
  test("NEVER는 전부 막는다", () => {
    expect(dsnWanted("NEVER", "failure")).toBe(false);
    expect(dsnWanted("NEVER", "delay")).toBe(false);
    expect(dsnWanted("NEVER", "success")).toBe(false);
  });

  test("나열한 종류만 보낸다", () => {
    expect(dsnWanted("FAILURE", "failure")).toBe(true);
    expect(dsnWanted("FAILURE", "delay")).toBe(false);
    expect(dsnWanted("DELAY", "delay")).toBe(true);
    expect(dsnWanted("SUCCESS,FAILURE", "success")).toBe(true);
    expect(dsnWanted("SUCCESS,FAILURE", "delay")).toBe(false);
  });

  test("대소문자를 구분하지 않는다", () => {
    expect(dsnWanted("failure", "failure")).toBe(true);
    expect(dsnWanted("never", "failure")).toBe(false);
  });
});

describe("Original-Recipient (RFC 3464 §2.3.2)", () => {
  /**
   * ★알리아스·리스트가 주소를 재작성하면 `Final-Recipient`는 발신자가 **모르는 주소**다.
   * 그때 이 줄이 없으면 사람이 "누구에게 실패했는지" 알 수 없다.
   */
  test("ORCPT가 있으면 DSN에 실린다", () => {
    const msg = buildDsn({
      originalEnvelopeFrom: "sender@x.test",
      reportingMta: "mx.test",
      recipients: [
        {
          rcpt: "rewritten@internal.test",
          action: DSN_ACTION.failed,
          status: "5.1.1",
          originalRecipient: "rfc822;original@y.test",
        },
      ],
      originalMessage: new TextEncoder().encode("From: sender@x.test\r\n\r\nbody\r\n"),
    })!;
    const text = new TextDecoder().decode(msg);
    expect(text).toContain("Original-Recipient: rfc822;original@y.test");
    expect(text).toContain("Final-Recipient: rfc822; rewritten@internal.test");
    // 순서 — Original이 Final보다 앞이다(§2.3.2)
    expect(text.indexOf("Original-Recipient")).toBeLessThan(text.indexOf("Final-Recipient"));
  });

  test("ORCPT가 없으면 그 줄이 없다", () => {
    const msg = buildDsn({
      originalEnvelopeFrom: "sender@x.test",
      reportingMta: "mx.test",
      recipients: [{ rcpt: "a@y.test", action: DSN_ACTION.failed, status: "5.1.1" }],
      originalMessage: new TextEncoder().encode("From: sender@x.test\r\n\r\nbody\r\n"),
    })!;
    expect(new TextDecoder().decode(msg).includes("Original-Recipient")).toBe(false);
  });

  /** 값은 헤더에 그대로 실리므로 제어문자가 통과하면 **줄 주입**이다. */
  test("제어문자가 든 값은 한 줄에 머문다", () => {
    const msg = buildDsn({
      originalEnvelopeFrom: "sender@x.test",
      reportingMta: "mx.test",
      recipients: [
        {
          rcpt: "a@y.test",
          action: DSN_ACTION.failed,
          status: "5.1.1",
          originalRecipient: "rfc822;a@y.test\r\nX-Injected: yes",
        },
      ],
      originalMessage: new TextEncoder().encode("From: sender@x.test\r\n\r\nbody\r\n"),
    })!;
    const text = new TextDecoder().decode(msg);
    const line = text.split("\r\n").find((l) => l.startsWith("Original-Recipient"))!;
    expect(line.includes("X-Injected")).toBe(true); // 같은 줄에 남았다(새 헤더가 되지 않았다)
    expect(text.split("\r\n").some((l) => l.startsWith("X-Injected:"))).toBe(false);
  });
});
