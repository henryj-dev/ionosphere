/**
 * 세션 단위 RCPT·오류 상한 (감사 H-3) — `RCPT TO`가 무제한 검증 오라클이 되는 것을 막는다.
 *
 * 배경: 맞으면 250·틀리면 550으로 답이 그대로 새고, SRS 주소 분기는 DB 조회 없이 HMAC 1회라
 * 비용이 거의 0이다. 세션당 RCPT 개수 상한도 연속 오류 상한도 **둘 다 없었다**.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { MAX_RCPT_PER_SESSION, MAX_SMTP_ERRORS_PER_SESSION } from "@ionosphere/core";
import { SmtpEngine, type SmtpAction } from "../src/engine.ts";

function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function text(actions: SmtpAction[]): string {
  return actions
    .filter((a): a is Extract<SmtpAction, { kind: "reply" }> => a.kind === "reply")
    .map((a) => a.text)
    .join("");
}

function greeted(): SmtpEngine {
  const e = new SmtpEngine({ hostname: "mx.test", maxSizeBytes: 1_000_000, tlsAvailable: false });
  e.greeting();
  e.feed(bytes("EHLO probe\r\n"));
  e.feed(bytes("MAIL FROM:<a@b.test>\r\n"));
  return e;
}

/** RCPT 한 건 — outcome을 주입해 트랜잭션을 진행시킨다. 반환은 그 왕복의 전체 응답 텍스트. */
function rcpt(e: SmtpEngine, addr: string, ok: boolean): string {
  const out = e.feed(bytes(`RCPT TO:<${addr}>\r\n`));
  const pending = out.some((a) => a.kind === "rcpt");
  if (!pending) return text(out); // 상한/구문 오류로 백엔드까지 가지 않은 경우
  const res = ok
    ? e.rcptResult({ ok: true })
    : e.rcptResult({ ok: false, code: 550, enhanced: "5.1.1", message: "No such user" });
  return text(out) + text(res);
}

describe("SMTP 세션 오류 상한 — 무차별 대입 오라클 처리량 제한", () => {
  test("거절된 RCPT가 누적되면 421로 끊는다 (RSET으로도 리셋되지 않는다)", () => {
    const e = greeted();
    let closedAt = 0;
    let sawClose = false;

    for (let i = 1; i <= MAX_SMTP_ERRORS_PER_SESSION + 5; i++) {
      // 공격자의 전형적 회피 시도: 매 시도마다 RSET으로 트랜잭션을 초기화한다.
      const out = e.feed(bytes(`RCPT TO:<guess${i}@victim.test>\r\n`));
      if (out.length === 0) break; // 이미 끊긴 세션
      const res = out.some((a) => a.kind === "rcpt")
        ? e.rcptResult({ ok: false, code: 550, enhanced: "5.1.1", message: "No such user" })
        : [];
      if (res.some((a) => a.kind === "close")) {
        sawClose = true;
        closedAt = i;
        expect(text(res)).toContain("421 4.7.0 Too many errors");
        break;
      }
      e.feed(bytes("RSET\r\n"));
      e.feed(bytes("MAIL FROM:<a@b.test>\r\n"));
    }

    expect(sawClose).toBe(true);
    // 상한을 넘긴 직후에 끊겨야 한다 — 세션 하나가 주는 정보량이 여기서 고정된다.
    expect(closedAt).toBe(MAX_SMTP_ERRORS_PER_SESSION + 1);
    // 끊긴 뒤에는 어떤 명령도 처리되지 않는다(오라클이 더 답하지 않는다).
    expect(e.feed(bytes("RCPT TO:<guess999@victim.test>\r\n"))).toEqual([]);
  });

  test("알 수 없는 명령 같은 다른 4xx/5xx도 같은 카운터에 들어간다", () => {
    const e = greeted();
    let sawClose = false;
    for (let i = 0; i <= MAX_SMTP_ERRORS_PER_SESSION + 2; i++) {
      const out = e.feed(bytes("FROBNICATE\r\n"));
      if (out.some((a) => a.kind === "close")) {
        sawClose = true;
        expect(text(out)).toContain("421 4.7.0 Too many errors");
        break;
      }
    }
    expect(sawClose).toBe(true);
  });

  test("정상 세션(수신자 여러 명 + 배달)은 상한에 걸리지 않는다", () => {
    const e = greeted();
    for (let i = 0; i < 5; i++) {
      expect(rcpt(e, `user${i}@b.test`, true)).toContain("250");
    }
    expect(text(e.feed(bytes("DATA\r\n")))).toContain("354");
    const done = e.feed(bytes("Subject: hi\r\n\r\nbody\r\n.\r\n"));
    expect(done.some((a) => a.kind === "deliver")).toBe(true);
    const res = e.deliveryResult({ ok: true, queuedId: "q1" });
    expect(text(res)).toContain("250");
    expect(res.some((a) => a.kind === "close")).toBe(false);
  });
});

describe("SMTP 세션 RCPT 개수 상한", () => {
  test(`${MAX_RCPT_PER_SESSION}건을 넘으면 452(일시)로 거절하고 세션은 유지한다`, () => {
    const e = greeted();
    for (let i = 0; i < MAX_RCPT_PER_SESSION; i++) {
      const out = e.feed(bytes(`RCPT TO:<u${i}@b.test>\r\n`));
      expect(out.some((a) => a.kind === "rcpt")).toBe(true);
      e.rcptResult({ ok: true });
    }
    // 상한 직후: 백엔드까지 가지 않고 452로 끊어낸다(오라클 비용을 태우지 않는다).
    const over = e.feed(bytes("RCPT TO:<over@b.test>\r\n"));
    expect(over.some((a) => a.kind === "rcpt")).toBe(false);
    expect(text(over)).toContain("452 4.5.3 Too many recipients");
    // 5xx가 아니라 4xx인 것이 핵심 — 정상 발신자의 메일이 영구 실패로 버려지면 안 된다.
    expect(text(over)).not.toContain("552");
    expect(over.some((a) => a.kind === "close")).toBe(false);
  });

  test("RSET/새 MAIL FROM으로 RCPT 카운터가 리셋되지 않는다", () => {
    const e = greeted();
    for (let i = 0; i < MAX_RCPT_PER_SESSION; i++) {
      e.feed(bytes(`RCPT TO:<u${i}@b.test>\r\n`));
      e.rcptResult({ ok: true });
    }
    e.feed(bytes("RSET\r\n"));
    e.feed(bytes("MAIL FROM:<a@b.test>\r\n"));
    // 리셋이 카운터를 지운다면 여기서 백엔드 검증(rcpt 액션)이 다시 나온다 = 상한 우회.
    const after = e.feed(bytes("RCPT TO:<again@b.test>\r\n"));
    expect(after.some((a) => a.kind === "rcpt")).toBe(false);
    expect(text(after)).toContain("452 4.5.3");
  });
});
