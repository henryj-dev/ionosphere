/** LmtpEngine — LHLO/HELO, MAIL/RCPT/DATA, 수신자별 응답, dot-unstuffing. */
import { describe, expect, test } from "@ionosphere/testkit";
import { MAX_RCPT_PER_SESSION, MAX_SMTP_ERRORS_PER_SESSION } from "@ionosphere/core";
import { LmtpEngine, type LmtpAction } from "../src/engine.ts";

const enc = new TextEncoder();
function engine() {
  return new LmtpEngine({ hostname: "lmtp.test" });
}
function feed(e: LmtpEngine, s: string): LmtpAction[] {
  return e.feed(enc.encode(s));
}
function replies(a: LmtpAction[]): string[] {
  return a.filter((x): x is { kind: "reply"; text: string } => x.kind === "reply").map((x) => x.text);
}

describe("LmtpEngine", () => {
  test("greeting + LHLO 멀티라인, HELO/EHLO는 500", () => {
    const e = engine();
    expect(replies(e.greeting())[0]).toBe("220 lmtp.test LMTP ready");
    const caps = replies(feed(e, "LHLO client\r\n"));
    expect(caps[0]).toBe("250-lmtp.test");
    expect(caps).toContain("250-PIPELINING");
    expect(caps[caps.length - 1]).toMatch(/^250 SIZE /);
    expect(replies(feed(e, "EHLO x\r\n"))[0]).toContain("500 5.5.1 LMTP requires LHLO");
  });

  test("RCPT는 verifyRcpt 액션 emit 후 대기 → rcptResult로 재개", () => {
    const e = engine();
    e.greeting();
    feed(e, "LHLO c\r\n");
    expect(replies(feed(e, "MAIL FROM:<s@x.test>\r\n"))[0]).toBe("250 2.1.0 OK");
    const a = feed(e, "RCPT TO:<bob@x.test>\r\n");
    expect(a).toEqual([{ kind: "verifyRcpt", rcpt: "bob@x.test" }]);
    expect(replies(e.rcptResult({ ok: true }))[0]).toBe("250 2.1.5 OK");
  });

  test("수신자별 응답: 2명 수락 → DATA → deliver → 각각 1줄", () => {
    const e = engine();
    e.greeting();
    feed(e, "LHLO c\r\n");
    feed(e, "MAIL FROM:<s@x.test>\r\n");
    feed(e, "RCPT TO:<a@x.test>\r\n");
    e.rcptResult({ ok: true });
    feed(e, "RCPT TO:<b@x.test>\r\n");
    e.rcptResult({ ok: true });
    expect(replies(feed(e, "DATA\r\n"))[0]).toContain("354");
    const afterData = feed(e, "Subject: hi\r\n\r\nbody\r\n.\r\n");
    const deliver = afterData.find((x) => x.kind === "deliver");
    expect(deliver).toBeDefined();
    if (deliver && deliver.kind === "deliver") {
      expect(deliver.env.rcptTo).toEqual(["a@x.test", "b@x.test"]);
      expect(Buffer.from(deliver.env.raw).toString()).toBe("Subject: hi\r\n\r\nbody\r\n");
    }
    // a 성공, b 실패 → 응답 2줄(RCPT 순서)
    const out = replies(
      e.deliverResult([
        { rcpt: "a@x.test", ok: true, code: 250, enhanced: "2.1.5", message: "delivered" },
        { rcpt: "b@x.test", ok: false, code: 552, enhanced: "5.2.2", message: "over quota" },
      ]),
    );
    expect(out).toEqual(["250 2.1.5 delivered", "552 5.2.2 over quota"]);
  });

  test("RCPT 거부 시 그 수신자만 5xx, 나머지 계속", () => {
    const e = engine();
    e.greeting();
    feed(e, "LHLO c\r\n");
    feed(e, "MAIL FROM:<s@x.test>\r\n");
    feed(e, "RCPT TO:<good@x.test>\r\n");
    e.rcptResult({ ok: true });
    feed(e, "RCPT TO:<bad@x.test>\r\n");
    expect(replies(e.rcptResult({ ok: false, code: 550, enhanced: "5.1.1", message: "no such user" }))[0]).toBe("550 5.1.1 no such user");
    // good만 남음 → DATA 후 1줄
    feed(e, "DATA\r\n");
    feed(e, "body\r\n.\r\n");
    const out = replies(e.deliverResult([{ rcpt: "good@x.test", ok: true, code: 250, message: "ok" }]));
    expect(out).toEqual(["250 2.0.0 ok"]);
  });

  test("dot-unstuffing: '..'로 시작한 줄은 점 하나 제거", () => {
    const e = engine();
    e.greeting();
    feed(e, "LHLO c\r\n");
    feed(e, "MAIL FROM:<s@x.test>\r\n");
    feed(e, "RCPT TO:<a@x.test>\r\n");
    e.rcptResult({ ok: true });
    feed(e, "DATA\r\n");
    const a = feed(e, "..dotted line\r\nnormal\r\n.\r\n");
    const deliver = a.find((x) => x.kind === "deliver");
    if (deliver && deliver.kind === "deliver") {
      expect(Buffer.from(deliver.env.raw).toString()).toBe(".dotted line\r\nnormal\r\n");
    }
  });

  test("순서 위반: LHLO 전 MAIL → 503, RCPT 전 DATA → 503", () => {
    const e = engine();
    e.greeting();
    expect(replies(feed(e, "MAIL FROM:<s@x.test>\r\n"))[0]).toContain("503");
    feed(e, "LHLO c\r\n");
    feed(e, "MAIL FROM:<s@x.test>\r\n");
    expect(replies(feed(e, "DATA\r\n"))[0]).toContain("503");
  });

  test("QUIT → 221 + close", () => {
    const e = engine();
    e.greeting();
    const a = feed(e, "QUIT\r\n");
    expect(replies(a)[0]).toContain("221");
    expect(a.some((x) => x.kind === "close")).toBe(true);
  });
});

describe("LmtpEngine — 세션 RCPT·오류 상한 (감사 H-3)", () => {
  // LMTP는 AUTH도 TLS도 없는 표면이라 SMTP와 같은 상한이 더 급하다.

  function ready(): LmtpEngine {
    const e = engine();
    e.greeting();
    feed(e, "LHLO client\r\n");
    feed(e, "MAIL FROM:<a@b.test>\r\n");
    return e;
  }

  test("거절된 RCPT가 누적되면 421로 끊는다 — RSET으로 리셋되지 않는다", () => {
    const e = ready();
    let closedAt = 0;
    for (let i = 1; i <= MAX_SMTP_ERRORS_PER_SESSION + 5; i++) {
      const out = feed(e, `RCPT TO:<guess${i}@victim.test>\r\n`);
      if (out.length === 0) break;
      const res = out.some((a) => a.kind === "verifyRcpt")
        ? e.rcptResult({ ok: false, code: 550, enhanced: "5.1.1", message: "no such user" })
        : [];
      if (res.some((a) => a.kind === "close")) {
        closedAt = i;
        expect(replies(res).join("")).toContain("421 4.7.0 too many errors");
        break;
      }
      feed(e, "RSET\r\n");
      feed(e, "MAIL FROM:<a@b.test>\r\n");
    }
    expect(closedAt).toBe(MAX_SMTP_ERRORS_PER_SESSION + 1);
    expect(feed(e, "RCPT TO:<more@victim.test>\r\n")).toEqual([]);
  });

  test("RCPT 개수 상한 초과는 452(일시)이고 세션은 유지된다", () => {
    const e = ready();
    for (let i = 0; i < MAX_RCPT_PER_SESSION; i++) {
      feed(e, `RCPT TO:<u${i}@b.test>\r\n`);
      e.rcptResult({ ok: true });
    }
    const over = feed(e, "RCPT TO:<over@b.test>\r\n");
    expect(over.some((a) => a.kind === "verifyRcpt")).toBe(false); // 백엔드까지 가지 않는다
    expect(replies(over).join("")).toContain("452 4.5.3 too many recipients");
    expect(over.some((a) => a.kind === "close")).toBe(false);
  });

  test("정상 세션(수신자 여러 명 + 배달)은 상한에 걸리지 않는다", () => {
    const e = ready();
    for (let i = 0; i < 5; i++) {
      feed(e, `RCPT TO:<u${i}@b.test>\r\n`);
      expect(replies(e.rcptResult({ ok: true }))[0]).toContain("250");
    }
    expect(replies(feed(e, "DATA\r\n"))[0]).toContain("354");
    const done = feed(e, "Subject: hi\r\n\r\nbody\r\n.\r\n");
    expect(done.some((a) => a.kind === "deliver")).toBe(true);
    const res = e.deliverResult(
      ["u0@b.test", "u1@b.test", "u2@b.test", "u3@b.test", "u4@b.test"].map((rcpt) => ({
        rcpt,
        ok: true,
        code: 250,
        enhanced: "2.0.0",
        message: "delivered",
      })),
    );
    expect(replies(res)).toHaveLength(5);
    expect(res.some((a) => a.kind === "close")).toBe(false);
  });
});
