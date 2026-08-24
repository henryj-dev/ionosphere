/**
 * Sieve `vacation`(RFC 5230) — **보내지 않을 이유**가 이 파일의 대부분이다.
 *
 * 자동 응답에서 어려운 것은 보내는 쪽이 아니라 멈추는 쪽이다. 잘못 보내면
 *  · 상대도 자동 응답이면 **무한 루프**
 *  · 메일링리스트에 답하면 **전원에게** 부재 알림
 *  · 바운스에 답하면 그 답이 다시 바운스돼 메일 폭풍
 * 이 된다. §4.6의 게이트를 한 줄씩 고정한다.
 */
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { claimVacationReply } from "@ionosphere/store";
import { parseMessage } from "@ionosphere/mime";
import { runSieve, type VacationRequest } from "@ionosphere/sieve";
import { buildVacationReply, decideVacation } from "../src/vacation.ts";

const OWN = ["me@x.test"];

function msg(extra: string, to = "me@x.test"): ReturnType<typeof parseMessage> {
  return parseMessage(
    new Uint8Array(Buffer.from(`From: friend@y.test\r\nTo: ${to}\r\nSubject: hi\r\nMessage-ID: <o@y.test>\r\n${extra}\r\nbody\r\n`)),
  );
}

const REQ: VacationRequest = {
  reason: "I am away until Monday.",
  days: 7,
  subject: null,
  from: null,
  addresses: [],
  handle: null,
  mime: false,
};

describe("vacation 파싱", () => {
  test("태그를 위치로 읽는다 — 본문이 제목으로 새지 않는다", () => {
    const r = runSieve('require ["vacation"];\nvacation :days 3 :subject "Away" "본문입니다";\n', {
      headers: new Map(), envelopeFrom: "a@y.test", envelopeTo: ["me@x.test"], size: 10,
    });
    expect(r.vacation?.reason).toBe("본문입니다");
    expect(r.vacation?.subject).toBe("Away");
    expect(r.vacation?.days).toBe(3);
  });

  /** ★`:mime`은 **값이 없는 태그**다 — 다음 인자를 소비하면 본문이 사라진다. */
  test("값 없는 태그(:mime)가 본문을 삼키지 않는다", () => {
    const r = runSieve('require ["vacation"];\nvacation :mime "본문입니다";\n', {
      headers: new Map(), envelopeFrom: "a@y.test", envelopeTo: ["me@x.test"], size: 10,
    });
    expect(r.vacation?.mime).toBe(true);
    expect(r.vacation?.reason).toBe("본문입니다");
  });

  test("태그 없이 쓰면 기본값(7일)이고 subject는 null이다", () => {
    const r = runSieve('require ["vacation"];\nvacation "away";\n', {
      headers: new Map(), envelopeFrom: "a@y.test", envelopeTo: ["me@x.test"], size: 10,
    });
    expect(r.vacation?.days).toBe(7);
    expect(r.vacation?.subject).toBe(null);
    expect(r.vacation?.reason).toBe("away");
  });

  /** §4.3 — 자동 응답은 배달에 더해지는 것이지 배달을 대신하지 않는다. */
  test("vacation은 암묵 keep을 취소하지 않는다", () => {
    const r = runSieve('require ["vacation"];\nvacation "away";\n', {
      headers: new Map(), envelopeFrom: "a@y.test", envelopeTo: ["me@x.test"], size: 10,
    });
    expect(r.keep).toBe(true);
  });

  test("거절과 함께 쓰면 자동 응답은 하지 않는다", () => {
    const r = runSieve('require ["vacation", "reject"];\nvacation "away";\nreject "no";\n', {
      headers: new Map(), envelopeFrom: "a@y.test", envelopeTo: ["me@x.test"], size: 10,
    });
    expect(r.reject).toBe("no");
    expect(r.vacation).toBe(null); // 받지 않겠다면서 답장하는 것은 모순이다
  });
});

describe("vacation 루프 방지 (§4.6)", () => {
  test("정상 메일에는 보낸다", () => {
    const d = decideVacation({ request: REQ, parsed: msg(""), envelopeFrom: "friend@y.test", ownAddresses: OWN });
    expect(d.send).toBe(true);
  });

  test("null 발신자(바운스)에는 보내지 않는다", () => {
    const d = decideVacation({ request: REQ, parsed: msg(""), envelopeFrom: "", ownAddresses: OWN });
    expect(d).toEqual({ send: false, reason: "null-sender" });
  });

  /** 우리 DSN도 이 헤더를 달고 나간다 — 이 검사가 없으면 우리 바운스에 우리 부재 응답이 붙는다. */
  test("Auto-Submitted가 있으면 보내지 않는다", () => {
    const d = decideVacation({
      request: REQ, parsed: msg("Auto-Submitted: auto-replied\r"), envelopeFrom: "friend@y.test", ownAddresses: OWN,
    });
    expect(d).toEqual({ send: false, reason: "auto-submitted" });
  });

  test("Auto-Submitted: no는 사람이 보낸 것이다", () => {
    const d = decideVacation({
      request: REQ, parsed: msg("Auto-Submitted: no\r"), envelopeFrom: "friend@y.test", ownAddresses: OWN,
    });
    expect(d.send).toBe(true);
  });

  test("메일링리스트에는 보내지 않는다", () => {
    for (const h of ["List-Id: <l.y.test>", "List-Post: <mailto:l@y.test>", "List-Unsubscribe: <x>"]) {
      const d = decideVacation({ request: REQ, parsed: msg(h + "\r"), envelopeFrom: "friend@y.test", ownAddresses: OWN });
      expect(d).toEqual({ send: false, reason: "mailing-list" });
    }
  });

  test("Precedence: bulk/list/junk에는 보내지 않는다", () => {
    for (const v of ["bulk", "list", "junk"]) {
      const d = decideVacation({ request: REQ, parsed: msg(`Precedence: ${v}\r`), envelopeFrom: "friend@y.test", ownAddresses: OWN });
      expect(d).toEqual({ send: false, reason: "bulk-precedence" });
    }
  });

  test("자기 자신에게는 보내지 않는다", () => {
    const d = decideVacation({ request: REQ, parsed: msg(""), envelopeFrom: "me@x.test", ownAddresses: OWN });
    expect(d).toEqual({ send: false, reason: "self" });
  });

  /**
   * ★수신자 헤더에 내 주소가 없으면 이 메일은 나를 **직접 향한 것이 아니다** —
   * 리스트 헤더가 없는 리스트, Bcc 대량 발송, 캐치올이 여기 걸린다.
   */
  test("To/Cc에 내 주소가 없으면 보내지 않는다", () => {
    const d = decideVacation({
      request: REQ, parsed: msg("", "someone-else@z.test"), envelopeFrom: "friend@y.test", ownAddresses: OWN,
    });
    expect(d).toEqual({ send: false, reason: "not-addressed-to-me" });
  });

  test(":addresses로 추가 주소를 인정한다", () => {
    const d = decideVacation({
      request: { ...REQ, addresses: ["alias@x.test"] },
      parsed: msg("", "alias@x.test"),
      envelopeFrom: "friend@y.test",
      ownAddresses: OWN,
    });
    expect(d.send).toBe(true);
  });
});

describe("vacation 중복 억제 (§4.5)", () => {
  test("같은 상대에게는 :days 안에 한 번만", async () => {
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    const args = { accountId: "acct", handle: "h1", recipient: "friend@y.test", days: 7 };
    expect(await claimVacationReply(db, args)).toBe(true);
    expect(await claimVacationReply(db, args)).toBe(false);
    expect(await claimVacationReply(db, args)).toBe(false);
    await db.close();
  });

  test("다른 상대는 각자 한 번씩 받는다", async () => {
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    expect(await claimVacationReply(db, { accountId: "acct", handle: "h1", recipient: "a@y.test", days: 7 })).toBe(true);
    expect(await claimVacationReply(db, { accountId: "acct", handle: "h1", recipient: "b@y.test", days: 7 })).toBe(true);
    await db.close();
  });

  test("주소는 대소문자를 구분하지 않는다", async () => {
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    expect(await claimVacationReply(db, { accountId: "a", handle: "h", recipient: "Friend@Y.test", days: 7 })).toBe(true);
    expect(await claimVacationReply(db, { accountId: "a", handle: "h", recipient: "friend@y.test", days: 7 })).toBe(false);
    await db.close();
  });

  test(":days가 지나면 다시 보낸다", async () => {
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    const t0 = 1_800_000_000_000;
    const args = { accountId: "acct", handle: "h1", recipient: "friend@y.test", days: 1 };
    expect(await claimVacationReply(db, { ...args, now: t0 })).toBe(true);
    expect(await claimVacationReply(db, { ...args, now: t0 + 60_000 })).toBe(false);
    expect(await claimVacationReply(db, { ...args, now: t0 + 2 * 24 * 3600_000 })).toBe(true);
    await db.close();
  });

  /** 계정 경계 — 다른 계정의 응답 이력이 판정에 섞이면 안 된다. */
  test("계정이 다르면 별개다", async () => {
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    expect(await claimVacationReply(db, { accountId: "a1", handle: "h", recipient: "f@y.test", days: 7 })).toBe(true);
    expect(await claimVacationReply(db, { accountId: "a2", handle: "h", recipient: "f@y.test", days: 7 })).toBe(true);
    await db.close();
  });

  /** §4.4 — 스크립트를 고쳐도 핸들이 같으면 억제가 이어지고, 다르면 새로 센다. */
  test("핸들이 다르면 새로 센다", async () => {
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    expect(await claimVacationReply(db, { accountId: "a", handle: "vac2026a", recipient: "f@y.test", days: 7 })).toBe(true);
    expect(await claimVacationReply(db, { accountId: "a", handle: "vac2026b", recipient: "f@y.test", days: 7 })).toBe(true);
    await db.close();
  });
});

describe("vacation 응답 조립", () => {
  test("Auto-Submitted를 달아 상대 자동응답기를 멈춘다", () => {
    const out = Buffer.from(buildVacationReply({ request: REQ, parsed: msg(""), to: "friend@y.test", from: "me@x.test" })).toString("utf8");
    expect(out).toContain("Auto-Submitted: auto-replied");
    expect(out).toContain("Precedence: bulk");
    expect(out).toContain("To: friend@y.test");
    expect(out).toContain("I am away until Monday.");
  });

  test("제목이 없으면 원 제목에 Auto:를 붙인다", () => {
    const out = Buffer.from(buildVacationReply({ request: REQ, parsed: msg(""), to: "f@y.test", from: "me@x.test" })).toString("utf8");
    expect(out).toContain("Subject: Auto: hi");
  });

  test("원 메일과 스레딩된다", () => {
    const out = Buffer.from(buildVacationReply({ request: REQ, parsed: msg(""), to: "f@y.test", from: "me@x.test" })).toString("utf8");
    expect(out).toContain("In-Reply-To: <o@y.test>");
  });

  /** 값의 출처가 사용자 스크립트와 원 메일이라 헤더 주입이 성립하면 안 된다. */
  test("CR/LF 주입을 막는다", () => {
    const out = Buffer.from(
      buildVacationReply({
        request: { ...REQ, subject: "x\r\nBcc: victim@z.test" },
        parsed: msg(""), to: "f@y.test", from: "me@x.test",
      }),
    ).toString("utf8");
    expect(out.split("\r\n").some((l) => l.startsWith("Bcc:"))).toBe(false);
    expect(parseMessage(new Uint8Array(Buffer.from(out, "utf8"))).headers.has("bcc")).toBe(false);
  });

  test(":mime이면 Content-Type을 덧붙이지 않는다", () => {
    const req = { ...REQ, mime: true, reason: 'Content-Type: text/html\r\n\r\n<p>away</p>' };
    const out = Buffer.from(buildVacationReply({ request: req, parsed: msg(""), to: "f@y.test", from: "me@x.test" })).toString("utf8");
    expect(out).toContain("Content-Type: text/html");
    expect(out).not.toContain("text/plain");
  });
});
