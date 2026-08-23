import { describe, expect, test } from "@ionosphere/testkit";
import { checkGreylist, type GreylistInput } from "../src/greylist.ts";
import { freshDb } from "./helpers.ts";

const DELAY_MS = 60_000;
const EXPIRE_MS = 36 * 60 * 60 * 1000;

function input(overrides: Partial<GreylistInput> = {}): GreylistInput {
  return { ip: "192.0.2.10", mailFrom: "alice@example.com", rcpt: "bob@example.net", ...overrides };
}

describe("checkGreylist", () => {
  test("첫 목격 → defer(retryAfterMs=delay)", async () => {
    const db = await freshDb();
    const result = await checkGreylist(db, input(), { now: 1_000_000 });
    expect(result).toEqual({ action: "defer", retryAfterMs: DELAY_MS });
    await db.close();
  });

  test("즉시 재방문(now 동일) → 다시 defer", async () => {
    const db = await freshDb();
    const now = 1_000_000;
    await checkGreylist(db, input(), { now });
    const result = await checkGreylist(db, input(), { now });
    expect(result).toEqual({ action: "defer", retryAfterMs: DELAY_MS });
    await db.close();
  });

  test("delay 경과 후 재방문 → accept", async () => {
    const db = await freshDb();
    const firstSeen = 1_000_000;
    await checkGreylist(db, input(), { now: firstSeen });
    const result = await checkGreylist(db, input(), { now: firstSeen + DELAY_MS });
    expect(result).toEqual({ action: "accept" });
    await db.close();
  });

  test("delay 경과 직전 재방문 → 남은 시간만큼 defer", async () => {
    const db = await freshDb();
    const firstSeen = 1_000_000;
    await checkGreylist(db, input(), { now: firstSeen });
    const result = await checkGreylist(db, input(), { now: firstSeen + DELAY_MS - 10_000 });
    expect(result).toEqual({ action: "defer", retryAfterMs: 10_000 });
    await db.close();
  });

  test("spfPass=true → 기록 없이 즉시 accept", async () => {
    const db = await freshDb();
    const result = await checkGreylist(db, input({ spfPass: true }), { now: 1_000_000 });
    expect(result).toEqual({ action: "accept" });

    const { rows } = await db.query({ sql: "SELECT * FROM dedup_tracking", params: [] });
    expect(rows.length).toBe(0);
    await db.close();
  });

  test("만료된 행 → 다시 최초 목격으로 취급(defer)", async () => {
    const db = await freshDb();
    const firstSeen = 1_000_000;
    await checkGreylist(db, input(), { now: firstSeen });
    // expireMs를 지나 만료된 뒤 재방문 — 이 시점엔 delay도 이미 지났지만 만료가 우선.
    const afterExpiry = firstSeen + EXPIRE_MS + 1;
    const result = await checkGreylist(db, input(), { now: afterExpiry });
    expect(result).toEqual({ action: "defer", retryAfterMs: DELAY_MS });
    await db.close();
  });

  test("서로 다른 트리플은 독립적으로 추적된다", async () => {
    const db = await freshDb();
    const now = 1_000_000;
    const a = await checkGreylist(db, input({ rcpt: "bob@example.net" }), { now });
    const b = await checkGreylist(db, input({ rcpt: "carol@example.net" }), { now: now + DELAY_MS });
    expect(a).toEqual({ action: "defer", retryAfterMs: DELAY_MS });
    // b는 서로 다른 트리플의 첫 목격이므로 now가 delay만큼 지났어도 defer.
    expect(b).toEqual({ action: "defer", retryAfterMs: DELAY_MS });
    await db.close();
  });

  test("커스텀 delayMs/expireMs 옵션 존중", async () => {
    const db = await freshDb();
    const now = 1_000_000;
    const opts = { delayMs: 5_000, expireMs: 60_000, now };
    const first = await checkGreylist(db, input(), opts);
    expect(first).toEqual({ action: "defer", retryAfterMs: 5_000 });
    const second = await checkGreylist(db, input(), { ...opts, now: now + 5_000 });
    expect(second).toEqual({ action: "accept" });
    await db.close();
  });
});
