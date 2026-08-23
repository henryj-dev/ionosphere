/**
 * DB 기반 maildrop 배타 잠금 (마이그레이션 005 + src/maildrop-lock.ts).
 *
 * 여기서 고정하는 것은 "락이 걸린다"가 아니라 **"두 세션이 동시에 같은 maildrop을 열 수 없다"**와
 * 그 반대편인 **"크래시한 세션이 계정을 영원히 잠그지 않는다"** 두 가지다. 전자가 깨지면
 * 세션 A가 expunge한 메시지를 세션 B가 RETR해 메일이 사라진 것처럼 보이고(RFC 1939 §3 위반),
 * 후자가 깨지면 계정이 POP3로 영영 못 들어온다.
 */
import { afterEach, beforeEach, describe, expect, test } from "@ionosphere/testkit";
import { ulid } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import { DbMaildropLock } from "../src/maildrop-lock.ts";
import { freshDb } from "./helpers.ts";

/** 테스트는 시각을 주입해 결정적으로 만든다(실시간 대기 없이 만료를 재현). */
const TTL_MS = 60_000;
const T0 = 1_700_000_000_000;

let db: DbDriver;
let lock: DbMaildropLock;
let acct: string;

beforeEach(async () => {
  db = await freshDb();
  lock = new DbMaildropLock(db, { ttlMs: TTL_MS });
  acct = ulid();
});

afterEach(async () => {
  await db.close();
});

async function lockRow(accountId: string): Promise<{ owner: string; expiresAt: number } | null> {
  const { rows } = await db.query({ sql: "SELECT owner, expires_at FROM maildrop_locks WHERE account_id = ?", params: [accountId] });
  const row = rows[0];
  return row ? { owner: String(row.owner), expiresAt: Number(row.expires_at) } : null;
}

describe("DbMaildropLock", () => {
  test("같은 계정에 동시 acquire — 정확히 하나만 성공", async () => {
    const results = await Promise.all([
      lock.acquire(acct, "sess-a", T0),
      lock.acquire(acct, "sess-b", T0),
      lock.acquire(acct, "sess-c", T0),
    ]);
    expect(results.filter((ok) => ok)).toHaveLength(1);

    // 이긴 소유자만 행에 남아 있어야 한다(패자가 덮어쓰지 않았음).
    const winner = ["sess-a", "sess-b", "sess-c"][results.indexOf(true)];
    expect(await lockRow(acct)).toEqual({ owner: winner!, expiresAt: T0 + TTL_MS });
  });

  test("release 후에는 다른 소유자가 잡을 수 있다", async () => {
    expect(await lock.acquire(acct, "sess-a", T0)).toBe(true);
    expect(await lock.acquire(acct, "sess-b", T0)).toBe(false);

    await lock.release(acct, "sess-a");
    expect(await lockRow(acct)).toBeNull();

    expect(await lock.acquire(acct, "sess-b", T0 + 1)).toBe(true);
  });

  test("남의 락은 release로 풀 수 없다", async () => {
    expect(await lock.acquire(acct, "sess-a", T0)).toBe(true);

    // [IN-USE]를 받은 세션이 끊기며 release를 부르는 상황 — 첫 세션의 락이 살아 있어야 한다.
    await lock.release(acct, "sess-b");
    expect(await lockRow(acct)).toEqual({ owner: "sess-a", expiresAt: T0 + TTL_MS });
    expect(await lock.acquire(acct, "sess-c", T0 + 1)).toBe(false);

    // 진짜 소유자가 풀면 그때 열린다.
    await lock.release(acct, "sess-a");
    expect(await lock.acquire(acct, "sess-c", T0 + 2)).toBe(true);
  });

  test("살아 있는 락은 탈취 불가, 만료된 락은 탈취 가능", async () => {
    expect(await lock.acquire(acct, "sess-a", T0)).toBe(true);

    // 만료 1ms 전 — 아직 살아 있는 세션이므로 뺏으면 안 된다.
    expect(await lock.acquire(acct, "sess-b", T0 + TTL_MS - 1)).toBe(false);
    expect((await lockRow(acct))?.owner).toBe("sess-a");

    // 만료 시점 — 크래시한 소유자로 간주하고 탈취(계정이 영원히 잠기지 않도록).
    expect(await lock.acquire(acct, "sess-b", T0 + TTL_MS)).toBe(true);
    expect(await lockRow(acct)).toEqual({ owner: "sess-b", expiresAt: T0 + TTL_MS + TTL_MS });

    // 탈취당한 옛 소유자는 이제 아무 권한이 없다.
    expect(await lock.refresh(acct, "sess-a", T0 + TTL_MS)).toBe(false);
    await lock.release(acct, "sess-a");
    expect((await lockRow(acct))?.owner).toBe("sess-b");
  });

  test("계정이 다르면 서로 막지 않는다", async () => {
    const other = ulid();
    expect(await lock.acquire(acct, "sess-a", T0)).toBe(true);
    expect(await lock.acquire(other, "sess-b", T0)).toBe(true);

    await lock.release(acct, "sess-a");
    expect(await lockRow(other)).not.toBeNull();
  });

  test("refresh는 자기 락만 연장한다 — 연장된 락은 원래 만료 시점에도 탈취 불가", async () => {
    expect(await lock.acquire(acct, "sess-a", T0)).toBe(true);

    // 남의 refresh는 실패하고 만료도 건드리지 않는다.
    expect(await lock.refresh(acct, "sess-b", T0 + 1_000)).toBe(false);
    expect((await lockRow(acct))?.expiresAt).toBe(T0 + TTL_MS);

    // 자기 refresh는 리스를 밀어낸다 — 유휴하지 않은 긴 세션이 TTL에 걸려 뺏기지 않도록.
    expect(await lock.refresh(acct, "sess-a", T0 + 30_000)).toBe(true);
    expect((await lockRow(acct))?.expiresAt).toBe(T0 + 30_000 + TTL_MS);
    expect(await lock.acquire(acct, "sess-b", T0 + TTL_MS)).toBe(false);

    // 갱신을 멈추면(크래시) 새 만료 시점 이후엔 정상적으로 탈취된다.
    expect(await lock.acquire(acct, "sess-b", T0 + 30_000 + TTL_MS)).toBe(true);
  });

  test("존재하지 않는 락의 refresh는 false(획득 없이 리스를 만들지 않는다)", async () => {
    expect(await lock.refresh(acct, "sess-a", T0)).toBe(false);
    expect(await lockRow(acct)).toBeNull();
  });
});

describe("만료 락 정리(sweepExpired)", () => {
  test("★다시 로그인하지 않는 계정의 행이 영원히 남지 않는다", async () => {
    const db = await freshDb();
    const lock = new DbMaildropLock(db, { ttlMs: 1000 });
    expect(await lock.acquire("gone-account", "owner-1", 0)).toBe(true);

    // 만료(1000) + 유예(ttl 1000)를 지난 시점
    const swept = await lock.sweepExpired(3000);
    expect(swept).toBe(1);
    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM maildrop_locks" });
    expect(Number(rows[0]!.n)).toBe(0);
    await db.close();
  });

  test("살아 있는 락은 정리하지 않는다", async () => {
    const db = await freshDb();
    const lock = new DbMaildropLock(db, { ttlMs: 1000 });
    await lock.acquire("live-account", "owner-1", 1000);

    expect(await lock.sweepExpired(1500)).toBe(0); // 아직 만료 전
    await db.close();
  });

  test("막 만료된 락은 유예 동안 남긴다 — 곧 재사용될 가능성이 높다", async () => {
    const db = await freshDb();
    const lock = new DbMaildropLock(db, { ttlMs: 1000 });
    await lock.acquire("recent", "owner-1", 0); // expires_at = 1000

    expect(await lock.sweepExpired(1500)).toBe(0); // 만료했지만 유예(1000) 안
    expect(await lock.sweepExpired(2500)).toBe(1); // 유예까지 지남
    await db.close();
  });
});
