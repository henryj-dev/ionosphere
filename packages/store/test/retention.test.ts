/**
 * 보존창 스윕 — 무엇을 지우고 **무엇을 지키는가**.
 *
 * 주석이 "주기 스위퍼가 수렴시킨다"고 약속한 대상들이 하나도 구현돼 있지 않아 전부
 * append-only로 자랐다. 다만 GC는 잘못 지우면 되돌릴 수 없으므로, 이 파일의 절반은
 * **지우지 않아야 하는 것**을 확인한다.
 */
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, MTA_QUEUE_STATUS, type DbDriver } from "@ionosphere/db";
import { runRetention } from "@ionosphere/store";
import { ulid } from "@ionosphere/core";

const DAY = 24 * 60 * 60 * 1000;
const NOW = 1_800_000_000_000;

async function fresh(): Promise<DbDriver> {
  const db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
  return db;
}

async function n(db: DbDriver, sql: string, params: unknown[] = []): Promise<number> {
  const { rows } = await db.query({ sql, params });
  return Number(rows[0]!.n);
}

async function seedAccount(db: DbDriver): Promise<string> {
  const tenantId = ulid();
  const accountId = ulid();
  await db.batch([
    { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?,?,1,?)", params: [tenantId, "t", NOW] },
    {
      sql: `INSERT INTO accounts (id, tenant_id, email, kind, status, modseq, changelog_floor, uidvalidity_last,
              quota_bytes, used_bytes, message_count, state_email, state_mailbox, state_thread, state_submission, state_sieve, created_at)
            VALUES (?,?,?,0,1,100,0,1,0,0,0,0,0,0,0,0,?)`,
      params: [accountId, tenantId, "a@x.test", NOW],
    },
  ]);
  return accountId;
}

describe("보존창 스윕", () => {
  test("오래된 change_log를 지우고 changelog_floor를 그만큼 올린다", async () => {
    const db = await fresh();
    const accountId = await seedAccount(db);
    await db.batch([
      { sql: "INSERT INTO change_log (account_id, modseq, entity, object_id, kind, created_at) VALUES (?,?,0,'m1',1,?)", params: [accountId, 10, NOW - 60 * DAY] },
      { sql: "INSERT INTO change_log (account_id, modseq, entity, object_id, kind, created_at) VALUES (?,?,0,'m2',1,?)", params: [accountId, 20, NOW - 40 * DAY] },
      { sql: "INSERT INTO change_log (account_id, modseq, entity, object_id, kind, created_at) VALUES (?,?,0,'m3',1,?)", params: [accountId, 30, NOW - 1 * DAY] },
    ]);

    const r = await runRetention(db, { now: NOW });
    expect(r.changeLog).toBe(2);
    expect(r.floorsAdvanced).toBe(1);
    expect(await n(db, "SELECT COUNT(*) AS n FROM change_log")).toBe(1);
    // floor는 지워진 것 중 **최대** modseq여야 한다 — 그 이하는 이제 답할 수 없다.
    expect(await n(db, "SELECT changelog_floor AS n FROM accounts WHERE id = ?", [accountId])).toBe(20);
    await db.close();
  });

  /** floor를 내리면 "행은 없는데 답할 수 있다고 주장"하게 된다 — 조용히 틀린 델타다. */
  test("floor는 단조 증가한다(더 높은 값을 되돌리지 않는다)", async () => {
    const db = await fresh();
    const accountId = await seedAccount(db);
    await db.batch([
      { sql: "UPDATE accounts SET changelog_floor = 999 WHERE id = ?", params: [accountId] },
      { sql: "INSERT INTO change_log (account_id, modseq, entity, object_id, kind, created_at) VALUES (?,?,0,'m1',1,?)", params: [accountId, 10, NOW - 60 * DAY] },
    ]);
    await runRetention(db, { now: NOW });
    expect(await n(db, "SELECT changelog_floor AS n FROM accounts WHERE id = ?", [accountId])).toBe(999);
    await db.close();
  });

  test("보존창 안의 thread_refs는 남는다", async () => {
    const db = await fresh();
    const accountId = await seedAccount(db);
    await db.batch([
      { sql: "INSERT INTO thread_refs (account_id, ref_hash, thread_id, created_at) VALUES (?,'old','t1',?)", params: [accountId, NOW - 200 * DAY] },
      { sql: "INSERT INTO thread_refs (account_id, ref_hash, thread_id, created_at) VALUES (?,'new','t2',?)", params: [accountId, NOW - 10 * DAY] },
    ]);
    const r = await runRetention(db, { now: NOW });
    expect(r.threadRefs).toBe(1);
    expect(await n(db, "SELECT COUNT(*) AS n FROM thread_refs")).toBe(1);
    await db.close();
  });

  /**
   * ★큐 보존창은 **가장 긴 레이트리밋 윈도우보다 길어야 한다.** 이 테이블이 곧 발송
   * 카운터라, 짧으면 카운트가 과소평가돼 한도가 뚫린다.
   */
  test("종료된 큐 행만 지우고 재시도 중인 행은 남긴다", async () => {
    const db = await fresh();
    const old = NOW - 30 * DAY;
    const mk = (status: number, createdAt: number): { sql: string; params: unknown[] } => ({
      sql: `INSERT INTO mta_queue (id, tenant_id, account_id, submission_id, blob_id, env_from, verp_token,
              rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, last_error, created_at)
            VALUES (?, 't1', NULL, NULL, 'b', 'f@x.test', 'v', 'r@y.test', 'y.test', ?, 0, ?, NULL, NULL, ?)`,
      params: [ulid(), status, createdAt, createdAt],
    });
    await db.batch([
      mk(MTA_QUEUE_STATUS.done, old),
      mk(MTA_QUEUE_STATUS.bounced, old),
      mk(MTA_QUEUE_STATUS.deferred, old), // 재시도 중 — 오래됐어도 지우면 안 된다
      mk(MTA_QUEUE_STATUS.queued, old),
      mk(MTA_QUEUE_STATUS.done, NOW - 1 * DAY), // 보존창 안
    ]);

    const r = await runRetention(db, { now: NOW });
    expect(r.queue).toBe(2);
    expect(await n(db, "SELECT COUNT(*) AS n FROM mta_queue")).toBe(3);
    expect(await n(db, `SELECT COUNT(*) AS n FROM mta_queue WHERE status IN (${MTA_QUEUE_STATUS.deferred}, ${MTA_QUEUE_STATUS.queued})`)).toBe(2);
    await db.close();
  });

  /**
   * ★`expunged`는 **일부러 손대지 않는다.** QRESYNC의 VANISHED가 거기서 나오는데 IMAP에는
   * 하한을 알릴 장치가 없다 — 지우면 오래 떠나 있던 클라이언트가 "삭제된 적 없다"는 답을
   * 받고 유령 메시지를 영영 들고 있게 된다. 이 테스트는 그 결정을 고정한다.
   */
  test("expunged 툼스톤은 아무리 오래돼도 지우지 않는다", async () => {
    const db = await fresh();
    await db.batch([
      { sql: "INSERT INTO expunged (mailbox_id, uid, modseq, created_at) VALUES ('mbx', 1, 5, ?)", params: [NOW - 3650 * DAY] },
    ]);
    await runRetention(db, { now: NOW });
    expect(await n(db, "SELECT COUNT(*) AS n FROM expunged")).toBe(1);
    await db.close();
  });

  test("두 번 돌려도 같은 결과(멱등)", async () => {
    const db = await fresh();
    const accountId = await seedAccount(db);
    await db.batch([
      { sql: "INSERT INTO change_log (account_id, modseq, entity, object_id, kind, created_at) VALUES (?,?,0,'m1',1,?)", params: [accountId, 10, NOW - 60 * DAY] },
    ]);
    await runRetention(db, { now: NOW });
    const second = await runRetention(db, { now: NOW });
    expect(second.changeLog).toBe(0);
    expect(second.floorsAdvanced).toBe(0);
    await db.close();
  });
});
