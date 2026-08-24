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
   * ★2026-08-24에 **뒤집힌 결정**이다. 예전엔 "IMAP에 하한을 알릴 장치가 없다"는 이유로
   * 툼스톤을 영영 두었는데, `mailboxes.expunged_floor`(migration 014)가 그 장치이고
   * `syncSince`가 하한 아래 요청을 차집합으로 답한다(RFC 7162 §3.2.5.2).
   *
   * ★순서가 이 테스트의 핵심이다: **floor를 먼저 올리고 그다음에 지운다.** 반대면
   * "행은 없는데 floor는 낮은" 창이 생기고, 그 사이 QRESYNC가 조용히 "삭제 없음"을
   * 돌려준다 — 클라이언트는 그것이 전부인 줄 안다.
   */
  test("보존창 밖 expunged 툼스톤을 지우고 floor를 올린다", async () => {
    const db = await fresh();
    await db.batch([
      { sql: "INSERT INTO mailboxes (id, account_id, parent_id, name, role, status, uidvalidity, uidnext, highestmodseq, total_count, unread_count, total_bytes, sort_order, subscribed, created_at) VALUES ('mbx', 'acc', '', 'INBOX', 'inbox', 1, 1, 10, 9, 0, 0, 0, 0, 1, ?)", params: [NOW] },
      { sql: "INSERT INTO expunged (mailbox_id, uid, modseq, created_at) VALUES ('mbx', 1, 5, ?)", params: [NOW - 3650 * DAY] },
      { sql: "INSERT INTO expunged (mailbox_id, uid, modseq, created_at) VALUES ('mbx', 2, 9, ?)", params: [NOW] }, // 보존창 안 — 남는다
    ]);
    const r = await runRetention(db, { now: NOW });
    expect(r.expunged).toBe(1);
    expect(r.expungedFloorsAdvanced).toBe(1);
    expect(await n(db, "SELECT COUNT(*) AS n FROM expunged")).toBe(1);
    // floor는 **지운 행의 최대 modseq**여야 한다(컷오프 시각이 아니라) — 그래야 틈이 없다
    expect(await n(db, "SELECT expunged_floor AS n FROM mailboxes WHERE id = 'mbx'")).toBe(5);
    await db.close();
  });

  /** 단조 증가 — 동시에 다른 스윕이 더 올려 뒀다면 되돌리지 않는다. */
  test("expunged_floor는 뒤로 가지 않는다", async () => {
    const db = await fresh();
    await db.batch([
      { sql: "INSERT INTO mailboxes (id, account_id, parent_id, name, role, status, uidvalidity, uidnext, highestmodseq, total_count, unread_count, total_bytes, sort_order, subscribed, expunged_floor, created_at) VALUES ('mbx', 'acc', '', 'INBOX', 'inbox', 1, 1, 10, 9, 0, 0, 0, 0, 1, 100, ?)", params: [NOW] },
      { sql: "INSERT INTO expunged (mailbox_id, uid, modseq, created_at) VALUES ('mbx', 1, 5, ?)", params: [NOW - 3650 * DAY] },
    ]);
    await runRetention(db, { now: NOW });
    expect(await n(db, "SELECT expunged_floor AS n FROM mailboxes WHERE id = 'mbx'")).toBe(100);
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
