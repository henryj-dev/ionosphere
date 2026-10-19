/**
 * 계정 삭제 드레인(SCHEMA §7-7) — 탈퇴한 계정의 메일·자격증명·sieve가 실제로 지워지는가 (2026-10-19 P8).
 *
 * 예전엔 `account-delete`가 status=2로 바꾸기만 하고 지우는 쪽이 없어 데이터가 영구히 남았다.
 * CI의 PG·MySQL(IONOSPHERE_TEST_PG_URL / IONOSPHERE_TEST_MYSQL_URL)에서도 돈다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { ACCOUNT_STATUS, allMigrations, migrate, openMysql, openPostgres, openSqlite, type DbDriver } from "@ionosphere/db";
import { ACCOUNT_DRAIN_DEADLINE_MS, ACCOUNT_DRAIN_GRACE_MS, accountDrainStatus, createAppPassword, createCredential, drainAccount, listDrainingAccounts, Store } from "../src/index.ts";
import { makeAppendInput } from "./helpers.ts";

const SCHEMA = "ionosphere_test_account_drain";

const opened: DbDriver[] = [];
afterEach(async () => {
  while (opened.length > 0) {
    try {
      await opened.pop()!.close();
    } catch {
      /* 이미 닫혔다 */
    }
  }
});
function track(db: DbDriver): DbDriver {
  opened.push(db);
  return db;
}

async function freshPostgres(base: string): Promise<DbDriver> {
  const admin = track(await openPostgres(base));
  await admin.query({ sql: `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE` });
  await admin.query({ sql: `CREATE SCHEMA ${SCHEMA}` });
  const url = new URL(base);
  url.searchParams.set("options", `-c search_path=${SCHEMA}`);
  const db = track(await openPostgres(url.toString()));
  await migrate(db, allMigrations);
  return db;
}

async function freshMysql(base: string): Promise<DbDriver> {
  const admin = track(await openMysql(base));
  await admin.query({ sql: `DROP DATABASE IF EXISTS \`${SCHEMA}\`` });
  await admin.query({ sql: `CREATE DATABASE \`${SCHEMA}\` CHARACTER SET utf8mb4` });
  const url = new URL(base);
  url.pathname = `/${SCHEMA}`;
  const db = track(await openMysql(url.toString()));
  await migrate(db, allMigrations);
  return db;
}

async function freshSqlite(): Promise<DbDriver> {
  const db = track(await openSqlite());
  await migrate(db, allMigrations);
  return db;
}

const dialects: { name: string; open: (() => Promise<DbDriver>) | null }[] = [
  { name: "sqlite", open: freshSqlite },
  { name: "postgres", open: process.env.IONOSPHERE_TEST_PG_URL ? () => freshPostgres(process.env.IONOSPHERE_TEST_PG_URL!) : null },
  { name: "mysql", open: process.env.IONOSPHERE_TEST_MYSQL_URL ? () => freshMysql(process.env.IONOSPHERE_TEST_MYSQL_URL!) : null },
];

/** 계정 하나에 매달린 행 수 — 드레인 뒤 전부 0이어야 한다. */
const OWNED: readonly [string, string][] = [
  ["accounts", "id"],
  ["messages", "account_id"],
  ["mailboxes", "account_id"],
  ["credentials", "account_id"],
  ["sieve_scripts", "account_id"],
  ["principals", "account_id"],
  ["change_log", "account_id"],
  ["modseq_claims", "account_id"],
  ["blob_refs", "account_id"],
  ["message_keywords", "account_id"],
  ["message_addresses", "account_id"],
  ["search_index", "account_id"],
  ["thread_refs", "account_id"],
  ["message_keywords", "account_id"],
  ["message_addresses", "account_id"],
  ["mta_queue", "account_id"],
];

async function ownedCounts(db: DbDriver, accountId: string): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const [table, col] of OWNED) {
    const { rows } = await db.query({ sql: `SELECT COUNT(*) AS n FROM ${table} WHERE ${col} = ?`, params: [accountId] });
    out[table] = Number(rows[0]!.n);
  }
  return out;
}

async function messageSideRows(db: DbDriver, messageIds: readonly string[]): Promise<number> {
  let n = 0;
  for (const id of messageIds) {
    for (const table of ["message_mailbox", "message_text", "message_header_projection"]) {
      const { rows } = await db.query({ sql: `SELECT COUNT(*) AS n FROM ${table} WHERE message_id = ?`, params: [id] });
      n += Number(rows[0]!.n);
    }
  }
  return n;
}

async function markDeleting(db: DbDriver, accountId: string, since: number): Promise<void> {
  await db.batch([{ sql: "UPDATE accounts SET status = ?, deleting_since = ? WHERE id = ?", params: [ACCOUNT_STATUS.deleting, since, accountId] }]);
}

/** 메일·앱 비밀번호·sieve·추가 메일함을 가진 계정. */
async function populatedAccount(db: DbDriver, store: Store, tenantId: string, email: string) {
  const { accountId, mailboxId: inboxId } = await store.createAccount({ tenantId, email });
  await createCredential(db, { accountId, password: "Correct-Horse-9" });
  await createAppPassword(db, accountId, "phone");
  await store.putSieveScript(accountId, "main", 'require "fileinto"; fileinto "Work";');
  const { mailboxId: work } = await store.createMailbox({ accountId, name: "Work" });
  const messageIds: string[] = [];
  for (let i = 0; i < 3; i++) {
    const { messageId } = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: i === 0 ? [inboxId, work] : [inboxId], sizeBytes: 100 + i }));
    messageIds.push(messageId);
  }
  return { accountId, messageIds };
}

for (const d of dialects) {
  describe.skipIf(d.open === null)(`계정 삭제 드레인 — ${d.name}`, () => {
    test("탈퇴한 계정의 메일·자격증명·sieve·메일함을 지우고 계정 행까지 없앤다. 다른 계정은 건드리지 않는다", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const gone = await populatedAccount(db, store, tenantId, "gone@ionosphere.test");
      const kept = await populatedAccount(db, store, tenantId, "kept@ionosphere.test");
      const keptBefore = await ownedCounts(db, kept.accountId);

      await markDeleting(db, gone.accountId, Date.now());
      const r = await drainAccount(db, gone.accountId);
      expect(r).toEqual({ messages: 3, done: true });

      const after = await ownedCounts(db, gone.accountId);
      expect(Object.entries(after).filter(([, n]) => n > 0)).toEqual([]);
      expect(await messageSideRows(db, gone.messageIds)).toBe(0);
      // 이웃 계정은 그대로
      expect(await ownedCounts(db, kept.accountId)).toEqual(keptBefore);
      // 같은 주소로 다시 가입할 수 있다(계정 행이 사라져 유니크 키가 풀렸다)
      await store.createAccount({ tenantId, email: "gone@ionosphere.test" });
    });

    test("활성·정지 계정은 드레인하지 않는다(status=2만)", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const active = await populatedAccount(db, store, tenantId, "active@ionosphere.test");
      const suspended = await populatedAccount(db, store, tenantId, "suspended@ionosphere.test");
      await db.batch([{ sql: "UPDATE accounts SET status = ? WHERE id = ?", params: [ACCOUNT_STATUS.suspended, suspended.accountId] }]);
      const before = [await ownedCounts(db, active.accountId), await ownedCounts(db, suspended.accountId)];

      expect(await drainAccount(db, active.accountId)).toEqual({ messages: 0, done: false });
      expect(await drainAccount(db, suspended.accountId)).toEqual({ messages: 0, done: false });
      expect(await listDrainingAccounts(db)).toEqual([]);
      expect([await ownedCounts(db, active.accountId), await ownedCounts(db, suspended.accountId)]).toEqual(before);
    });

    test("큰 계정은 쪽 상한만큼 지우고 돌아오고, 다음 호출이 이어서 끝낸다", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const { accountId, mailboxId } = await store.createAccount({ tenantId, email: "big@ionosphere.test" });
      for (let i = 0; i < 120; i++) await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [mailboxId] }));
      await markDeleting(db, accountId, Date.now());

      const first = await drainAccount(db, accountId, { maxPages: 1 });
      expect(first.done).toBe(false);
      expect(first.messages).toBe(98);
      const second = await drainAccount(db, accountId, { maxPages: 1 });
      expect(second).toEqual({ messages: 22, done: true });
      expect(Object.values(await ownedCounts(db, accountId)).every((n) => n === 0)).toBe(true);
    });

    test("발송 중(리스 유효) 큐 항목이 있으면 계정 행을 남겨 두고, 리스가 풀리면 끝낸다", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const { accountId } = await store.createAccount({ tenantId, email: "sending@ionosphere.test" });
      const now = Date.now();
      await db.batch([
        {
          sql: `INSERT INTO mta_queue (id, tenant_id, account_id, blob_id, env_from, rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?)`,
          params: ["01QUEUEINFLIGHT00000000000", tenantId, accountId, "c".repeat(64), "sending@ionosphere.test", "x@example.com", "example.com", now, now + 60_000, now],
        },
      ]);
      await markDeleting(db, accountId, now);

      expect((await drainAccount(db, accountId, { now })).done).toBe(false);
      const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM accounts WHERE id = ?", params: [accountId] });
      expect(Number(rows[0]!.n)).toBe(1);
      // 리스 만료 뒤 — 워커가 회수해 다시 보내기 전에 지운다
      expect((await drainAccount(db, accountId, { now: now + 120_000 })).done).toBe(true);
    });

    test("지표: 24시간 마감을 넘긴 계정을 overdue로 센다", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const now = Date.now();
      const { accountId: fresh } = await store.createAccount({ tenantId, email: "fresh@ionosphere.test" });
      const { accountId: stale } = await store.createAccount({ tenantId, email: "stale@ionosphere.test" });
      const { accountId: justNow } = await store.createAccount({ tenantId, email: "justnow@ionosphere.test" });
      await markDeleting(db, fresh, now - ACCOUNT_DRAIN_GRACE_MS - 60_000);
      await markDeleting(db, stale, now - ACCOUNT_DRAIN_DEADLINE_MS - 1);
      await markDeleting(db, justNow, now - 1_000);

      expect(await accountDrainStatus(db, now)).toEqual({ pending: 3, overdue: 1 });
      // 오래된 것부터, 유예(열린 JMAP 세션의 늦은 쓰기를 기다린다)가 지난 것만 드레인한다
      expect(await listDrainingAccounts(db, 10, now)).toEqual([stale, fresh]);
      await drainAccount(db, justNow);
      await drainAccount(db, stale);
      await drainAccount(db, fresh);
      expect(await accountDrainStatus(db, now)).toEqual({ pending: 0, overdue: 0 });
    });
  });
}
