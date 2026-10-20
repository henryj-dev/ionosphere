/**
 * LDAP/AD 외부 키의 최초 주인 기록 — 끊거나 계정이 탈퇴해도 같은 키를 다른 계정에 잇지 못한다.
 *
 * CI의 PG·MySQL(IONOSPHERE_TEST_PG_URL / IONOSPHERE_TEST_MYSQL_URL)에서도 돈다. 최초 연결 경합과
 * 같은 계정에 두 키를 동시에 잇는 UNIQUE 경합은 메모리 SQLite만으로 증명할 수 없다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { ACCOUNT_STATUS, allMigrations, migrate, openMysql, openPostgres, openSqlite, type DbDriver } from "@ionosphere/db";
import {
  directoryMembershipSource,
  drainAccount,
  linkDirectoryIdentityWithClaim,
  Store,
  syncDirectorySnapshot,
  unlinkDirectoryIdentityWithClaim,
} from "../src/index.ts";

const SCHEMA = "ionosphere_test_directory_claims";
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

async function insertIdentity(
  db: DbDriver,
  input: { id: string; tenantId: string; provider: string; externalKey: string; accountId?: string },
): Promise<void> {
  await db.batch([
    {
      sql: `INSERT INTO directory_identities
              (id, tenant_id, provider, external_key, account_id, login_names, display_name, last_seen_at, status)
            VALUES (?, ?, ?, ?, ?, '[]', ?, 1, 1)`,
      params: [input.id, input.tenantId, input.provider, input.externalKey, input.accountId ?? null, input.externalKey],
    },
  ]);
}

function link(db: DbDriver, tenantId: string, provider: string, externalKey: string, accountId: string) {
  return linkDirectoryIdentityWithClaim(db, { tenantId, provider, externalKey, accountId, displayName: externalKey, now: 1 });
}

for (const d of dialects) {
  describe.skipIf(d.open === null)(`디렉터리 외부 키 최초 주인 — ${d.name}`, () => {
    test("연결을 끊어도 다른 계정에는 다시 잇지 못하고 원래 계정에는 다시 잇는다", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const a = await store.createAccount({ tenantId, email: "a@ionosphere.test" });
      const b = await store.createAccount({ tenantId, email: "b@ionosphere.test" });
      await insertIdentity(db, { id: "dir-a", tenantId, provider: "ad", externalKey: "guid:one" });

      expect(await link(db, tenantId, "ad", "guid:one", a.accountId)).toBe("ok");
      expect(await unlinkDirectoryIdentityWithClaim(db, { tenantId, provider: "ad", externalKey: "guid:one", now: 2 })).toBe("ok");
      expect(await link(db, tenantId, "ad", "guid:one", b.accountId)).toBe("retired");
      expect(await link(db, tenantId, "ad", "guid:one", a.accountId)).toBe("ok");
    });

    test("같은 외부 키의 동시 최초 연결은 한 계정만 주인이 된다", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const accounts = await Promise.all(
        Array.from({ length: 6 }, (_, i) => store.createAccount({ tenantId, email: `race${i}@ionosphere.test` })),
      );
      await insertIdentity(db, { id: "dir-race", tenantId, provider: "ad", externalKey: "guid:race" });

      const results = await Promise.all(accounts.map((a) => link(db, tenantId, "ad", "guid:race", a.accountId)));
      expect(results.filter((r) => r === "ok")).toHaveLength(1);
      expect(results.filter((r) => r === "conflict")).toHaveLength(accounts.length - 1);
      const { rows: claims } = await db.query({ sql: "SELECT owner_id FROM identity_claims WHERE realm = 'directory'" });
      const { rows: identity } = await db.query({ sql: "SELECT account_id FROM directory_identities WHERE id = ?", params: ["dir-race"] });
      expect(claims).toHaveLength(1);
      expect(String(identity[0]!.account_id)).toBe(String(claims[0]!.owner_id));
    });

    test("사전 조회 뒤 다른 주인이 연결·해제해도 retired 연결을 남기지 않는다", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const a = await store.createAccount({ tenantId, email: "owner@ionosphere.test" });
      const b = await store.createAccount({ tenantId, email: "late@ionosphere.test" });
      await insertIdentity(db, { id: "dir-interleave", tenantId, provider: "ad", externalKey: "guid:interleave" });

      let injected = false;
      const interleavingDb: DbDriver = {
        dialect: db.dialect,
        async query(stmt) {
          const result = await db.query(stmt);
          // B가 빈 연결·묘비를 읽은 **직후**, A가 최초 연결하고 해제한다.
          if (!injected && stmt.sql.includes("SELECT d.account_id, c.owner_id")) {
            injected = true;
            expect(await link(db, tenantId, "ad", "guid:interleave", a.accountId)).toBe("ok");
            expect(await unlinkDirectoryIdentityWithClaim(db, { tenantId, provider: "ad", externalKey: "guid:interleave", now: 2 })).toBe("ok");
          }
          return result;
        },
        async batch(stmts) {
          return await db.batch(stmts);
        },
        insertIgnore(table, columns) {
          return db.insertIgnore(table, columns);
        },
        async close() {
          await db.close();
        },
      };

      expect(await link(interleavingDb, tenantId, "ad", "guid:interleave", b.accountId)).toBe("retired");
      const { rows } = await db.query({ sql: "SELECT account_id FROM directory_identities WHERE id = ?", params: ["dir-interleave"] });
      expect(rows[0]!.account_id).toBe(null);
    });

    test("같은 계정에 두 키를 동시에 잇다 진 쪽은 claim도 롤백된다", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const a = await store.createAccount({ tenantId, email: "one@ionosphere.test" });
      const b = await store.createAccount({ tenantId, email: "two@ionosphere.test" });
      await insertIdentity(db, { id: "dir-x", tenantId, provider: "ad", externalKey: "guid:x" });
      await insertIdentity(db, { id: "dir-y", tenantId, provider: "ad", externalKey: "guid:y" });

      const results = await Promise.all([link(db, tenantId, "ad", "guid:x", a.accountId), link(db, tenantId, "ad", "guid:y", a.accountId)]);
      expect(results.filter((r) => r === "ok")).toHaveLength(1);
      const { rows: linked } = await db.query({
        sql: "SELECT external_key FROM directory_identities WHERE tenant_id = ? AND provider = ? AND account_id = ?",
        params: [tenantId, "ad", a.accountId],
      });
      const winner = String(linked[0]!.external_key);
      const loser = winner === "guid:x" ? "guid:y" : "guid:x";
      // 진 쪽의 claim이 함께 롤백돼 다른 계정이 정상 연결할 수 있다.
      expect(await link(db, tenantId, "ad", loser, b.accountId)).toBe("ok");
      expect((await db.query({ sql: "SELECT COUNT(*) AS n FROM identity_claims WHERE realm = 'directory'" })).rows[0]!.n).toBe(2);
    });

    test("기능 도입 전 연결도 해제 직전에 claim하고, 외부 키 원문은 묘비에 남기지 않는다", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const a = await store.createAccount({ tenantId, email: "legacy@ionosphere.test" });
      const b = await store.createAccount({ tenantId, email: "new@ionosphere.test" });
      const externalKey = "CN=Private Person,OU=People,DC=example,DC=test";
      await insertIdentity(db, { id: "dir-legacy", tenantId, provider: "ldap", externalKey, accountId: a.accountId });

      expect(await unlinkDirectoryIdentityWithClaim(db, { tenantId, provider: "ldap", externalKey, now: 2 })).toBe("ok");
      expect(await link(db, tenantId, "ldap", externalKey, b.accountId)).toBe("retired");
      const claim = (await db.query({ sql: "SELECT provider, subject FROM identity_claims WHERE realm = 'directory'" })).rows[0]!;
      expect(String(claim.provider)).toBe(`${tenantId}:ldap`);
      expect(String(claim.subject)).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(JSON.stringify(claim).includes("Private Person")).toBe(false);
    });

    test("삭제 중인 계정에는 연결도 claim도 만들지 않는다", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const a = await store.createAccount({ tenantId, email: "deleting@ionosphere.test" });
      await insertIdentity(db, { id: "dir-deleting", tenantId, provider: "ad", externalKey: "guid:deleting" });
      await db.batch([
        {
          sql: "UPDATE accounts SET status = ?, deleting_since = ? WHERE id = ?",
          params: [ACCOUNT_STATUS.deleting, 1, a.accountId],
        },
      ]);

      expect(await link(db, tenantId, "ad", "guid:deleting", a.accountId)).toBe("conflict");
      expect((await db.query({ sql: "SELECT COUNT(*) AS n FROM identity_claims WHERE realm = 'directory'" })).rows[0]!.n).toBe(0);
      expect((await db.query({ sql: "SELECT account_id FROM directory_identities WHERE id = ?", params: ["dir-deleting"] })).rows[0]!.account_id).toBe(null);
    });

    test("오래된 sync 입력은 연결 해제를 되돌리거나 그룹 membership을 되살리지 않는다", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const a = await store.createAccount({ tenantId, email: "stale@ionosphere.test" });
      await insertIdentity(db, { id: "dir-stale", tenantId, provider: "ad", externalKey: "guid:stale" });
      expect(await link(db, tenantId, "ad", "guid:stale", a.accountId)).toBe("ok");
      const stale = {
        tenantId,
        provider: "ad",
        now: 10,
        identities: [{ externalKey: "guid:stale", loginNames: ["stale"], email: null, displayName: "Stale", groupExternalKeys: ["guid:group"] }],
        groups: [],
      } as const;
      expect(await unlinkDirectoryIdentityWithClaim(db, { tenantId, provider: "ad", externalKey: "guid:stale", now: 11 })).toBe("ok");
      await syncDirectorySnapshot(db, stale);

      const identity = await db.query({ sql: "SELECT account_id FROM directory_identities WHERE id = ?", params: ["dir-stale"] });
      const membership = await db.query({ sql: "SELECT 1 FROM account_memberships WHERE account_id = ? AND source = ?", params: [a.accountId, directoryMembershipSource("ad")] });
      expect(identity.rows[0]!.account_id).toBe(null);
      expect(membership.rows).toEqual([]);
    });

    test("store 직접 호출도 oidc: 행을 우회하지 못한다", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const a = await store.createAccount({ tenantId, email: "oidc@ionosphere.test" });
      await insertIdentity(db, { id: "dir-oidc", tenantId, provider: "oidc:corp", externalKey: "sub" });
      await expect(link(db, tenantId, "oidc:corp", "sub", a.accountId)).rejects.toThrow("OIDC identity");
      await expect(unlinkDirectoryIdentityWithClaim(db, { tenantId, provider: "oidc:corp", externalKey: "sub" })).rejects.toThrow("OIDC identity");
    });

    test("계정 드레인도 기존 디렉터리 연결을 claim한 뒤 행을 지운다", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const a = await store.createAccount({ tenantId, email: "gone@ionosphere.test" });
      const b = await store.createAccount({ tenantId, email: "next@ionosphere.test" });
      await insertIdentity(db, { id: "dir-gone", tenantId, provider: "ad", externalKey: "guid:gone", accountId: a.accountId });
      await db.batch([
        {
          sql: "UPDATE accounts SET status = ?, deleting_since = ? WHERE id = ?",
          params: [ACCOUNT_STATUS.deleting, 1, a.accountId],
        },
      ]);

      expect((await drainAccount(db, a.accountId, { now: 2 })).done).toBe(true);
      await insertIdentity(db, { id: "dir-reappeared", tenantId, provider: "ad", externalKey: "guid:gone" });
      expect(await link(db, tenantId, "ad", "guid:gone", b.accountId)).toBe("retired");
    });
  });
}
