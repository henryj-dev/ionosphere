/**
 * SSO 연결 식별자의 최초 주인 기록(마이그레이션 029) — 실DB에서 계약을 고정한다(2026-10-18 회원 공통 수치 결정 9).
 *
 * 끊은 sub를 다른 주체에 다시 잇지 못해야 하고, 해제와 다른 주체로의 연결이 동시에 와도 재사용되면 안 된다.
 * CI의 PG·MySQL(IONOSPHERE_TEST_PG_URL / IONOSPHERE_TEST_MYSQL_URL)에서도 돈다. 전용 스키마/DB를 쓴다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { ADMIN_ROLE, allMigrations, migrate, openMysql, openPostgres, openSqlite, type DbDriver } from "@ionosphere/db";
import { createAdminUser, linkAccountOidcIdentity, linkAdminIdentity, Store, unlinkAccountOidcIdentity, unlinkAdminIdentity } from "../src/index.ts";

const SCHEMA = "ionosphere_test_identity_claims";

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

for (const d of dialects) {
  describe.skipIf(d.open === null)(`SSO 연결 최초 주인 기록 — ${d.name}`, () => {
    test("관리자: 끊은 sub는 다른 관리자에 잇지 못하고, 원래 주인에는 다시 잇는다", async () => {
      const db = await d.open!();
      const a = (await createAdminUser(db, { username: "a@ionosphere.test", role: ADMIN_ROLE.owner }))!;
      const b = (await createAdminUser(db, { username: "b@ionosphere.test", role: ADMIN_ROLE.admin }))!;
      expect(await linkAdminIdentity(db, "staff", "emp-1", a)).toBe("ok");
      expect(await linkAdminIdentity(db, "staff", "emp-1", b)).toBe("conflict");
      expect(await unlinkAdminIdentity(db, "staff", a)).toBe(true);
      expect(await linkAdminIdentity(db, "staff", "emp-1", b)).toBe("retired");
      expect(await linkAdminIdentity(db, "staff", "emp-1", a)).toBe("ok");
    });

    test("메일 계정: 같은 규칙", async () => {
      const db = await d.open!();
      const store = new Store(db);
      const { tenantId } = await store.createTenant("t");
      const { accountId: alice } = await store.createAccount({ tenantId, email: "alice@ionosphere.test" });
      const { accountId: bob } = await store.createAccount({ tenantId, email: "bob@ionosphere.test" });
      expect(await linkAccountOidcIdentity(db, tenantId, "corp", "sub-1", alice)).toBe("ok");
      expect(await unlinkAccountOidcIdentity(db, tenantId, "corp", "sub-1")).toBe(true);
      expect(await linkAccountOidcIdentity(db, tenantId, "corp", "sub-1", bob)).toBe("retired");
      expect(await linkAccountOidcIdentity(db, tenantId, "corp", "sub-1", alice)).toBe("ok");
    });

    test("★처음 연결을 두 관리자가 동시에 해도 하나만 주인이 된다", async () => {
      const db = await d.open!();
      const ids: string[] = [];
      for (let i = 0; i < 6; i++) ids.push((await createAdminUser(db, { username: `r${i}@ionosphere.test`, role: ADMIN_ROLE.admin }))!);
      const results = await Promise.all(ids.map((id) => linkAdminIdentity(db, "staff", "race-sub", id).catch(() => "error" as const)));
      expect(results.filter((r) => r === "ok").length).toBe(1);
      const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM admin_identities WHERE provider = ? AND subject = ?", params: ["staff", "race-sub"] });
      expect(Number(rows[0]!.n)).toBe(1);
    });

    test("★해제와 다른 주체로의 연결이 동시에 와도 재사용되지 않는다", async () => {
      const db = await d.open!();
      const a = (await createAdminUser(db, { username: "x@ionosphere.test", role: ADMIN_ROLE.owner }))!;
      const b = (await createAdminUser(db, { username: "y@ionosphere.test", role: ADMIN_ROLE.admin }))!;
      for (let round = 0; round < 10; round++) {
        const sub = `round-${round}`;
        expect(await linkAdminIdentity(db, "staff", sub, a)).toBe("ok");
        await Promise.all([unlinkAdminIdentity(db, "staff", a), linkAdminIdentity(db, "staff", sub, b).catch(() => "error")]);
        const { rows } = await db.query({ sql: "SELECT admin_user_id FROM admin_identities WHERE provider = ? AND subject = ?", params: ["staff", sub] });
        expect(rows.every((r) => String(r.admin_user_id) !== b)).toBe(true);
      }
    });

    test("029는 이미 있는 연결을 그 주인으로 옮겨 적는다(다시 돌아도 멱등)", async () => {
      const db = await d.open!();
      // 029 이전 상태를 흉내 낸다: 기록을 비우고, 연결 행만 있는 상태에서 옮겨 적기 문장을 다시 돌린다.
      const a = (await createAdminUser(db, { username: "pre@ionosphere.test", role: ADMIN_ROLE.owner }))!;
      const store = new Store(db);
      const { tenantId } = await store.createTenant("bf");
      const { accountId } = await store.createAccount({ tenantId, email: "pre@ionosphere.test" });
      await linkAdminIdentity(db, "staff", "old-admin-sub", a);
      await linkAccountOidcIdentity(db, tenantId, "corp", "old-account-sub", accountId);
      await db.batch([{ sql: "DELETE FROM identity_claims" }]);
      const m029 = allMigrations.find((m) => m.version === 29)!;
      for (const sql of m029.statements.slice(1)) await db.batch([{ sql }]);
      for (const sql of m029.statements.slice(1)) await db.batch([{ sql }]); // 두 번 돌아도 된다
      const { rows } = await db.query({ sql: "SELECT realm, provider, subject, owner_id FROM identity_claims ORDER BY realm" });
      expect(rows.map((r) => [String(r.realm), String(r.provider), String(r.subject), String(r.owner_id)])).toEqual([
        ["account", "oidc:corp", "old-account-sub", accountId],
        ["admin", "staff", "old-admin-sub", a],
      ]);
    });
  });
}
