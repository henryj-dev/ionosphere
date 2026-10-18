/**
 * 마지막 운영자 owner 보호 — **동시성**을 실DB로 고정한다(2026-10-18, #46 사용자 결정).
 *
 * owner 두 명을 동시에 정지(또는 강등)하면 정확히 하나만 성공하고, 활성 운영자 owner가 0명이 되면 안 된다.
 * SQLite는 쓰기가 하나씩만 돌아 늘 통과하지만, 그것만으로는 아무것도 증명하지 못한다 — 그래서 CI의 실제
 * PG·MySQL(IONOSPHERE_TEST_PG_URL / IONOSPHERE_TEST_MYSQL_URL)에서 같은 경합을 여러 번 돌린다.
 *
 * 다른 DB 테스트 파일과 스키마가 겹치지 않게 전용 스키마/DB를 쓴다(node --test는 파일을 병렬로 돌린다).
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { ADMIN_ROLE, ADMIN_STATUS, allMigrations, migrate, openMysql, openPostgres, openSqlite, type DbDriver } from "@ionosphere/db";
import { createAdminUser, Store } from "@ionosphere/store";
import { createRegistry } from "../src/registry.ts";
import { runCommand } from "../src/dispatch.ts";
import type { CommandContext } from "../src/types.ts";

const SCHEMA = "ionosphere_test_owner_race";
const ROUNDS = 15;

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

async function activeOperatorOwners(db: DbDriver): Promise<number> {
  const { rows } = await db.query({
    sql: "SELECT COUNT(*) AS n FROM admin_users WHERE role = ? AND status = ? AND tenant_id IS NULL",
    params: [ADMIN_ROLE.owner, ADMIN_STATUS.active],
  });
  return Number(rows[0]?.n ?? 0);
}

/** 한 라운드: owner 둘을 만들고 두 명령을 동시에 낸다. 정확히 하나만 성공해야 한다. */
async function race(db: DbDriver, round: number, kind: "suspend" | "demote"): Promise<void> {
  await db.batch([{ sql: "DELETE FROM admin_users" }]);
  const a = `a${round}@ionosphere.test`;
  const b = `b${round}@ionosphere.test`;
  await createAdminUser(db, { username: a, role: ADMIN_ROLE.owner });
  await createAdminUser(db, { username: b, role: ADMIN_ROLE.owner });
  const ctx = { db, store: new Store(db), isRoot: true } as CommandContext;
  const registry = createRegistry();
  const call = (admin: string) =>
    kind === "suspend"
      ? runCommand(registry, ctx, "admin-user-suspend", { admin })
      : runCommand(registry, ctx, "admin-user-role-set", { admin, role: "admin" });
  const results = await Promise.allSettled([call(a), call(b)]);
  const ok = results.filter((r) => r.status === "fulfilled").length;
  expect({ round, kind, ok }).toEqual({ round, kind, ok: 1 });
  expect(await activeOperatorOwners(db)).toBe(1);
}

const dialects: { name: string; open: (() => Promise<DbDriver>) | null }[] = [
  { name: "sqlite", open: freshSqlite },
  { name: "postgres", open: process.env.IONOSPHERE_TEST_PG_URL ? () => freshPostgres(process.env.IONOSPHERE_TEST_PG_URL!) : null },
  { name: "mysql", open: process.env.IONOSPHERE_TEST_MYSQL_URL ? () => freshMysql(process.env.IONOSPHERE_TEST_MYSQL_URL!) : null },
];

for (const d of dialects) {
  describe.skipIf(d.open === null)(`마지막 운영자 owner 경합 — ${d.name}`, () => {
    test(`★동시 정지·강등에서 정확히 하나만 성공하고 활성 owner가 남는다(${ROUNDS}회)`, async () => {
      const db = await d.open!();
      for (let i = 0; i < ROUNDS; i++) {
        await race(db, i, "suspend");
        await race(db, i, "demote");
      }
    });
  });
}
