/**
 * 공유 인증 실패 카운터(마이그레이션 028) — 실DB에서 계약을 고정한다(2026-10-18 회원 공통 수치 결정 3).
 *
 * 서버 여러 대가 같은 카운터를 동시에 올려도 하나를 잃으면 안 된다. SQLite는 쓰기가 하나씩만 돌아 늘 통과하므로
 * CI의 실제 PG·MySQL(IONOSPHERE_TEST_PG_URL / IONOSPHERE_TEST_MYSQL_URL)에서도 돈다.
 * 다른 DB 테스트 파일과 겹치지 않게 전용 스키마/DB를 쓴다(node --test는 파일을 병렬로 돌린다).
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openMysql, openPostgres, openSqlite, type DbDriver } from "@ionosphere/db";
import { AuthFailureThrottle } from "@ionosphere/core";
import { DbAuthFailureStore } from "../src/auth-failures.ts";

const SCHEMA = "ionosphere_test_auth_failures";

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
  describe.skipIf(d.open === null)(`공유 인증 실패 카운터 — ${d.name}`, () => {
    test("없으면 만들고, 있으면 하나씩 더한다", async () => {
      const store = new DbAuthFailureStore(await d.open!());
      await store.recordFailure("account|u@ionosphere.test", 1000, 0);
      await store.recordFailure("account|u@ionosphere.test", 2000, 0);
      const got = await store.read(["account|u@ionosphere.test", "ip|203.0.113.9"]);
      expect(got.get("account|u@ionosphere.test")).toEqual({ fails: 2, lastFailAt: 2000 });
      expect(got.has("ip|203.0.113.9")).toBe(false);
    });

    test("마지막 실패가 초기화 기준보다 오래됐으면 1부터 다시 센다", async () => {
      const store = new DbAuthFailureStore(await d.open!());
      await store.recordFailure("ip|203.0.113.9", 1000, 0);
      await store.recordFailure("ip|203.0.113.9", 1000, 0);
      await store.recordFailure("ip|203.0.113.9", 50_000, 10_000);
      expect((await store.read(["ip|203.0.113.9"])).get("ip|203.0.113.9")).toEqual({ fails: 1, lastFailAt: 50_000 });
    });

    test("★동시에 올려도 하나도 잃지 않는다(서버 여러 대가 같은 버킷을 센다)", async () => {
      const store = new DbAuthFailureStore(await d.open!());
      const N = 20;
      await Promise.all(Array.from({ length: N }, (_, i) => store.recordFailure("account|race@ionosphere.test", 1000 + i, 0)));
      expect((await store.read(["account|race@ionosphere.test"])).get("account|race@ionosphere.test")?.fails).toBe(N);
    });

    test("clear·sweep은 대상만 지운다", async () => {
      const store = new DbAuthFailureStore(await d.open!());
      await store.recordFailure("ip|a", 1000, 0);
      await store.recordFailure("ip|b", 9000, 0);
      await store.recordFailure("ip|c", 9000, 0);
      await store.clear(["ip|b"]);
      await store.sweep(5000);
      const got = await store.read(["ip|a", "ip|b", "ip|c"]);
      expect([...got.keys()]).toEqual(["ip|c"]);
    });

    test("두 스로틀 인스턴스가 이 저장소로 같은 계정을 함께 센다", async () => {
      const store = new DbAuthFailureStore(await d.open!());
      const a = new AuthFailureThrottle({ shared: store });
      const b = new AuthFailureThrottle({ shared: store });
      const now = 1_000_000;
      for (let i = 0; i < 3; i++) await a.recordFailure({ account: "u@ionosphere.test" }, now);
      for (let i = 0; i < 2; i++) await b.recordFailure({ account: "u@ionosphere.test" }, now);
      expect(await a.blocked({ account: "u@ionosphere.test" }, now)).toBe(true);
      await b.clear({ account: "u@ionosphere.test" }, now);
      expect(await a.blocked({ account: "u@ionosphere.test" }, now)).toBe(false);
    });
  });
}
