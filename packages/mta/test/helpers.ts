import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { ulid } from "@ionosphere/core";

export async function freshDb(): Promise<DbDriver> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  return db;
}

/** mta_queue/suppressions는 FK 없는 정책(SCHEMA.md §1-4)이라 테넌트/계정 id는 임의 ULID로 충분. */
export function fakeTenantAccount(): { tenantId: string; accountId: string } {
  return { tenantId: ulid(), accountId: ulid() };
}

/**
 * 아웃바운드 게이트(PLAN.md §8 ②) 테스트용 — tenantId 소유의 status=1(검증됨) domains 행을 심는다.
 */
export async function verifiedDomain(db: DbDriver, tenantId: string, name: string): Promise<void> {
  const now = Date.now();
  await db.batch([
    {
      sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, ?, 1, ?, ?)",
      params: [ulid(), tenantId, name, now, now],
    },
  ]);
}
