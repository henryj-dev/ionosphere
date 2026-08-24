/**
 * 011 — `mta_queue` 시간창 인덱스 회귀.
 *
 * 인덱스가 "생겼는지"가 아니라 **질의가 실제로 그것을 타는지**를 본다. 인덱스는 만들어 두고
 * 질의가 안 타는 경우가 흔하고, 그러면 고친 것이 아니다. SQLite의 `EXPLAIN QUERY PLAN`이
 * 그 사실을 직접 말해 준다.
 */
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";

async function plan(sql: string, params: readonly unknown[]): Promise<string> {
  const db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
  const { rows } = await db.query({ sql: `EXPLAIN QUERY PLAN ${sql}`, params });
  await db.close();
  return rows.map((r) => String(r.detail)).join(" | ");
}

describe("mta_queue 시간창 인덱스", () => {
  /**
   * 시스템 relay 상한 — 포워딩·Sieve redirect·바운스 relay **한 건마다** 도는 질의다.
   * relay는 정의상 account_id가 NULL이라 ix_queue_account가 쓸모없었다.
   */
  test("tenant_id + created_at 집계가 ix_queue_tenant를 탄다", async () => {
    const detail = await plan(
      "SELECT COUNT(*) AS c FROM mta_queue WHERE tenant_id = ? AND created_at > ?",
      ["t", 0],
    );
    expect(detail).toContain("ix_queue_tenant");
    expect(detail).not.toContain("SCAN mta_queue");
  });

  /**
   * ★어뷰즈 스윕에는 인덱스를 **더하지 않았다** — 이미 테이블을 건드리지 않기 때문이다.
   * 이 테스트는 그 판단을 고정한다: 플래너가 이 질의를 커버링 인덱스로 처리하는 한
   * `(created_at)` 단독 인덱스는 쓰기 비용만 늘리는 순수 낭비다. 이 가정이 깨지면
   * (플랜이 `SCAN`으로 바뀌면) 여기서 드러나 다시 판단할 수 있다.
   */
  test("어뷰즈 스윕은 이미 커버링 인덱스를 타므로 새 인덱스가 필요 없다", async () => {
    const detail = await plan(
      "SELECT DISTINCT account_id FROM mta_queue WHERE created_at > ? AND account_id IS NOT NULL",
      [0],
    );
    expect(detail).toContain("COVERING INDEX");
    expect(detail).not.toContain("SCAN mta_queue");
  });

  test("마이그레이션은 재실행해도 안전하다(DDL 멱등)", async () => {
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    await migrate(db, allMigrations); // 두 번째는 no-op이어야 한다
    const { rows } = await db.query({
      sql: "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'ix_queue_tenant'",
      params: [],
    });
    expect(rows).toHaveLength(1);
    await db.close();
  });
});
