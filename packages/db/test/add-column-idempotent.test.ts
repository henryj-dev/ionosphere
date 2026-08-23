/**
 * `ALTER TABLE … ADD COLUMN` 재적용 멱등성 (마이그레이션 008이 의존하는 계약).
 *
 * 왜 필요한가: 마이그레이션 러너는 **문장 단위 멱등**을 전제로 실패 지점부터 재개한다.
 * 그런데 컬럼 추가는 SQLite·MySQL에 `IF NOT EXISTS`가 없어, 재개하면 "이미 있음"에서 멈춘다.
 * 실측으로 확인한 것(docs/DECISIONS-pending.md §1):
 *
 *   duplicate column name: expires_at   ← BatchConflictError로도 분류되지 않아 그대로 던져졌다
 *
 * 그래서 각 드라이버가 이 오류를 멱등 no-op으로 흡수한다. 이 파일은 그 계약을 지킨다.
 * (PostgreSQL은 오류를 내지 않고 `ADD COLUMN IF NOT EXISTS`로 바꿔 실행한다 — 문장 하나가
 *  실패하면 트랜잭션 전체가 중단 상태가 되어 삼킬 수 없기 때문이다.)
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "../src/index.ts";
import { isAddColumn } from "../src/ddl.ts";

describe("isAddColumn 판별", () => {
  test("ADD COLUMN만 잡는다", () => {
    expect(isAddColumn("ALTER TABLE suppressions ADD COLUMN expires_at BIGINT")).toBe(true);
    expect(isAddColumn("  alter table t add column x int  ")).toBe(true);
    // 흡수 대상이 아닌 것들 — 넓게 잡으면 진짜 실패까지 성공으로 보고한다
    expect(isAddColumn("ALTER TABLE t RENAME TO t2")).toBe(false);
    expect(isAddColumn("CREATE TABLE t (a INT)")).toBe(false);
    expect(isAddColumn("INSERT INTO t (a) VALUES (1)")).toBe(false);
  });
});

describe("SQLite — 재적용 흡수", () => {
  test("같은 ADD COLUMN을 두 번 실행해도 던지지 않는다", async () => {
    const db = await openSqlite(":memory:");
    await db.batch([{ sql: "CREATE TABLE t (a INTEGER)" }]);
    await db.batch([{ sql: "ALTER TABLE t ADD COLUMN b BIGINT" }]);
    // 재개 시나리오 — 여기서 던지면 마이그레이션이 사람 손을 필요로 한다
    const again = await db.batch([{ sql: "ALTER TABLE t ADD COLUMN b BIGINT" }]);
    expect(again[0]?.changes).toBe(0);
    await db.close();
  });

  test("컬럼은 한 번만 생기고 기존 데이터는 보존된다", async () => {
    const db = await openSqlite(":memory:");
    await db.batch([{ sql: "CREATE TABLE t (a INTEGER)" }]);
    await db.batch([{ sql: "INSERT INTO t (a) VALUES (7)" }]);
    await db.batch([{ sql: "ALTER TABLE t ADD COLUMN b BIGINT" }]);
    await db.batch([{ sql: "ALTER TABLE t ADD COLUMN b BIGINT" }]);
    const { rows } = await db.query({ sql: "SELECT a, b FROM t" });
    expect(rows).toEqual([{ a: 7, b: null }]);
    await db.close();
  });

  /** 흡수는 ADD COLUMN에만 걸려야 한다 — 다른 실패까지 삼키면 깨진 마이그레이션이 성공으로 보인다. */
  test("다른 오류는 그대로 던진다", async () => {
    const db = await openSqlite(":memory:");
    await expect(db.batch([{ sql: "ALTER TABLE nope ADD COLUMN b BIGINT" }])).rejects.toThrow();
    await expect(db.batch([{ sql: "SELECT * FROM nope" }])).rejects.toThrow();
    await db.close();
  });
});

describe("마이그레이션 전체 재실행", () => {
  test("migrate를 두 번 돌려도 안전하다(008 포함)", async () => {
    const db = await openSqlite(":memory:");
    const first = await migrate(db, allMigrations);
    expect(first).toBeGreaterThan(0);
    // 두 번째는 적용할 게 없어야 한다(버전 기록이 있으므로) — 던지지 않는 것이 핵심
    expect(await migrate(db, allMigrations)).toBe(0);
    await db.close();
  });

  /**
   * 진짜 재개 시나리오: 008의 문장이 이미 적용됐는데 **버전 기록 전에** 죽은 경우.
   * 러너는 008을 pending으로 보고 문장을 다시 실행한다 — 여기서 멈추면 안 된다.
   */
  test("008 문장이 이미 적용된 상태에서 재개해도 통과한다", async () => {
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    // 버전 기록만 지워 "문장은 돌았는데 기록 전에 죽은" 상태를 만든다
    await db.batch([{ sql: "DELETE FROM schema_migrations WHERE version = 8" }]);
    expect(await migrate(db, allMigrations)).toBe(1);
    const { rows } = await db.query({ sql: "SELECT version FROM schema_migrations WHERE version = 8" });
    expect(rows).toHaveLength(1);
    await db.close();
  });
});
