/**
 * 마이그레이션 배타 락 — **여러 인스턴스 동시 부팅**에서 스키마가 깨지지 않아야 한다.
 *
 * 왜 필요해졌나: 러너에 락이 없었다. 서버를 역할별로 분리하면 동시 부팅은 예외가 아니라 기본값이고,
 * 003 같은 테이블 재빌드(`CREATE …_rebuild` → `INSERT SELECT` → `DROP TABLE` → `RENAME`)가 겹치면
 * 한쪽이 원본을 DROP한 사이 다른 쪽이 그 원본을 읽어 **데이터가 사라질 수 있다**.
 *
 * 여기서는 SQLite 인메모리 공유 드라이버 하나를 여러 "인스턴스"가 쓰는 것으로 동시성을 흉내낸다.
 * (실제 프로세스 분리는 dialect-contract 테스트의 실DB 몫이다 — 여기서 검증하는 건 **락 프로토콜**이다.)
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { migrate, openSqlite, type DbDriver, type Migration } from "../src/index.ts";

/** 적용 횟수를 세는 마이그레이션 — 두 번 돌면 카운터가 2가 된다(= 락 실패). */
function countingMigration(counter: { n: number }): Migration {
  return {
    version: 1,
    name: "counting",
    // statements는 문자열이라 부수효과를 못 담는다. 대신 테이블 생성 자체를 비멱등으로 두어
    // 두 번 실행되면 SQL 오류가 나게 만든다(IF NOT EXISTS 없음).
    get statements(): readonly string[] {
      counter.n++;
      return ["CREATE TABLE once_only (id INTEGER PRIMARY KEY)"];
    },
  };
}

async function fresh(): Promise<DbDriver> {
  return openSqlite(":memory:");
}

describe("마이그레이션 락", () => {
  test("동시 호출해도 마이그레이션은 한 번만 적용된다", async () => {
    const db = await fresh();
    const m: Migration = { version: 1, name: "t", statements: ["CREATE TABLE t1 (id INTEGER PRIMARY KEY)"] };

    // 같은 드라이버로 동시에 5번 — 락이 없으면 CREATE TABLE이 중복 실행돼 터진다.
    const results = await Promise.all(Array.from({ length: 5 }, () => migrate(db, [m], { pollMs: 5 })));

    // 정확히 하나만 "1개 적용", 나머지는 "0개"(락을 얻었을 땐 이미 적용돼 있었다)
    expect(results.filter((n) => n === 1)).toHaveLength(1);
    expect(results.filter((n) => n === 0)).toHaveLength(4);

    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM schema_migrations" });
    expect(Number(rows[0]!.n)).toBe(1);
    await db.close();
  });

  test("★statements는 정확히 한 번만 읽힌다 — 두 번 실행되면 비멱등 DDL이 터진다", async () => {
    const db = await fresh();
    const counter = { n: 0 };
    const m = countingMigration(counter);

    await Promise.all(Array.from({ length: 4 }, () => migrate(db, [m], { pollMs: 5 })));
    expect(counter.n).toBe(1);
    await db.close();
  });

  test("적용할 게 없으면 락을 잡지 않는다 — 정상 재기동이 서로를 기다리지 않는다", async () => {
    const db = await fresh();
    const m: Migration = { version: 1, name: "t", statements: ["CREATE TABLE t2 (id INTEGER PRIMARY KEY)"] };
    expect(await migrate(db, [m])).toBe(1);

    // 두 번째 호출은 pending이 0이라 락 테이블을 건드리지 않아야 한다
    expect(await migrate(db, [m])).toBe(0);
    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM schema_lock" });
    expect(Number(rows[0]!.n)).toBe(0);
    await db.close();
  });

  test("락은 끝나면 해제된다 — 다음 마이그레이션이 매달리지 않는다", async () => {
    const db = await fresh();
    await migrate(db, [{ version: 1, name: "a", statements: ["CREATE TABLE a (id INTEGER PRIMARY KEY)"] }]);
    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM schema_lock" });
    expect(Number(rows[0]!.n)).toBe(0);

    // 새 버전이 추가돼도 정상 진행
    const n = await migrate(db, [
      { version: 1, name: "a", statements: ["CREATE TABLE a (id INTEGER PRIMARY KEY)"] },
      { version: 2, name: "b", statements: ["CREATE TABLE b (id INTEGER PRIMARY KEY)"] },
    ]);
    expect(n).toBe(1);
    await db.close();
  });

  test("마이그레이션이 실패해도 락은 풀린다 — 한 번의 실패가 영구 교착이 되면 안 된다", async () => {
    const db = await fresh();
    const bad: Migration = { version: 1, name: "bad", statements: ["THIS IS NOT SQL"] };
    await expect(migrate(db, [bad])).rejects.toThrow();

    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM schema_lock" });
    expect(Number(rows[0]!.n)).toBe(0); // finally에서 해제됨

    // 고친 마이그레이션은 바로 적용된다(락이 남아 있으면 60초 대기 후 실패했을 것)
    const good: Migration = { version: 1, name: "good", statements: ["CREATE TABLE ok (id INTEGER PRIMARY KEY)"] };
    expect(await migrate(db, [good], { waitMs: 2000, pollMs: 5 })).toBe(1);
    await db.close();
  });

  test("죽은 락(stale)은 뺏는다 — 크래시한 인스턴스가 영구 차단하지 못한다", async () => {
    const db = await fresh();
    await db.batch([
      {
        sql: `CREATE TABLE IF NOT EXISTS schema_lock (id VARCHAR(16) PRIMARY KEY, owner VARCHAR(64) NOT NULL, acquired_at BIGINT NOT NULL)`,
      },
    ]);
    // 1시간 전에 잡힌 채 죽은 락
    await db.batch([
      {
        sql: "INSERT INTO schema_lock (id, owner, acquired_at) VALUES ('migrate', 'dead-instance', ?)",
        params: [Date.now() - 3_600_000],
      },
    ]);

    const m: Migration = { version: 1, name: "t", statements: ["CREATE TABLE t3 (id INTEGER PRIMARY KEY)"] };
    expect(await migrate(db, [m], { staleMs: 60_000, waitMs: 2000, pollMs: 5 })).toBe(1);
    await db.close();
  });

  test("살아있는 락은 뺏지 않는다 — 대기 상한을 넘기면 실패한다", async () => {
    const db = await fresh();
    await db.batch([
      {
        sql: `CREATE TABLE IF NOT EXISTS schema_lock (id VARCHAR(16) PRIMARY KEY, owner VARCHAR(64) NOT NULL, acquired_at BIGINT NOT NULL)`,
      },
    ]);
    await db.batch([
      {
        sql: "INSERT INTO schema_lock (id, owner, acquired_at) VALUES ('migrate', 'live-instance', ?)",
        params: [Date.now()],
      },
    ]);

    const m: Migration = { version: 1, name: "t", statements: ["CREATE TABLE t4 (id INTEGER PRIMARY KEY)"] };
    // 방금 잡힌 락이라 stale이 아니다 → 대기하다 상한 초과
    await expect(migrate(db, [m], { staleMs: 60_000, waitMs: 120, pollMs: 20 })).rejects.toThrow(/락 획득 실패/);
    await db.close();
  });
});
