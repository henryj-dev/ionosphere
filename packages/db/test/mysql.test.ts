import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, BatchConflictError, migrate, openMysql, type DbDriver } from "@ionosphere/db";

/**
 * 연 드라이버를 적어 두고 테스트마다 반드시 닫는다.
 *
 * ★왜(2026-08-26 실사고): 각 테스트가 `await db.close()`를 **마지막 줄**에 두고 있었다.
 * 단언이 하나 깨지면 그 줄은 실행되지 않고, 살아남은 풀이 이벤트 루프를 붙잡아 node가
 * 종료하지 못한다. 그러면 "3초 만에 빨간 테스트"가 "25분 타임아웃"으로 둔갑한다 —
 * 2026-08-24부터 main의 CI가 실제로 그 상태였고, 무엇이 깨졌는지는 로그 끝에서 잘려
 * 보이지도 않았다. 느려진 게 아니라 멈춘 것이었다.
 *
 * `pool-error.test.ts`는 처음부터 try/finally로 이걸 지키고 있었다. 그 규율을 이 파일에도
 * 둔다 — 다만 테스트 본문을 전부 고치는 대신 여는 자리에서 등록하고 훅에서 닫는다.
 */
const opened: DbDriver[] = [];

function track(db: DbDriver): DbDriver {
  opened.push(db);
  return db;
}

afterEach(async () => {
  while (opened.length > 0) {
    // 테스트가 스스로 닫았으면 두 번째 close는 던질 수 있다. 정리가 실패를 가리면
    // 안 되므로 여기서 삼킨다 — 판정은 테스트가 한다.
    try {
      await opened.pop()!.close();
    } catch {
      /* 이미 닫혔다 */
    }
  }
});


/**
 * MySQL/MariaDB는 로컬/CI에 리처블할 때만 실행 (IONOSPHERE_TEST_MYSQL_URL 미설정이면 스킵).
 * URL 예: mysql://root:pw@127.0.0.1:3306/ionosphere_test
 * 테스트 DB는 utf8mb4 + InnoDB 전제(VARCHAR PK/인덱스 대형 프리픽스). 매 테스트 전에
 * 모든 테이블을 드롭해 깨끗한 스키마에서 시작한다(트랜잭셔널 DDL 없음 → 문장 단위).
 */
const baseUrl = process.env.IONOSPHERE_TEST_MYSQL_URL;

/**
 * 전용 테스트 DB 이름 — `IONOSPHERE_TEST_MYSQL_URL`이 가리키는 DB를 **직접 쓰지 않는다.**
 *
 * ★왜(2026-08-01 실사고): 이 파일은 예전에 스키마의 **전 테이블을 지웠다**(`dropAll`). 그런데
 * `apps/server/test/dialect-contract.test.ts`가 같은 env를 읽어 **같은 DB에서 마이그레이션을
 * 돌린다.** bun이 두 파일을 병렬 실행하면 이쪽 DROP이 저쪽 마이그레이션 중간에 끼어들어
 * 006(`INSERT INTO address_targets … SELECT ad.account_id FROM addresses`)이
 * `Unknown column 'ad.account_id'`로 죽었다 — 006이 그 컬럼을 제거하는 마이그레이션이라,
 * 테이블이 재생성된 직후 상태를 읽으면 컬럼이 없다.
 *
 * 증거: 같은 커밋(481d4ba)에서 CI 워크플로는 통과하고 Deploy의 verify 잡은 실패했다.
 * 코드가 같고 결과가 갈리는 것은 경합의 신호다(러너 부하에 따라 실행 순서가 달라진다).
 *
 * PG 쪽은 이미 전용 스키마(`ionosphere_test`)로 격리하고 있었다(`postgres.test.ts`) — MySQL만
 * 공유 DB를 쓰는 **비대칭**이 원인이었으므로 같은 패턴으로 맞춘다. MySQL은 스키마=DB이므로
 * 별도 DB를 만든다.
 */
const TEST_DB = "ionosphere_test";

/** `IONOSPHERE_TEST_MYSQL_URL`의 DB 이름만 전용 DB로 바꾼 URL. */
function scopedUrl(): string {
  const u = new URL(baseUrl!);
  u.pathname = `/${TEST_DB}`;
  return u.toString();
}

/** 전용 DB를 통째로 재생성한다 — 테이블 단위 DROP보다 단순하고 잔여물이 남지 않는다. */
async function freshTestDatabase(): Promise<void> {
  if (!baseUrl) return;
  const admin = track(await openMysql(baseUrl));
  await admin.query({ sql: `DROP DATABASE IF EXISTS \`${TEST_DB}\`` });
  await admin.query({ sql: `CREATE DATABASE \`${TEST_DB}\` CHARACTER SET utf8mb4` });
  await admin.close();
}

async function freshDb(): Promise<DbDriver> {
  await freshTestDatabase();
  const db = track(await openMysql(scopedUrl()));
  await migrate(db, allMigrations);
  return db;
}

describe.skipIf(!baseUrl)("MySQL 어댑터 (SCHEMA.md §1-3 계약)", () => {
  test("마이그레이션 전체 적용 + 재실행 멱등 (DDL 호환 검증)", async () => {
    await freshTestDatabase();
    const db = track(await openMysql(scopedUrl()));
    const applied = await migrate(db, allMigrations);
    // postgres.test.ts와 같은 이유로 개수를 박지 않는다 — 계약은 "미적용분 전부"다.
    expect(applied).toBe(allMigrations.length);
    // 재실행 멱등: CREATE INDEX IF NOT EXISTS(→ ER_DUP_KEYNAME 흡수) 포함 전 테이블 재생성 무해
    const second = await migrate(db, allMigrations);
    expect(second).toBe(0);
    const dbName = TEST_DB;
    const { rows } = await db.query({
      sql: "SELECT table_name AS t FROM information_schema.tables WHERE table_schema = ?",
      params: [dbName],
    });
    const tables = rows.map((r) => r.t);
    expect(tables).toContain("tenants");
    expect(tables).toContain("modseq_claims");
    expect(tables).toContain("background_jobs"); // cursor 예약어 컬럼 포함 테이블
    expect(tables).toContain("schema_migrations");
    await db.close();
  });

  test("성공 배치: 전 문장 커밋 + 영향 행 수 반환", async () => {
    const db = await freshDb();
    const results = await db.batch([
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: ["A".repeat(26), 1] },
      { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?, ?, 1, 0)", params: ["T".repeat(26), "t1"] },
    ]);
    expect(results.map((r) => r.changes)).toEqual([1, 1]);
    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM tenants" });
    expect(Number(rows[0]?.n)).toBe(1);
    await db.close();
  });

  test("★핵심 계약: modseq_claims PK 충돌 → 배치 전체 롤백 (낙관 잠금)", async () => {
    const db = await freshDb();
    const acct = "A".repeat(26);
    await db.batch([{ sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [acct, 5] }]);
    await expect(
      db.batch([
        { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [acct, 5] },
        { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?, ?, 1, 0)", params: ["T".repeat(26), "victim"] },
      ]),
    ).rejects.toBeInstanceOf(BatchConflictError);
    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM tenants" });
    expect(Number(rows[0]?.n)).toBe(0);
    await db.close();
  });

  test("문장 순서 무관 롤백: 충돌이 마지막 문장이어도 앞 문장 롤백", async () => {
    const db = await freshDb();
    const mbx = "M".repeat(26);
    await db.batch([
      { sql: "INSERT INTO message_mailbox (mailbox_id, uid, message_id, savedate) VALUES (?, 1, ?, 0)", params: [mbx, "X".repeat(26)] },
    ]);
    await expect(
      db.batch([
        { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?, ?, 1, 0)", params: ["T".repeat(26), "t"] },
        { sql: "INSERT INTO message_mailbox (mailbox_id, uid, message_id, savedate) VALUES (?, 1, ?, 0)", params: [mbx, "Y".repeat(26)] },
      ]),
    ).rejects.toBeInstanceOf(BatchConflictError);
    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM tenants" });
    expect(Number(rows[0]?.n)).toBe(0);
    await db.close();
  });

  test("0행 UPDATE는 에러 아님 — 리스 규율은 changes로 판정 (§9-4)", async () => {
    const db = await freshDb();
    const results = await db.batch([
      { sql: "UPDATE accounts SET modseq = 99 WHERE id = ?", params: ["없는계정".padEnd(26, "X")] },
    ]);
    expect(results[0]?.changes).toBe(0);
    await db.close();
  });

  test("매칭 UPDATE는 값 무변경이어도 changes=1 (FOUND_ROWS 의미 일치)", async () => {
    const db = await freshDb();
    await db.batch([
      { sql: "INSERT INTO accounts (id, tenant_id, email, created_at) VALUES (?, ?, ?, 0)", params: ["A".repeat(26), "T".repeat(26), "a@b.c"] },
    ]);
    // modseq를 이미 0 → 다시 0으로: 값은 안 바뀌지만 WHERE가 매칭됐으므로 changes=1이어야
    // SQLite/PG와 의미가 일치(리스 획득 판정 근거).
    const results = await db.batch([
      { sql: "UPDATE accounts SET modseq = 0 WHERE id = ?", params: ["A".repeat(26)] },
    ]);
    expect(results[0]?.changes).toBe(1);
    await db.close();
  });

  test("insertIgnore: 중복이어도 배치 생존 (§1-5 승인 분기)", async () => {
    const db = await freshDb();
    const sql = db.insertIgnore("blobs", ["id", "size_bytes", "backend", "status", "generation", "created_at"]);
    const blob = "b".repeat(64);
    await db.batch([{ sql, params: [blob, 10, 0, 0, 0, 0] }]);
    const results = await db.batch([
      { sql, params: [blob, 10, 0, 0, 0, 0] }, // 중복 — 무시돼야 함
      { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?, ?, 1, 0)", params: ["T".repeat(26), "t"] },
    ]);
    expect(results[0]?.changes).toBe(0);
    expect(results[1]?.changes).toBe(1);
    await db.close();
  });

  test("BIGINT 왕복: number로 반환 (2^53 미만 안전 규약)", async () => {
    const db = await freshDb();
    const bigVal = 9007199254740; // < 2^53
    await db.batch([
      { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?, ?, 1, ?)", params: ["T".repeat(26), "t", bigVal] },
    ]);
    const { rows } = await db.query({ sql: "SELECT created_at FROM tenants WHERE id = ?", params: ["T".repeat(26)] });
    expect(rows[0]?.created_at).toBe(bigVal);
    expect(typeof rows[0]?.created_at).toBe("number");
    await db.close();
  });
});
