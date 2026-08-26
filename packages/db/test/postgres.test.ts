import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, BatchConflictError, migrate, openPostgres, type DbDriver } from "@ionosphere/db";

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
 * PG는 로컬/CI에 리처블할 때만 실행 (IONOSPHERE_TEST_PG_URL 미설정이면 스킵).
 * search_path는 연결 문자열의 `options=-c search_path=...`로 커넥션마다 강제 —
 * 풀의 모든 물리 커넥션(재연결 포함)에 일관 적용된다.
 */
const baseUrl = process.env.IONOSPHERE_TEST_PG_URL;

async function freshTestSchema(): Promise<void> {
  if (!baseUrl) return;
  const admin = track(await openPostgres(baseUrl));
  await admin.query({ sql: "DROP SCHEMA IF EXISTS ionosphere_test CASCADE" });
  await admin.query({ sql: "CREATE SCHEMA ionosphere_test" });
  await admin.close();
}

function scopedUrl(): string {
  const url = new URL(baseUrl!);
  url.searchParams.set("options", "-c search_path=ionosphere_test");
  return url.toString();
}

async function freshDb(): Promise<DbDriver> {
  await freshTestSchema();
  const db = track(await openPostgres(scopedUrl()));
  await migrate(db, allMigrations);
  return db;
}

describe.skipIf(!baseUrl)("PG 어댑터 (SCHEMA.md §1-3 계약)", () => {
  test("마이그레이션 전체 적용 + 재실행 멱등", async () => {
    const db = track(await openPostgres(scopedUrl()));
    await freshTestSchema();
    const applied = await migrate(db, allMigrations);
    // 개수를 숫자로 박으면 마이그레이션을 추가할 때마다 깨진다. 실제로 001 시절의 `1`이
    // 그대로 남아 5개가 된 뒤 CI에서 터졌다 — 이 테스트는 env 게이트라 로컬에서 안 돌았다.
    // 계약은 "미적용분이 전부 적용된다"이지 "N개"가 아니다.
    expect(applied).toBe(allMigrations.length);
    const second = await migrate(db, allMigrations);
    expect(second).toBe(0);
    const { rows } = await db.query({
      sql: "SELECT table_name FROM information_schema.tables WHERE table_schema = 'ionosphere_test'",
    });
    const tables = rows.map((r) => r.table_name);
    expect(tables).toContain("tenants");
    expect(tables).toContain("modseq_claims");
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

  test("insertIgnore: 중복이어도 배치 생존 (§1-5 승인 분기)", async () => {
    const db = await freshDb();
    const sql = db.insertIgnore("blobs", ["id", "size_bytes", "backend", "status", "generation", "created_at"]);
    const blob = "b".repeat(64);
    await db.batch([{ sql, params: [blob, 10, 0, 0, 0, 0] }]);
    const results = await db.batch([
      { sql, params: [blob, 10, 0, 0, 0, 0] },
      { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?, ?, 1, 0)", params: ["T".repeat(26), "t"] },
    ]);
    expect(results[0]?.changes).toBe(0);
    expect(results[1]?.changes).toBe(1);
    await db.close();
  });

  test("자리표시자 변환: ? 3개 이상 → $1..$n", async () => {
    const db = await freshDb();
    await db.batch([
      {
        sql: "INSERT INTO addresses (id, tenant_id, domain_id, localpart, created_at) VALUES (?, ?, ?, ?, ?)",
        params: ["D".repeat(26), "T".repeat(26), "X".repeat(26), "info", 123],
      },
    ]);
    const { rows } = await db.query({
      sql: "SELECT localpart FROM addresses WHERE id = ? AND tenant_id = ? AND domain_id = ?",
      params: ["D".repeat(26), "T".repeat(26), "X".repeat(26)],
    });
    expect(rows[0]?.localpart).toBe("info");
    await db.close();
  });

  test("BIGINT 왕복: number로 반환 (2^53 미만 안전 규약)", async () => {
    const db = await freshDb();
    const bigModseq = 9007199254740; // < 2^53
    await db.batch([
      { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?, ?, 1, ?)", params: ["T".repeat(26), "t", bigModseq] },
    ]);
    const { rows } = await db.query({ sql: "SELECT created_at FROM tenants WHERE id = ?", params: ["T".repeat(26)] });
    expect(rows[0]?.created_at).toBe(bigModseq);
    expect(typeof rows[0]?.created_at).toBe("number");
    await db.close();
  });
});
