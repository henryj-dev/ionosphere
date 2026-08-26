import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, BatchConflictError, migrate, openSqlite, type DbDriver } from "@ionosphere/db";

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


async function freshDb(): Promise<DbDriver> {
  const db = track(await openSqlite());
  await migrate(db, allMigrations);
  return db;
}

describe("단일 원자 배치 (SCHEMA.md §1-1/§3)", () => {
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
    // 라이터 1이 modseq 5를 선점
    await db.batch([
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [acct, 5] },
    ]);
    // 라이터 2: 같은 modseq 클레임(1번 문장) + 무고한 삽입(2번 문장) — 전부 롤백돼야 함
    await expect(
      db.batch([
        { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [acct, 5] },
        { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?, ?, 1, 0)", params: ["T".repeat(26), "victim"] },
      ]),
    ).rejects.toBeInstanceOf(BatchConflictError);
    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM tenants" });
    expect(Number(rows[0]?.n)).toBe(0); // 2번 문장도 롤백됨
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
        // (mailbox_id, uid) PK 충돌 — UID 경합 시나리오
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
    expect(results[0]?.changes).toBe(0); // 성공하되 0행 — 호출자가 판정
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
});
