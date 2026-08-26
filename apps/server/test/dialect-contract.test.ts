/**
 * 방언 계약 테스트 — 4개 DbDriver(SQLite/PostgreSQL/MySQL/D1)가 동일한 스토어 계약을
 * 만족하는지 실연결로 검증한다. SQLite는 항상 실행(공유 하니스 검증), 나머지는 env 게이트:
 *   - IONOSPHERE_TEST_PG_URL     예: postgres://postgres:test@127.0.0.1:55432/ionosphere
 *   - IONOSPHERE_TEST_MYSQL_URL  예: mysql://root:test@127.0.0.1:33061/ionosphere
 *   - IONOSPHERE_TEST_D1_ACCOUNT + IONOSPHERE_TEST_D1_TOKEN (임시 DB를 만들고 끝나면 삭제)
 * 로컬/CI 구동 편의: `scripts/dialect-test.sh` (docker로 PG/MySQL 기동 후 실행).
 *
 * 검증 계약: 마이그레이션 001~003 적용, 낙관적 락(중복 modseq→BatchConflictError),
 * 배치 원자성(배치 내 제약위반 시 유효 문장까지 전체 롤백), 스토어 왕복(계정+INBOX·appendMessage
 * 다중문장 원자 배치·카운터 반영), insertIgnore 승인 분기(중복이면 changes=0),
 * maildrop 락 상호배제(두 세션이 같은 계정을 동시에 열 수 없다). 재실행 안전(고유 ULID 사용 — 영속 DB에도 반복 실행 가능).
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { ulid } from "@ionosphere/core";
import { allMigrations, BatchConflictError, migrate, openD1, openMysql, openPostgres, openSqlite, type DbDriver } from "@ionosphere/db";
import { DbMaildropLock, Store } from "@ionosphere/store";

async function runContract(db: DbDriver): Promise<void> {
  await migrate(db, allMigrations);
  // schema_migrations에 모든 버전 존재(fresh든 재실행이든 멱등적으로 참)
  const { rows: mig } = await db.query({ sql: "SELECT version FROM schema_migrations ORDER BY version" });
  expect(mig.map((r) => Number(r.version))).toEqual([...allMigrations].map((m) => m.version).sort((a, b) => a - b));

  // 낙관적 락 — 동일 modseq 재클레임 → BatchConflictError
  const a1 = ulid();
  await db.batch([{ sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [a1, 1] }]);
  await expect(db.batch([{ sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [a1, 1] }])).rejects.toBeInstanceOf(BatchConflictError);

  // 배치 원자성 — 배치 내 제약위반 시 전체 롤백(유효 문장도 반영 안 됨)
  const a2 = ulid();
  await expect(
    db.batch([
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [a2, 5] },
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [a2, 5] },
    ]),
  ).rejects.toBeInstanceOf(BatchConflictError);
  const { rows: lo } = await db.query({ sql: "SELECT COUNT(*) AS n FROM modseq_claims WHERE account_id = ?", params: [a2] });
  expect(Number(lo[0]!.n)).toBe(0);

  // 스토어 왕복 — 테넌트·계정(INBOX)·메시지 append(다중문장 원자 배치)·카운터
  const store = new Store(db);
  const { tenantId } = await store.createTenant("dc");
  const { accountId, mailboxId } = await store.createAccount({ tenantId, email: `dc-${ulid()}@contract.test` });
  expect(accountId).toBeTruthy();
  expect(mailboxId).toBeTruthy();
  const { messageId } = await store.appendMessage({
    accountId,
    mailboxIds: [mailboxId],
    blobId: "b".repeat(64),
    sizeBytes: 321,
    receivedAt: Date.now(),
    envelope: { subject: "hi", subjectBase: "hi", msgidHash: null, sentAt: null, preview: null, hasAttachment: false, addresses: [], threadRefHashes: [] },
    keywords: [],
  });
  expect(messageId).toBeTruthy();
  const { rows: acc } = await db.query({ sql: "SELECT message_count, used_bytes FROM accounts WHERE id = ?", params: [accountId] });
  expect(Number(acc[0]!.message_count)).toBe(1);
  expect(Number(acc[0]!.used_bytes)).toBe(321);

  // §1-5 승인 분기 — **중복이면 `changes`가 0이다.** 방언마다 문장이 다르고
  // (`INSERT IGNORE` · `ON CONFLICT DO NOTHING` · `INSERT OR IGNORE`) 그 셋이 같은 값을
  // 돌려주는 것이 계약이다. 표현이 다른데 의미가 같아야 하는 자리라 실연결로만 잴 수 있다.
  const dupAcct = ulid();
  const ignoreSql = db.insertIgnore("modseq_claims", ["account_id", "modseq"]);
  const [firstInsert] = await db.batch([{ sql: ignoreSql, params: [dupAcct, 7] }]);
  expect(firstInsert?.changes).toBe(1);
  const [dupInsert] = await db.batch([{ sql: ignoreSql, params: [dupAcct, 7] }]);
  expect(dupInsert?.changes).toBe(0);

  // **maildrop 락 — 두 세션이 같은 계정을 동시에 열 수 없다.**
  //
  // ★왜 스토어 테스트가 아니라 여기 있나 (2026-08-25 실사고): `acquire()`는 바로 위
  // `changes`를 "빈 자리를 잡았다"로 읽는다. MySQL의 `insertIgnore`가 `INSERT IGNORE`에서
  // `ON DUPLICATE KEY UPDATE`로 바뀌면서 중복이 1을 돌려줬고, 그래서 **살아 있는 남의
  // 락을 자기 것으로 착각했다.** MySQL 배포에서만 두 세션이 같은 maildrop을 열었다.
  //
  // `packages/store/test/maildrop-lock.test.ts`는 이 사고를 못 잡는다 — SQLite 인메모리로만
  // 돌아 MySQL 경로를 한 번도 안 타기 때문이다. 잡아낸 것은 어댑터의 changes 계약
  // 테스트였고, 그건 "락이 깨진다"는 말을 하지 않는다. 상호배제 자체를 방언마다 재는
  // 자리가 없었다는 뜻이고, 그 구멍을 여기서 막는다.
  const lockAcct = ulid();
  const lock = new DbMaildropLock(db, { ttlMs: 60_000 });
  const t0 = Date.now();
  expect(await lock.acquire(lockAcct, "sess-a", t0)).toBe(true);
  // 같은 시각의 두 번째 세션은 진다. 여기가 2026-08-25에 MySQL에서 true였다.
  expect(await lock.acquire(lockAcct, "sess-b", t0)).toBe(false);
  // 만료 전에는 탈취도 안 된다 — TTL 60초의 59초 지점.
  expect(await lock.acquire(lockAcct, "sess-b", t0 + 59_000)).toBe(false);
  // 그리고 영구 잠금이 아니다 — 놓아 주면 다음 세션이 잡는다.
  await lock.release(lockAcct, "sess-a");
  expect(await lock.acquire(lockAcct, "sess-b", t0 + 1)).toBe(true);
  await lock.release(lockAcct, "sess-b");
}

describe("방언 계약 (SQLite 항상 / PG·MySQL·D1 env 게이트)", () => {
  test("sqlite", async () => {
    const db = await openSqlite();
    try {
      await runContract(db);
    } finally {
      await db.close();
    }
  });

  const pgUrl = process.env.IONOSPHERE_TEST_PG_URL;
  (pgUrl ? test : test.skip)(
    "postgres",
    async () => {
      const db = await openPostgres(pgUrl!);
      try {
        await runContract(db);
      } finally {
        await db.close();
      }
    },
    30_000,
  );

  const myUrl = process.env.IONOSPHERE_TEST_MYSQL_URL;
  (myUrl ? test : test.skip)(
    "mysql",
    async () => {
      const db = await openMysql(myUrl!);
      try {
        await runContract(db);
      } finally {
        await db.close();
      }
    },
    30_000,
  );

  const d1Acct = process.env.IONOSPHERE_TEST_D1_ACCOUNT;
  const d1Tok = process.env.IONOSPHERE_TEST_D1_TOKEN;
  (d1Acct && d1Tok ? test : test.skip)(
    "d1 (임시 DB 생성→검증→삭제)",
    async () => {
      const base = "https://api.cloudflare.com/client/v4";
      const H = { Authorization: `Bearer ${d1Tok}`, "Content-Type": "application/json" };
      const cf = async (path: string, init?: RequestInit) => {
        const res = await fetch(`${base}/accounts/${d1Acct}${path}`, { headers: H, ...init });
        const j = (await res.json()) as { success: boolean; result?: { uuid: string }; errors?: unknown };
        if (!j.success) throw new Error(`CF ${path}: ${JSON.stringify(j.errors)}`);
        return j.result!;
      };
      const created = await cf("/d1/database", { method: "POST", body: JSON.stringify({ name: `ionosphere-d1-contract-${Date.now()}` }) });
      try {
        const db = openD1({ accountId: d1Acct!, databaseId: created.uuid, apiToken: d1Tok! });
        await runContract(db);
        await db.close();
      } finally {
        await cf(`/d1/database/${created.uuid}`, { method: "DELETE" });
      }
    },
    180_000,
  );
});
