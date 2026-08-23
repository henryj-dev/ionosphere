/**
 * Abuse 모니터링 단위테스트 (PLAN.md §8 통제 ④) — checkAccountAbuse(순수 판정),
 * suspendAccount(집행), MtaWorker.sweepAbuse(통합 스윕)를 각각 in-memory sqlite로 검증.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { ulid } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import { checkAccountAbuse, suspendAccount } from "../src/abuse.ts";
import { MtaWorker, type BlobReader, type MxRecord } from "../src/worker.ts";
import { freshDb } from "./helpers.ts";

/** mta_queue.status (SCHEMA.md §9-1). */
const Q_DONE = 2;
const Q_BOUNCED = 3;

/** accounts.status (SCHEMA.md §4). */
const ACCT_ACTIVE = 1;
const ACCT_SUSPENDED = 0;

async function insertAccount(db: DbDriver, overrides: Partial<{ id: string; tenantId: string; email: string; status: number }> = {}): Promise<string> {
  const id = overrides.id ?? ulid();
  const now = Date.now();
  await db.batch([
    {
      sql: `INSERT INTO accounts (id, tenant_id, email, display_name, kind, status, modseq, changelog_floor, uidvalidity_last, quota_bytes, used_bytes, message_count, state_email, state_mailbox, state_thread, state_submission, state_sieve, created_at)
            VALUES (?, ?, ?, NULL, 0, ?, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ?)`,
      params: [id, overrides.tenantId ?? ulid(), overrides.email ?? `${id}@example.test`, overrides.status ?? ACCT_ACTIVE, now],
    },
  ]);
  return id;
}

async function getAccountStatus(db: DbDriver, accountId: string): Promise<number> {
  const { rows } = await db.query({ sql: "SELECT status FROM accounts WHERE id = ?", params: [accountId] });
  const row = rows[0];
  if (!row) throw new Error(`account not found: ${accountId}`);
  return Number(row.status);
}

/** mta_queue에 (accountId, status) 행을 count개 직접 심는다 — enqueue 게이트를 우회. */
async function seedQueueRows(
  db: DbDriver,
  accountId: string,
  status: number,
  count: number,
  createdAt: number,
): Promise<void> {
  const tenantId = ulid();
  const stmts = Array.from({ length: count }, () => ({
    sql: `INSERT INTO mta_queue (id, tenant_id, account_id, submission_id, blob_id, env_from, verp_token, rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, last_error, created_at)
          VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, 0, ?, NULL, NULL, ?)`,
    params: [
      ulid(),
      tenantId,
      accountId,
      "b".repeat(64),
      "bounce@sender.test",
      "0".repeat(16),
      `${ulid()}@example.test`,
      "example.test",
      status,
      createdAt,
      createdAt,
    ],
  }));
  await db.batch(stmts);
}

function fakeBlobs(): BlobReader {
  return { get: async () => { throw new Error("unused in abuse sweep"); } };
}

function fakeResolveMx(): (domain: string) => Promise<MxRecord[]> {
  return async () => [];
}

describe("checkAccountAbuse", () => {
  test("표본 미달(< minSample) → ok, 바운스율이 높아도 정지하지 않음", async () => {
    const db = await freshDb();
    const accountId = ulid();
    const now = Date.now();
    await seedQueueRows(db, accountId, Q_DONE, 0, now);
    await seedQueueRows(db, accountId, Q_BOUNCED, 19, now); // sent=19 < minSample(20), rate=100%

    const verdict = await checkAccountAbuse(db, accountId, { now });
    expect(verdict.action).toBe("ok");
    expect(verdict.sent).toBe(19);
    expect(verdict.bounced).toBe(19);

    await db.close();
  });

  test("바운스율이 임계 미만 → ok", async () => {
    const db = await freshDb();
    const accountId = ulid();
    const now = Date.now();
    await seedQueueRows(db, accountId, Q_DONE, 19, now);
    await seedQueueRows(db, accountId, Q_BOUNCED, 1, now); // sent=20, bounced=1 → rate=5%

    const verdict = await checkAccountAbuse(db, accountId, { now });
    expect(verdict.action).toBe("ok");
    expect(verdict.sent).toBe(20);
    expect(verdict.bounced).toBe(1);
    expect(verdict.rate).toBeCloseTo(0.05, 5);

    await db.close();
  });

  test("바운스율이 임계 초과 → suspend", async () => {
    const db = await freshDb();
    const accountId = ulid();
    const now = Date.now();
    await seedQueueRows(db, accountId, Q_DONE, 17, now);
    await seedQueueRows(db, accountId, Q_BOUNCED, 3, now); // sent=20, bounced=3 → rate=15%

    const verdict = await checkAccountAbuse(db, accountId, { now });
    expect(verdict.action).toBe("suspend");
    if (verdict.action === "suspend") {
      expect(verdict.reason).toContain("15.0%");
    }
    expect(verdict.sent).toBe(20);
    expect(verdict.bounced).toBe(3);

    await db.close();
  });

  test("바운스율이 임계와 정확히 같음(strict >) → ok", async () => {
    const db = await freshDb();
    const accountId = ulid();
    const now = Date.now();
    await seedQueueRows(db, accountId, Q_DONE, 18, now);
    await seedQueueRows(db, accountId, Q_BOUNCED, 2, now); // sent=20, bounced=2 → rate=10% == 기본 임계

    const verdict = await checkAccountAbuse(db, accountId, { now });
    expect(verdict.action).toBe("ok");
    expect(verdict.rate).toBeCloseTo(0.1, 5);

    await db.close();
  });

  test("평가 창(windowMs) 밖의 오래된 행은 집계에서 제외됨", async () => {
    const db = await freshDb();
    const accountId = ulid();
    const now = Date.now();
    const windowMs = 24 * 60 * 60 * 1000;
    const oldCreatedAt = now - windowMs - 1000; // 창 밖 — 전부 바운스라도 카운트되면 안 됨
    await seedQueueRows(db, accountId, Q_BOUNCED, 20, oldCreatedAt);

    const verdict = await checkAccountAbuse(db, accountId, { now, windowMs });
    expect(verdict.action).toBe("ok"); // 창 밖 행은 안 세므로 sent=0 → 표본 미달
    expect(verdict.sent).toBe(0);
    expect(verdict.bounced).toBe(0);

    await db.close();
  });
});

describe("suspendAccount", () => {
  test("status 1(active) → 0(suspended)", async () => {
    const db = await freshDb();
    const accountId = await insertAccount(db, { status: ACCT_ACTIVE });

    await suspendAccount(db, accountId);
    expect(await getAccountStatus(db, accountId)).toBe(ACCT_SUSPENDED);

    await db.close();
  });

  test("멱등 — 이미 suspended인 계정은 에러 없이 그대로 유지", async () => {
    const db = await freshDb();
    const accountId = await insertAccount(db, { status: ACCT_SUSPENDED });

    await suspendAccount(db, accountId);
    expect(await getAccountStatus(db, accountId)).toBe(ACCT_SUSPENDED);

    await db.close();
  });
});

describe("MtaWorker.sweepAbuse", () => {
  test("활성화 시 — 고바운스 계정은 정지, 정상 계정은 그대로", async () => {
    const db = await freshDb();
    const now = Date.now();

    const highBounceAccount = await insertAccount(db);
    await seedQueueRows(db, highBounceAccount, Q_DONE, 15, now);
    await seedQueueRows(db, highBounceAccount, Q_BOUNCED, 5, now); // sent=20, rate=25%

    const cleanAccount = await insertAccount(db);
    await seedQueueRows(db, cleanAccount, Q_DONE, 20, now);

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(),
      resolveMx: fakeResolveMx(),
      ehloName: "worker.test",
      abuse: { enabled: true, now },
    });

    const result = await worker.sweepAbuse();
    expect(result).toEqual({ checked: 2, suspended: 1 });

    expect(await getAccountStatus(db, highBounceAccount)).toBe(ACCT_SUSPENDED);
    expect(await getAccountStatus(db, cleanAccount)).toBe(ACCT_ACTIVE);

    await db.close();
  });

  test("비활성화(abuse 옵션 미지정) — sweepAbuse가 아무것도 하지 않음", async () => {
    const db = await freshDb();
    const now = Date.now();

    const highBounceAccount = await insertAccount(db);
    await seedQueueRows(db, highBounceAccount, Q_DONE, 15, now);
    await seedQueueRows(db, highBounceAccount, Q_BOUNCED, 5, now); // sent=20, rate=25%

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(),
      resolveMx: fakeResolveMx(),
      ehloName: "worker.test",
      // abuse 미지정 — 기본 비활성
    });

    const result = await worker.sweepAbuse();
    expect(result).toEqual({ checked: 0, suspended: 0 });
    expect(await getAccountStatus(db, highBounceAccount)).toBe(ACCT_ACTIVE); // 손대지 않음

    await db.close();
  });
});
