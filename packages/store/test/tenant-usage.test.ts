/** 테넌트 사용량 미터링 — 계정 카운터 합산 + 최근 창 발송 미터(mta_queue). */
import { describe, expect, test } from "@ionosphere/testkit";
import { ulid } from "@ionosphere/core";
import { setupFixture, makeAppendInput } from "./helpers.ts";

async function enqueue(db: Awaited<ReturnType<typeof setupFixture>>["db"], tenantId: string, status: number, createdAt: number) {
  await db.batch([
    {
      sql: `INSERT INTO mta_queue (id, tenant_id, account_id, blob_id, env_from, rcpt, rcpt_domain, status, attempts, next_attempt, created_at)
            VALUES (?, ?, NULL, ?, 's@x.test', 'r@y.test', 'y.test', ?, 0, ?, ?)`,
      params: [ulid(), tenantId, "b".repeat(64), status, createdAt, createdAt],
    },
  ]);
}

describe("Store.tenantUsage", () => {
  test("계정/메시지/저장 집계 + 발송 상태별 미터", async () => {
    const { db, store, tenantId, accountId, inboxId } = await setupFixture();
    // 두 번째 계정(정지 status=2)
    await store.createAccount({ tenantId, email: "b@acme.test" });
    // 메시지 2통(500+300 bytes)
    await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId], sizeBytes: 500 }));
    await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId], sizeBytes: 300 }));

    const now = 1_800_000_000_000;
    await enqueue(db, tenantId, 2, now - 1000); // delivered
    await enqueue(db, tenantId, 2, now - 2000); // delivered
    await enqueue(db, tenantId, 3, now - 3000); // bounced
    await enqueue(db, tenantId, 0, now - 4000); // queued(pending)
    await enqueue(db, tenantId, 4, now - 5000); // deferred(pending)
    await enqueue(db, tenantId, 2, now - 40 * 86_400_000); // 창 밖(30일 초과) → 제외

    const u = await store.tenantUsage(tenantId, { now });
    expect(u.tenantId).toBe(tenantId);
    expect(u.accounts).toBe(2);
    expect(u.activeAccounts).toBe(2); // createAccount 기본 status=1
    expect(u.messages).toBe(2);
    expect(u.storageBytes).toBe(800);
    expect(u.window.delivered).toBe(2); // 창 밖 1건 제외
    expect(u.window.bounced).toBe(1);
    expect(u.window.pending).toBe(2); // queued + deferred
    await db.close();
  });

  test("빈 테넌트 → 0 집계", async () => {
    const { db, store } = await setupFixture();
    const { tenantId } = await store.createTenant("empty");
    const u = await store.tenantUsage(tenantId);
    expect(u).toMatchObject({ accounts: 0, messages: 0, storageBytes: 0 });
    expect(u.window.delivered).toBe(0);
    await db.close();
  });
});
