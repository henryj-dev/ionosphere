/**
 * suppression 자동 만료 (마이그레이션 008).
 *
 * `exhausted`는 "상대가 영구 거절했다"가 아니라 **"우리가 며칠간 못 보내서 포기했다"**이다.
 * 원인이 우리 쪽 DNS·네트워크 장애일 수 있는데 지금까지는 hardBounce와 똑같이 영구로 남아,
 * 장애가 복구돼도 그때 큐에 있던 정상 수신자가 영영 막혔다. 그걸 시간이 풀어 주도록 했다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { ulid } from "@ionosphere/core";
import { SUPPRESSION_REASON } from "@ionosphere/db";
import { enqueueMessage } from "../src/enqueue.ts";
import { SUPPRESSION_EXHAUSTED_TTL_MS, suppressionExpiresAt } from "../src/suppression.ts";
import { freshDb, verifiedDomain } from "./helpers.ts";

const BLOB = "a".repeat(64);

async function seedAccount(db: Awaited<ReturnType<typeof freshDb>>, tenantId: string, email: string): Promise<string> {
  const id = ulid();
  await db.batch([
    {
      sql: "INSERT INTO accounts (id, tenant_id, email, status, uidvalidity_last, created_at) VALUES (?, ?, ?, 1, 1, ?)",
      params: [id, tenantId, email, Date.now()],
    },
  ]);
  return id;
}

async function suppress(
  db: Awaited<ReturnType<typeof freshDb>>,
  o: { tenantId: string; email: string; reason: number; expiresAt: number | null },
): Promise<void> {
  await db.batch([
    {
      sql: "INSERT INTO suppressions (tenant_id, email, reason, source, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
      params: [o.tenantId, o.email, o.reason, "test", Date.now(), o.expiresAt],
    },
  ]);
}

async function fixture() {
  const db = await freshDb();
  const tenantId = ulid();
  await verifiedDomain(db, tenantId, "acme.test");
  const accountId = await seedAccount(db, tenantId, "alice@acme.test");
  return { db, tenantId, accountId };
}

function send(db: Awaited<ReturnType<typeof freshDb>>, tenantId: string, accountId: string, rcpt: string, now?: number) {
  return enqueueMessage(
    db,
    { tenantId, accountId, blobId: BLOB, sizeBytes: 10, envFrom: "alice@acme.test", rcpts: [rcpt] },
    { ...(now !== undefined ? { now } : {}) },
  );
}

describe("만료 정책", () => {
  test("exhausted는 TTL이 붙고 hardBounce는 영구(null)다", () => {
    const now = 1_700_000_000_000;
    expect(suppressionExpiresAt(SUPPRESSION_REASON.exhausted, now)).toBe(now + SUPPRESSION_EXHAUSTED_TTL_MS);
    // 상대의 5xx 영구 거절은 다시 보내도 같은 답이다 — 시간이 풀어 줄 이유가 없다.
    expect(suppressionExpiresAt(SUPPRESSION_REASON.hardBounce, now)).toBeNull();
  });
});

describe("게이트 판정", () => {
  test("만료 전이면 차단된다", async () => {
    const { db, tenantId, accountId } = await fixture();
    const now = Date.now();
    await suppress(db, { tenantId, email: "blocked@remote.test", reason: SUPPRESSION_REASON.exhausted, expiresAt: now + 60_000 });

    const res = await send(db, tenantId, accountId, "blocked@remote.test", now);
    expect(res.queuedIds).toHaveLength(0);
    expect(res.skipped.map((s) => s.reason)).toEqual(["suppressed"]);
    await db.close();
  });

  test("★만료 후에는 다시 보낼 수 있다 — 이게 이 파일의 이유다", async () => {
    const { db, tenantId, accountId } = await fixture();
    const now = Date.now();
    await suppress(db, { tenantId, email: "recovered@remote.test", reason: SUPPRESSION_REASON.exhausted, expiresAt: now - 1 });

    const res = await send(db, tenantId, accountId, "recovered@remote.test", now);
    expect(res.queuedIds).toHaveLength(1);
    expect(res.skipped).toHaveLength(0);
    await db.close();
  });

  test("hardBounce(만료 없음)는 시간이 지나도 계속 차단된다", async () => {
    const { db, tenantId, accountId } = await fixture();
    await suppress(db, { tenantId, email: "hard@remote.test", reason: SUPPRESSION_REASON.hardBounce, expiresAt: null });

    // 아주 먼 미래로 시각을 밀어도 풀리면 안 된다
    const res = await send(db, tenantId, accountId, "hard@remote.test", Date.now() + 10 * 365 * 24 * 3600_000);
    expect(res.queuedIds).toHaveLength(0);
    expect(res.skipped.map((s) => s.reason)).toEqual(["suppressed"]);
    await db.close();
  });

  test("만료 경계: expires_at === now 는 이미 만료다", async () => {
    const { db, tenantId, accountId } = await fixture();
    const now = Date.now();
    await suppress(db, { tenantId, email: "edge@remote.test", reason: SUPPRESSION_REASON.exhausted, expiresAt: now });

    const res = await send(db, tenantId, accountId, "edge@remote.test", now);
    expect(res.queuedIds).toHaveLength(1);
    await db.close();
  });

  /**
   * 만료된 행을 **지우지 않고 남기는** 것이 설계다 — 왜 한 번 막혔는지가 운영 정보고,
   * 반복해서 exhausted에 걸리는 주소를 알아보려면 이력이 남아야 한다.
   */
  test("만료돼도 행은 남는다(이력 보존)", async () => {
    const { db, tenantId, accountId } = await fixture();
    const now = Date.now();
    await suppress(db, { tenantId, email: "recovered@remote.test", reason: SUPPRESSION_REASON.exhausted, expiresAt: now - 1 });
    await send(db, tenantId, accountId, "recovered@remote.test", now);

    const { rows } = await db.query({ sql: "SELECT email FROM suppressions WHERE tenant_id = ?", params: [tenantId] });
    expect(rows).toHaveLength(1);
    await db.close();
  });
});
