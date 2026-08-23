import { describe, expect, test } from "@ionosphere/testkit";
import { ulid } from "@ionosphere/core";
import { DEFAULT_RATE_LIMIT, enqueueMessage as realEnqueueMessage, OutboundRejectedError } from "../src/enqueue.ts";
import { fakeTenantAccount, freshDb, verifiedDomain } from "./helpers.ts";

/**
 * 이 파일의 테스트는 **발신자 소유 검증의 대상이 아니다** — 각자 다른 게이트(도메인·레이트리밋·
 * 필드 정확성)를 본다. 소유 검증은 기본 on이라 가짜 accountId로는 전부 걸리므로 여기서만 끈다.
 * 검증 자체의 회귀는 sender-ownership.test.ts가 지킨다.
 */
const enqueueMessage: typeof realEnqueueMessage = (db, input, opts) =>
  realEnqueueMessage(db, input, { requireSenderOwnership: false, ...opts });

describe("enqueueMessage", () => {
  test("행 생성 — 필드 정확성 (tenant_id/account_id/blob_id/env_from/rcpt/rcpt_domain/verp_token/status/attempts)", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");
    const submissionId = ulid();

    const before = Date.now();
    const result = await enqueueMessage(db, {
      tenantId,
      accountId,
      submissionId,
      blobId: "b".repeat(64), sizeBytes: 100,
      envFrom: "bounce@sender.test",
      rcpts: ["Alice@Example.test", "bob@example.test"],
    });

    expect(result.queuedIds).toHaveLength(2);
    expect(result.skipped).toEqual([]);

    const { rows } = await db.query({
      sql: "SELECT * FROM mta_queue WHERE id IN (?, ?) ORDER BY rcpt ASC",
      params: result.queuedIds,
    });
    expect(rows).toHaveLength(2);

    const bobRow = rows.find((r) => r.rcpt === "bob@example.test");
    const aliceRow = rows.find((r) => r.rcpt === "Alice@Example.test");
    expect(bobRow).toBeDefined();
    expect(aliceRow).toBeDefined();

    for (const row of rows) {
      expect(row.tenant_id).toBe(tenantId);
      expect(row.account_id).toBe(accountId);
      expect(row.submission_id).toBe(submissionId);
      expect(row.blob_id).toBe("b".repeat(64));
      expect(row.env_from).toBe("bounce@sender.test");
      expect(Number(row.status)).toBe(0); // queued
      expect(Number(row.attempts)).toBe(0);
      expect(row.lease_until).toBeNull();
      expect(row.last_error).toBeNull();
      expect(typeof row.verp_token).toBe("string");
      expect(String(row.verp_token)).toHaveLength(16); // 16-hex
      expect(Number(row.next_attempt)).toBeGreaterThanOrEqual(before);
    }

    expect(bobRow?.rcpt_domain).toBe("example.test");
    // rcpt 원문 대소문자는 보존, rcpt_domain만 소문자 정규화 대상이 아님(원문 rcpt 그대로) —
    // 도메인 매칭/그룹핑용 rcpt_domain은 소문자로 저장
    expect(aliceRow?.rcpt).toBe("Alice@Example.test");
    expect(aliceRow?.rcpt_domain).toBe("example.test");

    // verp_token은 행마다 서로 달라야 함
    expect(bobRow?.verp_token).not.toBe(aliceRow?.verp_token);

    await db.close();
  });

  test("suppression에 걸린 수신자는 skipped로 빠지고 큐에 적재되지 않음", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");

    await db.batch([
      {
        sql: "INSERT INTO suppressions (tenant_id, email, reason, source, created_at) VALUES (?, ?, 0, 'test', ?)",
        params: [tenantId, "blocked@example.test", Date.now()],
      },
    ]);

    const result = await enqueueMessage(db, {
      tenantId,
      accountId,
      blobId: "c".repeat(64), sizeBytes: 100,
      envFrom: "bounce@sender.test",
      rcpts: ["blocked@example.test", "ok@example.test"],
    });

    expect(result.queuedIds).toHaveLength(1);
    expect(result.skipped).toEqual([{ rcpt: "blocked@example.test", reason: "suppressed" }]);

    const { rows } = await db.query({
      sql: "SELECT rcpt FROM mta_queue WHERE tenant_id = ?",
      params: [tenantId],
    });
    expect(rows.map((r) => r.rcpt)).toEqual(["ok@example.test"]);

    await db.close();
  });

  test("모든 수신자가 suppressed면 빈 배치 — DB에 아무 행도 적재하지 않음", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");
    await db.batch([
      {
        sql: "INSERT INTO suppressions (tenant_id, email, reason, source, created_at) VALUES (?, ?, 0, 'test', ?)",
        params: [tenantId, "blocked@example.test", Date.now()],
      },
    ]);

    const result = await enqueueMessage(db, {
      tenantId,
      accountId,
      blobId: "d".repeat(64), sizeBytes: 100,
      envFrom: "bounce@sender.test",
      rcpts: ["blocked@example.test"],
    });

    expect(result.queuedIds).toEqual([]);
    expect(result.skipped).toEqual([{ rcpt: "blocked@example.test", reason: "suppressed" }]);

    await db.close();
  });

  test("sendAt이 next_attempt로 그대로 반영됨(예약 발송)", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");
    const sendAt = Date.now() + 3_600_000;

    const result = await enqueueMessage(db, {
      tenantId,
      accountId,
      blobId: "e".repeat(64), sizeBytes: 100,
      envFrom: "bounce@sender.test",
      rcpts: ["future@example.test"],
      sendAt,
    });

    const { rows } = await db.query({
      sql: "SELECT next_attempt FROM mta_queue WHERE id = ?",
      params: result.queuedIds,
    });
    expect(Number(rows[0]?.next_attempt)).toBe(sendAt);

    await db.close();
  });
});

describe("enqueueMessage — 아웃바운드 게이트 (PLAN.md §8 ②)", () => {
  test("envFrom 도메인이 같은 테넌트의 status=1이면 통과", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "verified.test");

    const result = await enqueueMessage(db, {
      tenantId,
      accountId,
      blobId: "1".repeat(64), sizeBytes: 100,
      envFrom: "sender@verified.test",
      rcpts: ["rcpt@example.test"],
    });
    expect(result.queuedIds).toHaveLength(1);

    await db.close();
  });

  test("envFrom 도메인이 status=0(미검증)이면 OutboundRejectedError(domain-unverified)", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();
    const now = Date.now();
    await db.batch([
      {
        sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, 'unverified.test', 0, ?, ?)",
        params: [ulid(), tenantId, now, now],
      },
    ]);

    const promise = enqueueMessage(db, {
      tenantId,
      accountId,
      blobId: "2".repeat(64), sizeBytes: 100,
      envFrom: "sender@unverified.test",
      rcpts: ["rcpt@example.test"],
    });
    await expect(promise).rejects.toThrow(OutboundRejectedError);
    await expect(promise.catch((e) => e)).resolves.toMatchObject({ reason: "domain-unverified" });

    await db.close();
  });

  test("envFrom 도메인이 다른 테넌트 소유면 거부", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();
    const otherTenantId = ulid();
    await verifiedDomain(db, otherTenantId, "other-tenant.test");

    const promise = enqueueMessage(db, {
      tenantId,
      accountId,
      blobId: "3".repeat(64), sizeBytes: 100,
      envFrom: "sender@other-tenant.test",
      rcpts: ["rcpt@example.test"],
    });
    await expect(promise.catch((e) => e)).resolves.toMatchObject({
      name: "OutboundRejectedError",
      reason: "domain-unverified",
    });

    await db.close();
  });

  test("envFrom에 도메인부가 없으면 거부", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();

    const promise = enqueueMessage(db, {
      tenantId,
      accountId,
      blobId: "4".repeat(64), sizeBytes: 100,
      envFrom: "no-domain",
      rcpts: ["rcpt@example.test"],
    });
    await expect(promise.catch((e) => e)).resolves.toMatchObject({ reason: "domain-unverified" });

    await db.close();
  });

  test("system 선언은 미검증/미등록 도메인이어도 게이트를 우회 (DSN 등 시스템 발송)", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();

    const result = await enqueueMessage(db, {
      tenantId,
      accountId,
      blobId: "5".repeat(64), sizeBytes: 100,
      envFrom: "mailer-daemon@unknown-domain.test",
      rcpts: ["rcpt@example.test"],
      system: { relayPerHour: 100, envFrom: "srs" },
    });
    expect(result.queuedIds).toHaveLength(1);

    await db.close();
  });
});

describe("enqueueMessage — 계정별 레이트리밋 (PLAN.md §8 ③)", () => {
  test("perMinute:3 — 3rcpt까지 통과, 같은 분 내 4번째 rcpt는 rate-limited", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");
    const now = Date.now();

    const ok = await enqueueMessage(
      db,
      {
        tenantId,
        accountId,
        blobId: "a".repeat(64), sizeBytes: 100,
        envFrom: "bounce@sender.test",
        rcpts: ["r1@example.test", "r2@example.test", "r3@example.test"],
      },
      { rateLimit: { perMinute: 3 }, now },
    );
    expect(ok.queuedIds).toHaveLength(3);

    const promise = enqueueMessage(
      db,
      {
        tenantId,
        accountId,
        blobId: "b".repeat(64), sizeBytes: 100,
        envFrom: "bounce@sender.test",
        rcpts: ["r4@example.test"],
      },
      { rateLimit: { perMinute: 3 }, now: now + 1000 },
    );
    await expect(promise.catch((e) => e)).resolves.toMatchObject({
      name: "OutboundRejectedError",
      reason: "rate-limited",
    });

    await db.close();
  });

  test("윈도우 경과 후(now 이동) 다시 허용됨", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");
    const now = Date.now();

    await enqueueMessage(
      db,
      {
        tenantId,
        accountId,
        blobId: "c".repeat(64), sizeBytes: 100,
        envFrom: "bounce@sender.test",
        rcpts: ["r1@example.test", "r2@example.test", "r3@example.test"],
      },
      { rateLimit: { perMinute: 3 }, now },
    );

    // 60초 경과 → perMinute 윈도우 밖이므로 다시 허용
    const later = await enqueueMessage(
      db,
      {
        tenantId,
        accountId,
        blobId: "d".repeat(64), sizeBytes: 100,
        envFrom: "bounce@sender.test",
        rcpts: ["r4@example.test"],
      },
      { rateLimit: { perMinute: 3 }, now: now + 60_001 },
    );
    expect(later.queuedIds).toHaveLength(1);

    await db.close();
  });

  test("다중 수신자 비용 합산 — 3rcpt 발송 후 1rcpt 발송(perMinute:3)은 두 번째가 거부됨", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");
    const now = Date.now();

    const first = await enqueueMessage(
      db,
      {
        tenantId,
        accountId,
        blobId: "e".repeat(64), sizeBytes: 100,
        envFrom: "bounce@sender.test",
        rcpts: ["r1@example.test", "r2@example.test", "r3@example.test"],
      },
      { rateLimit: { perMinute: 3 }, now },
    );
    expect(first.queuedIds).toHaveLength(3);

    const second = enqueueMessage(
      db,
      {
        tenantId,
        accountId,
        blobId: "f".repeat(64), sizeBytes: 100,
        envFrom: "bounce@sender.test",
        rcpts: ["r4@example.test"],
      },
      { rateLimit: { perMinute: 3 }, now },
    );
    await expect(second.catch((e) => e)).resolves.toMatchObject({ reason: "rate-limited" });

    await db.close();
  });

  test("perHour/perDay는 perMinute와 독립적으로 강제됨", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");
    const now = Date.now();

    // perMinute은 넉넉히 두고 perHour만 좁게 — 1분 이내라 perMinute은 통과해야 하는데
    // perHour 한도(2)를 3번째 rcpt에서 넘겨 거부되는지 확인
    const promise = enqueueMessage(
      db,
      {
        tenantId,
        accountId,
        blobId: "g".repeat(64), sizeBytes: 100,
        envFrom: "bounce@sender.test",
        rcpts: ["r1@example.test", "r2@example.test", "r3@example.test"],
      },
      { rateLimit: { perMinute: 100, perHour: 2 }, now },
    );
    await expect(promise.catch((e) => e)).resolves.toMatchObject({ reason: "rate-limited" });

    // perDay도 동일하게 독립 검증
    const dayPromise = enqueueMessage(
      db,
      {
        tenantId,
        accountId,
        blobId: "h".repeat(64), sizeBytes: 100,
        envFrom: "bounce@sender.test",
        rcpts: ["s1@example.test", "s2@example.test", "s3@example.test"],
      },
      { rateLimit: { perMinute: 100, perHour: 100, perDay: 2 }, now },
    );
    await expect(dayPromise.catch((e) => e)).resolves.toMatchObject({ reason: "rate-limited" });

    await db.close();
  });

  test("opts 생략 시 레이트리밋 없음 — 기본 한도(perMinute=30 등)를 넘어도 통과", async () => {
    const db = await freshDb();
    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");
    expect(DEFAULT_RATE_LIMIT.perMinute).toBe(30);

    const rcpts = Array.from({ length: DEFAULT_RATE_LIMIT.perMinute + 5 }, (_, i) => `r${i}@example.test`);
    const result = await enqueueMessage(db, {
      tenantId,
      accountId,
      blobId: "i".repeat(64), sizeBytes: 100,
      envFrom: "bounce@sender.test",
      rcpts,
    });
    expect(result.queuedIds).toHaveLength(rcpts.length);

    await db.close();
  });
});
