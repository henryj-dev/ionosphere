/**
 * 발신자 소유 검증(opt-in).
 *
 * 기존 게이트는 envFrom의 **도메인**이 테넌트 소유·검증됨인지만 본다. 그래서 같은 테넌트
 * 안에서는 아무 계정이나 다른 계정을 사칭해 보낼 수 있다(ceo@ 사칭 등).
 *
 * 기본 off인 이유: "누가 누구 이름으로 보낼 수 있는가"는 제품 정책이다. 공유 사서함·대리
 * 발송처럼 의도적으로 다른 주소를 쓰는 정상 흐름이 있어, 서버가 범위를 임의로 정하면
 * 멀쩡히 쓰던 배포가 조용히 끊긴다. 그래서 **기본 동작이 바뀌지 않는다는 것도 함께 검증**한다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { ulid } from "@ionosphere/core";
import { enqueueMessage, OutboundRejectedError } from "../src/enqueue.ts";
import { freshDb, verifiedDomain } from "./helpers.ts";

const BLOB = "a".repeat(64);

async function seedAccount(
  db: Awaited<ReturnType<typeof freshDb>>,
  tenantId: string,
  email: string,
): Promise<string> {
  const id = ulid();
  await db.batch([
    {
      sql: "INSERT INTO accounts (id, tenant_id, email, status, uidvalidity_last, created_at) VALUES (?, ?, ?, 1, 1, ?)",
      params: [id, tenantId, email, Date.now()],
    },
  ]);
  return id;
}

/** 알리아스 주소 + 그 목적지(팬아웃 모델) — "이 계정이 쓸 수 있는 주소"의 다른 형태. */
async function seedAlias(
  db: Awaited<ReturnType<typeof freshDb>>,
  tenantId: string,
  localpart: string,
  domain: string,
  accountId: string,
): Promise<void> {
  const { rows } = await db.query({ sql: "SELECT id FROM domains WHERE tenant_id = ? AND name = ?", params: [tenantId, domain] });
  const addressId = ulid();
  await db.batch([
    {
      sql: "INSERT INTO addresses (id, tenant_id, domain_id, localpart, forward_to, created_at) VALUES (?, ?, ?, ?, NULL, ?)",
      params: [addressId, tenantId, String(rows[0]!.id), localpart, Date.now()],
    },
    { sql: "INSERT INTO address_targets (address_id, account_id) VALUES (?, ?)", params: [addressId, accountId] },
  ]);
}

/** `on`을 명시적으로 넘긴다 — 빈 옵션(`{}`)은 이제 **기본값 on**이라 해제가 되지 않는다. */
function send(db: Awaited<ReturnType<typeof freshDb>>, tenantId: string, accountId: string, envFrom: string, on: boolean) {
  return enqueueMessage(
    db,
    { tenantId, accountId, blobId: BLOB, sizeBytes: 10, envFrom, rcpts: ["out@remote.test"] },
    { requireSenderOwnership: on },
  );
}

describe("발신자 소유 검증", () => {
  /**
   * ★기본값이 on이라는 것 자체가 회귀 대상이다. 기본값을 조립층(app.ts)이 아니라 게이트에
   * 둔 이유도 여기 있다 — enqueueMessage를 직접 부르는 갈래가 검사 없이 지나가면 안 된다.
   */
  test("기본값으로 남의 주소 발송이 막힌다(opts를 넘기지 않아도)", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await verifiedDomain(db, tenantId, "acme.test");
    const alice = await seedAccount(db, tenantId, "alice@acme.test");
    await seedAccount(db, tenantId, "ceo@acme.test");

    const err = await enqueueMessage(db, {
      tenantId,
      accountId: alice,
      blobId: BLOB,
      sizeBytes: 10,
      envFrom: "ceo@acme.test",
      rcpts: ["out@remote.test"],
    }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OutboundRejectedError);
    expect((err as OutboundRejectedError).reason).toBe("sender-not-owned");

    await db.close();
  });

  test("명시적으로 false를 넘기면 종전 동작(사칭 통과) — 대리 발송 배포용 탈출구", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await verifiedDomain(db, tenantId, "acme.test");
    const alice = await seedAccount(db, tenantId, "alice@acme.test");
    await seedAccount(db, tenantId, "ceo@acme.test");

    const res = await send(db, tenantId, alice, "ceo@acme.test", false);
    expect(res.queuedIds).toHaveLength(1);

    await db.close();
  });

  test("켜면 남의 주소로는 보낼 수 없다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await verifiedDomain(db, tenantId, "acme.test");
    const alice = await seedAccount(db, tenantId, "alice@acme.test");
    await seedAccount(db, tenantId, "ceo@acme.test");

    const err = await send(db, tenantId, alice, "ceo@acme.test", true).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OutboundRejectedError);
    expect((err as OutboundRejectedError).reason).toBe("sender-not-owned");

    await db.close();
  });

  test("켜도 자기 주소와 자기를 가리키는 알리아스는 통과한다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await verifiedDomain(db, tenantId, "acme.test");
    const alice = await seedAccount(db, tenantId, "alice@acme.test");
    await seedAlias(db, tenantId, "sales", "acme.test", alice);

    expect((await send(db, tenantId, alice, "alice@acme.test", true)).queuedIds).toHaveLength(1);
    expect((await send(db, tenantId, alice, "sales@acme.test", true)).queuedIds).toHaveLength(1);

    await db.close();
  });

  test("캐치올은 소유로 치지 않는다 — 허용하면 도메인 전체 사칭이 된다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await verifiedDomain(db, tenantId, "acme.test");
    const alice = await seedAccount(db, tenantId, "alice@acme.test");
    await seedAlias(db, tenantId, "*", "acme.test", alice);

    const err = await send(db, tenantId, alice, "anyone@acme.test", true).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OutboundRejectedError);

    await db.close();
  });
});

/**
 * 감사 5차 L-9 회귀 — 수신 경로(`resolveRoute`)는 `+tag`를 떼고 매칭하는데 **발신 소유 검증만
 * 안 뗐다.** 정규화가 갈라져서 `user+tag@`로 보내는 정상 사용자가 550을 받았다.
 */
describe("subaddress 정규화 (L-9)", () => {
  test("user+tag@ 로 보내도 자기 주소로 인정된다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await verifiedDomain(db, tenantId, "sender.test");
    const accountId = await seedAccount(db, tenantId, "user@sender.test");

    const r = await enqueueMessage(db, {
      tenantId,
      accountId,
      blobId: BLOB,
      sizeBytes: 10,
      envFrom: "user+newsletter@sender.test",
      rcpts: ["dest@remote.test"],
    });
    expect(r.queuedIds).toHaveLength(1);

    await db.close();
  });

  test("tag를 떼어도 남의 주소면 여전히 거부된다(우회 아님)", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await verifiedDomain(db, tenantId, "sender.test");
    const accountId = await seedAccount(db, tenantId, "user@sender.test");

    let rejected: OutboundRejectedError | null = null;
    try {
      await enqueueMessage(db, {
        tenantId,
        accountId,
        blobId: BLOB,
        sizeBytes: 10,
        envFrom: "ceo+x@sender.test",
        rcpts: ["dest@remote.test"],
      });
    } catch (err) {
      rejected = err as OutboundRejectedError;
    }
    expect(rejected).toBeInstanceOf(OutboundRejectedError);
    expect(rejected!.reason).toBe("sender-not-owned");

    await db.close();
  });
});
