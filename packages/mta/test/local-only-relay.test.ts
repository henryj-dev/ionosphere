/**
 * `localOnly` 게이트의 릴레이 예외.
 *
 * localOnly를 켠 이유는 "정책상 외부를 막고 싶다"가 아니라 **"나갈 길이 없다"**였다
 * (아웃바운드 25 차단). 그래서 릴레이를 붙인 발신 도메인까지 막는 건 원래 의도가 아니다.
 * 게이트를 플래그가 아니라 **실제 능력**에 묶어, 릴레이를 등록하는 것만으로 그 도메인의
 * 외부 발송이 열리게 한다 — 설정을 두 군데 맞추지 않아도 되도록.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { ulid } from "@ionosphere/core";
import { enqueueMessage, OutboundRejectedError } from "../src/enqueue.ts";
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

async function send(
  db: Awaited<ReturnType<typeof freshDb>>,
  o: { tenantId: string; accountId: string; rcpt: string; hasRelayFor?: (t: string, d: string) => Promise<boolean> },
) {
  return enqueueMessage(
    db,
    { tenantId: o.tenantId, accountId: o.accountId, blobId: BLOB, sizeBytes: 10, envFrom: "alice@acme.test", rcpts: [o.rcpt] },
    { localOnly: true, ...(o.hasRelayFor ? { hasRelayFor: o.hasRelayFor } : {}) },
  );
}

async function fixture() {
  const db = await freshDb();
  const tenantId = ulid();
  await verifiedDomain(db, tenantId, "acme.test");
  const accountId = await seedAccount(db, tenantId, "alice@acme.test");
  return { db, tenantId, accountId };
}

describe("localOnly + 릴레이 능력", () => {
  test("릴레이가 없으면 외부 수신자는 종전대로 거절된다", async () => {
    const { db, tenantId, accountId } = await fixture();
    const err = await send(db, { tenantId, accountId, rcpt: "out@remote.test" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OutboundRejectedError);
    expect((err as OutboundRejectedError).reason).toBe("external-disabled");
    await db.close();
  });

  test("★릴레이가 있으면 외부 수신자가 통과한다 — 이게 이 파일의 이유다", async () => {
    const { db, tenantId, accountId } = await fixture();
    const res = await send(db, { tenantId, accountId, rcpt: "out@remote.test", hasRelayFor: async () => true });
    expect(res.queuedIds).toHaveLength(1);
    await db.close();
  });

  test("판정은 **발신** 도메인으로 한다 — 수신 도메인이 아니다", async () => {
    const { db, tenantId, accountId } = await fixture();
    const seen: { tenantId: string; senderDomain: string }[] = [];
    await send(db, {
      tenantId,
      accountId,
      rcpt: "out@remote.test",
      hasRelayFor: async (t, d) => {
        seen.push({ tenantId: t, senderDomain: d });
        return true;
      },
    });
    expect(seen).toEqual([{ tenantId, senderDomain: "acme.test" }]);
    await db.close();
  });

  test("릴레이가 그 도메인엔 없으면 여전히 거절된다", async () => {
    const { db, tenantId, accountId } = await fixture();
    const err = await send(db, {
      tenantId,
      accountId,
      rcpt: "out@remote.test",
      hasRelayFor: async (_t, d) => d === "other.test",
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OutboundRejectedError);
    expect((err as OutboundRejectedError).reason).toBe("external-disabled");
    await db.close();
  });

  test("로컬 수신자는 릴레이 여부와 무관하게 통과한다", async () => {
    const { db, tenantId, accountId } = await fixture();
    const res = await send(db, { tenantId, accountId, rcpt: "bob@acme.test" });
    expect(res.queuedIds).toHaveLength(1);
    await db.close();
  });

  /**
   * 조회 실패를 "릴레이 없음"으로 뭉개면, DB가 잠깐 흔들리는 동안 릴레이를 붙여 둔 도메인의
   * 메일이 **550으로 영구 거절**된다 — 사용자에겐 설정이 사라진 것으로 보인다.
   * 던져서 상위가 4xx로 돌리게 해야 클라이언트가 재시도한다.
   */
  test("릴레이 조회가 실패하면 영구 거절이 아니라 예외로 올린다", async () => {
    const { db, tenantId, accountId } = await fixture();
    const err = await send(db, {
      tenantId,
      accountId,
      rcpt: "out@remote.test",
      hasRelayFor: async () => {
        throw new Error("DB 연결 끊김");
      },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err).not.toBeInstanceOf(OutboundRejectedError);
    await db.close();
  });

  test("localOnly가 꺼져 있으면 릴레이 판정 자체를 하지 않는다", async () => {
    const { db, tenantId, accountId } = await fixture();
    let called = false;
    const res = await enqueueMessage(
      db,
      { tenantId, accountId, blobId: BLOB, sizeBytes: 10, envFrom: "alice@acme.test", rcpts: ["out@remote.test"] },
      {
        hasRelayFor: async () => {
          called = true;
          return false;
        },
      },
    );
    expect(res.queuedIds).toHaveLength(1);
    expect(called).toBe(false);
    await db.close();
  });
});
