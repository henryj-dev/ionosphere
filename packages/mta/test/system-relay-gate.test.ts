/**
 * 감사 5차 C-1 ④ + H-4 ② 회귀 — 시스템 relay 게이트.
 *
 * 예전 구조는 `internal: true` 불리언 하나가 게이트 다섯 개를 한꺼번에 껐고, 상한은
 * `opts?.relayPerHour !== undefined`일 때만 걸렸다. 그래서 **옵션을 안 넘긴 호출부 하나**가
 * 상한 없는 증폭 채널이 됐다. 지금은 `system` 선언이 상한과 봉투발신자 규율을 **필수 필드로**
 * 요구하므로 "옵션을 안 넘겨서 상한이 사라지는" 상태 자체가 표현 불가능하다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { ulid } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import { enqueueMessage, OutboundRejectedError } from "../src/enqueue.ts";
import { freshDb, verifiedDomain } from "./helpers.ts";

/** 테넌트 1개 + 검증된 도메인 1개. */
async function seed(db: DbDriver, domain: string): Promise<string> {
  const tenantId = ulid();
  await verifiedDomain(db, tenantId, domain);
  return tenantId;
}

describe("시스템 relay 게이트 (C-1)", () => {
  test("relay 상한은 옵션 없이도 걸린다 — system 선언이 상한을 함께 요구하므로", async () => {
    const db = await freshDb();
    const tenantId = await seed(db, "ours.test");

    // 상한 2. 세 번째 수신자에서 걸려야 한다.
    const relay = { relayPerHour: 2, envFrom: "srs" } as const;
    const base = { tenantId, sizeBytes: 10, envFrom: "srs@ours.test", system: relay };

    await enqueueMessage(db, { ...base, blobId: "a".repeat(64), rcpts: ["one@remote.test"] });
    await enqueueMessage(db, { ...base, blobId: "b".repeat(64), rcpts: ["two@remote.test"] });

    // 세 번째 — enqueueMessage에 **옵션 인자를 넘기지 않아도** 상한이 산다.
    let rejected: OutboundRejectedError | null = null;
    try {
      await enqueueMessage(db, { ...base, blobId: "c".repeat(64), rcpts: ["three@remote.test"] });
    } catch (err) {
      rejected = err as OutboundRejectedError;
    }
    expect(rejected).toBeInstanceOf(OutboundRejectedError);
    expect(rejected!.reason).toBe("rate-limited");

    await db.close();
  });

  test("null-sender 선언은 호출자가 넘긴 봉투발신자를 버리고 <>로 강제한다", async () => {
    const db = await freshDb();
    const tenantId = await seed(db, "ours.test");

    // 호출자가 공격자 제어 값을 넘겨도(과거 relayBounce가 그랬다) 저장되는 것은 <>다.
    await enqueueMessage(db, {
      tenantId,
      blobId: "d".repeat(64),
      sizeBytes: 10,
      envFrom: "ceo@호스팅고객.test",
      rcpts: ["victim@bank.example"],
      system: { relayPerHour: 100, envFrom: "null-sender" },
    });

    const { rows } = await db.query({ sql: "SELECT env_from FROM mta_queue" });
    expect(rows).toHaveLength(1);
    expect(String(rows[0]!.env_from)).toBe("");

    await db.close();
  });

  test("srs 선언인데 봉투발신자가 재작성되지 않았으면 거부한다", async () => {
    const db = await freshDb();
    const tenantId = await seed(db, "ours.test");

    let rejected: OutboundRejectedError | null = null;
    try {
      await enqueueMessage(db, {
        tenantId,
        blobId: "e".repeat(64),
        sizeBytes: 10,
        envFrom: "", // 도메인부 없음 — SRS 재작성 실패
        rcpts: ["x@remote.test"],
        system: { relayPerHour: 100, envFrom: "srs" },
      });
    } catch (err) {
      rejected = err as OutboundRejectedError;
    }
    expect(rejected).toBeInstanceOf(OutboundRejectedError);
    expect(rejected!.reason).toBe("invalid-address");

    await db.close();
  });
});

describe("localOnly 게이트가 미검증 도메인 행에 속지 않는다 (H-4 ②)", () => {
  test("타 테넌트가 만든 미검증 행은 외부 도메인을 로컬로 만들지 못한다", async () => {
    const db = await freshDb();
    const senderTenant = await seed(db, "ours.test");
    const now = Date.now();

    // 공격 테넌트가 gmail.com **미검증(status=0)** 행을 만든다 — domains.name에 UNIQUE가 없다.
    const attackerTenant = ulid();
    await db.batch([
      {
        sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, ?, 0, ?, ?)",
        params: [ulid(), attackerTenant, "gmail.com", now, now],
      },
    ]);

    // 내부 전용 배포에서 gmail.com으로 발송 — 예전엔 미검증 행 때문에 통과해 외부로 샜다.
    let rejected: OutboundRejectedError | null = null;
    try {
      await enqueueMessage(
        db,
        {
          tenantId: senderTenant,
          blobId: "f".repeat(64),
          sizeBytes: 10,
          envFrom: "user@ours.test",
          rcpts: ["target@gmail.com"],
        },
        { localOnly: true },
      );
    } catch (err) {
      rejected = err as OutboundRejectedError;
    }
    expect(rejected).toBeInstanceOf(OutboundRejectedError);
    expect(rejected!.reason).toBe("external-disabled");

    await db.close();
  });

  test("자기 테넌트의 미검증 도메인은 여전히 로컬로 취급된다(진단 가능성 유지)", async () => {
    const db = await freshDb();
    const tenantId = await seed(db, "ours.test");
    const now = Date.now();
    await db.batch([
      {
        sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, ?, 0, ?, ?)",
        params: [ulid(), tenantId, "pending.test", now, now],
      },
    ]);

    const r = await enqueueMessage(
      db,
      {
        tenantId,
        blobId: "0".repeat(64),
        sizeBytes: 10,
        envFrom: "user@ours.test",
        rcpts: ["someone@pending.test"],
      },
      { localOnly: true },
    );
    expect(r.queuedIds).toHaveLength(1);

    await db.close();
  });
});
