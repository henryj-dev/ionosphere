/**
 * `webhook_endpoints.secret` 봉인 — 정본 저장소의 저장 시 암호화(감사 §1 민감 자산).
 *
 * 핵심 회귀는 **서명 동치**다: 봉인은 저장 포맷만 바꿔야 하고, 배달 행에 복사되는 값은
 * 여전히 평문이어야 한다. 사본이 봉인문이 되면 워커가 그 문자열로 HMAC을 계산해
 * 수신측 검증이 전부 깨진다 — 그런데 배달 자체는 200으로 성공하므로 조용히 깨진다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { createHmac } from "node:crypto";
import { seal } from "@ionosphere/core";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { Store } from "../src/store.ts";
import { StoreError } from "../src/errors.ts";

const MASTER_KEY = "test-master-key-0123456789";
const SECRET = "sk_webhook_topsecret";
const PAYLOAD = '{"event":"inbound"}';

interface Fixture {
  db: DbDriver;
  store: Store;
  accountId: string;
}

async function setup(masterKey?: string): Promise<Fixture> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const store = new Store(db, masterKey === undefined ? {} : { masterKey });
  const { tenantId } = await store.createTenant("acme");
  const { accountId } = await store.createAccount({ tenantId, email: `wh-${Math.random().toString(36).slice(2)}@acme.test` });
  return { db, store, accountId };
}

/** 엔드포인트 정본 행의 secret 컬럼 원문(가공 없이). */
async function storedEndpointSecret(db: DbDriver, id: string): Promise<string> {
  const { rows } = await db.query({ sql: "SELECT secret FROM webhook_endpoints WHERE id = ?", params: [id] });
  return String(rows[0]!.secret);
}

/** 배달 행에 복사된 시크릿 사본. */
async function deliverySecret(db: DbDriver, accountId: string): Promise<string> {
  const { rows } = await db.query({ sql: "SELECT secret FROM webhook_deliveries WHERE account_id = ? ORDER BY created_at DESC LIMIT 1", params: [accountId] });
  return String(rows[0]!.secret);
}

function sign(secret: string, body: string): string {
  return "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
}

describe("webhook 엔드포인트 시크릿 봉인", () => {
  test("마스터키가 있으면 DB에 평문이 남지 않는다", async () => {
    const { db, store, accountId } = await setup(MASTER_KEY);
    const id = await store.addWebhookEndpoint(accountId, "https://hook.test/in", SECRET);

    const stored = await storedEndpointSecret(db, id);
    expect(stored.startsWith("enc$v1$")).toBe(true);
    expect(stored).not.toContain(SECRET);

    await db.close();
  });

  /**
   * ★핵심 회귀 — 봉인 전과 **같은 HMAC**이 나와야 한다. 사본이 봉인문으로 새면
   * 이 단언이 깨진다(그리고 실제 배달에서는 아무 에러 없이 서명만 틀린다).
   */
  test("배달 사본은 복호된 평문이라 서명이 그대로 맞는다", async () => {
    const { db, store, accountId } = await setup(MASTER_KEY);
    await store.addWebhookEndpoint(accountId, "https://hook.test/in", SECRET);

    expect(await store.enqueueWebhookDeliveries(accountId, PAYLOAD)).toBe(1);
    const copy = await deliverySecret(db, accountId);

    expect(copy).toBe(SECRET);
    expect(sign(copy, PAYLOAD)).toBe(sign(SECRET, PAYLOAD));

    await db.close();
  });

  test("마스터키가 없으면 plain$ 평문 저장이 유지되고 배달도 된다", async () => {
    const { db, store, accountId } = await setup(undefined);
    const id = await store.addWebhookEndpoint(accountId, "https://hook.test/in", SECRET);

    expect(await storedEndpointSecret(db, id)).toBe(`plain$${SECRET}`);
    await store.enqueueWebhookDeliveries(accountId, PAYLOAD);
    expect(await deliverySecret(db, accountId)).toBe(SECRET);

    await db.close();
  });

  /**
   * 봉인 도입 **이전에** 저장된 날평문(접두사 없음) — 스키마 동결이라 백필 마이그레이션이
   * 수단으로 없다. 마이그레이션 없이 그대로 읽혀야 한다.
   */
  test("접두사 없는 기존 평문 행이 마이그레이션 없이 읽힌다", async () => {
    const { db, store, accountId } = await setup(MASTER_KEY);
    await db.batch([
      {
        sql: "INSERT INTO webhook_endpoints (id, account_id, url, secret, active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
        params: ["E".repeat(26), accountId, "https://legacy.test/in", SECRET, Date.now()],
      },
    ]);

    expect(await store.enqueueWebhookDeliveries(accountId, PAYLOAD)).toBe(1);
    expect(await deliverySecret(db, accountId)).toBe(SECRET);

    await db.close();
  });

  test("빈 시크릿은 서명 없음으로 그대로 흐른다", async () => {
    const { db, store, accountId } = await setup(MASTER_KEY);
    await db.batch([
      {
        sql: "INSERT INTO webhook_endpoints (id, account_id, url, secret, active, created_at) VALUES (?, ?, ?, '', 1, ?)",
        params: ["F".repeat(26), accountId, "https://nosig.test/in", Date.now()],
      },
    ]);

    await store.enqueueWebhookDeliveries(accountId, PAYLOAD);
    expect(await deliverySecret(db, accountId)).toBe("");

    await db.close();
  });

  /**
   * 컬럼 폭 VARCHAR(128)이 봉인 결과를 담지 못하는 경계 — sqlite는 폭을 무시하지만
   * postgres/mysql은 절단·에러이고 **절단된 봉인문은 두 번 다시 열리지 않는다**.
   * 그래서 저장 시점에 거부한다(fail closed).
   */
  test("봉인 결과가 컬럼 폭을 넘는 긴 시크릿은 거부한다", async () => {
    const { db, store, accountId } = await setup(MASTER_KEY);

    // 39바이트는 통과(봉인 126자), 40바이트는 초과(130자) — 경계를 양쪽에서 고정한다.
    // base64가 3바이트 단위라 126 다음이 곧 130이다(127·128·129는 나올 수 없는 길이).
    expect(seal("a".repeat(39), MASTER_KEY).value.length).toBe(126);
    expect(seal("a".repeat(40), MASTER_KEY).value.length).toBe(130);

    await store.addWebhookEndpoint(accountId, "https://hook.test/ok", "a".repeat(39));
    await expect(store.addWebhookEndpoint(accountId, "https://hook.test/too-long", "a".repeat(40))).rejects.toBeInstanceOf(StoreError);

    await db.close();
  });
});
