/**
 * 비활성 계정이 목적지에 섞였을 때의 배달 — **중복 누적 회귀**.
 *
 * 과거 결함: 라우팅이 `accounts.status`를 보지 않아 비활성 계정을 목적지로 내줬고, 배달 단계에서
 * 스토어가 "account not active"로 던졌다. 그 예외가 팬아웃 합성기(combineFanoutOutcomes)를
 * **건너뛰어** 트랜잭션 전체가 451이 됐고, 발신측이 재시도할 때마다 **살아 있는 계정에 사본이
 * 쌓였다**(재현: 1회차 1건 → 2회차 2건). 합성기는 바로 그 중복을 막으려고 만든 것인데
 * 예외 경로가 우회했다.
 *
 * 두 층으로 막는다:
 *  ① resolveRoute가 활성 계정만 목적지로 내준다 → RCPT에서 정직하게 "수신자 없음"이 나온다
 *  ② deliverToAccount가 계정 단위 실패를 처분값(tempfail)으로 흡수한다 → ①과 배달 사이에
 *    계정이 정지되는 레이스에서도 다른 계정의 배달이 무효화되지 않는다
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ulid } from "@ionosphere/core";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver, smtpDeliver } from "./helpers.ts";

let app: IonosphereApp;
let blobRoot: string;
let tenantId: string;
let domainId: string;
let aliveInbox: string;
let deadInbox: string;
let deadAccountId: string;

async function addAlias(localpart: string, accountIds: string[]): Promise<void> {
  const addressId = ulid();
  await app.db.batch([
    {
      sql: "INSERT INTO addresses (id, tenant_id, domain_id, localpart, forward_to, created_at) VALUES (?, ?, ?, ?, NULL, ?)",
      params: [addressId, tenantId, domainId, localpart, Date.now()],
    },
    ...accountIds.map((accountId) => ({
      sql: "INSERT INTO address_targets (address_id, account_id) VALUES (?, ?)",
      params: [addressId, accountId],
    })),
  ]);
}

async function countIn(mailboxId: string): Promise<number> {
  const { rows } = await app.db.query({
    sql: "SELECT COUNT(*) AS n FROM message_mailbox WHERE mailbox_id = ?",
    params: [mailboxId],
  });
  return Number(rows[0]!.n);
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-fanout-inactive-"));
  app = new IonosphereApp({
    hostname: "test.local",
    dbPath: ":memory:",
    blobRoot,
    smtpPort: 0,
    runMtaWorker: false,
    runWebhookWorker: false,
    runReaper: false,
    blobGcMode: "off",
    resolver: offlineResolver(),
  });
  await app.start();

  ({ tenantId } = await app.store.createTenant("acme"));
  domainId = ulid();
  const now = Date.now();
  await app.db.batch([
    {
      sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, 'a.test', 1, ?, ?)",
      params: [domainId, tenantId, now, now],
    },
    { sql: "INSERT INTO domain_name_claims (name, domain_id) VALUES ('a.test', ?)", params: [domainId] },
  ]);

  const alive = await app.store.createAccount({ tenantId, email: "alive@a.test" });
  const dead = await app.store.createAccount({ tenantId, email: "dead@a.test" });
  deadAccountId = dead.accountId;
  aliveInbox = (await app.store.getMailboxByRole(alive.accountId, "inbox"))!.id;
  deadInbox = (await app.store.getMailboxByRole(dead.accountId, "inbox"))!.id;

  // REST DELETE /v1/accounts/:id 와 같은 형태(소프트 삭제)
  await app.db.batch([{ sql: "UPDATE accounts SET status = 2 WHERE id = ?", params: [deadAccountId] }]);

  await addAlias("team", [alive.accountId, deadAccountId]); // 활성 + 비활성 혼합
  await addAlias("ghost", [deadAccountId]); // 비활성만
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

function send(to: string): Promise<{ rcpt: { code: number }[]; final: { code: number } }> {
  return smtpDeliver({ port: app.smtpPort, from: "s@remote.example", to, data: "Subject: hi\n\nbody\n" });
}

describe("비활성 계정이 섞인 팬아웃", () => {
  test("활성 계정에만 배달하고 250으로 답한다 — 재시도를 유발하지 않는다", async () => {
    const res = await send("team@a.test");

    // ★250이 핵심이다. 451이면 발신측이 재시도하고, 그 재시도마다 alive에 사본이 쌓였다.
    expect(res.final.code).toBe(250);
    expect(await countIn(aliveInbox)).toBe(1);
    expect(await countIn(deadInbox)).toBe(0);
  });

  test("목적지가 전부 비활성이면 RCPT에서 거절한다(451 루프가 아니라 550)", async () => {
    const res = await send("ghost@a.test");

    expect(res.rcpt[0]!.code).toBe(550);
    expect(await countIn(deadInbox)).toBe(0);
  });

  test("accounts.email 직접 매치 폴백도 비활성 계정을 거절한다", async () => {
    // 알리아스 없이 계정 이메일로 직접 오는 경로 — 팬아웃 목적지와 같은 조건이어야 한다.
    const res = await send("dead@a.test");

    expect(res.rcpt[0]!.code).toBe(550);
    expect(await countIn(deadInbox)).toBe(0);
  });
});
