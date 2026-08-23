/**
 * 알리아스 팬아웃 e2e (006) — 수신 주소 1개 → 로컬 계정 N개.
 *
 * 요구한 계층을 그대로 세운다: 서비스 → 테넌트 → 도메인 여러 개 → 계정/주소.
 *   테넌트 acme
 *     ├ a.test  (검증됨)
 *     └ b.test  (검증됨)
 * 한 테넌트가 도메인 둘을 소유하므로 `team@a.test` 알리아스가 **도메인을 가로질러**
 * alice@a.test와 bob@b.test 양쪽에 배달될 수 있다. 예전엔 addresses 행당 목적지가 하나뿐이라
 * forward_to로 외부 SMTP를 한 바퀴 돌아야만 흉내낼 수 있었다(SRS 필요·루프가드 소모).
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
let aliceInbox: string;
let bobInbox: string;

/** 검증된 도메인 행 + 이름 앵커 — CLI add-domain의 preVerified와 같은 형태. */
async function addVerifiedDomain(tenantId: string, name: string): Promise<string> {
  const domainId = ulid();
  const now = Date.now();
  await app.db.batch([
    {
      sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, ?, 1, ?, ?)",
      params: [domainId, tenantId, name, now, now],
    },
    { sql: "INSERT INTO domain_name_claims (name, domain_id) VALUES (?, ?)", params: [name, domainId] },
  ]);
  return domainId;
}

/** 주소 행 + 목적지 계정들을 한 배치로(= API/CLI가 하는 것과 같은 형태). */
async function addAlias(tenantId: string, domainId: string, localpart: string, accountIds: string[]): Promise<void> {
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

async function deliverTo(rcpt: string): Promise<number> {
  const r = await smtpDeliver({
    port: app.smtpPort,
    from: "sender@remote.example",
    to: rcpt,
    data: ["From: sender@remote.example", `To: ${rcpt}`, "Subject: fanout", "", "body"].join("\r\n"),
  });
  return r.final.code;
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-fanout-"));
  app = new IonosphereApp({
    hostname: "mx.test",
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

  const { tenantId } = await app.store.createTenant("acme");
  const domainA = await addVerifiedDomain(tenantId, "a.test");
  const domainB = await addVerifiedDomain(tenantId, "b.test");

  const alice = await app.store.createAccount({ tenantId, email: "alice@a.test" });
  const bob = await app.store.createAccount({ tenantId, email: "bob@b.test" });
  aliceInbox = (await app.store.getMailboxByRole(alice.accountId, "inbox"))!.id;
  bobInbox = (await app.store.getMailboxByRole(bob.accountId, "inbox"))!.id;

  // 팬아웃: 한 주소 → 도메인이 다른 두 계정
  await addAlias(tenantId, domainA, "team", [alice.accountId, bob.accountId]);
  // 같은 유저의 두 번째 주소(다른 도메인) — userA@a.test / userA@b.test 형태
  await addAlias(tenantId, domainB, "alice", [alice.accountId]);
  // 한 도메인 안 두 번째 주소 — otherA@a.test 형태
  await addAlias(tenantId, domainA, "sales", [alice.accountId]);
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("알리아스 팬아웃", () => {
  test("한 주소로 온 메일이 도메인을 가로질러 두 계정 INBOX에 모두 들어간다", async () => {
    expect(await deliverTo("team@a.test")).toBe(250);
    expect(await countIn(aliceInbox)).toBe(1);
    expect(await countIn(bobInbox)).toBe(1);
  });

  test("같은 유저의 다른 도메인 주소(alice@b.test)도 같은 계정으로 배달된다", async () => {
    expect(await deliverTo("alice@b.test")).toBe(250);
    expect(await countIn(aliceInbox)).toBe(2);
    expect(await countIn(bobInbox)).toBe(1); // 팬아웃 대상이 아니므로 그대로
  });

  test("한 도메인 안의 두 번째 주소(sales@a.test)도 같은 계정으로 배달된다", async () => {
    expect(await deliverTo("sales@a.test")).toBe(250);
    expect(await countIn(aliceInbox)).toBe(3);
  });

  test("목적지가 하나도 없는 주소는 550 — 팬아웃 도입이 '수신자 없음'을 흐리지 않는다", async () => {
    expect(await deliverTo("ghost@a.test")).toBe(550);
  });
});
