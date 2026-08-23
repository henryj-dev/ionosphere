/**
 * 수신 라우팅의 도메인 검증 게이트 — 크로스 테넌트 수신 탈취 회귀 테스트.
 *
 * 과거 결함: resolveRoute가 `domains.status`를 보지 않았다. 그래서 아무 테넌트나 남의 도메인
 * 이름으로 domains 행을 만들고(검증 불필요) 캐치올 알리아스 `*`를 걸면, **정확 매치가 없는
 * 주소의 수신을 통째로 가져갈 수 있었다.** forward_to까지 걸면 그대로 외부로 빠진다.
 * 발송 게이트(enqueue.ts)는 status=1을 검사했는데 수신 경로만 빠져 있었다.
 *
 * status=1이 이름당 하나뿐임은 domain_name_claims.name이 PK라 보장된다(두 번째 테넌트의
 * 검증은 409). 따라서 이 조건 하나로 라우팅 갈래가 유일해진다.
 *
 * 같은 결함의 **폴백판**도 함께 잠근다: resolveRoute는 addresses에 행이 없으면 accounts.email로
 * 직접 라우팅하는데, 이 경로에는 도메인 게이트가 없었다. 계정 생성이 addresses 행을 만들지
 * 않으므로 폴백은 예외가 아니라 기본 동작이고, accounts.email은 전역 UNIQUE일 뿐 도메인 소유와
 * 무관해서 남의 검증된 도메인 이름으로 계정만 만들어 두면 수신이 넘어갔다.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ulid } from "@ionosphere/core";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver, smtpDeliver } from "./helpers.ts";

const SRS_SECRET = "test-srs-secret";
const DOMAIN = "victim.test";

let app: IonosphereApp;
let blobRoot: string;

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-domverify-"));
  app = new IonosphereApp({
    hostname: "mx.test",
    dbPath: ":memory:",
    blobRoot,
    smtpPort: 0,
    srsSecret: SRS_SECRET, // 포워딩 활성 — 탈취가 실제 relay로 이어지는 조건을 재현
    runMtaWorker: false,
    runWebhookWorker: false,
    runReaper: false,
    blobGcMode: "off",
    resolver: offlineResolver(),
  });
  await app.start();

  const now = Date.now();

  // ── 정상 소유자(테넌트 A): victim.test를 **검증 완료**(status=1)하고 정확 매치 알리아스 보유
  const { tenantId: ownerTenant } = await app.store.createTenant("owner");
  const ownerDomainId = ulid();
  const { accountId } = await app.store.createAccount({ tenantId: ownerTenant, email: `ceo@${DOMAIN}` });
  const ownerAddressId = ulid();
  await app.db.batch([
    {
      sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, ?, 1, ?, ?)",
      params: [ownerDomainId, ownerTenant, DOMAIN, now, now],
    },
    { sql: "INSERT INTO domain_name_claims (name, domain_id) VALUES (?, ?)", params: [DOMAIN, ownerDomainId] },
    {
      sql: "INSERT INTO addresses (id, tenant_id, domain_id, localpart, forward_to, created_at) VALUES (?, ?, ?, 'ceo', NULL, ?)",
      params: [ownerAddressId, ownerTenant, ownerDomainId, now],
    },
    { sql: "INSERT INTO address_targets (address_id, account_id) VALUES (?, ?)", params: [ownerAddressId, accountId] },
  ]);

  // ── 공격자(테넌트 B): **같은 이름**으로 미검증 도메인 행 + 캐치올 → 외부 포워딩
  const { tenantId: attackerTenant } = await app.store.createTenant("attacker");
  const attackerDomainId = ulid();
  await app.db.batch([
    {
      sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, ?, 0, ?, ?)",
      params: [attackerDomainId, attackerTenant, DOMAIN, now, now],
    },
    {
      sql: "INSERT INTO addresses (id, tenant_id, domain_id, localpart, forward_to, created_at) VALUES (?, ?, ?, '*', ?, ?)",
      params: [ulid(), attackerTenant, attackerDomainId, "attacker@evil.test", now],
    },
  ]);

  // ── 폴백 경로(addresses 행 없이 accounts.email로만 라우팅) 재현.
  //    store.createAccount는 addresses 행을 만들지 않으므로 이게 계정의 기본 상태다.
  await app.store.createAccount({ tenantId: ownerTenant, email: `cto@${DOMAIN}` }); // 정상 소유자
  await app.store.createAccount({ tenantId: attackerTenant, email: `cfo@${DOMAIN}` }); // 공격자 선점
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

async function relayedTo(rcpt: string): Promise<boolean> {
  const { rows } = await app.db.query({ sql: "SELECT rcpt FROM mta_queue WHERE rcpt = ?", params: [rcpt] });
  return rows.length > 0;
}

describe("미검증 도메인 캐치올은 수신을 가져갈 수 없다", () => {
  test("미검증 캐치올로만 매칭되는 주소는 거절된다", async () => {
    const res = await smtpDeliver({
      port: app.smtpPort,
      from: "sender@remote.example",
      to: `unknown@${DOMAIN}`,
      data: "Subject: hi\n\nbody\n",
    });

    expect(res.final.code).toBe(550);
    expect(await relayedTo("attacker@evil.test")).toBe(false);
  });

  test("검증된 소유자의 정확 매치 알리아스는 정상 배달된다", async () => {
    const res = await smtpDeliver({
      port: app.smtpPort,
      from: "sender@remote.example",
      to: `ceo@${DOMAIN}`,
      data: "Subject: hi\n\nbody\n",
    });

    expect(res.final.code).toBe(250);
  });
});

describe("accounts.email 폴백도 같은 도메인 게이트를 지난다", () => {
  test("남의 도메인 이름으로 선점한 계정으로는 수신이 넘어가지 않는다", async () => {
    const res = await smtpDeliver({
      port: app.smtpPort,
      from: "sender@remote.example",
      to: `cfo@${DOMAIN}`,
      data: "Subject: hi\n\nbody\n",
    });

    expect(res.final.code).toBe(550);
    expect(await relayedTo("attacker@evil.test")).toBe(false);
  });

  test("검증된 소유 도메인의 계정은 addresses 행 없이도 폴백으로 배달된다", async () => {
    const res = await smtpDeliver({
      port: app.smtpPort,
      from: "sender@remote.example",
      to: `cto@${DOMAIN}`,
      data: "Subject: hi\n\nbody\n",
    });

    expect(res.final.code).toBe(250);
  });
});
