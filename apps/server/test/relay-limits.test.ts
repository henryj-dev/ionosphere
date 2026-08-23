/**
 * 시스템 relay(포워딩·Sieve redirect·바운스)의 증폭·총량 한도.
 *
 * 과거 결함 두 가지:
 *  ① 대상 수 상한이 없었다. 루프 가드는 홉 수(forwardMaxHops, 기본 10)만 보는데, 대상이 N개면
 *     홉마다 N배로 늘어나 N^10까지 증폭될 수 있었다. 홉만 묶고 **분기를 안 묶은** 것이다.
 * ⚠ 이 파일은 설정이 테스트마다 달라 **각 테스트 안에서 앱을 기동**한다(마이그레이션 + 리스너).
 * 그 비용이 테스트 예산에 들어가므로 bun 기본 5초로는 전체 스위트 부하에서 간헐 실패한다 —
 * 다른 e2e와 같은 예산(E2E_HOOK_TIMEOUT_MS)을 명시한다.
 *
 *  ② 레이트리밋이 `accountId`가 있을 때만 걸렸다. relay는 귀속 계정이 없어(§9-1 NULL)
 *     한도가 **아예 없었다** — 무인증 발신자가 알리아스로 밀어넣는 만큼 그대로 외부로 나갔다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ulid } from "@ionosphere/core";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver, smtpDeliver } from "./helpers.ts";

const SRS_SECRET = "relay-limit-secret";

interface Fixture {
  app: IonosphereApp;
  blobRoot: string;
  tenantId: string;
}

const active: Fixture[] = [];

afterEach(async () => {
  for (const f of active.splice(0)) {
    await f.app.stop();
    rmSync(f.blobRoot, { recursive: true, force: true });
  }
});

/** 도메인 + forward-only 알리아스 하나를 심은 앱. */
async function setup(opts: { forwardTo: string; relayPerHour?: number }): Promise<Fixture> {
  const blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-relaylimit-"));
  const app = new IonosphereApp({
    hostname: "test.local",
    dbPath: ":memory:",
    blobRoot,
    smtpPort: 0,
    srsSecret: SRS_SECRET,
    runMtaWorker: false, // 큐 적재만 관측
    runWebhookWorker: false,
    runReaper: false,
    blobGcMode: "off",
    resolver: offlineResolver(),
    ...(opts.relayPerHour !== undefined ? { relayPerHour: opts.relayPerHour } : {}),
  });
  await app.start();

  const { tenantId } = await app.store.createTenant("t");
  const domainId = ulid();
  const now = Date.now();
  await app.db.batch([
    {
      sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, 'test.local', 1, ?, ?)",
      params: [domainId, tenantId, now, now],
    },
    {
      sql: "INSERT INTO addresses (id, tenant_id, domain_id, localpart, forward_to, created_at) VALUES (?, ?, ?, 'fwd', ?, ?)",
      params: [ulid(), tenantId, domainId, opts.forwardTo, now],
    },
  ]);

  const f: Fixture = { app, blobRoot, tenantId };
  active.push(f);
  return f;
}

async function queuedRcpts(f: Fixture): Promise<string[]> {
  const { rows } = await f.app.db.query({ sql: "SELECT rcpt FROM mta_queue ORDER BY created_at" });
  return rows.map((r) => String(r.rcpt));
}

async function sendToAlias(f: Fixture): Promise<number> {
  const res = await smtpDeliver({
    port: f.app.smtpPort,
    from: "sender@remote.example",
    to: "fwd@test.local",
    data: "Subject: hi\n\nbody\n",
  });
  return res.final.code;
}

describe("relay 증폭·총량 한도", () => {
  test("대상 수가 상한을 넘으면 아무것도 릴레이하지 않는다(fail closed)", async () => {
    // 5개 — MAX_RELAY_TARGETS(4) 초과. 부분 릴레이가 아니라 전량 중단이어야 한다.
    const f = await setup({ forwardTo: "a@x.test, b@x.test, c@x.test, d@x.test, e@x.test" });

    await sendToAlias(f);

    expect(await queuedRcpts(f)).toHaveLength(0);
  }, E2E_HOOK_TIMEOUT_MS);

  test("상한 이내면 정상 릴레이된다(한도가 기능을 죽이지 않는다)", async () => {
    const f = await setup({ forwardTo: "a@x.test, b@x.test" });

    const code = await sendToAlias(f);

    expect(code).toBe(250);
    expect((await queuedRcpts(f)).sort()).toEqual(["a@x.test", "b@x.test"]);
  }, E2E_HOOK_TIMEOUT_MS);

  test("테넌트 시간당 relay 총량을 넘으면 더 적재하지 않는다", async () => {
    const f = await setup({ forwardTo: "only@x.test", relayPerHour: 1 });

    expect(await sendToAlias(f)).toBe(250);
    expect(await queuedRcpts(f)).toEqual(["only@x.test"]);

    // 두 번째는 한도 초과 — relay가 적재되지 않는다.
    await sendToAlias(f);
    expect(await queuedRcpts(f)).toEqual(["only@x.test"]);
  }, E2E_HOOK_TIMEOUT_MS);
});
