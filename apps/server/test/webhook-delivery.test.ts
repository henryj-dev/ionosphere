/** 수신 웹훅 적재 e2e — 활성 엔드포인트가 있으면 배달 시 webhook_deliveries 적재. */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver, smtpDeliver } from "./helpers.ts";

let app: IonosphereApp;
let blobRoot: string;
let accountId: string;

/** 한 통 배달 — 공용 SMTP 헬퍼. */
async function deliver(subject: string): Promise<void> {
  const r = await smtpDeliver({
    port: app.smtpPort,
    from: "sender@remote.example",
    to: "user@test.local",
    data: ["From: sender@remote.example", "To: user@test.local", `Subject: ${subject}`, "", "hi"].join("\r\n"),
  });
  if (r.final.code !== 250) throw new Error(`smtp ${r.final.text}`);
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-wh-"));
  // 워커는 끔(가짜 fetch 못 넣으므로) — 적재만 검증. 워커 동작은 @ionosphere/webhook 유닛테스트.
  app = new IonosphereApp({ hostname: "test.local", dbPath: ":memory:", blobRoot, smtpPort: 0, pop3Port: 0, runWebhookWorker: false, resolver: offlineResolver() });
  await app.start();
  accountId = (await app.createUser("user@test.local", "pw")).accountId;
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("웹훅 적재", () => {
  test("엔드포인트 없으면 적재 안 함", async () => {
    await deliver("no hook");
    const { rows } = await app.db.query({ sql: "SELECT COUNT(*) AS n FROM webhook_deliveries", params: [] });
    expect(Number(rows[0]!.n)).toBe(0);
  });

  test("활성 엔드포인트 → 배달 시 적재(페이로드에 수신 정보)", async () => {
    await app.store.addWebhookEndpoint(accountId, "https://hook.test/inbound", "sk_test");
    await deliver("hello hook");
    const { rows } = await app.db.query({ sql: "SELECT url, payload, status FROM webhook_deliveries ORDER BY created_at DESC LIMIT 1", params: [] });
    expect(rows).toHaveLength(1);
    expect(String(rows[0]!.url)).toBe("https://hook.test/inbound");
    expect(Number(rows[0]!.status)).toBe(0); // queued
    const payload = JSON.parse(String(rows[0]!.payload)) as { event: string; subject: string; from: { email: string }[] };
    expect(payload.event).toBe("inbound");
    expect(payload.subject).toBe("hello hook");
    expect(payload.from[0]!.email).toBe("sender@remote.example");
  });

  test("비활성 엔드포인트는 적재 제외", async () => {
    const before = Number((await app.db.query({ sql: "SELECT COUNT(*) AS n FROM webhook_deliveries", params: [] })).rows[0]!.n);
    // 새 계정 + 비활성 엔드포인트
    const eid = await app.store.addWebhookEndpoint(accountId, "https://hook.test/off", "");
    await app.db.batch([{ sql: "UPDATE webhook_endpoints SET active = 0 WHERE id = ?", params: [eid] }]);
    // 여전히 활성 엔드포인트(inbound) 1개 있으므로 그건 적재됨 — off는 제외
    await deliver("mixed");
    const { rows } = await app.db.query({ sql: "SELECT url FROM webhook_deliveries WHERE created_at >= ? ", params: [0] });
    void before;
    const urls = rows.map((r) => String(r.url));
    expect(urls).not.toContain("https://hook.test/off");
  });
});
