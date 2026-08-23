/** Sieve 배달 필터 e2e — 활성 스크립트가 수신 메일을 fileinto/discard로 라우팅. */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver, smtpDeliver } from "./helpers.ts";

let app: IonosphereApp;
let blobRoot: string;
let accountId: string;
let filteredId: string;
let inboxId: string;

/** 한 통 배달 — 공용 SMTP 헬퍼(부하에서 깨지던 손수 파서를 대체). */
async function deliver(subject: string): Promise<void> {
  const r = await smtpDeliver({
    port: app.smtpPort,
    from: "sender@remote.example",
    to: "user@test.local",
    data: [`From: sender@remote.example`, `To: user@test.local`, `Subject: ${subject}`, "", "body"].join("\r\n"),
  });
  if (r.final.code !== 250) throw new Error(`smtp ${r.final.text}`);
}

async function countIn(mailboxId: string): Promise<number> {
  const { rows } = await app.db.query({ sql: "SELECT COUNT(*) AS n FROM message_mailbox WHERE mailbox_id = ?", params: [mailboxId] });
  return Number(rows[0]!.n);
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-sieve-"));
  app = new IonosphereApp({ hostname: "test.local", dbPath: ":memory:", blobRoot, smtpPort: 0, pop3Port: 0, resolver: offlineResolver() });
  await app.start();
  const created = await app.createUser("user@test.local", "pw");
  accountId = created.accountId;
  inboxId = (await app.store.getMailboxByRole(accountId, "inbox"))!.id;
  filteredId = (await app.store.createMailbox({ accountId, name: "Filtered" })).mailboxId;
  // 활성 Sieve 스크립트 심기
  const script = `require ["fileinto"];
    if header :contains "subject" "invoice" { fileinto "Filtered"; }
    elsif header :contains "subject" "spam" { discard; }`;
  await app.db.batch([
    { sql: "INSERT INTO sieve_scripts (id, account_id, name, content, active, created_at) VALUES (?, ?, ?, ?, 1, ?)", params: ["S".repeat(26), accountId, "main", script, Date.now()] },
  ]);
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("Sieve 배달 라우팅", () => {
  test("fileinto — 'invoice' 메일은 Filtered로(INBOX 아님)", async () => {
    await deliver("your invoice #42");
    expect(await countIn(filteredId)).toBe(1);
    expect(await countIn(inboxId)).toBe(0);
  });

  test("암묵 keep — 매칭 없으면 INBOX", async () => {
    await deliver("hello there");
    expect(await countIn(inboxId)).toBe(1);
    expect(await countIn(filteredId)).toBe(1); // 이전 테스트 것 그대로
  });

  test("discard — 'spam' 메일은 어디에도 안 들어감", async () => {
    const before = (await countIn(inboxId)) + (await countIn(filteredId));
    await deliver("cheap spam offer");
    const after = (await countIn(inboxId)) + (await countIn(filteredId));
    expect(after).toBe(before); // 폐기 — 저장 안 됨
  });
});
