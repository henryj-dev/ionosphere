/**
 * Sieve `reject` e2e — **사유가 발신자에게 실제로 도달하는가**.
 *
 * 이 액션의 존재 이유가 그것이다. `discard`는 조용히 버리는 것이라 250으로 답하지만,
 * `reject`는 "받지 않겠다"를 알리는 것이라 **5xx와 사유가 나가지 않으면 아무 일도 하지 않은
 * 것**이 된다. 그래서 여기서는 저장 상태가 아니라 **SMTP 응답**을 본다.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver, smtpDeliver } from "./helpers.ts";

let app: IonosphereApp;
let blobRoot: string;
let accountId: string;
let inboxId: string;

async function deliver(subject: string): Promise<{ code: number; text: string }> {
  const r = await smtpDeliver({
    port: app.smtpPort,
    from: "sender@remote.example",
    to: "user@test.local",
    data: ["From: sender@remote.example", "To: user@test.local", `Subject: ${subject}`, "", "body"].join("\r\n"),
  });
  return r.final;
}

async function inboxCount(): Promise<number> {
  const { rows } = await app.db.query({
    sql: "SELECT COUNT(*) AS n FROM message_mailbox WHERE mailbox_id = ?",
    params: [inboxId],
  });
  return Number(rows[0]!.n);
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-reject-"));
  app = new IonosphereApp({ hostname: "test.local", dbPath: ":memory:", blobRoot, smtpPort: 0, pop3Port: 0, resolver: offlineResolver() });
  await app.start();
  accountId = (await app.createUser("user@test.local", "pw")).accountId;
  inboxId = (await app.store.getMailboxByRole(accountId, "inbox"))!.id;
  const script = `require ["reject"];
    if header :contains "subject" "nope" { reject "I do not accept mail about that."; }
    if header :contains "subject" "inject" { reject "line one\r\nX-Evil: yes"; }`;
  await app.db.batch([
    {
      sql: "INSERT INTO sieve_scripts (id, account_id, name, content, active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
      params: ["R".repeat(26), accountId, "main", script, Date.now()],
    },
  ]);
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("Sieve reject e2e", () => {
  test("거절 사유가 SMTP 5xx로 발신자에게 간다", async () => {
    const before = await inboxCount();
    const final = await deliver("nope please");
    expect(final.code).toBe(550);
    expect(final.text).toContain("I do not accept mail about that.");
    // 배달되지 않아야 한다 — 거절인데 저장되면 규칙이 무의미하다.
    expect(await inboxCount()).toBe(before);
  });

  test("규칙에 안 걸리면 평소대로 배달된다", async () => {
    const before = await inboxCount();
    const final = await deliver("hello there");
    expect(final.code).toBe(250);
    expect(await inboxCount()).toBe(before + 1);
  });

  /**
   * ★사유는 **사용자가 쓴 문자열**이고 그대로 응답 줄에 실린다. CR/LF가 들어가면 그것이 곧
   * 응답 주입이다 — 우리가 만든 응답이 상대 파서에게 여러 줄로 보인다.
   */
  test("사유의 CR/LF는 응답 줄을 쪼개지 못한다", async () => {
    const final = await deliver("inject this");
    expect(final.code).toBe(550);
    /**
     * 지켜야 하는 성질은 "그 문자열이 안 보인다"가 아니라 **"응답이 한 줄이다"** 다.
     * CR/LF를 공백으로 치환하므로 텍스트는 남지만 새 줄을 시작하지 못한다 — 문자열 부재를
     * 요구하면 정상 거절 사유까지 못 싣는다(DSN 진단 문구와 같은 판단).
     */
    expect(final.text.includes("\r") || final.text.includes("\n")).toBe(false);
    expect(final.text).toBe("550 5.7.1 line one  X-Evil: yes");
  });
});
