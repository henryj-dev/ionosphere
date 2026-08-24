/**
 * Sieve `mailbox` 확장(RFC 5490)의 **배달 경로** e2e — `fileinto :create`가 실제로 메일함을
 * 만드는가.
 *
 * ★단위테스트는 "생성 요청이 남는다"까지만 본다. 실제로 만들어지지 않으면 사용자에게는
 * 예전과 똑같이 "규칙을 만들었는데 메일이 INBOX에 있다"로 보이므로, 여기서 끝까지 확인한다.
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

async function deliver(subject: string): Promise<void> {
  const r = await smtpDeliver({
    port: app.smtpPort,
    from: "sender@remote.example",
    to: "user@test.local",
    data: ["From: sender@remote.example", "To: user@test.local", `Subject: ${subject}`, "", "body"].join("\r\n"),
  });
  if (r.final.code !== 250) throw new Error(`smtp ${r.final.text}`);
}

/** "A/B" 경로 → mailboxId(없으면 null). 계층은 parentId다. */
async function findPath(path: string): Promise<string | null> {
  const rows = await app.store.listMailboxes(accountId);
  const byId = new Map(rows.map((r) => [r.id, r]));
  for (const r of rows) {
    const segs = [r.name];
    let cur = r;
    for (let d = 0; d < 20 && cur.parentId !== ""; d++) {
      const p = byId.get(cur.parentId);
      if (!p) break;
      segs.unshift(p.name);
      cur = p;
    }
    if (segs.join("/") === path) return r.id;
  }
  return null;
}

async function countIn(mailboxId: string): Promise<number> {
  const { rows } = await app.db.query({ sql: "SELECT COUNT(*) AS n FROM message_mailbox WHERE mailbox_id = ?", params: [mailboxId] });
  return Number(rows[0]!.n);
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-sieve-create-"));
  app = new IonosphereApp({ hostname: "test.local", dbPath: ":memory:", blobRoot, smtpPort: 0, pop3Port: 0, resolver: offlineResolver() });
  await app.start();
  const created = await app.createUser("user@test.local", "pw");
  accountId = created.accountId;
  inboxId = (await app.store.getMailboxByRole(accountId, "inbox"))!.id;

  /**
   * `create`가 붙은 것과 안 붙은 것을 한 스크립트에 둔다 — 둘의 차이가 이 파일의 요지다.
   * `mailboxexists`도 같이 걸어 주입된 목록이 실제 메일함과 맞는지 본다.
   */
  const script = `require ["fileinto", "mailbox"];
    if header :contains "subject" "deep" { fileinto :create "Lists/Dev/Patches"; }
    elsif header :contains "subject" "nocreate" { fileinto "Missing/Box"; }
    elsif header :contains "subject" "exists" {
      if mailboxexists "INBOX" { fileinto :create "Confirmed"; }
    }`;
  await app.db.batch([
    {
      sql: "INSERT INTO sieve_scripts (id, account_id, name, content, active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
      params: ["S".repeat(26), accountId, "main", script, Date.now()],
    },
  ]);
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("fileinto :create (RFC 5490 §3.2)", () => {
  /** ★중간 단계(`Lists`, `Lists/Dev`)까지 만들어야 한다 — 부모 없이는 자식을 만들 수 없다. */
  test("없는 경로를 조상까지 만들고 그 안에 배달한다", async () => {
    expect(await findPath("Lists/Dev/Patches")).toBe(null);
    await deliver("deep nesting test");

    expect(await findPath("Lists")).not.toBe(null);
    expect(await findPath("Lists/Dev")).not.toBe(null);
    const leaf = await findPath("Lists/Dev/Patches");
    expect(leaf).not.toBe(null);
    expect(await countIn(leaf!)).toBe(1);
    expect(await countIn(inboxId)).toBe(0);
  });

  /**
   * ★`:create` 없이 없는 메일함을 지정하면 **여전히 INBOX 폴백**이다. 그게 규격이고
   * (§3.2: `:create`가 있을 때만 만든다) 오타로 메일함이 생기지 않게 하는 안전장치다.
   */
  test(":create 없이 없는 메일함이면 만들지 않고 INBOX로", async () => {
    const before = await countIn(inboxId);
    await deliver("nocreate please");
    expect(await findPath("Missing/Box")).toBe(null);
    expect(await countIn(inboxId)).toBe(before + 1);
  });

  test("mailboxexists가 실제 메일함 목록을 본다", async () => {
    await deliver("exists check");
    const box = await findPath("Confirmed");
    expect(box).not.toBe(null);
    expect(await countIn(box!)).toBe(1);
  });

  /** 두 번째 배달은 이미 있는 메일함을 **다시 만들지 않고** 그대로 쓴다. */
  test("이미 있으면 다시 만들지 않는다", async () => {
    const first = await findPath("Lists/Dev/Patches");
    await deliver("deep nesting again");
    expect(await findPath("Lists/Dev/Patches")).toBe(first);
    expect(await countIn(first!)).toBe(2);
  });
});
