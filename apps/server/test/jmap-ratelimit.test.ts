/**
 * 회귀 테스트 — JMAP EmailSubmission이 **운영자가 설정한 레이트리밋을 따르는지**.
 *
 * 과거 결함: app.ts가 rateLimit을 SMTP submission(587/465)에만 넘기고 JmapServer에는 넘기지
 * 않아, jmap-backend가 DEFAULT_RATE_LIMIT으로 폴백했다. 즉 IONOSPHERE_RATE_PER_MINUTE를 걸어도
 * JMAP 경로만 한도를 우회했다. 옵션이 갈래마다 손으로 재작성되던 구조의 사고.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

let app: IonosphereApp;
let blobRoot: string;
let base: string;
let accountId: string;
const AUTH = "Basic " + Buffer.from("rl@test.local:pw-rl-1").toString("base64");

async function jmapCall(methodCalls: unknown[], using: string[]): Promise<{ methodResponses: unknown[][] }> {
  const res = await fetch(`${base}/jmap/api`, {
    method: "POST",
    headers: { authorization: AUTH, "content-type": "application/json" },
    body: JSON.stringify({ using, methodCalls }),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as { methodResponses: unknown[][] };
}

const MAIL_USING = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"];
const SUB_USING = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:submission", "urn:ietf:params:jmap:mail"];

/** 초안 하나를 만들고 emailId를 돌려준다. */
async function createDraft(draftsId: string, subject: string): Promise<string> {
  const raw = [`Subject: ${subject}`, "From: rl@test.local", "To: dest@example.test", "", "body"].join("\r\n");
  const up = await fetch(`${base}/jmap/upload/${accountId}`, { method: "POST", headers: { authorization: AUTH }, body: raw });
  const blobId = ((await up.json()) as { blobId: string }).blobId;
  const imp = await jmapCall(
    [["Email/set", { accountId, create: { e: { blobId, mailboxIds: { [draftsId]: true }, keywords: { $draft: true } } } }, "c0"]],
    MAIL_USING,
  );
  return ((imp.methodResponses[0] as [string, Record<string, unknown>, string])[1].created as Record<string, { id: string }>).e!.id;
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-jmap-rl-"));
  app = new IonosphereApp({
    hostname: "test.local",
    dbPath: ":memory:",
    blobRoot,
    smtpPort: 0,
    pop3Port: 0,
    jmapPort: 0,
    // 운영자 한도: 분당 1통. JMAP도 이 값을 따라야 한다.
    rateLimit: { perMinute: 1 },
    resolver: offlineResolver(),
  });
  await app.start();
  const created = await app.createUser("rl@test.local", "pw-rl-1");
  accountId = created.accountId;
  base = `http://127.0.0.1:${app.jmapPort}`;

  // 발신 도메인 검증 시드(발송 게이트 통과용)
  const { rows } = await app.db.query({ sql: "SELECT tenant_id FROM accounts WHERE email = ?", params: ["rl@test.local"] });
  const tenantId = String(rows[0]!.tenant_id);
  await app.db.batch([
    {
      sql: "INSERT OR IGNORE INTO domains (id, tenant_id, name, name_utf8, status, verify_token, claimed_at, created_at) VALUES (?, ?, ?, NULL, 1, NULL, ?, ?)",
      params: ["R".repeat(26), tenantId, "test.local", Date.now(), Date.now()],
    },
  ]);
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("JMAP EmailSubmission 레이트리밋", () => {
  test("perMinute=1 설정 시 두 번째 발송은 rateLimit으로 거부된다", async () => {
    const cr = await jmapCall([["Mailbox/set", { accountId, create: { d: { name: "Drafts", role: "drafts" } } }, "c0"]], MAIL_USING);
    const draftsId = ((cr.methodResponses[0] as [string, Record<string, unknown>, string])[1].created as Record<string, { id: string }>).d!.id;

    const idn = await jmapCall([["Identity/get", { accountId, ids: null }, "c0"]], SUB_USING);
    const identityId = ((idn.methodResponses[0] as [string, Record<string, unknown>, string])[1].list as Record<string, unknown>[])[0]!.id as string;

    const first = await createDraft(draftsId, "first");
    const second = await createDraft(draftsId, "second");

    // 1통째 — 한도 내이므로 성공
    const r1 = await jmapCall([["EmailSubmission/set", { accountId, create: { s1: { emailId: first, identityId } } }, "c0"]], SUB_USING);
    const a1 = (r1.methodResponses[0] as [string, Record<string, unknown>, string])[1];
    expect(Object.keys(a1.created as Record<string, unknown>)).toEqual(["s1"]);

    // 2통째 — perMinute=1을 넘겼으므로 거부되어야 한다(과거엔 DEFAULT_RATE_LIMIT라 통과했음)
    const r2 = await jmapCall([["EmailSubmission/set", { accountId, create: { s2: { emailId: second, identityId } } }, "c0"]], SUB_USING);
    const a2 = (r2.methodResponses[0] as [string, Record<string, unknown>, string])[1];
    expect(a2.created as Record<string, unknown>).toEqual({});
    const notCreated = a2.notCreated as Record<string, { type: string }>;
    expect(notCreated.s2?.type).toBe("rateLimit");
  });
});
