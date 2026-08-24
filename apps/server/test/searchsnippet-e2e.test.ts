/**
 * JMAP `SearchSnippet/get`(RFC 8621 §5) e2e — `message_text`가 실제로 읽히는 유일한 경로.
 *
 * ★계정 경계를 여기서 확인한다. `message_text`에는 `account_id`가 없어서(PK가
 * message_id+field) 질의가 `messages`를 통해 좁히지 않으면 **id만 알면 남의 메일 본문이
 * 나온다**. 그 조인이 빠지는 것이 이 기능에서 가장 위험한 실수라 테스트로 고정한다.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver, smtpDeliver } from "./helpers.ts";

let app: IonosphereApp;
let blobRoot: string;
let base: string;
let accountId: string;
let otherEmailId: string;

const AUTH = "Basic " + Buffer.from("you@test.local:pw-snip").toString("base64");

async function jmapCall(methodCalls: unknown[]): Promise<unknown[][]> {
  const res = await fetch(`${base}/jmap/api`, {
    method: "POST",
    headers: { authorization: AUTH, "content-type": "application/json" },
    body: JSON.stringify({ using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"], methodCalls }),
  });
  expect(res.status).toBe(200);
  return ((await res.json()) as { methodResponses: unknown[][] }).methodResponses;
}

function body(r: unknown[][]): Record<string, unknown> {
  return (r[0] as [string, Record<string, unknown>, string])[1];
}
function methodName(r: unknown[][]): string {
  return (r[0] as [string, unknown, string])[0];
}

async function deliver(to: string, subject: string, text: string): Promise<void> {
  const r = await smtpDeliver({
    port: app.smtpPort,
    from: "sender@remote.example",
    to,
    data: ["From: sender@remote.example", `To: ${to}`, `Subject: ${subject}`, "", text].join("\r\n"),
  });
  if (r.final.code !== 250) throw new Error(`smtp ${r.final.text}`);
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-snippet-"));
  app = new IonosphereApp({
    hostname: "test.local",
    dbPath: ":memory:",
    blobRoot,
    smtpPort: 0,
    pop3Port: 0,
    jmapPort: 0,
    resolver: offlineResolver(),
  });
  await app.start();
  const me = await app.createUser("you@test.local", "pw-snip");
  accountId = me.accountId;
  const other = await app.createUser("other@test.local", "pw-other");
  base = `http://127.0.0.1:${app.jmapPort}`;

  await deliver("you@test.local", "quarterly report ready", "The quarterly report is attached. Please review <soon>.");
  await deliver("you@test.local", "lunch", "no keyword here at all");
  // 남의 계정 메일 — 아래에서 그 id로 조각을 요청해 본다
  await deliver("other@test.local", "secret quarterly plan", "confidential quarterly numbers");

  const { rows } = await app.db.query({
    sql: "SELECT id FROM messages WHERE account_id = ?",
    params: [other.accountId],
  });
  otherEmailId = String(rows[0]!.id);
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

async function myEmailIds(): Promise<string[]> {
  const { rows } = await app.db.query({ sql: "SELECT id FROM messages WHERE account_id = ? ORDER BY received_at", params: [accountId] });
  return rows.map((r) => String(r.id));
}

describe("SearchSnippet/get", () => {
  test("제목과 본문의 매치를 <mark>로 표시한다", async () => {
    const ids = await myEmailIds();
    const r = await jmapCall([["SearchSnippet/get", { accountId, filter: { text: "quarterly" }, emailIds: ids }, "c0"]]);
    expect(methodName(r)).toBe("SearchSnippet/get");
    const list = body(r).list as { emailId: string; subject: string | null; preview: string | null }[];

    const hit = list.find((x) => x.subject !== null)!;
    expect(hit.subject).toBe("<mark>quarterly</mark> report ready");
    expect(hit.preview).toContain("<mark>quarterly</mark>");
  });

  /** ★본문의 `<soon>`이 이스케이프돼야 한다 — 그대로면 클라이언트 DOM에 태그가 들어간다. */
  test("원문의 꺾쇠는 이스케이프된다", async () => {
    const ids = await myEmailIds();
    const r = await jmapCall([["SearchSnippet/get", { accountId, filter: { text: "review" }, emailIds: ids }, "c0"]]);
    const list = body(r).list as { preview: string | null }[];
    const hit = list.find((x) => x.preview !== null)!;
    expect(hit.preview).toContain("&lt;soon&gt;");
    expect(hit.preview!.includes("<soon>")).toBe(false);
  });

  /** 매치 없음(null)과 메시지 없음(notFound)은 다르다. */
  test("매치가 없으면 null, 없는 id는 notFound", async () => {
    const ids = await myEmailIds();
    const r = await jmapCall([["SearchSnippet/get", { accountId, filter: { text: "quarterly" }, emailIds: [...ids, "Z".repeat(26)] }, "c0"]]);
    const out = body(r);
    const list = out.list as { subject: string | null; preview: string | null }[];
    expect(list.some((x) => x.subject === null && x.preview === null)).toBe(true); // "lunch" 메일
    expect(out.notFound).toEqual(["Z".repeat(26)]);
  });

  /**
   * ★계정 경계 — 남의 메시지 id로 요청하면 **본문이 아니라 notFound**가 나와야 한다.
   * `message_text`에 account_id가 없으므로 조인이 빠지면 여기서 본문이 새어 나온다.
   */
  test("남의 계정 메시지는 notFound다", async () => {
    const r = await jmapCall([["SearchSnippet/get", { accountId, filter: { text: "quarterly" }, emailIds: [otherEmailId] }, "c0"]]);
    const out = body(r);
    expect(out.list).toEqual([]);
    expect(out.notFound).toEqual([otherEmailId]);
    expect(JSON.stringify(out)).not.toContain("confidential");
  });

  /** 구조 조건만 있으면 표시할 글자가 없다. */
  test("전문 검색어가 없는 필터면 조각도 없다", async () => {
    const ids = await myEmailIds();
    const r = await jmapCall([["SearchSnippet/get", { accountId, filter: { inMailbox: "whatever" }, emailIds: ids }, "c0"]]);
    const list = body(r).list as { subject: string | null; preview: string | null }[];
    expect(list.every((x) => x.subject === null && x.preview === null)).toBe(true);
  });

  test("emailIds가 배열이 아니면 invalidArguments", async () => {
    const r = await jmapCall([["SearchSnippet/get", { accountId, filter: {}, emailIds: "nope" }, "c0"]]);
    expect(methodName(r)).toBe("error");
    expect(body(r).type).toBe("invalidArguments");
  });

  /** 조각은 본문 원문을 읽으므로 /get류보다 비싸다 — 상한이 없으면 계정 전체가 메모리에 온다. */
  test("상한을 넘으면 requestTooLarge", async () => {
    const many = Array.from({ length: 101 }, (_, i) => String(i).padStart(26, "0"));
    const r = await jmapCall([["SearchSnippet/get", { accountId, filter: {}, emailIds: many }, "c0"]]);
    expect(methodName(r)).toBe("error");
    expect(body(r).type).toBe("requestTooLarge");
  });
});
