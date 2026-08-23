/**
 * Phase 4 e2e: 실 HTTP JMAP 세션 — Session 디스커버리 + Core/echo + Mailbox get/query/changes.
 * 프로토콜 상세는 proto-jmap 단위테스트가 커버 — 여기선 HTTP 어댑터·인증·스토어 연동 검증.
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
const AUTH = "Basic " + Buffer.from("you@test.local:pw-jmap-1").toString("base64");

async function jmapCall(methodCalls: unknown[], using = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]): Promise<{ methodResponses: unknown[][]; sessionState: string }> {
  const res = await fetch(`${base}/jmap/api`, {
    method: "POST",
    headers: { authorization: AUTH, "content-type": "application/json" },
    body: JSON.stringify({ using, methodCalls }),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as { methodResponses: unknown[][]; sessionState: string };
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-jmap-e2e-"));
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
  await app.createUser("you@test.local", "pw-jmap-1");
  base = `http://127.0.0.1:${app.jmapPort}`;

  /**
   * ★accountId 확보를 **이 훅 안에서** 한다. 예전엔 파일 끝에 두 번째 beforeAll을 두고
   * 거기서 세션을 조회했는데, node:test에서 루트 `before`가 여러 개면 뒤엣것이 앞선 스위트와
   * 경쟁해 **하위 테스트가 통째로 cancelled**가 된다(실측: 31건 취소, 두 번째 훅을 지우면 0건).
   * bun에서는 순차 실행이라 드러나지 않았다. 훅을 하나로 합치면 순서 문제가 사라진다.
   */
  const sessionRes = await fetch(`${base}/jmap/session`, { headers: { authorization: AUTH } });
  const session = (await sessionRes.json()) as { primaryAccounts: Record<string, string> };
  cachedAcc = session.primaryAccounts["urn:ietf:params:jmap:mail"];
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("자동발견 — /.well-known/jmap (RFC 8620 §2.2)", () => {
  test("★표준 발견 경로가 세션 자원을 준다", async () => {
    const res = await fetch(`${base}/.well-known/jmap`, { headers: { authorization: AUTH } });
    expect(res.status).toBe(200);
    const session = (await res.json()) as { primaryAccounts: Record<string, string>; apiUrl: string };
    // `/jmap/session`과 **같은 객체**여야 한다 — 규격대로 발견한 클라이언트가 여기서
    // apiUrl·계정을 읽고 이어서 붙는다.
    expect(session.primaryAccounts["urn:ietf:params:jmap:mail"]).toBe(cachedAcc);
    expect(session.apiUrl).toContain("/jmap/api");
  });

  test("인증은 세션 자원과 동일하게 요구한다", async () => {
    const res = await fetch(`${base}/.well-known/jmap`);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain("Basic");
  });
});

describe("인증", () => {
  test("Basic 없이 → 401 + WWW-Authenticate", async () => {
    const res = await fetch(`${base}/jmap/session`);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain("Basic");
  });

  test("틀린 비번 → 401", async () => {
    const res = await fetch(`${base}/jmap/session`, { headers: { authorization: "Basic " + Buffer.from("you@test.local:wrong").toString("base64") } });
    expect(res.status).toBe(401);
  });
});

describe("Session 리소스", () => {
  test("GET /jmap/session — capabilities/accounts/URL", async () => {
    const res = await fetch(`${base}/jmap/session`, { headers: { authorization: AUTH } });
    expect(res.status).toBe(200);
    const s = (await res.json()) as Record<string, unknown>;
    const caps = s.capabilities as Record<string, unknown>;
    expect(caps["urn:ietf:params:jmap:core"]).toBeDefined();
    expect(caps["urn:ietf:params:jmap:mail"]).toBeDefined();
    expect(s.apiUrl).toContain("/jmap/api");
    const primary = s.primaryAccounts as Record<string, string>;
    expect(primary["urn:ietf:params:jmap:mail"]).toBeTruthy();
    expect(s.username).toBe("you@test.local");
  });
});

describe("Core/echo + Mailbox", () => {
  test("Core/echo 왕복", async () => {
    const r = await jmapCall([["Core/echo", { hi: 1 }, "c0"]]);
    expect(r.methodResponses[0]).toEqual(["Core/echo", { hi: 1 }, "c0"]);
  });

  test("Mailbox/get ids=null → INBOX 노출(JMAP 형태)", async () => {
    const r = await jmapCall([["Mailbox/get", { accountId: acc(), ids: null }, "c0"]]);
    const [name, args] = r.methodResponses[0] as [string, Record<string, unknown>, string];
    expect(name).toBe("Mailbox/get");
    const list = args.list as Record<string, unknown>[];
    const inbox = list.find((m) => m.role === "inbox")!;
    expect(inbox).toBeDefined();
    expect(inbox.name).toBe("INBOX");
    expect(inbox.parentId).toBeNull();
    expect(inbox.myRights).toMatchObject({ mayReadItems: true });
    expect(typeof args.state).toBe("string");
  });

  test("Mailbox/query filter+정렬 → id 목록, queryState", async () => {
    const r = await jmapCall([["Mailbox/query", { accountId: acc(), filter: { role: "inbox" }, sort: [{ property: "name" }] }, "c0"]]);
    const [, args] = r.methodResponses[0] as [string, Record<string, unknown>, string];
    expect(Array.isArray(args.ids)).toBe(true);
    expect((args.ids as string[]).length).toBe(1);
    expect(args.total).toBe(1);
    expect(args.canCalculateChanges).toBe(false);
  });

  test("Mailbox/query 백레퍼런스 → Mailbox/get", async () => {
    const r = await jmapCall([
      ["Mailbox/query", { accountId: acc() }, "c0"],
      ["Mailbox/get", { accountId: acc(), "#ids": { resultOf: "c0", name: "Mailbox/query", path: "/ids" } }, "c1"],
    ]);
    const [name, args] = r.methodResponses[1] as [string, Record<string, unknown>, string];
    expect(name).toBe("Mailbox/get");
    expect((args.list as unknown[]).length).toBeGreaterThan(0);
  });

  test("Mailbox/changes — sinceState=0은 현재 state까지", async () => {
    const r = await jmapCall([["Mailbox/changes", { accountId: acc(), sinceState: "0" }, "c0"]]);
    const [name, args] = r.methodResponses[0] as [string, Record<string, unknown>, string];
    expect(name).toBe("Mailbox/changes");
    expect(typeof args.newState).toBe("string");
    expect(Array.isArray(args.created)).toBe(true);
  });

  test("잘못된 sinceState → cannotCalculateChanges (미래 state)", async () => {
    const r = await jmapCall([["Mailbox/changes", { accountId: acc(), sinceState: "99999" }, "c0"]]);
    expect(r.methodResponses[0]![0]).toBe("error");
    expect((r.methodResponses[0]![1] as { type: string }).type).toBe("cannotCalculateChanges");
  });

  test("미지원 capability 요청 → 400", async () => {
    const res = await fetch(`${base}/jmap/api`, {
      method: "POST",
      headers: { authorization: AUTH, "content-type": "application/json" },
      body: JSON.stringify({ using: ["urn:bogus"], methodCalls: [["Core/echo", {}, "c0"]] }),
    });
    expect(res.status).toBe(400);
  });
});

/** SMTP로 원문 1통 배달(app.smtpPort) — 공용 헬퍼. */
async function deliverMessage(rawMessage: string): Promise<void> {
  const r = await smtpDeliver({
    port: app.smtpPort,
    ehlo: "test.local",
    from: "sender@remote.example",
    to: "you@test.local",
    data: rawMessage,
  });
  if (r.final.code !== 250) throw new Error(`smtp rejected: ${r.final.text}`);
}

const SAMPLE_EMAIL = [
  "From: Alice <alice@remote.example>",
  "To: you@test.local",
  "Subject: jmap email test",
  "Message-ID: <jmap-1@remote.example>",
  "Date: Fri, 25 Jul 2026 12:00:00 +0000",
  'Content-Type: multipart/alternative; boundary="B"',
  "",
  "--B",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "plain body here",
  "--B",
  "Content-Type: text/html; charset=utf-8",
  "",
  "<p>html body here</p>",
  "--B--",
  "",
].join("\n");

describe("Email get/query/changes", () => {
  test("SMTP 배달 → Email/query(inMailbox INBOX) → id 반환", async () => {
    await deliverMessage(SAMPLE_EMAIL);
    // INBOX id 확보
    const mbxRes = await jmapCall([["Mailbox/query", { accountId: acc(), filter: { role: "inbox" } }, "c0"]]);
    const inboxId = ((mbxRes.methodResponses[0] as [string, Record<string, unknown>, string])[1].ids as string[])[0]!;

    const r = await jmapCall([["Email/query", { accountId: acc(), filter: { inMailbox: inboxId }, sort: [{ property: "receivedAt", isAscending: false }] }, "c0"]]);
    const [, args] = r.methodResponses[0] as [string, Record<string, unknown>, string];
    expect(args.total).toBe(1);
    expect((args.ids as string[]).length).toBe(1);
  });

  test("Email/query FTS: text/subject 필터가 search_index로 매칭", async () => {
    await deliverMessage(SAMPLE_EMAIL); // subject "jmap email test", body "plain body here"
    const q = async (filter: Record<string, unknown>) => {
      const r = await jmapCall([["Email/query", { accountId: acc(), filter }, "c0"]]);
      return (r.methodResponses[0] as [string, Record<string, unknown>, string])[1].ids as string[];
    };
    expect((await q({ text: "jmap" })).length).toBeGreaterThanOrEqual(1); // subject 토큰
    expect((await q({ subject: "email" })).length).toBeGreaterThanOrEqual(1); // subject 필드
    expect((await q({ text: "존재하지않는단어xyz" })).length).toBe(0); // 매치 없음
    // 미지원 필터 키는 unsupportedFilter 에러
    const bad = await jmapCall([["Email/query", { accountId: acc(), filter: { nope: "x" } }, "c0"]]);
    expect((bad.methodResponses[0] as [string, Record<string, unknown>, string])[0]).toBe("error");
  });

  test("Email/query 백레퍼런스 → Email/get(메타) — 주소/키워드/mailboxIds", async () => {
    const mbxRes = await jmapCall([["Mailbox/query", { accountId: acc(), filter: { role: "inbox" } }, "c0"]]);
    const inboxId = ((mbxRes.methodResponses[0] as [string, Record<string, unknown>, string])[1].ids as string[])[0]!;
    const r = await jmapCall([
      ["Email/query", { accountId: acc(), filter: { inMailbox: inboxId } }, "c0"],
      [
        "Email/get",
        { accountId: acc(), "#ids": { resultOf: "c0", name: "Email/query", path: "/ids" }, properties: ["subject", "from", "to", "keywords", "mailboxIds", "receivedAt", "hasAttachment"] },
        "c1",
      ],
    ]);
    const [name, args] = r.methodResponses[1] as [string, Record<string, unknown>, string];
    expect(name).toBe("Email/get");
    const email = (args.list as Record<string, unknown>[])[0]!;
    expect(email.subject).toBe("jmap email test");
    expect((email.from as { email: string }[])[0]!.email).toBe("alice@remote.example");
    expect((email.mailboxIds as Record<string, boolean>)[inboxId]).toBe(true);
    expect(typeof email.receivedAt).toBe("string");
  });

  test("Email/get 본문 — bodyStructure + textBody/htmlBody + bodyValues(fetch 플래그)", async () => {
    const q = await jmapCall([["Email/query", { accountId: acc() }, "c0"]]);
    const emailId = ((q.methodResponses[0] as [string, Record<string, unknown>, string])[1].ids as string[])[0]!;
    const r = await jmapCall([
      [
        "Email/get",
        { accountId: acc(), ids: [emailId], properties: ["bodyStructure", "textBody", "htmlBody", "bodyValues", "messageId"], fetchAllBodyValues: true },
        "c0",
      ],
    ]);
    const email = ((r.methodResponses[0] as [string, Record<string, unknown>, string])[1].list as Record<string, unknown>[])[0]!;
    expect((email.bodyStructure as { type: string }).type).toBe("multipart/alternative");
    const textPid = (email.textBody as { partId: string }[])[0]!.partId;
    const htmlPid = (email.htmlBody as { partId: string }[])[0]!.partId;
    const values = email.bodyValues as Record<string, { value: string }>;
    expect(values[textPid]!.value).toBe("plain body here");
    expect(values[htmlPid]!.value).toBe("<p>html body here</p>");
    expect((email.messageId as string[])[0]).toBe("jmap-1@remote.example");
  });

  test("Email/get ids=null → invalidArguments", async () => {
    const r = await jmapCall([["Email/get", { accountId: acc(), ids: null }, "c0"]]);
    expect(r.methodResponses[0]![0]).toBe("error");
    expect((r.methodResponses[0]![1] as { type: string }).type).toBe("invalidArguments");
  });
});

describe("Identity + 블롭 업로드/import/download", () => {
  test("Identity/get — 기본 신원(계정 이메일)", async () => {
    const r = await jmapCall([["Identity/get", { accountId: acc(), ids: null }, "c0"]], ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:submission"]);
    const [name, args] = r.methodResponses[0] as [string, Record<string, unknown>, string];
    expect(name).toBe("Identity/get");
    const list = args.list as Record<string, unknown>[];
    expect(list.length).toBeGreaterThanOrEqual(1);
    expect(list[0]!.email).toBe("you@test.local");
  });

  test("업로드 → Email/set create(import) → get 확인 → download 왕복", async () => {
    const rawMime = ["Subject: imported via jmap", "From: me@test.local", "To: you@test.local", "", "imported body"].join("\r\n");
    // 1) 업로드
    const up = await fetch(`${base}/jmap/upload/${acc()}`, { method: "POST", headers: { authorization: AUTH, "content-type": "message/rfc822" }, body: rawMime });
    expect(up.status).toBe(201);
    const upBody = (await up.json()) as { blobId: string; size: number };
    expect(upBody.blobId).toBeTruthy();

    // 2) INBOX id
    const mbx = await jmapCall([["Mailbox/query", { accountId: acc(), filter: { role: "inbox" } }, "c0"]]);
    const inboxId = ((mbx.methodResponses[0] as [string, Record<string, unknown>, string])[1].ids as string[])[0]!;

    // 3) import
    const cr = await jmapCall([
      ["Email/set", { accountId: acc(), create: { c1: { blobId: upBody.blobId, mailboxIds: { [inboxId]: true }, keywords: { $draft: true } } } }, "c0"],
    ]);
    const created = (cr.methodResponses[0] as [string, Record<string, unknown>, string])[1].created as Record<string, { id: string; threadId: string }>;
    expect(created.c1).toBeDefined();
    const emailId = created.c1!.id;

    // 4) get 확인
    const g = await jmapCall([["Email/get", { accountId: acc(), ids: [emailId], properties: ["subject", "keywords", "mailboxIds"] }, "c0"]]);
    const email = ((g.methodResponses[0] as [string, Record<string, unknown>, string])[1].list as Record<string, unknown>[])[0]!;
    expect(email.subject).toBe("imported via jmap");
    expect((email.keywords as Record<string, boolean>).$draft).toBe(true);
    expect((email.mailboxIds as Record<string, boolean>)[inboxId]).toBe(true);

    // 5) download 왕복
    const dl = await fetch(`${base}/jmap/download/${acc()}/${upBody.blobId}/msg.eml`, { headers: { authorization: AUTH } });
    expect(dl.status).toBe(200);
    expect(await dl.text()).toBe(rawMime);
  });

  test("업로드 인증 없이 → 401", async () => {
    const up = await fetch(`${base}/jmap/upload/${acc()}`, { method: "POST", body: "x" });
    expect(up.status).toBe(401);
  });
});

describe("Thread/get", () => {
  test("Email의 threadId로 Thread/get → emailIds 포함", async () => {
    const q = await jmapCall([
      ["Email/query", { accountId: acc(), limit: 1 }, "c0"],
      ["Email/get", { accountId: acc(), "#ids": { resultOf: "c0", name: "Email/query", path: "/ids" }, properties: ["threadId"] }, "c1"],
    ]);
    const email = ((q.methodResponses[1] as [string, Record<string, unknown>, string])[1].list as Record<string, unknown>[])[0]!;
    const threadId = email.threadId as string;
    expect(typeof threadId).toBe("string");

    const t = await jmapCall([["Thread/get", { accountId: acc(), ids: [threadId] }, "c0"]]);
    const [name, args] = t.methodResponses[0] as [string, Record<string, unknown>, string];
    expect(name).toBe("Thread/get");
    const thread = (args.list as Record<string, unknown>[])[0]!;
    expect(thread.id).toBe(threadId);
    expect((thread.emailIds as string[]).length).toBeGreaterThanOrEqual(1);
    expect((thread.emailIds as string[])).toContain(email.id as string);
  });

  test("없는 threadId → notFound", async () => {
    const t = await jmapCall([["Thread/get", { accountId: acc(), ids: ["01ZZZZZZZZZZZZZZZZZZZZZZZZZ"] }, "c0"]]);
    expect(((t.methodResponses[0] as [string, Record<string, unknown>, string])[1].notFound as string[]).length).toBe(1);
  });
});

describe("Email/set (keywords)", () => {
  async function firstEmailId(): Promise<string> {
    const q = await jmapCall([["Email/query", { accountId: acc(), limit: 1 }, "c0"]]);
    return ((q.methodResponses[0] as [string, Record<string, unknown>, string])[1].ids as string[])[0]!;
  }
  async function keywordsOf(id: string): Promise<Record<string, boolean>> {
    const g = await jmapCall([["Email/get", { accountId: acc(), ids: [id], properties: ["keywords"] }, "c0"]]);
    return ((g.methodResponses[0] as [string, Record<string, unknown>, string])[1].list as Record<string, unknown>[])[0]!.keywords as Record<string, boolean>;
  }

  test("patch 경로로 $seen 추가/제거", async () => {
    const id = await firstEmailId();
    const r = await jmapCall([["Email/set", { accountId: acc(), update: { [id]: { "keywords/$seen": true } } }, "c0"]]);
    expect((r.methodResponses[0] as [string, Record<string, unknown>, string])[1].updated).toHaveProperty(id);
    expect((await keywordsOf(id)).$seen).toBe(true);

    await jmapCall([["Email/set", { accountId: acc(), update: { [id]: { "keywords/$seen": null } } }, "c0"]]);
    expect((await keywordsOf(id)).$seen).toBeUndefined();
  });

  test("keywords 전체 교체", async () => {
    const id = await firstEmailId();
    await jmapCall([["Email/set", { accountId: acc(), update: { [id]: { keywords: { $flagged: true, $seen: true } } } }, "c0"]]);
    const kw = await keywordsOf(id);
    expect(kw.$flagged).toBe(true);
    expect(kw.$seen).toBe(true);
    // 전체 교체 → 빈 객체면 모두 제거
    await jmapCall([["Email/set", { accountId: acc(), update: { [id]: { keywords: {} } } }, "c0"]]);
    expect(Object.keys(await keywordsOf(id))).toEqual([]);
  });

  test("mailboxIds 전체 교체(이동) — INBOX→새 메일함, get으로 확인", async () => {
    // 전용 메일 배달 + 대상 메일함 생성
    await deliverMessage(SAMPLE_EMAIL.replace("jmap email test", "move test " + Date.now()));
    const id = await firstEmailId();
    const inboxRes = await jmapCall([["Mailbox/query", { accountId: acc(), filter: { role: "inbox" } }, "c0"]]);
    const inboxId = ((inboxRes.methodResponses[0] as [string, Record<string, unknown>, string])[1].ids as string[])[0]!;
    const cr = await jmapCall([["Mailbox/set", { accountId: acc(), create: { t: { name: "MoveTarget" + Date.now() } } }, "c0"]]);
    const target = ((cr.methodResponses[0] as [string, Record<string, unknown>, string])[1].created as Record<string, { id: string }>).t!.id;

    const r = await jmapCall([["Email/set", { accountId: acc(), update: { [id]: { mailboxIds: { [target]: true } } } }, "c0"]]);
    expect((r.methodResponses[0] as [string, Record<string, unknown>, string])[1].updated).toHaveProperty(id);

    const g = await jmapCall([["Email/get", { accountId: acc(), ids: [id], properties: ["mailboxIds"] }, "c0"]]);
    const mailboxIds = ((g.methodResponses[0] as [string, Record<string, unknown>, string])[1].list as Record<string, unknown>[])[0]!.mailboxIds as Record<string, boolean>;
    expect(mailboxIds[target]).toBe(true);
    expect(mailboxIds[inboxId]).toBeUndefined(); // INBOX에서 빠짐
  });

  test("빈 mailboxIds → notUpdated(invalidProperties)", async () => {
    const id = await firstEmailId();
    const r = await jmapCall([["Email/set", { accountId: acc(), update: { [id]: { mailboxIds: {} } } }, "c0"]]);
    const [, args] = r.methodResponses[0] as [string, Record<string, unknown>, string];
    expect(args.updated).toEqual({});
    expect((args.notUpdated as Record<string, { type: string }>)[id]!.type).toBe("invalidProperties");
  });

  test("destroy — 파기 후 Email/get은 notFound", async () => {
    await deliverMessage(SAMPLE_EMAIL.replace("jmap email test", "destroy test " + Date.now()));
    const id = await firstEmailId();
    const r = await jmapCall([["Email/set", { accountId: acc(), destroy: [id] }, "c0"]]);
    expect((r.methodResponses[0] as [string, Record<string, unknown>, string])[1].destroyed).toEqual([id]);
    const g = await jmapCall([["Email/get", { accountId: acc(), ids: [id] }, "c0"]]);
    expect(((g.methodResponses[0] as [string, Record<string, unknown>, string])[1].notFound as string[])).toEqual([id]);
  });
});

describe("Mailbox/set", () => {
  test("create → get 확인 → rename → destroy", async () => {
    // create (creationId 사용)
    const cr = await jmapCall([["Mailbox/set", { accountId: acc(), create: { new1: { name: "Projects" } } }, "c0"]]);
    const [, createArgs] = cr.methodResponses[0] as [string, Record<string, unknown>, string];
    const created = createArgs.created as Record<string, { id: string; myRights: unknown }>;
    expect(created.new1).toBeDefined();
    const mbxId = created.new1!.id;
    expect(created.new1!.myRights).toBeDefined();
    expect(createArgs.notCreated).toEqual({});

    // get 확인
    const g = await jmapCall([["Mailbox/get", { accountId: acc(), ids: [mbxId] }, "c0"]]);
    const email = ((g.methodResponses[0] as [string, Record<string, unknown>, string])[1].list as Record<string, unknown>[])[0]!;
    expect(email.name).toBe("Projects");
    expect(email.parentId).toBeNull();

    // rename
    const up = await jmapCall([["Mailbox/set", { accountId: acc(), update: { [mbxId]: { name: "Projects2026" } } }, "c0"]]);
    expect((up.methodResponses[0] as [string, Record<string, unknown>, string])[1].updated).toHaveProperty(mbxId);
    const g2 = await jmapCall([["Mailbox/get", { accountId: acc(), ids: [mbxId] }, "c0"]]);
    expect(((g2.methodResponses[0] as [string, Record<string, unknown>, string])[1].list as Record<string, unknown>[])[0]!.name).toBe("Projects2026");

    // destroy
    const de = await jmapCall([["Mailbox/set", { accountId: acc(), destroy: [mbxId] }, "c0"]]);
    expect((de.methodResponses[0] as [string, Record<string, unknown>, string])[1].destroyed).toEqual([mbxId]);
  });

  test("자식 있는 부모를 creationId 참조로 생성(중첩)", async () => {
    const r = await jmapCall([
      [
        "Mailbox/set",
        { accountId: acc(), create: { parent: { name: "Archive" }, child: { name: "2026", parentId: "#parent" } } },
        "c0",
      ],
    ]);
    const created = (r.methodResponses[0] as [string, Record<string, unknown>, string])[1].created as Record<string, { id: string }>;
    expect(created.parent).toBeDefined();
    expect(created.child).toBeDefined();
    // child가 parent 아래인지 확인
    const g = await jmapCall([["Mailbox/get", { accountId: acc(), ids: [created.child!.id] }, "c0"]]);
    expect(((g.methodResponses[0] as [string, Record<string, unknown>, string])[1].list as Record<string, unknown>[])[0]!.parentId).toBe(created.parent!.id);
  });

  test("INBOX 삭제 거부 → notDestroyed", async () => {
    const inboxRes = await jmapCall([["Mailbox/query", { accountId: acc(), filter: { role: "inbox" } }, "c0"]]);
    const inboxId = ((inboxRes.methodResponses[0] as [string, Record<string, unknown>, string])[1].ids as string[])[0]!;
    const r = await jmapCall([["Mailbox/set", { accountId: acc(), destroy: [inboxId] }, "c0"]]);
    const [, args] = r.methodResponses[0] as [string, Record<string, unknown>, string];
    expect(args.destroyed).toEqual([]);
    expect(args.notDestroyed as Record<string, unknown>).toHaveProperty(inboxId);
  });

  test("ifInState 불일치 → stateMismatch(메서드 에러)", async () => {
    const r = await jmapCall([["Mailbox/set", { accountId: acc(), ifInState: "99999", create: { x: { name: "X" } } }, "c0"]]);
    expect(r.methodResponses[0]![0]).toBe("error");
    expect((r.methodResponses[0]![1] as { type: string }).type).toBe("stateMismatch");
  });
});

describe("EmailSubmission (발송)", () => {
  test("import 초안 → EmailSubmission/set + onSuccessUpdateEmail(Sent 이동), 큐 적재", async () => {
    // 발신 도메인 검증 시드(§8 게이트 통과용)
    const { rows: accRows } = await app.db.query({ sql: "SELECT tenant_id FROM accounts WHERE email = ?", params: ["you@test.local"] });
    const tenantId = String(accRows[0]!.tenant_id);
    await app.db.query({ sql: "SELECT 1" });
    await app.db.batch([
      {
        sql: "INSERT OR IGNORE INTO domains (id, tenant_id, name, name_utf8, status, verify_token, claimed_at, created_at) VALUES (?, ?, ?, NULL, 1, NULL, ?, ?)",
        params: ["D".repeat(26), tenantId, "test.local", Date.now(), Date.now()],
      },
    ]);

    // Drafts 메일함 + 초안 import
    const cr = await jmapCall([["Mailbox/set", { accountId: acc(), create: { d: { name: "Drafts" + Date.now(), role: "drafts" } } }, "c0"]]);
    const draftsId = ((cr.methodResponses[0] as [string, Record<string, unknown>, string])[1].created as Record<string, { id: string }>).d!.id;
    const raw = ["Subject: outgoing", "From: you@test.local", "To: dest@example.test", "", "hello world"].join("\r\n");
    const up = await fetch(`${base}/jmap/upload/${acc()}`, { method: "POST", headers: { authorization: AUTH }, body: raw });
    const blobId = ((await up.json()) as { blobId: string }).blobId;
    const imp = await jmapCall([["Email/set", { accountId: acc(), create: { e: { blobId, mailboxIds: { [draftsId]: true }, keywords: { $draft: true } } } }, "c0"]]);
    const draftId = ((imp.methodResponses[0] as [string, Record<string, unknown>, string])[1].created as Record<string, { id: string }>).e!.id;

    // 식별자
    const idn = await jmapCall([["Identity/get", { accountId: acc(), ids: null }, "c0"]], ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:submission"]);
    const identityId = ((idn.methodResponses[0] as [string, Record<string, unknown>, string])[1].list as Record<string, unknown>[])[0]!.id as string;

    // INBOX(Sent 대용 목적지) — 실제론 Sent지만 여기선 draftsId→INBOX로 이동 확인
    const inboxRes = await jmapCall([["Mailbox/query", { accountId: acc(), filter: { role: "inbox" } }, "c0"]]);
    const inboxId = ((inboxRes.methodResponses[0] as [string, Record<string, unknown>, string])[1].ids as string[])[0]!;

    // EmailSubmission/set + onSuccessUpdateEmail(초안→INBOX 이동, $draft 제거)
    const sub = await jmapCall(
      [
        [
          "EmailSubmission/set",
          {
            accountId: acc(),
            create: { s1: { emailId: draftId, identityId } },
            onSuccessUpdateEmail: { "#s1": { mailboxIds: { [inboxId]: true }, "keywords/$draft": null } },
          },
          "c0",
        ],
      ],
      ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:submission", "urn:ietf:params:jmap:mail"],
    );
    const [, subArgs] = sub.methodResponses[0] as [string, Record<string, unknown>, string];
    expect(subArgs.notCreated).toEqual({});
    const subCreated = subArgs.created as Record<string, { id: string; undoStatus: string }>;
    expect(subCreated.s1).toBeDefined();
    expect(subCreated.s1!.undoStatus).toBe("final");

    // 큐 적재 확인
    const { rows: q } = await app.db.query({ sql: "SELECT rcpt, env_from FROM mta_queue WHERE submission_id = ?", params: [subCreated.s1!.id] });
    expect(q.length).toBe(1);
    expect(String(q[0]!.rcpt)).toBe("dest@example.test");
    expect(String(q[0]!.env_from)).toBe("you@test.local");

    // onSuccessUpdateEmail 반영 — 초안이 INBOX로 이동, $draft 제거
    const g = await jmapCall([["Email/get", { accountId: acc(), ids: [draftId], properties: ["mailboxIds", "keywords"] }, "c0"]]);
    const email = ((g.methodResponses[0] as [string, Record<string, unknown>, string])[1].list as Record<string, unknown>[])[0]!;
    expect((email.mailboxIds as Record<string, boolean>)[inboxId]).toBe(true);
    expect((email.mailboxIds as Record<string, boolean>)[draftsId]).toBeUndefined();
    expect((email.keywords as Record<string, boolean>).$draft).toBeUndefined();

    // EmailSubmission/get
    const sg = await jmapCall([["EmailSubmission/get", { accountId: acc(), ids: [subCreated.s1!.id] }, "c0"]], ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:submission"]);
    const sgEmail = ((sg.methodResponses[0] as [string, Record<string, unknown>, string])[1].list as Record<string, unknown>[])[0]!;
    expect(sgEmail.emailId).toBe(draftId);
    expect(sgEmail.identityId).toBe(identityId);
  });

  test("미검증 발신 도메인(envelope) → notCreated(forbidden)", async () => {
    const q = await jmapCall([["Email/query", { accountId: acc(), limit: 1 }, "c0"]]);
    const emailId = ((q.methodResponses[0] as [string, Record<string, unknown>, string])[1].ids as string[])[0]!;
    const idn = await jmapCall([["Identity/get", { accountId: acc(), ids: null }, "c0"]], ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:submission"]);
    const identityId = ((idn.methodResponses[0] as [string, Record<string, unknown>, string])[1].list as Record<string, unknown>[])[0]!.id as string;
    const sub = await jmapCall(
      [["EmailSubmission/set", { accountId: acc(), create: { s: { emailId, identityId, envelope: { mailFrom: { email: "x@unverified.test" }, rcptTo: [{ email: "a@b.test" }] } } } }, "c0"]],
      ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:submission"],
    );
    const [, args] = sub.methodResponses[0] as [string, Record<string, unknown>, string];
    expect(args.created).toEqual({});
    expect((args.notCreated as Record<string, { type: string }>).s!.type).toBe("forbidden");
  });
});

/** 세션에서 주 계정 id 조회(테스트 헬퍼). */
let cachedAcc: string | undefined;
function acc(): string {
  return cachedAcc ?? "";
}

