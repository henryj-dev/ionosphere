/**
 * JMAP 발신측 헤더·봉투 주입 실측 (감사 5차 §9-5 항목 9 후속).
 *
 * 수신측 생성 경로(`packages/core/src/received.ts`)는 `headerSafeToken`이 조립 함수 안에서
 * CR/LF·제어문자를 거부하는 것이 확인됐으나, JMAP 발신측은 별개 경로라 미검증으로 남았다.
 * 여기서는 "코드를 보니 안전해 보인다"가 아니라 **실제로 주입을 시도하고 결과 바이트를 확인**한다.
 *
 * 검증하는 구조적 사실:
 *   ① `Email/set` create는 **blobId import 전용**이다 — 헤더를 조립하는 코드가 존재하지 않으므로
 *      클라이언트가 헤더 필드를 넘겨 메시지를 만들 수단 자체가 없다(미구현 = fail closed).
 *   ② `EmailSubmission/set`의 봉투는 클라이언트 값이지만 `enqueueMessage` 안의
 *      `isSafeEnvelopeAddress` 게이트를 반드시 통과한다 — 게이트가 조립 함수 안에 있어 우회 불가.
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
let accountId = "";
let identityId = "";
let draftsId = "";
const AUTH = "Basic " + Buffer.from("you@test.local:pw-inject-1").toString("base64");

const CORE = "urn:ietf:params:jmap:core";
const MAIL = "urn:ietf:params:jmap:mail";
const SUBMISSION = "urn:ietf:params:jmap:submission";

type MethodResponse = [string, Record<string, unknown>, string];

async function jmapCall(methodCalls: unknown[], using: string[] = [CORE, MAIL]): Promise<MethodResponse[]> {
  const res = await fetch(`${base}/jmap/api`, {
    method: "POST",
    headers: { authorization: AUTH, "content-type": "application/json" },
    body: JSON.stringify({ using, methodCalls }),
  });
  expect(res.status).toBe(200);
  return ((await res.json()) as { methodResponses: MethodResponse[] }).methodResponses;
}

async function upload(raw: string): Promise<string> {
  const res = await fetch(`${base}/jmap/upload/${accountId}`, {
    method: "POST",
    headers: { authorization: AUTH, "content-type": "message/rfc822" },
    body: raw,
  });
  expect(res.status).toBe(201);
  return ((await res.json()) as { blobId: string }).blobId;
}

/**
 * 성공(id)과 실패(err) 중 하나만 채워진다. exactOptionalPropertyTypes 때문에 `| undefined`를
 * 명시해야 한다 — 선택 프로퍼티에 undefined를 "넣는" 것과 "빼는" 것이 구분되는 설정이다.
 */
type SetOutcome = { id?: string | undefined; err?: Record<string, unknown> | undefined };

/** import 한 건 — 성공하면 emailId, 실패하면 SetError를 돌려준다. */
async function importDraft(props: Record<string, unknown>): Promise<SetOutcome> {
  const [resp] = await jmapCall([["Email/set", { accountId, create: { e: props } }, "c0"]]);
  const args = resp![1];
  const created = args.created as Record<string, { id: string }>;
  const notCreated = args.notCreated as Record<string, Record<string, unknown>>;
  return created.e ? { id: created.e.id } : { err: notCreated.e };
}

async function submit(props: Record<string, unknown>): Promise<SetOutcome> {
  const [resp] = await jmapCall([["EmailSubmission/set", { accountId, create: { s: props } }, "c0"]], [CORE, SUBMISSION, MAIL]);
  const args = resp![1];
  const created = args.created as Record<string, { id: string }>;
  const notCreated = args.notCreated as Record<string, Record<string, unknown>>;
  return created.s ? { id: created.s.id } : { err: notCreated.s };
}

/** 이번 계정이 큐에 넣은 모든 행 — 주입이 실제로 SMTP 명령 줄까지 갔는지 확인하는 정본. */
async function queueRows(): Promise<{ envFrom: string; rcpt: string }[]> {
  const { rows } = await app.db.query({ sql: "SELECT env_from, rcpt FROM mta_queue ORDER BY created_at", params: [] });
  return rows.map((r) => ({ envFrom: String(r.env_from), rcpt: String(r.rcpt) }));
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-jmap-inject-"));
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
  await app.createUser("you@test.local", "pw-inject-1");
  base = `http://127.0.0.1:${app.jmapPort}`;

  const sess = (await (await fetch(`${base}/jmap/session`, { headers: { authorization: AUTH } })).json()) as {
    primaryAccounts: Record<string, string>;
  };
  accountId = sess.primaryAccounts[MAIL]!;

  // 발신 도메인 검증 시드 — 이게 없으면 모든 발송이 domain-unverified에서 먼저 걸려
  // 봉투 주입 게이트까지 도달하지 못한다(테스트가 엉뚱한 이유로 통과하는 것을 막는다).
  const { rows } = await app.db.query({ sql: "SELECT tenant_id FROM accounts WHERE email = ?", params: ["you@test.local"] });
  const tenantId = String(rows[0]!.tenant_id);
  await app.db.batch([
    {
      sql: "INSERT OR IGNORE INTO domains (id, tenant_id, name, name_utf8, status, verify_token, claimed_at, created_at) VALUES (?, ?, ?, NULL, 1, NULL, ?, ?)",
      params: ["D".repeat(26), tenantId, "test.local", Date.now(), Date.now()],
    },
  ]);

  const [mbx] = await jmapCall([["Mailbox/set", { accountId, create: { d: { name: "Drafts", role: "drafts" } } }, "c0"]]);
  draftsId = ((mbx![1].created as Record<string, { id: string }>).d!).id;

  const [idn] = await jmapCall([["Identity/get", { accountId, ids: null }, "c0"]], [CORE, SUBMISSION]);
  identityId = ((idn![1].list as Record<string, unknown>[])[0]!.id) as string;
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("Email/set create — 임의 헤더 지정 수단이 있는가", () => {
  test("RFC 8621 헤더 지정 형식(header:X-Foo·headers·from·subject)은 메시지 바이트에 전혀 반영되지 않는다", async () => {
    const raw = ["Subject: benign", "From: you@test.local", "To: dest@example.test", "", "body"].join("\r\n");
    const blobId = await upload(raw);

    // RFC 8621 §4.1.3이 정의하는 임의 헤더 지정 형식을 전부 동원한다.
    const { id, err } = await importDraft({
      blobId,
      mailboxIds: { [draftsId]: true },
      "header:X-Injected": "evil",
      "header:X-Injected:asText": "evil",
      "header:Authentication-Results": "test.local; dkim=pass header.d=victim.test",
      headers: [
        { name: "X-Injected", value: "evil" },
        { name: "Authentication-Results", value: "test.local; spf=pass" },
      ],
      from: [{ email: "ceo@victim.test" }],
      subject: "spoofed",
      bodyStructure: { type: "text/plain", partId: "1" },
      textBody: [{ partId: "1", type: "text/plain" }],
      bodyValues: { "1": { value: "injected body" } },
    });
    expect(err).toBeUndefined();
    expect(id).toBeTruthy();

    // 결과 바이트 = 업로드한 원문 그대로. 조립된 헤더가 하나도 없다.
    const dl = await fetch(`${base}/jmap/download/${accountId}/${blobId}/msg.eml`, { headers: { authorization: AUTH } });
    expect(dl.status).toBe(200);
    const bytes = await dl.text();
    expect(bytes).toBe(raw);
    expect(bytes).not.toContain("X-Injected");
    expect(bytes).not.toContain("Authentication-Results");
    expect(bytes).not.toContain("spoofed");
    expect(bytes).not.toContain("ceo@victim.test");
  });

  test("blobId 없이 헤더 프로퍼티만 주면 생성 자체가 거부된다(조립 경로 부재의 직접 증거)", async () => {
    const { id, err } = await importDraft({
      mailboxIds: { [draftsId]: true },
      "header:X-Injected": "evil",
      from: [{ email: "ceo@victim.test" }],
      subject: "spoofed",
      bodyValues: { "1": { value: "hi" } },
    });
    expect(id).toBeUndefined();
    expect(err?.type).toBe("invalidProperties");
    expect(err?.properties).toEqual(["blobId"]);
  });
});

describe("EmailSubmission/set — 봉투 주입", () => {
  let draftId = "";

  beforeAll(async () => {
    const raw = ["Subject: outgoing", "From: you@test.local", "To: dest@example.test", "", "hello"].join("\r\n");
    const blobId = await upload(raw);
    const { id } = await importDraft({ blobId, mailboxIds: { [draftsId]: true }, keywords: { $draft: true } });
    draftId = id!;
  });

  test("mailFrom에 CRLF + SMTP 명령을 넣으면 거부되고 큐에 아무것도 남지 않는다", async () => {
    const before = (await queueRows()).length;
    const { id, err } = await submit({
      emailId: draftId,
      identityId,
      envelope: {
        mailFrom: { email: "you@test.local\r\nRCPT TO:<attacker@evil.test>" },
        rcptTo: [{ email: "dest@example.test" }],
      },
    });
    expect(id).toBeUndefined();
    expect(err?.type).toBe("forbidden");
    expect(String(err?.description)).toContain("unsafe envelope-from");
    expect((await queueRows()).length).toBe(before);
  });

  /**
   * 큐에 안 남는 것만으로는 부족하다 — 예전엔 `createSubmission`이 큐 적재보다 **먼저** 실행돼
   * 거부된 봉투의 **CRLF 주입 페이로드가 `email_submissions` 행으로 남았다.** `EmailSubmission/get`이
   * 그 행을 유령 제출로 보여 주기까지 했다. 봉투 검사를 행 생성 앞으로 당겨 닫았다.
   */
  test("거부된 봉투는 email_submissions에 고아 행도 남기지 않는다", async () => {
    const countSubs = async (): Promise<number> => {
      const { rows } = await app.db.query({ sql: "SELECT COUNT(*) AS n FROM email_submissions" });
      return Number(rows[0]!.n);
    };
    const before = await countSubs();

    const { err } = await submit({
      emailId: draftId,
      identityId,
      envelope: {
        mailFrom: { email: "you@test.local\r\nRCPT TO:<attacker@evil.test>" },
        rcptTo: [{ email: "dest@example.test" }],
      },
    });
    expect(err?.type).toBe("forbidden");
    expect(await countSubs()).toBe(before);

    // 주입 문자열이 DB 어디에도 남지 않는다(로그·백업으로 새어나갈 수 있다).
    const { rows } = await app.db.query({ sql: "SELECT env_from FROM email_submissions" });
    for (const r of rows) expect(String(r.env_from)).not.toContain("RCPT TO");
  });

  test("rcptTo에 CRLF + SMTP 명령을 넣으면 거부되고 큐에 아무것도 남지 않는다", async () => {
    const before = (await queueRows()).length;
    const { id, err } = await submit({
      emailId: draftId,
      identityId,
      envelope: {
        mailFrom: { email: "you@test.local" },
        rcptTo: [{ email: "dest@example.test\r\nDATA\r\nSubject: forged\r\n.\r\n" }],
      },
    });
    expect(id).toBeUndefined();
    expect(err?.type).toBe("forbidden");
    expect(String(err?.description)).toContain("unsafe recipient");
    expect((await queueRows()).length).toBe(before);
  });

  test("bare LF만으로도 거부된다(수신 MTA가 LF를 줄 끝으로 보는 SMTP smuggling 차단)", async () => {
    const before = (await queueRows()).length;
    const { id, err } = await submit({
      emailId: draftId,
      identityId,
      envelope: { mailFrom: { email: "you@test.local" }, rcptTo: [{ email: "dest@example.test\nRCPT TO:<attacker@evil.test>" }] },
    });
    expect(id).toBeUndefined();
    expect(err?.type).toBe("forbidden");
    expect((await queueRows()).length).toBe(before);
  });

  test("NUL·제어문자가 든 봉투 주소도 거부된다", async () => {
    const before = (await queueRows()).length;
    const { id, err } = await submit({
      emailId: draftId,
      identityId,
      envelope: { mailFrom: { email: "you@test.local" }, rcptTo: [{ email: "dest\u0000x@example.test" }] },
    });
    expect(id).toBeUndefined();
    expect(err?.type).toBe("forbidden");
    expect((await queueRows()).length).toBe(before);
  });

  test("검증된 도메인이라도 계정이 소유하지 않은 주소는 봉투발신자가 될 수 없다", async () => {
    const before = (await queueRows()).length;
    const { id, err } = await submit({
      emailId: draftId,
      identityId,
      envelope: { mailFrom: { email: "ceo@test.local" }, rcptTo: [{ email: "dest@example.test" }] },
    });
    expect(id).toBeUndefined();
    expect(err?.type).toBe("forbidden");
    expect(String(err?.description)).toContain("not owned by account");
    expect((await queueRows()).length).toBe(before);
  });

  test("정상 봉투는 여전히 통과한다(가드가 기능을 죽이지 않았다는 회귀 확인)", async () => {
    const { id, err } = await submit({
      emailId: draftId,
      identityId,
      envelope: { mailFrom: { email: "you@test.local" }, rcptTo: [{ email: "dest@example.test" }] },
    });
    expect(err).toBeUndefined();
    expect(id).toBeTruthy();
    const rows = await queueRows();
    const mine = rows.filter((r) => r.rcpt === "dest@example.test");
    expect(mine.length).toBeGreaterThan(0);
    expect(mine.every((r) => r.envFrom === "you@test.local")).toBe(true);
  });
});

describe("헤더에서 유도되는 수신자(envelope 미지정)", () => {
  test("To 헤더에 CR/LF를 심어도 큐의 rcpt에는 제어문자가 없다", async () => {
    // 접힌 줄(folding)로 위장한 주입 시도 — 파서가 unfold 한 결과가 그대로 rcpt가 되면
    // 큐를 거쳐 SMTP 명령 줄에 제어문자가 실린다.
    const raw = [
      "Subject: folded",
      "From: you@test.local",
      "To: victim@example.test,",
      "\tattacker@evil.test",
      "",
      "hello",
    ].join("\r\n");
    const blobId = await upload(raw);
    const { id: emailId } = await importDraft({ blobId, mailboxIds: { [draftsId]: true } });
    expect(emailId).toBeTruthy();

    const { id, err } = await submit({ emailId, identityId });
    // 접힌 주소는 정상 파싱돼 수신자가 된다(주입이 아니라 RFC 5322 folding의 정상 동작).
    expect(err).toBeUndefined();
    expect(id).toBeTruthy();

    const rows = await queueRows();
    for (const r of rows) {
      expect(/[\u0000-\u001f\u007f]/.test(r.rcpt)).toBe(false);
      expect(/[\u0000-\u001f\u007f]/.test(r.envFrom)).toBe(false);
    }
  });
});
