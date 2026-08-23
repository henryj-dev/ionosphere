/**
 * Sieve redirect(RFC 5228 §4.2) 배달 — 릴레이 적재 + 암묵적 keep 취소.
 *
 * 이전 동작: redirect는 로그만 남기고 **조용히 무시**됐다("sieve redirect not implemented").
 * 사용자가 전달 규칙을 켜도 아무 일도 일어나지 않는, 실패가 보이지 않는 종류의 버그였다.
 *
 * 여기서 고정하는 계약:
 *  - redirect는 forward_to와 같은 릴레이 경로(SRS 재작성·루프가드·internal 게이트 우회)를 쓴다.
 *  - redirect는 암묵적 keep을 취소한다 — `redirect`만 있는 스크립트는 로컬에 사본을 남기지 않는다.
 *  - 단 릴레이가 불가능/실패하면 **INBOX로 보존**한다(유실보다 중복·지연이 낫다).
 *  - 대상 수 한도(RFC 5228 §2.10.3) 초과는 오류 → 릴레이 없이 INBOX 폴백(대량 릴레이 방지).
 *
 * MtaWorker는 끄고 mta_queue 적재만 검증한다(실제 외부 발송 없음).
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver, smtpDeliver } from "./helpers.ts";

const SRS_SECRET = "sieve-redirect-test-secret";
const SCRIPT_ID = "R".repeat(26);

/** 한 통 배달 — 공용 SMTP 헬퍼. 250이 아니면 실패로 본다. */
async function deliver(port: number, subject: string): Promise<void> {
  const r = await smtpDeliver({
    port,
    from: "sender@remote.example",
    to: "user@test.local",
    data: ["From: sender@remote.example", "To: user@test.local", `Subject: ${subject}`, "", "body"].join("\r\n"),
  });
  if (r.final.code !== 250) throw new Error(`smtp ${r.final.text}`);
}

/** 테스트별로 활성 스크립트를 갈아끼운다(계정당 활성 1개). */
async function setScript(app: IonosphereApp, accountId: string, content: string): Promise<void> {
  await app.db.batch([
    { sql: "DELETE FROM sieve_scripts WHERE account_id = ?", params: [accountId] },
    {
      sql: "INSERT INTO sieve_scripts (id, account_id, name, content, active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
      params: [SCRIPT_ID, accountId, "main", content, Date.now()],
    },
  ]);
}

async function queueRcpts(app: IonosphereApp): Promise<string[]> {
  const { rows } = await app.db.query({ sql: "SELECT rcpt, env_from FROM mta_queue ORDER BY created_at" });
  return rows.map((r) => String(r.rcpt));
}

async function queueEnvFroms(app: IonosphereApp): Promise<string[]> {
  const { rows } = await app.db.query({ sql: "SELECT env_from FROM mta_queue ORDER BY created_at" });
  return rows.map((r) => String(r.env_from));
}

async function inboxCount(app: IonosphereApp, mailboxId: string): Promise<number> {
  const { rows } = await app.db.query({
    sql: "SELECT COUNT(*) AS n FROM message_mailbox WHERE mailbox_id = ?",
    params: [mailboxId],
  });
  return Number(rows[0]!.n);
}

describe("Sieve redirect — SRS 활성", () => {
  let app: IonosphereApp;
  let blobRoot: string;
  let accountId: string;
  let inboxId: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-sieve-redirect-"));
    app = new IonosphereApp({
      hostname: "test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      srsSecret: SRS_SECRET,
      runMtaWorker: false, // 큐 적재만 검증
      resolver: offlineResolver(),
    });
    await app.start();
    const created = await app.createUser("user@test.local", "pw");
    accountId = created.accountId;
    inboxId = (await app.store.getMailboxByRole(accountId, "inbox"))!.id;
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("redirect만 있는 스크립트 — 릴레이 적재되고 로컬 사본은 없다(암묵 keep 취소)", async () => {
    await setScript(app, accountId, `redirect "ext@remote.test";`);
    await deliver(app.smtpPort, "hello");

    expect(await queueRcpts(app)).toEqual(["ext@remote.test"]);
    expect(await inboxCount(app, inboxId)).toBe(0); // RFC 5228 §4.2 — redirect가 암묵적 keep을 취소
    // envelope from은 SRS0=...@test.local로 재작성(원 도메인 SPF로 발송하지 않기 위해)
    expect((await queueEnvFroms(app))[0]).toMatch(/^SRS0=.+@test\.local$/);
  });

  test("keep + redirect — 릴레이와 로컬 저장이 함께 일어난다", async () => {
    await setScript(app, accountId, `keep;\nredirect "both@remote.test";`);
    const before = (await queueRcpts(app)).length;
    await deliver(app.smtpPort, "keep and redirect");

    const rcpts = await queueRcpts(app);
    expect(rcpts.length).toBe(before + 1);
    expect(rcpts[rcpts.length - 1]).toBe("both@remote.test");
    expect(await inboxCount(app, inboxId)).toBe(1);
  });

  test("여러 대상 redirect — 한 번의 적재로 대상 수만큼 큐 행", async () => {
    await setScript(app, accountId, `redirect "a@remote.test";\nredirect "b@remote.test";`);
    const before = (await queueRcpts(app)).length;
    await deliver(app.smtpPort, "fanout");

    const rcpts = await queueRcpts(app);
    expect(rcpts.length).toBe(before + 2);
    expect(rcpts.slice(-2).sort()).toEqual(["a@remote.test", "b@remote.test"]);
  });

  test("한도 초과(5개) — 릴레이 없이 INBOX 폴백(스크립트 하나로 대량 릴레이 금지)", async () => {
    const many = ["v", "w", "x", "y", "z"].map((c) => `redirect "${c}@remote.test";`).join("\n");
    await setScript(app, accountId, many);
    const before = (await queueRcpts(app)).length;
    const inboxBefore = await inboxCount(app, inboxId);
    await deliver(app.smtpPort, "too many");

    expect((await queueRcpts(app)).length).toBe(before); // 한 건도 릴레이되지 않음
    expect(await inboxCount(app, inboxId)).toBe(inboxBefore + 1); // 오류 정책 = INBOX 폴백
  });

  /**
   * 감사 5차 M-15 회귀 — 예전엔 `X-Ionosphere-Forwarded` **발생 횟수만** 셌기 때문에, 미인증
   * 원격 발신자가 헤더를 손으로 붙이는 것만으로 **피해자의 Sieve redirect를 무력화**할 수
   * 있었다(미인증 원격 DoS). 이 테스트는 예전에 그 동작을 "루프가드"라 부르며 단언하던 자리다.
   */
  test("위조된 X-Ionosphere-Forwarded는 redirect를 무력화하지 못한다", async () => {
    await setScript(app, accountId, `redirect "loop@remote.test";`);
    const before = (await queueRcpts(app)).length;

    const forged = Array.from({ length: 11 }, () => "X-Ionosphere-Forwarded: test.local").join("\r\n");
    const r = await smtpDeliver({
      port: app.smtpPort,
      from: "sender@remote.example",
      to: "user@test.local",
      data: ["From: sender@remote.example", "To: user@test.local", "Subject: looped", forged, "", "body"].join("\r\n"),
    });
    expect(r.final.code).toBe(250);
    // 봉인이 없는 값은 우리가 만든 것이 아니므로 무시된다 → 사용자의 redirect가 살아 있다.
    expect((await queueRcpts(app)).length).toBe(before + 1);
  });

  test("봉인된 표식이 한도를 넘으면 릴레이 대신 INBOX 보존(유실 금지)", async () => {
    await setScript(app, accountId, `redirect "loop@remote.test";`);

    // 1) 한 번 redirect시켜 우리 봉인 표식을 얻는다. 봉인은 Message-ID에 묶이므로 고정한다.
    const messageId = "<sieve-loop-seal@remote.example>";
    const head = ["From: sender@remote.example", "To: user@test.local", `Message-ID: ${messageId}`];
    await smtpDeliver({
      port: app.smtpPort,
      from: "sender@remote.example",
      to: "user@test.local",
      data: [...head, "Subject: seal", "", "body"].join("\r\n"),
    });
    const { rows } = await app.db.query({
      sql: "SELECT blob_id FROM mta_queue WHERE rcpt = 'loop@remote.test' ORDER BY created_at DESC LIMIT 1",
    });
    const text = Buffer.from(await app.blobs.get(String(rows[0]!.blob_id))).toString("latin1");
    const marker = /^X-Ionosphere-Forwarded: (.+)$/m.exec(text)?.[1]?.trim();
    expect(marker).toBeDefined();

    // 2) 그 표식을 한도(기본 10) 초과로 붙여 되먹인다 → 릴레이 차단 + INBOX 보존.
    const before = (await queueRcpts(app)).length;
    const inboxBefore = await inboxCount(app, inboxId);
    const sealed = Array.from({ length: 11 }, () => `X-Ionosphere-Forwarded: ${marker}`).join("\r\n");
    const r = await smtpDeliver({
      port: app.smtpPort,
      from: "sender@remote.example",
      to: "user@test.local",
      data: [...head, "Subject: looped", sealed, "", "body"].join("\r\n"),
    });
    expect(r.final.code).toBe(250);

    expect((await queueRcpts(app)).length).toBe(before); // 루프가드로 릴레이 차단
    expect(await inboxCount(app, inboxId)).toBe(inboxBefore + 1); // 그래도 메일은 남아야 한다
  });
});

describe("Sieve redirect — SRS 미설정", () => {
  let app: IonosphereApp;
  let blobRoot: string;
  let accountId: string;
  let inboxId: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-sieve-redirect-nosrs-"));
    app = new IonosphereApp({
      hostname: "test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      runMtaWorker: false,
      resolver: offlineResolver(),
    }); // srsSecret 없음
    await app.start();
    const created = await app.createUser("user@test.local", "pw");
    accountId = created.accountId;
    inboxId = (await app.store.getMailboxByRole(accountId, "inbox"))!.id;
    await setScript(app, accountId, `redirect "ext@remote.test";`);
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("SRS 없으면 릴레이하지 않되 INBOX에 보존한다(유실 금지)", async () => {
    await deliver(app.smtpPort, "no srs");
    expect(await queueRcpts(app)).toEqual([]); // SRS 없이 릴레이하면 수신측 SPF에서 거부된다
    expect(await inboxCount(app, inboxId)).toBe(1); // redirect가 keep을 취소해선 안 되는 유일한 경우
  });
});
