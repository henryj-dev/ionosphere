/**
 * Received 트레이스 헤더 — 실제 SMTP 왕복으로 배선을 검증한다.
 *
 * 조립 자체(주입 방어·RFC 3848 키워드·for 절)는 packages/core/test/received.test.ts가 지킨다.
 * 여기서는 **갈래마다 실제로 붙는가**와 **루프 가드가 끊는가**만 본다.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MAX_RECEIVED_HOPS } from "@ionosphere/core";
import { IonosphereApp } from "../src/app.ts";
import { offlineResolver, smtpDeliver } from "./helpers.ts";

const E2E_HOOK_TIMEOUT_MS = 25_000;

let app: IonosphereApp;
let dir: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "ionosphere-received-"));
  app = new IonosphereApp({
    hostname: "test.local",
    dbPath: join(dir, "t.db"),
    blobRoot: join(dir, "blobs"),
    smtpPort: 0,
    pop3Port: 0,
    submissionPort: 0,
    resolver: offlineResolver(),
    runMtaWorker: false,
  });
  await app.start();
  await app.createUser("user@test.local", "pw-received");
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(dir, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

/** 저장된 메시지의 raw를 꺼낸다. */
async function storedRaw(): Promise<string> {
  const { rows } = await app.db.query({ sql: "SELECT blob_id FROM messages ORDER BY received_at DESC LIMIT 1" });
  const blobId = String(rows[0]!.blob_id);
  const g = await app.db.query({ sql: "SELECT generation FROM blobs WHERE id = ?", params: [blobId] });
  return Buffer.from(await app.blobs.get(blobId, Number(g.rows[0]?.generation ?? 0))).toString("utf8");
}

function message(extraHeaders = ""): string {
  return `${extraHeaders}From: s@remote.example\r\nTo: user@test.local\r\nSubject: trace\r\n\r\nbody\r\n`;
}

describe("수신(SMTP 25)", () => {
  test("Received가 최상단에 정확히 하나 붙는다", async () => {
    const res = await smtpDeliver({
      port: app.smtpPort,
      ehlo: "relay.example",
      from: "s@remote.example",
      to: "user@test.local",
      data: message(),
    });
    expect(res.final.code).toBe(250);

    const raw = await storedRaw();
    // Received-SPF가 그 위에 온다(RFC 7208 §9.1) — Received는 두 번째다.
    expect(raw.startsWith("Received-SPF: ")).toBe(true);
    expect(raw).toContain("Received: from relay.example");
    expect(raw.indexOf("Received-SPF:")).toBeLessThan(raw.indexOf("Received: from"));
    expect(raw.split("\r\n").filter((l) => l.startsWith("Received:"))).toHaveLength(1);
    // 평문 세션 → ESMTP (RFC 3848). by는 우리 authserv-id.
    expect(raw).toContain("with ESMTP");
    expect(raw).toContain("by test.local");
    // 접속 IP가 주소 리터럴로 들어간다(RFC 5321 §4.4 SHOULD)
    expect(raw).toMatch(/from relay\.example \(\[(127\.0\.0\.1|::1)\]\)/);
  }, E2E_HOOK_TIMEOUT_MS);

  /**
   * §7.6: for 절을 여러 수신자에 적으면 BCC 수신자 신원이 노출된다.
   * §4.4는 더 강하게 "MUST contain exactly one <path>".
   */
  test("수신자가 2명 이상이면 for 절을 적지 않는다 — BCC 노출 방지", async () => {
    await app.createUser("second@test.local", "pw-second");
    const res = await smtpDeliver({
      port: app.smtpPort,
      ehlo: "relay.example",
      from: "s@remote.example",
      to: ["user@test.local", "second@test.local"],
      data: message(),
    });
    expect(res.final.code).toBe(250);

    const raw = await storedRaw();
    expect(raw).toContain("Received: from relay.example");
    expect(raw).not.toContain("for <");
  }, E2E_HOOK_TIMEOUT_MS);

  test("EHLO에 CRLF를 넣어도 헤더가 늘지 않는다", async () => {
    // 엔진이 EHLO 인자를 어디까지 받아 주든, 조립 단계 가드가 최종 방어선이다.
    const res = await smtpDeliver({
      port: app.smtpPort,
      ehlo: "evil.example",
      from: "s@remote.example",
      to: "user@test.local",
      data: message("X-Probe: 1\r\n"),
    });
    expect(res.final.code).toBe(250);
    const raw = await storedRaw();
    const header = raw.split("\r\n\r\n")[0]!;
    expect(header.split("\r\n").filter((l) => l.startsWith("Received:"))).toHaveLength(1);
    expect(header.toLowerCase()).not.toContain("bcc:");
  }, E2E_HOOK_TIMEOUT_MS);
});

describe("루프 차단 (RFC 5321 §6.3)", () => {
  test(`Received가 ${MAX_RECEIVED_HOPS}개 이상이면 554로 끊는다`, async () => {
    const loop = Array.from(
      { length: MAX_RECEIVED_HOPS },
      (_, i) => `Received: from h${i}.example ([203.0.113.${i % 255}])\r\n\tby h${i}.example;\r\n\tTue, 28 Jul 2026 06:12:03 +0000\r\n`,
    ).join("");
    const res = await smtpDeliver({
      port: app.smtpPort,
      ehlo: "relay.example",
      from: "s@remote.example",
      to: "user@test.local",
      data: message(loop),
    });
    expect(res.final.code).toBe(554);
  }, E2E_HOOK_TIMEOUT_MS);

  test("상한 아래(한 개 모자람)는 통과한다 — 정상 다단 포워딩을 끊지 않는다", async () => {
    const loop = Array.from(
      { length: MAX_RECEIVED_HOPS - 1 },
      (_, i) => `Received: from h${i}.example ([203.0.113.${i % 255}])\r\n\tby h${i}.example;\r\n\tTue, 28 Jul 2026 06:12:03 +0000\r\n`,
    ).join("");
    const res = await smtpDeliver({
      port: app.smtpPort,
      ehlo: "relay.example",
      from: "s@remote.example",
      to: "user@test.local",
      data: message(loop),
    });
    expect(res.final.code).toBe(250);
  }, E2E_HOOK_TIMEOUT_MS);
});

describe("제출(587) — 인증된 발송", () => {
  /**
   * 사용자 IP를 **넣는다**(RFC 5321 §4.4 SHOULD: EHLO 이름 + TCP 연결에서 얻은 IP).
   * RFC 6409는 MSA에 별도 예외를 두지 않고 trace 헤더를 [SMTP-MTA] 동작으로 넘긴다.
   * §7.6이 노출 우려를 인정하지만 생략을 권하지는 않으므로 표준을 따른다.
   */
  test("큐에 적재되는 원문에 ESMTPA Received가 붙고 접속 IP가 들어간다", async () => {
    await app.createUser("sender@test.local", "pw-submit");
    const res = await smtpDeliver({
      port: app.submissionPort,
      ehlo: "client.example",
      from: "sender@test.local",
      to: "out@remote.example",
      auth: { user: "sender@test.local", pass: "pw-submit" },
      data: "From: sender@test.local\r\nTo: out@remote.example\r\nSubject: s\r\n\r\nb\r\n",
    });
    expect(res.final.code).toBe(250);

    const { rows } = await app.db.query({ sql: "SELECT blob_id FROM mta_queue ORDER BY created_at DESC LIMIT 1" });
    const blobId = String(rows[0]!.blob_id);
    const g = await app.db.query({ sql: "SELECT generation FROM blobs WHERE id = ?", params: [blobId] });
    const raw = Buffer.from(await app.blobs.get(blobId, Number(g.rows[0]?.generation ?? 0))).toString("utf8");

    expect(raw.startsWith("Received: from client.example")).toBe(true);
    // 인증된 세션이므로 A가 붙는다(RFC 3848). 테스트는 평문이라 S는 없다.
    expect(raw).toContain("with ESMTPA");
    // ★by 절은 설정한 호스트명이어야 한다. 제출 백엔드에 authservId를 빠뜨리면 기본값
    // "localhost"가 그대로 나가고, 실제로 라이브 메일에 그렇게 찍혔다.
    expect(raw).toContain("by test.local");
    expect(raw).not.toContain("by localhost");
    expect(raw).toMatch(/from client\.example \(\[(127\.0\.0\.1|::1)\]\)/);
    expect(raw).toContain("for <out@remote.example>");
    expect(raw.split("\r\n").filter((l) => l.startsWith("Received:"))).toHaveLength(1);
  }, E2E_HOOK_TIMEOUT_MS);
});
