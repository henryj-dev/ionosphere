/**
 * 발송 정책이 **SMTP 제출 경로까지 실제로 도달하는가**.
 *
 * 배경(실제 버그): 백엔드가 정책을 필드 단위로 받아 enqueueMessage 호출부에서 손으로
 * 재조립했다. 그래서 app.ts가 넘긴 `requireSenderOwnership: false`가 **조용히 버려져**
 * SMTP 제출에서는 해제가 아예 동작하지 않았다(JMAP은 정책 객체를 그대로 받아 정상이었다).
 * 갈래마다 옵션을 재작성하면 한쪽만 빠진다 — 이 저장소가 반복해 겪은 사고다.
 *
 * 이 파일은 그 통로를 지킨다. 여기서 검증하는 건 "사칭을 허용해도 되는가"가 아니라
 * **"설정한 값이 그 갈래에 도착하는가"**다.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { offlineResolver, smtpDeliver } from "./helpers.ts";

const E2E_HOOK_TIMEOUT_MS = 25_000;

let app: IonosphereApp;
let dir: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "ionosphere-submit-policy-"));
  app = new IonosphereApp({
    hostname: "test.local",
    dbPath: join(dir, "t.db"),
    blobRoot: join(dir, "blobs"),
    submissionPort: 0,
    resolver: offlineResolver(),
    runMtaWorker: false,
    // ★이 값이 SMTP 제출 갈래까지 도달하는지가 이 파일의 주제다.
    requireSenderOwnership: false,
  });
  await app.start();
  await app.createUser("alice@test.local", "pw-alice");
  await app.createUser("ceo@test.local", "pw-ceo");
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(dir, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("정책 전달 (SMTP 제출)", () => {
  test("requireSenderOwnership=false가 SMTP 제출에도 적용된다", async () => {
    const res = await smtpDeliver({
      port: app.submissionPort,
      ehlo: "client.example",
      from: "ceo@test.local", // alice가 ceo를 사칭 — 해제했으므로 통과해야 한다
      to: "alice@test.local",
      auth: { user: "alice@test.local", pass: "pw-alice" },
      data: "From: ceo@test.local\r\nTo: alice@test.local\r\nSubject: s\r\n\r\nb\r\n",
    });
    // 정책이 버려지던 시절엔 기본값(on)이 걸려 550 sender-not-owned로 끊겼다.
    expect(res.final.code).toBe(250);
  }, E2E_HOOK_TIMEOUT_MS);

  test("실제로 큐에 적재됐다 — 250만 보고 판단하지 않는다", async () => {
    const { rows } = await app.db.query({
      sql: "SELECT env_from, rcpt FROM mta_queue ORDER BY created_at DESC LIMIT 1",
    });
    expect(rows[0]?.env_from).toBe("ceo@test.local");
  }, E2E_HOOK_TIMEOUT_MS);
});
