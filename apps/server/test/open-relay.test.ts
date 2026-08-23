/**
 * 감사 5차 C-1 회귀 — SRS reverse relay를 통한 **미인증 오픈 릴레이 + DKIM 서명 탈취**.
 *
 * 원래 공격(전부 인증·계정·테넌트 불필요, 포트 25):
 *   MAIL FROM:<ceo@호스팅중인고객도메인.com>          ← DKIM 키가 여기서 선택된다
 *   RCPT TO:<SRS0=HHHH=TT=bank.example=victim@attacker.test>
 *   DATA / <임의 본문> / .
 * → 250 수락 → victim@bank.example로 우리 IP에서, 고객 도메인 DKIM 서명이 붙은 채,
 *   속도 제한 없이 발송(= DMARC를 통과하는 완전한 사칭 메일).
 *
 * 성립 조건이 네 겹이었고 이 파일은 네 겹 전부를 각각 검증한다:
 *   ① SRS 분기가 `@` 오른쪽 **포워더 도메인이 우리 것인지 보지 않았다**
 *   ② 바운스가 아닌 메일도 반송 취급했다(MAIL FROM이 비어 있지 않아도 통과)
 *   ③ `relayBounce`가 봉투발신자로 **공격자의 MAIL FROM을 그대로** 넘겼다(DKIM 키 선택의 축)
 *   ④ `relayBounce`가 `enqueueMessage`에 옵션을 안 넘겨 **relay 상한이 사라졌다**
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ulid } from "@ionosphere/core";
import { srsForward } from "@ionosphere/srs";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

const SRS_SECRET = "open-relay-regression-secret";

/** 최소 SMTP 대화. RCPT에서 거절되면 그 응답을, 아니면 DATA 응답을 돌려준다. */
async function sendOne(port: number, from: string, to: string, data: string): Promise<string> {
  const sock = connect(port, "127.0.0.1");
  let buf = "";
  const pending: ((line: string) => void)[] = [];
  sock.on("data", (c) => {
    buf += c.toString("latin1");
    let i: number;
    while ((i = buf.indexOf("\r\n")) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 2);
      pending.shift()?.(line);
    }
  });
  const line = () => new Promise<string>((resolve) => pending.push(resolve));
  const send = (s: string) => sock.write(s);
  await line(); // 220
  send("EHLO attacker.test\r\n");
  await new Promise<void>((resolve) => {
    const onLine = (l: string) => (l.startsWith("250 ") ? resolve() : pending.unshift(onLine));
    pending.push(onLine);
  });
  send(`MAIL FROM:<${from}>\r\n`);
  await line();
  send(`RCPT TO:<${to}>\r\n`);
  const rcptResp = await line();
  if (!rcptResp.startsWith("250")) {
    send("QUIT\r\n");
    sock.end();
    await new Promise<void>((resolve) => sock.on("close", () => resolve()));
    return rcptResp;
  }
  send("DATA\r\n");
  await line(); // 354
  send(data.replace(/\r?\n/g, "\r\n") + "\r\n.\r\n");
  const dataResp = await line();
  send("QUIT\r\n");
  sock.end();
  await new Promise<void>((resolve) => sock.on("close", () => resolve()));
  return dataResp;
}

describe("C-1 — SRS reverse relay 오픈 릴레이", () => {
  let app: IonosphereApp;
  let blobRoot: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-openrelay-"));
    app = new IonosphereApp({
      hostname: "test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      srsSecret: SRS_SECRET,
      runMtaWorker: false, // 큐 적재만 검증 — 실제 외부 발송 없음
      resolver: offlineResolver(),
    });
    await app.start();

    const { tenantId } = await app.store.createTenant("t");
    const now = Date.now();
    await app.db.batch([
      {
        sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, ?, 1, ?, ?)",
        params: [ulid(), tenantId, "test.local", now, now],
      },
    ]);
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  async function queueRows() {
    const { rows } = await app.db.query({ sql: "SELECT env_from, rcpt FROM mta_queue ORDER BY created_at" });
    return rows.map((r) => ({ envFrom: String(r.env_from), rcpt: String(r.rcpt) }));
  }

  test("① 유효한 SRS 토큰이라도 포워더 도메인이 우리 것이 아니면 RCPT 거부", async () => {
    // 공격자는 자기 도메인을 `@` 오른쪽에 붙인다. HMAC 페이로드에 포워더 도메인이 없으므로
    // 토큰 자체는 유효하다 — 그래서 도메인 소유 검사가 따로 필요하다.
    const token = srsForward("victim@bank.example", "attacker.test", { secret: SRS_SECRET });
    expect(token).toMatch(/@attacker\.test$/);

    const before = (await queueRows()).length;
    const resp = await sendOne(app.smtpPort, "ceo@test.local", token, "Subject: x\r\n\r\nbody\r\n");

    expect(resp).toStartWith("550"); // no such user — SRS 분기를 타지 못한다
    expect((await queueRows()).length).toBe(before);
  });

  test("② 우리 도메인 SRS 주소라도 봉투발신자가 비어 있지 않으면 반송하지 않는다", async () => {
    // RFC 5321 §4.5.5 — DSN의 reverse-path는 null이다. 비어 있지 않으면 바운스가 아니라
    // 우리를 릴레이로 쓰려는 시도다. C-1의 공격 시나리오가 정확히 이 형태였다.
    const token = srsForward("victim@bank.example", "test.local", { secret: SRS_SECRET });
    const before = (await queueRows()).length;

    const resp = await sendOne(app.smtpPort, "ceo@test.local", token, "Subject: 사칭\r\n\r\n임의 본문\r\n");

    expect(resp).not.toStartWith("250"); // 배달 처분이 없어 수락되지 않는다
    expect((await queueRows()).length).toBe(before); // 릴레이 적재 0
  });

  test("③ 진짜 바운스(<>)는 반송하되 봉투발신자는 <>로 강제된다 — DKIM 키가 선택될 수 없다", async () => {
    const token = srsForward("victim@bank.example", "test.local", { secret: SRS_SECRET });
    const before = (await queueRows()).length;

    const resp = await sendOne(app.smtpPort, "", token, "Subject: bounce\r\n\r\nfailed\r\n");

    expect(resp).toStartWith("250");
    const rows = await queueRows();
    expect(rows.length).toBe(before + 1);
    const relay = rows[rows.length - 1]!;
    expect(relay.rcpt).toBe("victim@bank.example");
    // 봉투발신자에 도메인이 없으면 워커의 selectorFor가 어떤 키도 고를 수 없다.
    expect(relay.envFrom).toBe("");
  });
});
