/**
 * 회귀 테스트 — LMTP가 **수신자별로 다른 상태**를 응답하는지 (RFC 2033의 존재 이유).
 *
 * 과거 결함: 어댑터가 SMTP deliver()의 **단일 결과를 모든 수신자에게 복사**했다.
 *   `return env.rcptTo.map((rcpt) => res.ok ? {ok:true,...} : {ok:false,...})`
 * 그래서 수신자 3명 중 1명만 쿼터 초과여도 전원 실패(또는 전원 성공)로 보고됐다.
 * 상류 MTA는 실패한 1명 때문에 **성공한 수신자에게도 재전송**해 중복 배달을 만들 수 있었다.
 *
 * 이 테스트는 한 계정만 쿼터를 꽉 채운 뒤, 같은 트랜잭션의 두 수신자가 서로 다른 코드를
 * 받는지 확인한다(정상=250, 쿼터=452).
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

class Client {
  private readonly sock: Socket;
  private buf = "";
  private readonly lines: string[] = [];
  private waiters: ((l: string) => void)[] = [];
  constructor(port: number) {
    this.sock = connect(port, "127.0.0.1");
    /**
     * ★소켓 오류를 삼킨다. QUIT 직후 end()로 끊으면 서버 응답이 오는 중에 소켓이 닫혀
     * `ECONNRESET`이 난다. node:test는 **테스트 종료 후의 비동기 오류를 파일 실패로 잡는다**
     * (bun은 넘어갔다) — 리스너가 없으면 그것이 uncaughtException이 되어 파일 전체가 죽는다.
     * 여기서 보는 것은 프로토콜 응답이지 소켓 종료 방식이 아니므로 무시가 맞다.
     */
    this.sock.on("error", () => {});
    this.sock.on("data", (c) => {
      this.buf += c.toString("latin1");
      let i: number;
      while ((i = this.buf.indexOf("\r\n")) >= 0) {
        const line = this.buf.slice(0, i);
        this.buf = this.buf.slice(i + 2);
        const w = this.waiters.shift();
        if (w) w(line);
        else this.lines.push(line);
      }
    });
  }
  line(): Promise<string> {
    const q = this.lines.shift();
    return q !== undefined ? Promise.resolve(q) : new Promise((r) => this.waiters.push(r));
  }
  async lhloDone(): Promise<void> {
    let l = await this.line();
    while (l.startsWith("250-")) l = await this.line();
  }
  send(s: string): void {
    this.sock.write(s);
  }
  end(): void {
    this.sock.end();
  }
}

describe("LMTP 수신자별 응답", () => {
  let app: IonosphereApp;
  let blobRoot: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-lmtp-pr-"));
    app = new IonosphereApp({
      hostname: "test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      lmtpPort: 0,
      resolver: offlineResolver(),
    });
    await app.start();
    const ok = await app.createUser("ok@test.local", "pw");
    const full = await app.createUser("full@test.local", "pw");
    // full@ 계정만 쿼터를 1바이트로 — 어떤 메시지든 초과한다.
    await app.db.batch([
      { sql: "UPDATE accounts SET quota_bytes = 1 WHERE id = ?", params: [full.accountId] },
    ]);
    expect(ok.accountId).not.toBe(full.accountId);
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("한 수신자가 쿼터 초과여도 다른 수신자는 250을 받는다", async () => {
    const c = new Client(app.lmtpPort);
    await c.line(); // greeting
    c.send("LHLO test\r\n");
    await c.lhloDone();

    c.send("MAIL FROM:<sender@remote.test>\r\n");
    expect(await c.line()).toMatch(/^250/);
    c.send("RCPT TO:<ok@test.local>\r\n");
    expect(await c.line()).toMatch(/^250/);
    c.send("RCPT TO:<full@test.local>\r\n");
    expect(await c.line()).toMatch(/^250/);

    c.send("DATA\r\n");
    expect(await c.line()).toMatch(/^354/);
    c.send("Subject: mixed\r\nFrom: sender@remote.test\r\n\r\nbody text here\r\n.\r\n");

    // RCPT 순서대로 1줄씩 — 첫째는 성공, 둘째는 쿼터 초과.
    const first = await c.line();
    const second = await c.line();
    expect(first).toMatch(/^250/); // ok@ 는 정상 배달
    expect(second).toMatch(/^452/); // full@ 만 실패
    expect(second).toContain("4.2.2");

    c.send("QUIT\r\n");
    c.end();
  });

  test("정상 배달된 수신자의 INBOX에만 메시지가 들어간다", async () => {
    const { rows } = await app.db.query({
      sql: `SELECT a.email, a.message_count FROM accounts a WHERE a.email IN ('ok@test.local','full@test.local') ORDER BY a.email`,
    });
    const byEmail = new Map(rows.map((r) => [String(r.email), Number(r.message_count)]));
    expect(byEmail.get("full@test.local")).toBe(0); // 쿼터 초과 → 저장 안 됨
    expect(byEmail.get("ok@test.local")).toBeGreaterThan(0);
  });

  test("전원 정상이면 전원 250", async () => {
    const c = new Client(app.lmtpPort);
    await c.line();
    c.send("LHLO test\r\n");
    await c.lhloDone();
    c.send("MAIL FROM:<sender@remote.test>\r\n");
    await c.line();
    c.send("RCPT TO:<ok@test.local>\r\n");
    await c.line();
    c.send("DATA\r\n");
    await c.line();
    c.send("Subject: all-ok\r\nFrom: sender@remote.test\r\n\r\nbody\r\n.\r\n");
    expect(await c.line()).toMatch(/^250/);
    c.send("QUIT\r\n");
    c.end();
  });
});
