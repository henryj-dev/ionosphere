/** LMTP 조립 e2e — IonosphereApp LMTP 리스너로 배달 → INBOX 반영 + 수신자별 응답. */
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

describe("LMTP e2e", () => {
  let app: IonosphereApp;
  let blobRoot: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-lmtp-"));
    app = new IonosphereApp({ hostname: "test.local", dbPath: ":memory:", blobRoot, smtpPort: 0, pop3Port: 0, lmtpPort: 0, resolver: offlineResolver() });
    await app.start();
    await app.createUser("rcpt@test.local", "pw");
  }, E2E_HOOK_TIMEOUT_MS);
  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("LMTP 배달 → 수신자별 250 + INBOX에 저장, 없는 수신자는 550", async () => {
    const c = new Client(app.lmtpPort);
    expect(await c.line()).toContain("220 ");
    c.send("LHLO relay.test\r\n");
    await c.lhloDone();
    c.send("MAIL FROM:<sender@remote.test>\r\n");
    expect(await c.line()).toContain("250");
    c.send("RCPT TO:<rcpt@test.local>\r\n");
    expect(await c.line()).toContain("250");
    c.send("RCPT TO:<ghost@test.local>\r\n"); // 없는 사용자 → RCPT에서 550
    expect(await c.line()).toContain("550");
    c.send("DATA\r\n");
    expect(await c.line()).toContain("354");
    c.send("Subject: lmtp hi\r\n\r\nbody\r\n.\r\n");
    // 수락된 수신자(rcpt)만 응답 1줄
    expect(await c.line()).toContain("250");
    c.send("QUIT\r\n");
    await c.line();
    c.end();

    // 스토어 반영 확인
    const acc = await app.store.getAccountByEmail("rcpt@test.local");
    const { rows } = await app.db.query({ sql: "SELECT message_count FROM accounts WHERE id = ?", params: [acc!.id] });
    expect(Number(rows[0]!.message_count)).toBe(1);
  });
});
