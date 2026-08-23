/** ManageSieve e2e — 실 소켓으로 스크립트 관리 + 활성 스크립트의 배달 적용 확인. */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

let app: IonosphereApp;
let blobRoot: string;
let accountId: string;

const openClients: SieveClient[] = [];

/** 줄/리터럴 응답 클라이언트 — 완결 응답(OK/NO/BYE 라인)까지 수신. */
class SieveClient {
  private readonly socket: Socket;
  private buffer = "";
  private waiter: { resolve: (s: string) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> } | null = null;
  private pendingLiteral = 0;

  constructor(port: number) {
    this.socket = connect(port, "127.0.0.1");
    openClients.push(this);
    this.socket.on("data", (c) => {
      this.buffer += c.toString("latin1");
      this.tryComplete();
    });
  }

  /** 완결 판정: 리터럴 밖에서 OK/NO/BYE로 시작하는 줄이 나오면 응답 끝. */
  private tryComplete(): void {
    if (!this.waiter) return;
    const lines = this.buffer.split("\r\n");
    let i = 0;
    let literal = 0;
    while (i < lines.length - 1) {
      const line = lines[i]!;
      if (literal > 0) {
        literal -= Buffer.byteLength(line, "latin1") + 2;
        i++;
        continue;
      }
      const m = /\{(\d+)\+?\}$/.exec(line);
      if (m) {
        literal = Number(m[1]);
        i++;
        continue;
      }
      if (/^(OK|NO|BYE)\b/.test(line)) {
        const w = this.waiter;
        this.waiter = null;
        clearTimeout(w.timer);
        const consumed = lines.slice(0, i + 1).join("\r\n") + "\r\n";
        this.buffer = this.buffer.slice(consumed.length);
        w.resolve(consumed);
        return;
      }
      i++;
    }
  }

  read(): Promise<string> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("read timeout")), 4000);
      this.waiter = { resolve, reject, timer };
      this.tryComplete();
    });
  }
  send(s: string): void {
    this.socket.write(s);
  }
  close(): void {
    this.socket.destroy();
  }
}

function plainB64(user: string, pass: string): string {
  const NUL = "\u0000";
  return Buffer.from(`${NUL}${user}${NUL}${pass}`, "utf8").toString("base64");
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-msieve-"));
  app = new IonosphereApp({ hostname: "test.local", dbPath: ":memory:", blobRoot, smtpPort: 0, pop3Port: 0, manageSievePort: 0, resolver: offlineResolver() });
  await app.start();
  const created = await app.createUser("user@test.local", "pw");
  accountId = created.accountId;
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  for (const c of openClients) c.close();
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("ManageSieve 세션", () => {
  test("greeting → AUTHENTICATE → PUTSCRIPT → SETACTIVE → LISTSCRIPTS → GETSCRIPT", async () => {
    const c = new SieveClient(app.manageSievePort);
    const greeting = await c.read();
    expect(greeting).toContain('"IMPLEMENTATION"');
    expect(greeting).toContain('"SIEVE"');
    expect(greeting.trim().endsWith("OK") || greeting.includes("\r\nOK")).toBe(true);

    c.send(`AUTHENTICATE "PLAIN" "${plainB64("user@test.local", "pw")}"\r\n`);
    expect(await c.read()).toStartWith("OK");

    const script = 'require ["fileinto"];\r\nif header :contains "subject" "bill" { fileinto "Bills"; }\r\n';
    c.send(`PUTSCRIPT "main" {${Buffer.byteLength(script, "utf8")}+}\r\n${script}\r\n`);
    expect(await c.read()).toStartWith("OK");

    c.send(`SETACTIVE "main"\r\n`);
    expect(await c.read()).toStartWith("OK");

    c.send("LISTSCRIPTS\r\n");
    const list = await c.read();
    expect(list).toContain('"main" ACTIVE');

    c.send(`GETSCRIPT "main"\r\n`);
    const got = await c.read();
    expect(got).toContain("fileinto");
    expect(got).toMatch(/\{\d+\}/); // 리터럴로 반환

    c.send("LOGOUT\r\n");
    expect(await c.read()).toStartWith("OK");
    c.close();

    // 저장·활성 확인 — store 직접
    expect(await app.store.getActiveSieveScript(accountId)).toContain("fileinto");
  });

  test("잘못된 스크립트 PUTSCRIPT → NO(검증 실패)", async () => {
    const c = new SieveClient(app.manageSievePort);
    await c.read();
    c.send(`AUTHENTICATE "PLAIN" "${plainB64("user@test.local", "pw")}"\r\n`);
    await c.read();
    const bad = 'if header "subject" {\r\n'; // 미완결 문법
    c.send(`PUTSCRIPT "bad" {${Buffer.byteLength(bad, "utf8")}+}\r\n${bad}\r\n`);
    expect(await c.read()).toStartWith("NO");
    c.close();
  });

  test("인증 전 명령 거부, 활성 스크립트 삭제 거부", async () => {
    const c = new SieveClient(app.manageSievePort);
    await c.read();
    c.send("LISTSCRIPTS\r\n");
    expect(await c.read()).toContain("Authenticate first");
    c.send(`AUTHENTICATE "PLAIN" "${plainB64("user@test.local", "pw")}"\r\n`);
    await c.read();
    c.send(`DELETESCRIPT "main"\r\n`); // 이전 테스트에서 활성화됨
    expect(await c.read()).toStartWith("NO");
    c.close();
  });
});
