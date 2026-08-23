/** LmtpServer 실소켓 왕복 — LHLO→MAIL→RCPT×2→DATA→수신자별 응답 2줄. */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { LmtpServer, type LmtpBackend } from "../src/server.ts";

let servers: LmtpServer[] = [];
afterEach(async () => {
  await Promise.all(servers.map((s) => s.close()));
  servers = [];
});

class Client {
  private readonly sock: Socket;
  private buf = "";
  private readonly lines: string[] = []; // 미소비 완성 줄 큐(waiter 등록 전 도착분 보존)
  private waiters: ((line: string) => void)[] = [];
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
    const queued = this.lines.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    return new Promise((r) => this.waiters.push(r));
  }
  send(s: string): void {
    this.sock.write(s);
  }
  end(): void {
    this.sock.end();
  }
  /** 서버가 연결을 끊을 때까지 — 유휴 타임아웃이 실제로 소켓을 닫는지 확인용. */
  closed(): Promise<void> {
    return new Promise((r) => this.sock.once("close", () => r()));
  }
}

function backend(overrides: Partial<LmtpBackend> = {}): LmtpBackend {
  return {
    verifyRecipient: async (addr) => (addr.startsWith("bad") ? { ok: false, code: 550, enhanced: "5.1.1", message: "no such user" } : { ok: true }),
    deliverLmtp: async (env) =>
      env.rcptTo.map((rcpt) => (rcpt.startsWith("full") ? { rcpt, ok: false, code: 452, enhanced: "4.2.2", message: "mailbox full" } : { rcpt, ok: true, code: 250, enhanced: "2.1.5", message: "delivered" })),
    ...overrides,
  };
}

async function start(be: LmtpBackend, extra: Partial<ConstructorParameters<typeof LmtpServer>[0]> = {}): Promise<number> {
  const s = new LmtpServer({ hostname: "lmtp.test", backend: be, ...extra });
  servers.push(s);
  return s.listen(0);
}

describe("LmtpServer 왕복", () => {
  test("수신자별 응답: a 성공 / full@ 실패 → DATA 후 2줄", async () => {
    const port = await start(backend());
    const c = new Client(port);
    expect(await c.line()).toContain("220 ");
    c.send("LHLO client\r\n");
    // 멀티라인 250 소비
    let l = await c.line();
    while (l.startsWith("250-")) l = await c.line();
    expect(l).toMatch(/^250 /);
    c.send("MAIL FROM:<s@x.test>\r\n");
    expect(await c.line()).toContain("250");
    c.send("RCPT TO:<a@x.test>\r\n");
    expect(await c.line()).toContain("250");
    c.send("RCPT TO:<full@x.test>\r\n");
    expect(await c.line()).toContain("250");
    c.send("DATA\r\n");
    expect(await c.line()).toContain("354");
    c.send("Subject: t\r\n\r\nhi\r\n.\r\n");
    // 수신자별 응답 2줄(RCPT 순서)
    expect(await c.line()).toBe("250 2.1.5 delivered");
    expect(await c.line()).toBe("452 4.2.2 mailbox full");
    c.send("QUIT\r\n");
    expect(await c.line()).toContain("221");
    c.end();
  });

  test("RCPT 검증 실패 → 그 수신자만 550", async () => {
    const port = await start(backend());
    const c = new Client(port);
    await c.line();
    c.send("LHLO client\r\n");
    let l = await c.line();
    while (l.startsWith("250-")) l = await c.line();
    c.send("MAIL FROM:<s@x.test>\r\n");
    await c.line();
    c.send("RCPT TO:<bad@x.test>\r\n");
    expect(await c.line()).toContain("550");
    c.end();
  });
});

/**
 * 유휴 타임아웃(감사 L-13). LMTP만 6개 프로토콜 중 유일하게 이게 없었다 —
 * AUTH도 TLS도 없는 표면이라 켜는 순간 무인증 slowloris가 성립하고,
 * 전 프로토콜이 단일 프로세스라 fd가 마르면 25·587·993이 함께 죽는다.
 *
 * `socket.setTimeout()`만 부르고 `timeout` 리스너를 빠뜨리면 node는 이벤트만 내고
 * **소켓을 닫지 않는다**. 그래서 속성이 아니라 "실제로 끊기는가"를 본다.
 */
describe("LmtpServer 유휴 타임아웃", () => {
  test("아무것도 보내지 않으면 421과 함께 끊긴다", async () => {
    const port = await start(backend(), { idleTimeoutMs: 150 });
    const c = new Client(port);
    expect(await c.line()).toContain("220 ");
    // 이후 아무 명령도 보내지 않는다 — slowloris가 붙들고 있는 모양 그대로.
    expect(await c.line()).toContain("421 4.4.2");
    await c.closed();
  });

  test("명령을 계속 보내는 정상 세션은 끊기지 않는다", async () => {
    const port = await start(backend(), { idleTimeoutMs: 300 });
    const c = new Client(port);
    await c.line();
    for (let i = 0; i < 4; i++) {
      c.send("NOOP\r\n");
      expect(await c.line()).toContain("250");
      await new Promise((r) => setTimeout(r, 100)); // 타임아웃보다 짧은 간격 = 활동 중
    }
    c.end();
  });
});
