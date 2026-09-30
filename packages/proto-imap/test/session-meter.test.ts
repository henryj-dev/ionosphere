/**
 * 인증 전 마감 + 세션 종료 요약 — 어댑터 수준.
 *
 * ★이 파일이 있는 이유(2026-09-30 사서함 호스트 조사). 993에 인증하지 않은 연결이 오래 붙어
 * 있었고(인증 전에도 30분 유휴 타임아웃뿐이었다), 하루 1 GB의 IMAP 트래픽이 어느 계정·어느
 * 주소의 것인지 journal로는 되짚을 수 없었다. 여기서 보는 것은 두 가지다:
 *  1. 인증하지 않으면 활동이 있어도 마감에 끊긴다(NOOP으로 연장되지 않는다).
 *  2. 세션이 닫히면 계정·주소·요청 수·바이트가 담긴 요약이 **한 번** 나온다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { SESSION_CLOSE_REASON, type SessionSummary } from "@ionosphere/core";
import { ImapServer, type ImapBackend } from "../src/server.ts";

let servers: ImapServer[] = [];
let sockets: Socket[] = [];
afterEach(async () => {
  for (const s of sockets) s.destroy();
  sockets = [];
  await Promise.all(servers.map((s) => s.close()));
  servers = [];
});

const backend: ImapBackend = {
  authenticate: async (user, pass) => (user === "u@imap.test" && pass === "pw" ? { accountId: "acct-1" } : null),
  // 요청 수만 세면 되므로 어떤 요청이든 NO로 답한다.
  request: async () => ({ kind: "no", message: "stub" }),
};

async function start(preauthDeadlineMs: number): Promise<{ port: number; summaries: SessionSummary[] }> {
  const summaries: SessionSummary[] = [];
  const server = new ImapServer({
    hostname: "imap.test",
    backend,
    allowInsecureAuth: true,
    sessions: { report: (s) => void summaries.push(s) },
    preauthDeadlineMs,
  });
  servers.push(server);
  return { port: await server.listen(0, "127.0.0.1"), summaries };
}

/** 한 연결의 전체 수신을 모은다. `closed`는 서버가 끊을 때 풀린다. */
function client(port: number): { send: (s: string) => void; text: () => string; closed: Promise<void>; waitFor: (needle: string) => Promise<void> } {
  const sock = connect(port, "127.0.0.1");
  sockets.push(sock);
  let buf = "";
  sock.on("data", (c: Buffer) => (buf += c.toString("latin1")));
  sock.on("error", () => {});
  const closed = new Promise<void>((resolve) => sock.once("close", () => resolve()));
  const waitFor = async (needle: string): Promise<void> => {
    const until = Date.now() + 4000;
    while (!buf.includes(needle)) {
      if (Date.now() > until) throw new Error(`timeout waiting for ${needle}; got ${JSON.stringify(buf)}`);
      await new Promise((r) => setTimeout(r, 10));
    }
  };
  return { send: (s) => sock.write(s), text: () => buf, closed, waitFor };
}

async function waitSummary(summaries: SessionSummary[]): Promise<SessionSummary> {
  const until = Date.now() + 4000;
  while (summaries.length === 0) {
    if (Date.now() > until) throw new Error("세션 요약이 오지 않았다");
    await new Promise((r) => setTimeout(r, 10));
  }
  return summaries[0]!;
}

describe("IMAP 인증 전 마감", () => {
  test("★인증하지 않으면 NOOP을 보내도 마감에 끊긴다", async () => {
    const { port, summaries } = await start(300);
    const c = client(port);
    await c.waitFor("* OK");
    // 유휴 타이머라면 이 NOOP들이 연결을 연장했을 것이다 — 절대 마감이라 연장되지 않아야 한다.
    const noop = setInterval(() => c.send("n NOOP\r\n"), 50);
    try {
      await c.closed;
    } finally {
      clearInterval(noop);
    }
    expect(c.text()).toContain("* BYE login timeout");
    const s = await waitSummary(summaries);
    expect(s.reason).toBe(SESSION_CLOSE_REASON.preauth);
    expect(s.accountId).toBeUndefined();
  });

  test("인증하면 마감이 풀린다", async () => {
    const { port } = await start(300);
    const c = client(port);
    await c.waitFor("* OK");
    c.send("a1 LOGIN u@imap.test pw\r\n");
    await c.waitFor("a1 OK");
    await new Promise((r) => setTimeout(r, 500));
    expect(c.text()).not.toContain("BYE");
  });
});

describe("IMAP 세션 종료 요약", () => {
  test("★계정·주소·요청 수·바이트가 한 번 보고된다", async () => {
    const { port, summaries } = await start(60_000);
    const c = client(port);
    await c.waitFor("* OK");
    c.send("a0 LOGIN u@imap.test wrong\r\n");
    await c.waitFor("a0 NO");
    c.send("a1 LOGIN u@imap.test pw\r\n");
    await c.waitFor("a1 OK");
    c.send('a2 LIST "" "*"\r\n');
    await c.waitFor("a2 ");
    c.send("a3 LOGOUT\r\n");
    await c.closed;
    const s = await waitSummary(summaries);
    expect(s.surface).toBe("imap");
    expect(s.ip).toBe("127.0.0.1");
    expect(s.user).toBe("u@imap.test");
    expect(s.accountId).toBe("acct-1");
    expect(s.authFailures).toBe(1);
    expect(s.requests).toBeGreaterThan(0);
    expect(s.bytesIn).toBeGreaterThan(0);
    expect(s.bytesOut).toBeGreaterThan(0);
    expect(s.reason).toBe(SESSION_CLOSE_REASON.closed);
    // 한 번만 — 닫힘 경로가 여럿(end·destroy·error)이어도 중복 보고하지 않는다.
    await new Promise((r) => setTimeout(r, 50));
    expect(summaries.length).toBe(1);
  });
});
