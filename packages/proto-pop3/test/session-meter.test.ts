/**
 * POP3 인증 전 마감 + 세션 종료 요약 — 어댑터 수준(IMAP `session-meter.test.ts`와 같은 이유).
 *
 * 2026-09-30 조사에서 995에 **연결당 ~350 B만 주고받고 붙어 있는 연결 61개**가 있었다.
 * 인증 전에도 10분 유휴 타임아웃뿐이라 그 사이 한 줄씩만 보내면 무기한 점유가 가능했다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { SESSION_CLOSE_REASON, type SessionSummary } from "@ionosphere/core";
import { InProcessMaildropLock, Pop3Server, type Pop3Backend } from "../src/server.ts";

let servers: Pop3Server[] = [];
let sockets: Socket[] = [];
afterEach(async () => {
  for (const s of sockets) s.destroy();
  sockets = [];
  await Promise.all(servers.map((s) => s.close()));
  servers = [];
});

function backend(): Pop3Backend {
  const lock = new InProcessMaildropLock();
  const body = new TextEncoder().encode("Subject: A\r\n\r\nbody\r\n");
  return {
    authenticate: async (u, p) => (u === "alice" && p === "secret" ? { accountId: "acc-1" } : null),
    openMaildrop: async (id) =>
      (await lock.acquire(id, "o")) ? { ok: true, messages: [{ uidl: "u1", sizeBytes: body.length, ref: "m" }] } : { ok: false, inUse: true },
    retrieve: async () => body,
    commitDeletions: async () => {},
    releaseMaildrop: async (id) => void (await lock.release(id, "o")),
  };
}

async function start(preauthDeadlineMs: number): Promise<{ port: number; summaries: SessionSummary[] }> {
  const summaries: SessionSummary[] = [];
  const server = new Pop3Server({
    hostname: "pop3.test",
    backend: backend(),
    allowInsecureAuth: true,
    sessions: { report: (s) => void summaries.push(s) },
    preauthDeadlineMs,
  });
  servers.push(server);
  return { port: await server.listen(0, "127.0.0.1"), summaries };
}

function client(port: number): { send: (s: string) => void; closed: Promise<void>; waitFor: (n: string) => Promise<void> } {
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
  return { send: (s) => sock.write(s), closed, waitFor };
}

async function waitSummary(summaries: SessionSummary[]): Promise<SessionSummary> {
  const until = Date.now() + 4000;
  while (summaries.length === 0) {
    if (Date.now() > until) throw new Error("세션 요약이 오지 않았다");
    await new Promise((r) => setTimeout(r, 10));
  }
  return summaries[0]!;
}

describe("POP3 인증 전 마감·세션 요약", () => {
  test("★인증하지 않으면 명령을 보내도 마감에 끊긴다", async () => {
    const { port, summaries } = await start(300);
    const c = client(port);
    await c.waitFor("+OK");
    const noop = setInterval(() => c.send("CAPA\r\n"), 50);
    try {
      await c.closed;
    } finally {
      clearInterval(noop);
    }
    const s = await waitSummary(summaries);
    expect(s.reason).toBe(SESSION_CLOSE_REASON.preauth);
    expect(s.accountId).toBeUndefined();
  });

  test("★인증 뒤 세션은 계정·요청 수·바이트로 요약된다 — maildrop 해제 뒤에도 계정이 남는다", async () => {
    const { port, summaries } = await start(300);
    const c = client(port);
    await c.waitFor("+OK");
    c.send("USER alice\r\n");
    await c.waitFor("+OK");
    c.send("PASS secret\r\n");
    await c.waitFor("maildrop");
    // 마감(300ms)을 넘겨도 인증했으므로 끊기지 않아야 한다.
    await new Promise((r) => setTimeout(r, 450));
    c.send("RETR 1\r\n");
    await c.waitFor("body");
    c.send("QUIT\r\n");
    await c.closed;
    const s = await waitSummary(summaries);
    expect(s.surface).toBe("pop3");
    expect(s.user).toBe("alice");
    expect(s.accountId).toBe("acc-1");
    // openMaildrop + retrieve + commitDeletions
    expect(s.requests).toBe(3);
    expect(s.bytesOut).toBeGreaterThan(0);
    expect(s.reason).toBe(SESSION_CLOSE_REASON.closed);
  });
});
