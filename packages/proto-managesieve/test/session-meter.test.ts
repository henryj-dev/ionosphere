/**
 * ManageSieve(4190) — IP 프리픽스 상한과 인증 전 마감.
 *
 * 4190만 `peerLimit`을 받지 않았다(2026-09-30 확인). 같은 주소가 다른 포트에서 상한에 닿아도
 * 여기로는 무제한 붙을 수 있었고, 인증 전 30분 유휴 타임아웃뿐이라 오래 점유할 수 있었다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { PeerConnectionLimiter, SESSION_CLOSE_REASON, type SessionSummary } from "@ionosphere/core";
import { ManageSieveServer, type ManageSieveBackend } from "../src/server.ts";

const denyBackend: ManageSieveBackend = {
  authenticate: () => Promise.resolve(null),
  putScript: () => Promise.resolve({ ok: false, message: "no" }),
  checkScript: () => ({ ok: false, message: "no" }),
  listScripts: () => Promise.resolve([]),
  getScript: () => Promise.resolve(null),
  deleteScript: () => Promise.resolve({ ok: false, message: "no" }),
  setActive: () => Promise.resolve({ ok: false, message: "no" }),
  renameScript: () => Promise.resolve({ ok: false, message: "no" }),
};

let server: ManageSieveServer | null = null;
let sockets: Socket[] = [];
afterEach(async () => {
  for (const s of sockets) s.destroy();
  sockets = [];
  await server?.close();
  server = null;
});

function open(port: number): { sock: Socket; closed: Promise<void>; text: () => string } {
  const sock = connect(port, "127.0.0.1");
  sockets.push(sock);
  let buf = "";
  sock.on("data", (c: Buffer) => (buf += c.toString("latin1")));
  sock.on("error", () => {});
  return { sock, closed: new Promise<void>((r) => sock.once("close", () => r())), text: () => buf };
}

describe("ManageSieve 연결 제한", () => {
  test("★IP 프리픽스 상한이 4190에도 걸린다", async () => {
    let rejected = 0;
    server = new ManageSieveServer({
      hostname: "sieve.test",
      backend: denyBackend,
      peerLimit: new PeerConnectionLimiter({ limit: 1, onReject: () => rejected++ }),
    });
    const port = await server.listen(0, "127.0.0.1");
    const first = open(port);
    await new Promise<void>((r) => first.sock.once("data", () => r()));
    const second = open(port);
    await second.closed;
    expect(rejected).toBe(1);
    expect(first.sock.destroyed).toBe(false);
  });

  test("★인증하지 않으면 마감에 끊기고 요약이 남는다", async () => {
    const summaries: SessionSummary[] = [];
    server = new ManageSieveServer({
      hostname: "sieve.test",
      backend: denyBackend,
      sessions: { report: (s) => void summaries.push(s) },
      preauthDeadlineMs: 200,
    });
    const port = await server.listen(0, "127.0.0.1");
    const c = open(port);
    await c.closed;
    expect(c.text()).toContain('BYE "login timeout"');
    const until = Date.now() + 2000;
    while (summaries.length === 0 && Date.now() < until) await new Promise((r) => setTimeout(r, 10));
    expect(summaries[0]?.reason).toBe(SESSION_CLOSE_REASON.preauth);
    expect(summaries[0]?.surface).toBe("managesieve");
  });
});
