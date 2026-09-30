/**
 * SessionMeter — 실제 TCP 소켓으로 본다(바이트 계수·close 이벤트가 소켓 구현에 달려 있다).
 *
 * ★반쪽 닫기 테스트가 요점이다. 어댑터 테스트의 node 클라이언트는 FIN을 받으면 스스로 닫아서
 * "마감이 `end()`만 하면 FIN을 무시하는 상대는 끝까지 붙어 있다"는 결함을 가렸다(코드 검수 재현).
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { createServer, connect, type Server, type Socket } from "node:net";
import { SESSION_CLOSE_REASON, SessionMeter, type SessionSummary } from "@ionosphere/core";

let server: Server | null = null;
let clients: Socket[] = [];
afterEach(async () => {
  for (const c of clients) c.destroy();
  clients = [];
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = null;
});

/** 서버 쪽 소켓마다 meter를 붙이고, 클라이언트는 **FIN을 무시**한다(allowHalfOpen). */
async function setup(
  opts: { preauthDeadlineMs: number; closeGraceMs: number },
  onMeter: (m: SessionMeter, s: Socket) => void = () => {},
): Promise<{ summaries: SessionSummary[] }> {
  const summaries: SessionSummary[] = [];
  server = createServer((sock) => {
    const meter = new SessionMeter({
      surface: "imap",
      socket: sock,
      reporter: { report: (s) => void summaries.push(s) },
      preauthDeadlineMs: opts.preauthDeadlineMs,
      closeGraceMs: opts.closeGraceMs,
      onPreauthDeadline: () => sock.end(),
    });
    onMeter(meter, sock);
  });
  await new Promise<void>((r) => server!.listen(0, "127.0.0.1", () => r()));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  const c = connect({ port, host: "127.0.0.1", allowHalfOpen: true });
  c.on("error", () => {});
  c.on("end", () => {
    /* FIN을 받아도 닫지 않는다 — 점유를 흉내 낸다 */
  });
  clients.push(c);
  return { summaries };
}

async function waitFor<T>(get: () => T | undefined, ms = 3000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = get();
    if (v !== undefined) return v;
    if (Date.now() > until) throw new Error("timeout");
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("SessionMeter", () => {
  test("★FIN을 무시하는 상대도 유예 뒤 강제로 끊긴다", async () => {
    const { summaries } = await setup({ preauthDeadlineMs: 100, closeGraceMs: 100 });
    const s = await waitFor(() => summaries[0]);
    expect(s.reason).toBe(SESSION_CLOSE_REASON.preauth);
    expect(s.durationMs).toBeGreaterThanOrEqual(150);
  });

  test("★마감으로 끊긴 연결에 유휴 타이머가 돌아도 사유는 preauth로 남는다", async () => {
    let meter: SessionMeter | null = null;
    const { summaries } = await setup({ preauthDeadlineMs: 50, closeGraceMs: 200 }, (m) => (meter = m));
    await new Promise((r) => setTimeout(r, 100));
    meter!.idleTimedOut();
    const s = await waitFor(() => summaries[0]);
    expect(s.reason).toBe(SESSION_CLOSE_REASON.preauth);
  });

  test("마감 뒤 도착한 인증 성공은 무시한다", async () => {
    let meter: SessionMeter | null = null;
    const { summaries } = await setup({ preauthDeadlineMs: 50, closeGraceMs: 100 }, (m) => (meter = m));
    await new Promise((r) => setTimeout(r, 80));
    expect(meter!.deadlinePassed).toBe(true);
    meter!.authenticated("acct-late");
    const s = await waitFor(() => summaries[0]);
    expect(s.accountId).toBeUndefined();
  });

  test("인증 후 유휴 타임아웃은 idle로 남고, 유예 뒤 끊긴다", async () => {
    const { summaries } = await setup({ preauthDeadlineMs: 5000, closeGraceMs: 50 }, (m, sock) => {
      m.authenticated("acct-1");
      setTimeout(() => {
        m.idleTimedOut();
        sock.end();
      }, 30);
    });
    const s = await waitFor(() => summaries[0]);
    expect(s.reason).toBe(SESSION_CLOSE_REASON.idle);
    expect(s.accountId).toBe("acct-1");
  });
});
