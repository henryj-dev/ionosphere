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

describe("SessionMeter — 진행 중 요약·명령 분포", () => {
  /**
   * ★살아 있는 세션이 주기마다 증분을 보고하는가(2026-10-01). 종료 요약만 있으면 며칠 열린 채
   * 초당 수십 번 왕복하는 세션은 끝날 때까지 journal에 없었다.
   */
  test("★활동이 있는 주기만 증분을 보고하고, 종료 요약에는 명령 분포가 들어간다", async () => {
    const progress: import("@ionosphere/core").SessionProgress[] = [];
    const summaries: SessionSummary[] = [];
    let meter: SessionMeter | null = null;
    let serverSock: Socket | null = null;
    server = createServer((sock) => {
      serverSock = sock;
      meter = new SessionMeter({
        surface: "imap",
        socket: sock,
        reporter: { report: (s) => void summaries.push(s), progress: (p) => void progress.push(p) },
        preauthDeadlineMs: 0,
        onPreauthDeadline: () => {},
        countCommands: true,
        progressIntervalMs: 60,
        progressMinCommands: 1,
        progressMinBytes: 1,
      });
      sock.on("data", () => {});
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", () => r()));
    const addr = server.address();
    const c = connect(typeof addr === "object" && addr ? addr.port : 0, "127.0.0.1");
    c.on("error", () => {});
    clients.push(c);
    await waitFor(() => meter ?? undefined);

    meter!.command("NOOP");
    meter!.command("NOOP");
    meter!.command("IDLE");
    c.write("x".repeat(10));
    await waitFor(() => progress[0]);
    expect(progress[0]!.commandsDelta).toBe(3);
    expect(progress[0]!.bytesInDelta).toBe(10);
    expect(progress[0]!.commandCounts).toEqual({ IDLE: 1, NOOP: 2 });

    // 조용한 주기 두어 번 — 문턱 아래라 줄이 늘지 않아야 한다(정상 세션이 줄을 쏟지 않게).
    await new Promise((r) => setTimeout(r, 200));
    expect(progress.length).toBe(1);

    meter!.command("NOOP");
    await waitFor(() => progress[1]);
    expect(progress[1]!.commandsDelta).toBe(1);
    expect(progress[1]!.commands).toBe(4);

    serverSock!.destroy();
    const s = await waitFor(() => summaries[0]);
    expect(s.commands).toBe(4);
    expect(s.commandCounts).toEqual({ IDLE: 1, NOOP: 3 });
    // 진행 줄은 닫힌 세션이 아니다 — 종료 요약은 정확히 한 번.
    await new Promise((r) => setTimeout(r, 150));
    expect(summaries.length).toBe(1);
  });

  test("모르는 명령 표본은 정제·절단하고 세션당 5개로 묶는다", async () => {
    const summaries: SessionSummary[] = [];
    let meter: SessionMeter | null = null;
    let serverSock: Socket | null = null;
    server = createServer((sock) => {
      serverSock = sock;
      meter = new SessionMeter({
        surface: "imap",
        socket: sock,
        reporter: { report: (s) => void summaries.push(s) },
        preauthDeadlineMs: 0,
        onPreauthDeadline: () => {},
        countCommands: true,
      });
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", () => r()));
    const addr = server.address();
    const c = connect(typeof addr === "object" && addr ? addr.port : 0, "127.0.0.1");
    c.on("error", () => {});
    clients.push(c);
    await waitFor(() => meter ?? undefined);
    meter!.unknownCommand("xlist\r\n<script>");
    meter!.unknownCommand("A".repeat(100));
    for (let i = 0; i < 10; i++) meter!.unknownCommand(`CMD${i}`);
    serverSock!.destroy();
    const s = await waitFor(() => summaries[0]);
    expect(s.unknownCommands?.length).toBe(5);
    // 개행·꺾쇠 같은 문자는 `?`로 — 로그 한 줄을 깨거나 주입하지 못하게.
    expect(s.unknownCommands?.[0]).toBe("XLIST???SCRIPT?");
    expect(s.unknownCommands?.[1]!.length).toBe(32);
  });
});
