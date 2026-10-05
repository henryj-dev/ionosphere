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

describe("IMAP 명령 계측", () => {
  /**
   * ★백엔드를 부르지 않는 명령도 세어지는가(2026-10-01). 감사 이벤트는 백엔드 요청에만 남아,
   * 초당 수십 번 도는 NOOP·IDLE·BAD 루프가 지표에 흔적을 남기지 않았다.
   * result=bad가 command와 함께 나와야 "어떤 명령이 BAD로 도는가"에 답한다.
   */
  test("★명령마다 결과가 보고되고, 종료 요약에 분포·모르는 명령 표본이 남는다", async () => {
    const results: string[] = [];
    const summaries: SessionSummary[] = [];
    const server = new ImapServer({
      hostname: "imap.test",
      backend,
      allowInsecureAuth: true,
      sessions: { report: (s) => void summaries.push(s) },
      onCommandResult: (command, result) => void results.push(`${command}:${result}`),
    });
    servers.push(server);
    const port = await server.listen(0, "127.0.0.1");
    const c = client(port);
    await c.waitFor("* OK");
    c.send("a1 NOOP\r\n");
    await c.waitFor("a1 OK");
    c.send("a2 XYZZY\r\n");
    await c.waitFor("a2 BAD");
    c.send("a3 LOGIN u@imap.test pw\r\n");
    await c.waitFor("a3 OK");
    c.send("a4 NOOP\r\n");
    await c.waitFor("a4 OK");
    c.send("\r\n"); // 태그조차 없는 줄 — 파싱 실패
    await c.waitFor("* BAD");
    c.send("a5 LOGOUT\r\n");
    await c.closed;

    expect(results).toEqual(["NOOP:ok", "unknown:bad", "LOGIN:ok", "NOOP:ok", "unparsed:bad", "LOGOUT:ok"]);
    const s = await waitSummary(summaries);
    expect(s.commands).toBe(6);
    expect(s.commandCounts).toEqual({ LOGIN: 1, LOGOUT: 1, NOOP: 2, unknown: 1, unparsed: 1 });
    expect(s.unknownCommands).toEqual(["XYZZY"]);
    // 백엔드를 부르지 않은 명령은 requests에 안 들어간다 — 둘의 차이가 곧 이번 사고의 신호였다.
    expect(s.requests).toBe(0);
  });

  test("진행 중 세션은 주기마다 한 줄을 남긴다(닫히기 전에 보인다)", async () => {
    const progress: number[] = [];
    const server = new ImapServer({
      hostname: "imap.test",
      backend,
      allowInsecureAuth: true,
      sessions: { report: () => {}, progress: (p) => void progress.push(p.commandsDelta ?? -1) },
      sessionProgressIntervalMs: 80,
    });
    servers.push(server);
    const port = await server.listen(0, "127.0.0.1");
    const c = client(port);
    await c.waitFor("* OK");
    // 기본 문턱(주기당 명령 30개)을 넘겨야 줄이 남는다 — 정상 세션은 여기 못 미친다.
    for (let i = 0; i < 40; i++) c.send(`n${i} NOOP\r\n`);
    await c.waitFor("n39 OK");
    const until = Date.now() + 2000;
    while (progress.length === 0 && Date.now() < until) await new Promise((r) => setTimeout(r, 10));
    expect(progress[0]).toBe(40);
  });

  /** 결과를 모으는 서버 하나를 띄우고 로그인까지 한 클라이언트를 돌려준다. */
  async function loggedIn(): Promise<{ results: string[]; summaries: SessionSummary[]; c: ReturnType<typeof client> }> {
    const results: string[] = [];
    const summaries: SessionSummary[] = [];
    const server = new ImapServer({
      hostname: "imap.test",
      backend,
      allowInsecureAuth: true,
      sessions: { report: (s) => void summaries.push(s) },
      onCommandResult: (command, result) => void results.push(`${command}:${result}`),
    });
    servers.push(server);
    const c = client(await server.listen(0, "127.0.0.1"));
    await c.waitFor("* OK");
    c.send("a0 LOGIN u@imap.test pw\r\n");
    await c.waitFor("a0 OK");
    results.length = 0;
    return { results, summaries, c };
  }

  /**
   * ★같은 태그를 재사용한 파이프라인(RFC는 SHOULD NOT일 뿐, 실제로 나온다). 태그당 하나만 들던
   * 첫 판은 앞 명령의 응답이 나가기 전에 뒤 명령이 덮어써 LIST 결과가 NOOP으로 집계됐다(검수 재현).
   */
  test("★같은 태그를 재사용해도 결과가 명령 순서대로 붙는다", async () => {
    const { results, c } = await loggedIn();
    c.send('t LIST "" "*"\r\nt NOOP\r\n');
    const until = Date.now() + 2000;
    while (results.length < 2 && Date.now() < until) await new Promise((r) => setTimeout(r, 10));
    expect(results).toEqual(["LIST:no", "NOOP:ok"]);
  });

  test("★대량 파이프라인에서도 결과가 빠지지 않는다(300개)", async () => {
    const { results, c } = await loggedIn();
    c.send(Array.from({ length: 300 }, (_, i) => `n${i} NOOP\r\n`).join(""));
    await c.waitFor("n299 OK");
    expect(results.length).toBe(300);
  });

  /**
   * 태그 `*`·`%`는 RFC상 불가지만 **거부하지 않고 센다**. 거부는 새 BAD 경로라 "BAD를 받으면 재시도하는
   * 루프" 가설과 같은 방향으로 작동할 수 있어, 쓰는 클라이언트가 있는지 먼저 본다(stardust 지적).
   */
  test("★`*`·`%` 태그는 거부하지 않고 wildcardTags로 센다", async () => {
    const { results, summaries, c } = await loggedIn();
    c.send("* NOOP\r\n");
    await c.waitFor("* OK NOOP completed");
    c.send("%1 NOOP\r\n");
    await c.waitFor("%1 OK");
    c.send("z LOGOUT\r\n");
    await c.closed;
    // `*` 태그의 완료는 untagged 줄과 구별되지 않아 결과를 추적하지 않는다. `%`는 추적한다.
    expect(results).toEqual(["NOOP:ok", "LOGOUT:ok"]);
    const s = await waitSummary(summaries);
    expect(s.wildcardTags).toBe(2);
    expect(s.commandCounts?.NOOP).toBe(2);
    expect(s.reads).toBeGreaterThan(0);
  });

  test("모르는 UID 하위 명령은 UID로 묶고, 알려진 확장 이름만 그대로 남긴다", async () => {
    const { summaries, c } = await loggedIn();
    c.send("u1 UID BOGUS 1\r\n");
    await c.waitFor("u1 BAD");
    c.send("u2 XLIST \"\" *\r\n");
    await c.waitFor("u2 BAD");
    c.send("z LOGOUT\r\n");
    await c.closed;
    const s = await waitSummary(summaries);
    expect(s.unknownCommands).toEqual(["UID?OTHER", "XLIST"]);
  });

  /**
   * ★2026-10-05 BAD 표본 PR 3차 리뷰: 태그 없이 친 `user private-password`는 둘째 단어가 명령 이름
   * 자리에 와서 `PRIVATE-PASSWORD`로 요약에 남았다. `UID "secret"`은 quoted 내용이 하위 이름으로
   * 되살아났다. 이제 알려진 확장 이름이 아니면 OTHER뿐이다.
   */
  test("★모르는 명령 이름 자리의 비밀은 요약에 남지 않는다", async () => {
    const { summaries, c } = await loggedIn();
    c.send("user private-password\r\n");
    await c.waitFor("user BAD");
    c.send('u1 UID "quoted-secret"\r\n');
    await c.waitFor("u1 BAD");
    c.send("u2 UID atom-secret 1\r\n");
    await c.waitFor("u2 BAD");
    c.send("z LOGOUT\r\n");
    await c.closed;
    const s = await waitSummary(summaries);
    expect(s.unknownCommands).toEqual(["OTHER", "UID?OTHER"]);
    const text = JSON.stringify(s).toUpperCase();
    for (const secret of ["PRIVATE-PASSWORD", "QUOTED-SECRET", "ATOM-SECRET"]) expect(text).not.toContain(secret);
  });
});
