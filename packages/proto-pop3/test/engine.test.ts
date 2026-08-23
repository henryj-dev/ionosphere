import { describe, expect, test } from "@ionosphere/testkit";
import { Pop3Engine, type Pop3Action, type Pop3EngineMessage } from "../src/engine.ts";

// 이 파일은 **프로토콜 흐름**을 검사한다(TLS 정책이 아니라). RFC 8314 게이트가 기본 차단이라
// 평문 엔진으로는 인증 단계에 들어갈 수 없으므로 allowInsecureAuth로 명시 완화한다.
// TLS 정책 자체는 apps/server/test/pop3-secure.test.ts가 검증한다.

const enc = new TextEncoder();
const CRLF_BYTES = new Uint8Array([0x0d, 0x0a]);

function feed(engine: Pop3Engine, line: string): Pop3Action[] {
  return engine.feed(enc.encode(`${line}\r\n`));
}

/** USER/PASS/openMaildrop 전 과정을 성공 경로로 밀어넣는 테스트 헬퍼. */
function loginSuccess(engine: Pop3Engine, messages: Pop3EngineMessage[]): void {
  feed(engine, "USER alice");
  const passActions = feed(engine, "PASS secret");
  expect(passActions).toEqual([{ kind: "auth", user: "alice", pass: "secret" }]);
  const authActions = engine.authResult({ accountId: "acc-1" });
  expect(authActions).toEqual([{ kind: "openMaildrop" }]);
  const openActions = engine.openMaildropResult({ ok: true, messages });
  expect(openActions).toHaveLength(1);
  expect(openActions[0]?.kind).toBe("reply");
}

const fixtureMsgs: Pop3EngineMessage[] = [
  { uidl: "uid-1", sizeBytes: 100, ref: "m1" },
  { uidl: "uid-2", sizeBytes: 200, ref: "m2" },
  { uidl: "uid-3", sizeBytes: 300, ref: "m3" },
];

function concatAll(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

function stuffTestLine(line: Uint8Array): Uint8Array {
  if (line.length > 0 && line[0] === 0x2e) {
    const out = new Uint8Array(line.length + 1);
    out[0] = 0x2e;
    out.set(line, 1);
    return out;
  }
  return line;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return Buffer.from(a).equals(Buffer.from(b));
}

/** 헤더 3줄 + 빈줄 + 본문(dot-line/lone-dot/8비트 바이트 포함) 5줄짜리 원시 메시지 픽스처. */
function buildFixtureRaw(): { rawLines: Uint8Array[]; rawBytes: Uint8Array } {
  const rawLines = [
    enc.encode("From: a@example.com"),
    enc.encode("To: b@example.com"),
    enc.encode("Subject: test"),
    enc.encode(""),
    enc.encode("hello world"),
    enc.encode(".leading dot line"),
    enc.encode("."),
    new Uint8Array([0xff, 0xfe, 0x00, 0x41]),
    enc.encode("tail"),
  ];
  const rawBytes = concatAll(rawLines.map((l) => concatAll([l, CRLF_BYTES])));
  return { rawLines, rawBytes };
}

describe("Pop3Engine — 인사말/CAPA", () => {
  test("greeting", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    expect(engine.greeting()).toEqual([{ kind: "reply", text: "+OK pop.test POP3 server ready" }]);
  });

  test("CAPA — AUTHORIZATION/TRANSACTION 둘 다 동일 필수 세트 광고", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    const before = feed(engine, "CAPA");
    expect(before).toHaveLength(1);
    const textBefore = (before[0] as { kind: "reply"; text: string }).text;
    for (const cap of ["USER", "TOP", "UIDL", "RESP-CODES", "AUTH-RESP-CODE", "PIPELINING", "IMPLEMENTATION ionosphere"]) {
      expect(textBefore).toContain(cap);
    }
    expect(textBefore.startsWith("+OK")).toBe(true);
    // reply 액션 텍스트는 끝 CRLF 미포함 (어댑터 writeText가 추가) — 종결자는 "\r\n."
    expect(textBefore.endsWith("\r\n.")).toBe(true);

    loginSuccess(engine, [{ uidl: "u1", sizeBytes: 10, ref: "m1" }]);
    const after = feed(engine, "CAPA");
    const textAfter = (after[0] as { kind: "reply"; text: string }).text;
    expect(textAfter).toContain("UIDL");
  });
});

describe("Pop3Engine — 인증", () => {
  test("USER/PASS 성공 경로 → TRANSACTION 전이", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    loginSuccess(engine, fixtureMsgs);
    expect(feed(engine, "STAT")).toEqual([{ kind: "reply", text: "+OK 3 600" }]);
  });

  test("PASS 오류 → [AUTH], username 초기화되어 재시도 시 USER부터 필요", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    feed(engine, "USER alice");
    const passActions = feed(engine, "PASS wrong");
    expect(passActions).toEqual([{ kind: "auth", user: "alice", pass: "wrong" }]);
    const authActions = engine.authResult(null);
    expect(authActions).toEqual([{ kind: "reply", text: "-ERR [AUTH] authentication failed" }]);

    const retryPass = feed(engine, "PASS anything");
    expect(retryPass).toEqual([{ kind: "reply", text: "-ERR bad sequence of commands" }]);
  });

  test("openMaildrop inUse → [IN-USE], AUTHORIZATION 유지", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    feed(engine, "USER alice");
    feed(engine, "PASS secret");
    engine.authResult({ accountId: "acc-1" });
    const openActions = engine.openMaildropResult({ ok: false, inUse: true });
    expect(openActions).toEqual([{ kind: "reply", text: "-ERR [IN-USE] maildrop locked" }]);

    const statActions = feed(engine, "STAT");
    expect(statActions).toEqual([{ kind: "reply", text: "-ERR bad sequence of commands" }]);
  });

  test("APOP — 항상 -ERR (구현 금지 정책, PROTOCOLS.md §3)", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    const actions = feed(engine, "APOP alice c4c9334bac560ecc979e58001b3e22fb");
    expect(actions).toEqual([{ kind: "reply", text: "-ERR APOP not supported" }]);
  });
});

describe("Pop3Engine — TRANSACTION 조회 명령", () => {
  test("STAT/LIST/UIDL — 메시지 3건", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    loginSuccess(engine, fixtureMsgs);

    expect(feed(engine, "STAT")).toEqual([{ kind: "reply", text: "+OK 3 600" }]);

    expect(feed(engine, "LIST")).toEqual([
      { kind: "reply", text: "+OK 3 messages (600 octets)\r\n1 100\r\n2 200\r\n3 300\r\n." },
    ]);
    expect(feed(engine, "LIST 2")).toEqual([{ kind: "reply", text: "+OK 2 200" }]);

    expect(feed(engine, "UIDL")).toEqual([
      { kind: "reply", text: "+OK\r\n1 uid-1\r\n2 uid-2\r\n3 uid-3\r\n." },
    ]);
    expect(feed(engine, "UIDL 3")).toEqual([{ kind: "reply", text: "+OK 3 uid-3" }]);
  });

  test("out-of-range 메시지 번호 → -ERR", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    loginSuccess(engine, fixtureMsgs);
    expect(feed(engine, "RETR 99")).toEqual([{ kind: "reply", text: "-ERR no such message" }]);
    expect(feed(engine, "DELE 0")).toEqual([{ kind: "reply", text: "-ERR no such message" }]);
    expect(feed(engine, "LIST 4")).toEqual([{ kind: "reply", text: "-ERR no such message" }]);
  });
});

describe("Pop3Engine — RETR/TOP 바이트 정확성", () => {
  test("RETR — 바이트 완전 보존 + dot-stuffing (8비트 포함)", () => {
    const { rawLines, rawBytes } = buildFixtureRaw();
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    loginSuccess(engine, [{ uidl: "uid-1", sizeBytes: rawBytes.length, ref: "m1" }]);

    const retrActions = feed(engine, "RETR 1");
    expect(retrActions).toEqual([{ kind: "retrieve", msgnum: 1 }]);

    const resultActions = engine.retrieveResult({ ok: true, bytes: rawBytes });
    expect(resultActions).toHaveLength(1);
    const action = resultActions[0]!;
    expect(action.kind).toBe("replyBinary");
    const got = (action as { kind: "replyBinary"; bytes: Uint8Array }).bytes;

    const expectedBody = concatAll([
      ...rawLines.map((l) => concatAll([stuffTestLine(l), CRLF_BYTES])),
      enc.encode(".\r\n"),
    ]);
    const expected = concatAll([enc.encode(`+OK ${rawBytes.length} octets\r\n`), expectedBody]);
    expect(bytesEqual(got, expected)).toBe(true);
  });

  test("RETR — 삭제 마크된 메시지는 -ERR (조회 액션 방출 안 함)", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    loginSuccess(engine, fixtureMsgs);
    feed(engine, "DELE 2");
    expect(feed(engine, "RETR 2")).toEqual([{ kind: "reply", text: "-ERR message deleted" }]);
  });

  test("RETR — 백엔드 조회 실패 → [SYS/TEMP]", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    loginSuccess(engine, fixtureMsgs);
    feed(engine, "RETR 1");
    const result = engine.retrieveResult({ ok: false });
    expect(result).toEqual([{ kind: "reply", text: "-ERR [SYS/TEMP] failed to retrieve message" }]);
  });

  test("TOP — 헤더 전체 + 지정한 본문 줄 수만", () => {
    const { rawLines, rawBytes } = buildFixtureRaw();
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    loginSuccess(engine, [{ uidl: "uid-1", sizeBytes: rawBytes.length, ref: "m1" }]);

    const topActions = feed(engine, "TOP 1 2");
    expect(topActions).toEqual([{ kind: "retrieve", msgnum: 1 }]);

    const resultActions = engine.retrieveResult({ ok: true, bytes: rawBytes });
    const action = resultActions[0]!;
    expect(action.kind).toBe("replyBinary");
    const got = (action as { kind: "replyBinary"; bytes: Uint8Array }).bytes;

    // headers(3줄) + blank(1) + 본문 첫 2줄("hello world", ".leading dot line")
    const expectedLines = [rawLines[0]!, rawLines[1]!, rawLines[2]!, new Uint8Array(0), rawLines[4]!, rawLines[5]!];
    const expectedBody = concatAll([
      ...expectedLines.map((l) => concatAll([stuffTestLine(l), CRLF_BYTES])),
      enc.encode(".\r\n"),
    ]);
    const expected = concatAll([enc.encode("+OK top of message follows\r\n"), expectedBody]);
    expect(bytesEqual(got, expected)).toBe(true);
  });

  test("TOP n 0 — 본문 없이 헤더+빈줄만", () => {
    const { rawLines, rawBytes } = buildFixtureRaw();
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    loginSuccess(engine, [{ uidl: "uid-1", sizeBytes: rawBytes.length, ref: "m1" }]);
    feed(engine, "TOP 1 0");
    const resultActions = engine.retrieveResult({ ok: true, bytes: rawBytes });
    const got = (resultActions[0] as { kind: "replyBinary"; bytes: Uint8Array }).bytes;
    const expectedLines = [rawLines[0]!, rawLines[1]!, rawLines[2]!, new Uint8Array(0)];
    const expectedBody = concatAll([
      ...expectedLines.map((l) => concatAll([l, CRLF_BYTES])),
      enc.encode(".\r\n"),
    ]);
    const expected = concatAll([enc.encode("+OK top of message follows\r\n"), expectedBody]);
    expect(bytesEqual(got, expected)).toBe(true);
  });
});

describe("Pop3Engine — DELE/RSET/QUIT (UPDATE 커밋)", () => {
  test("DELE→STAT 제외→RSET 복원→DELE+QUIT 커밋(refs 확인)", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    loginSuccess(engine, fixtureMsgs);

    expect(feed(engine, "DELE 1")).toEqual([{ kind: "reply", text: "+OK message 1 deleted" }]);
    expect(feed(engine, "STAT")).toEqual([{ kind: "reply", text: "+OK 2 500" }]);

    expect(feed(engine, "RSET")).toEqual([
      { kind: "reply", text: "+OK maildrop has 3 messages (600 octets)" },
    ]);
    expect(feed(engine, "STAT")).toEqual([{ kind: "reply", text: "+OK 3 600" }]);

    feed(engine, "DELE 1");
    feed(engine, "DELE 3");

    const quitActions = feed(engine, "QUIT");
    expect(quitActions).toHaveLength(1);
    const commitAction = quitActions[0]!;
    expect(commitAction.kind).toBe("commitDeletions");
    const messages = (commitAction as { kind: "commitDeletions"; messages: readonly Pop3EngineMessage[] }).messages;
    expect(messages.map((m) => m.ref)).toEqual(["m1", "m3"]);

    const commitResultActions = engine.commitDeletionsResult(true);
    expect(commitResultActions).toEqual([
      { kind: "reply", text: "+OK pop.test POP3 server signing off" },
      { kind: "close" },
    ]);
  });

  test("QUIT — DELE 없으면 commitDeletions 메시지 목록이 비어있음", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    loginSuccess(engine, fixtureMsgs);
    const quitActions = feed(engine, "QUIT");
    expect(quitActions).toEqual([{ kind: "commitDeletions", messages: [] }]);
  });

  test("QUIT — AUTHORIZATION 상태에서는 커밋 없이 바로 종료", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    const quitActions = feed(engine, "QUIT");
    expect(quitActions).toEqual([
      { kind: "reply", text: "+OK pop.test POP3 server signing off" },
      { kind: "close" },
    ]);
  });

  test("commitDeletions 실패 → [SYS/TEMP], 그래도 연결은 종료", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    loginSuccess(engine, fixtureMsgs);
    feed(engine, "DELE 1");
    feed(engine, "QUIT");
    const commitResultActions = engine.commitDeletionsResult(false);
    expect(commitResultActions).toEqual([
      { kind: "reply", text: "-ERR [SYS/TEMP] failed to commit deletions" },
      { kind: "close" },
    ]);
  });
});

describe("Pop3Engine — 파이프라이닝", () => {
  test("비동기 대기 중 도착한 이후 명령은 continuation 이후에만 처리", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    feed(engine, "USER alice");
    // PASS + STAT을 한 청크로 투입 — PASS가 auth 대기를 걸어 STAT은 버퍼에 남는다.
    const actions = engine.feed(enc.encode("PASS secret\r\nSTAT\r\n"));
    expect(actions).toEqual([{ kind: "auth", user: "alice", pass: "secret" }]);

    const authActions = engine.authResult({ accountId: "acc-1" });
    expect(authActions).toEqual([{ kind: "openMaildrop" }]);

    const openActions = engine.openMaildropResult({ ok: true, messages: fixtureMsgs });
    expect(openActions).toEqual([
      { kind: "reply", text: "+OK maildrop has 3 messages (600 octets)" },
      { kind: "reply", text: "+OK 3 600" },
    ]);
  });
});

describe("Pop3Engine — 버퍼 상한 (감사 H-2 회귀)", () => {
  // 배경: feed()가 상한 없이 누적하고 drain()은 "\n"이 없으면 break만 했다. 미인증
  // (AUTHORIZATION) 상태에서 TCP 연결 하나로 성립하고, 계속 전송하므로 유휴 타임아웃도
  // 발동하지 않는다 — 300MB 투입 시 방출 액션 0, RSS 90MB → 1836MB(2026-07-30 실측).
  // 전 프로토콜이 단일 프로세스라 메일 서비스 전체가 멈춘다.

  /** 상한(4096)의 몇 배를 개행 없이 흘린다 — 실측 300MB의 축소판. */
  const FLOOD = "A".repeat(4096);

  test("개행 없는 스트림은 상한에서 끊긴다 — 미인증 상태에서", () => {
    const engine = new Pop3Engine({ hostname: "pop.test" });
    // 첫 청크는 상한 이내라 아직 아무 일도 없다(정상 명령이 쪼개져 도착한 경우와 구분).
    expect(engine.feed(enc.encode(FLOOD))).toEqual([]);
    // 두 번째 청크에서 상한 초과 → 즉시 에러 + close.
    expect(engine.feed(enc.encode(FLOOD))).toEqual([
      { kind: "reply", text: "-ERR line too long, closing connection" },
      { kind: "close" },
    ]);
    // 끊긴 뒤에는 아무리 더 밀어넣어도 방출도 누적도 없다(어댑터가 소켓을 닫기 전 잔여 바이트).
    for (let i = 0; i < 100; i++) expect(engine.feed(enc.encode(FLOOD))).toEqual([]);
  });

  test("백엔드 대기 중 파이프라인 누적에도 상한이 있다 (PASS로 여는 미인증 창)", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    feed(engine, "USER alice");
    expect(engine.feed(enc.encode("PASS secret\r\n"))).toEqual([
      { kind: "auth", user: "alice", pass: "secret" },
    ]);
    // auth 대기 중이라 drain()이 돌지 못한다 — 이 구간에는 라인 상한이 아니라
    // MAX_PIPELINE_PENDING_BYTES(1MB)가 걸린다.
    const chunk = enc.encode(`${"NOOP\r\n".repeat(1000)}`); // 6KB
    let closed: Pop3Action[] = [];
    for (let i = 0; i < 200 && closed.length === 0; i++) {
      const out = engine.feed(chunk);
      if (out.length > 0) closed = out;
    }
    expect(closed).toEqual([
      { kind: "reply", text: "-ERR line too long, closing connection" },
      { kind: "close" },
    ]);
  });

  test("상한 이하의 긴 명령과 쪼개져 도착하는 정상 명령은 그대로 동작한다", () => {
    const engine = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
    // 상한 직전 길이의 USER — 거부되면 안 된다(상한이 정상 트래픽을 자르지 않는지).
    const longName = "u".repeat(4000);
    expect(feed(engine, `USER ${longName}`)).toEqual([{ kind: "reply", text: "+OK" }]);
    // 한 바이트씩 쪼개진 명령도 완결되면 정상 처리된다.
    const actions: Pop3Action[] = [];
    for (const ch of "CAPA\r\n") actions.push(...engine.feed(enc.encode(ch)));
    expect(actions).toHaveLength(1);
    expect(actions[0]?.kind).toBe("reply");
  });
});
