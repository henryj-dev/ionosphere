/** ImapEngine — 선인증 명령 표면 + SASL PLAIN + 파이프라이닝 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction } from "../src/engine.ts";

const enc = new TextEncoder();

function engine(opts: { secure?: boolean; allowInsecureAuth?: boolean } = { allowInsecureAuth: true }): ImapEngine {
  return new ImapEngine({ hostname: "imap.test", ...opts });
}

function feed(e: ImapEngine, text: string): ImapAction[] {
  return e.feed(enc.encode(text));
}

function replies(actions: ImapAction[]): string[] {
  return actions.filter((a): a is { kind: "reply"; text: string } => a.kind === "reply").map((a) => a.text);
}

function plainB64(user: string, pass: string): string {
  return Buffer.from(`\u0000${user}\u0000${pass}`, "utf8").toString("base64");
}

describe("ImapEngine — 인사말/기본 명령", () => {
  test("greeting에 CAPABILITY 코드 포함", () => {
    const texts = replies(engine().greeting());
    expect(texts[0]).toContain("* OK [CAPABILITY IMAP4rev1");
    expect(texts[0]).toContain("AUTH=PLAIN");
  });

  test("평문 + allowInsecureAuth 없음 → LOGINDISABLED 광고, LOGIN/AUTH 거부", () => {
    const e = engine({});
    expect(replies(e.greeting())[0]).toContain("LOGINDISABLED");
    expect(replies(feed(e, "a1 LOGIN u p\r\n"))[0]).toContain("a1 NO [PRIVACYREQUIRED]");
    expect(replies(feed(e, "a2 AUTHENTICATE PLAIN\r\n"))[0]).toContain("a2 NO [PRIVACYREQUIRED]");
  });

  test("CAPABILITY / NOOP / 미지원 명령 / LOGOUT", () => {
    const e = engine();
    const caps = replies(feed(e, "a1 CAPABILITY\r\n"));
    // capability 목록은 증분마다 자라므로 핵심만 검사 (정확일치는 유지비만 큼)
    // rev2를 광고하면서도 rev1을 **먼저** 낸다 — 둘 다 지원하는 서버는 rev1로 시작하고
    // 클라이언트의 `ENABLE IMAP4rev2`로 전환한다(RFC 9051 §6.3.1).
    expect(caps[0]).toStartWith("* CAPABILITY IMAP4rev1 IMAP4rev2 LITERAL- SASL-IR");
    expect(caps[0]).toContain("AUTH=PLAIN");
    expect(caps[0]).toContain("AUTH=XOAUTH2");
    expect(caps[0]).toContain("AUTH=OAUTHBEARER");
    expect(caps[1]).toBe("a1 OK CAPABILITY completed");

    expect(replies(feed(e, "a2 NOOP\r\n"))).toEqual(["a2 OK NOOP completed"]);
    expect(replies(feed(e, "a3 FROBNICATE\r\n"))).toEqual(["a3 BAD unknown command"]);

    const out = feed(e, "a4 LOGOUT\r\n");
    expect(replies(out)).toEqual(["* BYE imap.test logging out", "a4 OK LOGOUT completed"]);
    expect(out[out.length - 1]).toEqual({ kind: "close" });
    expect(feed(e, "a5 NOOP\r\n")).toEqual([]); // 종료 후 무시
  });

  test("ID — untagged ID + OK", () => {
    const out = replies(feed(engine(), 'a1 ID ("name" "tb")\r\n'));
    expect(out[0]).toContain("* ID (");
    expect(out[1]).toBe("a1 OK ID completed");
  });
});

describe("ImapEngine — LOGIN", () => {
  test("성공: auth 액션 → authResult → OK[CAPABILITY], 상태 전이", () => {
    const e = engine();
    const out = feed(e, "a1 LOGIN alice secret\r\n");
    expect(out).toEqual([{ kind: "auth", user: "alice", pass: "secret" }]);
    const done = replies(e.authResult({ accountId: "acc1" }));
    expect(done[0]).toContain("a1 OK [CAPABILITY");
    // 인증 후 CAPABILITY에는 AUTH=/LOGINDISABLED 없음
    expect(done[0]).not.toContain("AUTH=PLAIN");
    expect(replies(feed(e, "a2 LOGIN x y\r\n"))[0]).toContain("a2 BAD");
  });

  test("실패: NO [AUTHENTICATIONFAILED], 재시도 가능", () => {
    const e = engine();
    feed(e, "a1 LOGIN alice wrong\r\n");
    expect(replies(e.authResult(null))[0]).toBe("a1 NO [AUTHENTICATIONFAILED] authentication failed");
    expect(feed(e, "a2 LOGIN alice right\r\n")).toEqual([{ kind: "auth", user: "alice", pass: "right" }]);
  });

  test("sync 리터럴 자격증명 — continuation 후 조립", () => {
    const e = engine();
    const first = feed(e, "a1 LOGIN {5}\r\n");
    expect(replies(first)).toEqual(["+ OK"]);
    const second = feed(e, "al ce {2}\r\n"); // 공백 포함 사용자명(리터럴이라 유효)
    expect(replies(second)).toEqual(["+ OK"]);
    const third = feed(e, "pw\r\n");
    expect(third).toEqual([{ kind: "auth", user: "al ce", pass: "pw" }]);
  });

  test("인자 부족/과다 → BAD", () => {
    expect(replies(feed(engine(), "a1 LOGIN onlyuser\r\n"))[0]).toContain("a1 BAD");
    expect(replies(feed(engine(), "a1 LOGIN a b c\r\n"))[0]).toContain("a1 BAD");
  });
});

describe("ImapEngine — AUTHENTICATE PLAIN", () => {
  test("SASL-IR: initial response 동봉", () => {
    const e = engine();
    const out = feed(e, `a1 AUTHENTICATE PLAIN ${plainB64("bob", "pw123")}\r\n`);
    expect(out).toEqual([{ kind: "auth", user: "bob", pass: "pw123" }]);
    expect(replies(e.authResult({ accountId: "x" }))[0]).toContain("a1 OK");
  });

  test("IR 없이: '+ ' continuation → 데이터 라인", () => {
    const e = engine();
    expect(replies(feed(e, "a1 AUTHENTICATE PLAIN\r\n"))).toEqual(["+ "]);
    const out = feed(e, `${plainB64("bob", "pw")}\r\n`);
    expect(out).toEqual([{ kind: "auth", user: "bob", pass: "pw" }]);
  });

  test("'*' 취소 → BAD", () => {
    const e = engine();
    feed(e, "a1 AUTHENTICATE PLAIN\r\n");
    expect(replies(feed(e, "*\r\n"))[0]).toBe("a1 BAD authentication cancelled");
    // 취소 후 새 명령 정상 처리
    expect(replies(feed(e, "a2 NOOP\r\n"))).toEqual(["a2 OK NOOP completed"]);
  });

  test("불량 base64 / authzid 사용 / 빈 authcid → 거부", () => {
    const e1 = engine();
    expect(replies(feed(e1, "a1 AUTHENTICATE PLAIN !!!!\r\n"))[0]).toContain("a1 BAD invalid base64");

    const e2 = engine();
    const noNul = Buffer.from("no-separators", "utf8").toString("base64");
    expect(replies(feed(e2, `a1 AUTHENTICATE PLAIN ${noNul}\r\n`))[0]).toContain("a1 NO [AUTHENTICATIONFAILED]");

    const e3 = engine();
    const emptyUser = Buffer.from("\u0000\u0000pw", "utf8").toString("base64");
    expect(replies(feed(e3, `a1 AUTHENTICATE PLAIN ${emptyUser}\r\n`))[0]).toContain("a1 NO [AUTHENTICATIONFAILED]");
  });

  test("미지원 메커니즘 → NO [CANNOT]", () => {
    expect(replies(feed(engine(), "a1 AUTHENTICATE SCRAM-SHA-256\r\n"))[0]).toContain("a1 NO [CANNOT]");
  });
});

describe("ImapEngine — AUTHENTICATE XOAUTH2/OAUTHBEARER", () => {
  const A = "\u0001";
  const xoauth2 = (user: string, token: string) => Buffer.from(`user=${user}${A}auth=Bearer ${token}${A}${A}`, "utf8").toString("base64");
  const oauthbearer = (user: string, token: string) => Buffer.from(`n,a=${user},${A}auth=Bearer ${token}${A}${A}`, "utf8").toString("base64");

  test("XOAUTH2 SASL-IR: 토큰이 pass로 흘러 auth 액션", () => {
    const e = engine();
    const out = feed(e, `a1 AUTHENTICATE XOAUTH2 ${xoauth2("bob@x.test", "tok-1")}\r\n`);
    expect(out).toEqual([{ kind: "auth", user: "bob@x.test", pass: "tok-1" }]);
    expect(replies(e.authResult({ accountId: "acc" }))[0]).toContain("a1 OK");
  });

  test("OAUTHBEARER continuation: '+ ' 후 데이터 라인", () => {
    const e = engine();
    expect(replies(feed(e, "a1 AUTHENTICATE OAUTHBEARER\r\n"))).toEqual(["+ "]);
    const out = feed(e, `${oauthbearer("carol@x.test", "tok-2")}\r\n`);
    expect(out).toEqual([{ kind: "auth", user: "carol@x.test", pass: "tok-2" }]);
  });

  test("잘못된 토큰은 백엔드가 거부(authResult null → NO)", () => {
    const e = engine();
    feed(e, `a1 AUTHENTICATE XOAUTH2 ${xoauth2("bob@x.test", "bad")}\r\n`);
    expect(replies(e.authResult(null))[0]).toContain("a1 NO [AUTHENTICATIONFAILED]");
  });

  test("형식 오류(Bearer 없음) → NO [AUTHENTICATIONFAILED]", () => {
    const e = engine();
    const bad = Buffer.from(`user=bob${A}${A}`, "utf8").toString("base64");
    expect(replies(feed(e, `a1 AUTHENTICATE XOAUTH2 ${bad}\r\n`))[0]).toContain("a1 NO [AUTHENTICATIONFAILED]");
  });

  test("CAPABILITY가 AUTH=XOAUTH2/OAUTHBEARER 광고", () => {
    expect(replies(feed(engine(), "a1 CAPABILITY\r\n"))[0]).toContain("AUTH=XOAUTH2");
  });
});

describe("ImapEngine — 파이프라이닝/ENABLE", () => {
  test("auth 대기 중 도착한 명령은 버퍼링 후 순서대로 처리", () => {
    const e = engine();
    const out = feed(e, "a1 LOGIN alice pw\r\na2 NOOP\r\na3 CAPABILITY\r\n");
    expect(out).toEqual([{ kind: "auth", user: "alice", pass: "pw" }]); // NOOP/CAPABILITY는 아직
    const done = replies(e.authResult({ accountId: "acc" }));
    expect(done[0]).toContain("a1 OK");
    expect(done[1]).toBe("a2 OK NOOP completed");
    expect(done[2]).toContain("* CAPABILITY");
    expect(done[3]).toBe("a3 OK CAPABILITY completed");
  });

  test("ENABLE — 인증 전 BAD, 인증 후 아는 확장만 ENABLED(미지 확장 무시)", () => {
    const e = engine();
    expect(replies(feed(e, "a1 ENABLE CONDSTORE\r\n"))[0]).toContain("a1 BAD");
    feed(e, "a2 LOGIN u p\r\n");
    e.authResult({ accountId: "acc" });
    const out = replies(feed(e, "a3 ENABLE CONDSTORE UTF8=ACCEPT\r\n"));
    expect(out[0]).toBe("* ENABLED CONDSTORE"); // UTF8=ACCEPT는 미등록 — 생략
    expect(out[1]).toBe("a3 OK ENABLE completed");
  });
});

describe("ImapEngine — 인증 전 리터럴/큐 상한 (감사 M-7 회귀)", () => {
  // 배경: 리더는 인증 상태를 모르므로, 어차피 거절할 LOGIN 한 줄을 위해 미인증 연결마다
  // 리터럴을 25MB까지 버퍼링했다. IMAP 유휴 타임아웃 30분 × 1024 연결이면 이론상 25GB.
  // 25MB가 필요한 명령은 APPEND뿐이고 APPEND는 인증을 요구한다 — 그래서 상한을 상태로 나눈다.

  /** LOGIN → auth 액션 → 성공 결과까지 밀어넣는다. */
  function login(e: ImapEngine): void {
    const out = feed(e, "a1 LOGIN alice secret\r\n");
    expect(out).toEqual([{ kind: "auth", user: "alice", pass: "secret" }]);
    expect(replies(e.authResult({ accountId: "acc-1" }))[0]).toContain("a1 OK");
  }

  test("미인증 상태의 거대 리터럴 선언은 거절된다 — 데이터를 받기 전에", () => {
    const e = engine();
    // sync 리터럴이라 continuation(+ OK)을 보내지 않으면 클라이언트는 데이터를 보내지 않는다.
    expect(replies(feed(e, "a1 LOGIN {100000}\r\n"))).toEqual(["* BAD literal too large"]);
    // 세션은 살아 있고 다음 명령은 정상 처리된다(끊지 않고 거절만).
    expect(replies(feed(e, "a2 NOOP\r\n"))).toEqual(["a2 OK NOOP completed"]);
  });

  test("미인증이어도 정상 크기 리터럴(LOGIN 인자)은 통과한다", () => {
    const e = engine();
    expect(replies(feed(e, "a1 LOGIN {5}\r\n"))).toEqual(["+ OK"]);
    const out = feed(e, "alice secret\r\n");
    expect(out).toEqual([{ kind: "auth", user: "alice", pass: "secret" }]);
  });

  test("인증 후에는 APPEND용 리터럴 상한이 복원된다", () => {
    const e = engine();
    login(e);
    // 인증 전이라면 "literal too large"였을 크기 — 이제 continuation이 나와야 APPEND가 산다.
    expect(replies(feed(e, "a2 APPEND INBOX {100000}\r\n"))).toEqual(["+ OK"]);
  });

  test("백엔드 대기 중 파이프라인 큐에도 바이트 상한이 있다", () => {
    const e = engine();
    // LOGIN이 auth 대기를 걸어 이후 라인은 전부 queued로 쌓인다.
    expect(feed(e, "a1 LOGIN alice secret\r\n")).toEqual([
      { kind: "auth", user: "alice", pass: "secret" },
    ]);
    const chunk = "a NOOP\r\n".repeat(10000); // 80KB
    let closed: ImapAction[] = [];
    for (let i = 0; i < 40 && closed.length === 0; i++) {
      const out = feed(e, chunk);
      if (out.length > 0) closed = out;
    }
    expect(replies(closed)).toEqual(["* BYE too much pipelined data"]);
    expect(closed[closed.length - 1]).toEqual({ kind: "close" });
  });

  test("정상 파이프라이닝은 상한에 걸리지 않는다", () => {
    const e = engine();
    expect(feed(e, "a1 LOGIN alice secret\r\na2 NOOP\r\na3 NOOP\r\n")).toEqual([
      { kind: "auth", user: "alice", pass: "secret" },
    ]);
    const resumed = replies(e.authResult({ accountId: "acc-1" }));
    expect(resumed[0]).toContain("a1 OK");
    expect(resumed.slice(1)).toEqual(["a2 OK NOOP completed", "a3 OK NOOP completed"]);
  });
});
