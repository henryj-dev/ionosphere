/**
 * BAD 원문 표본 — 어댑터 수준(command-sample.ts·server.ts).
 *
 * ★이 파일이 있는 이유(2026-10-05 v2026.10.05 배포 뒤 실측). UID FETCH BAD가 5분마다 2건씩 꾸준히
 * 쌓였는데 지표는 "UID FETCH가 BAD"까지만 말했다. 무엇을 물었기에 BAD인지 알려면 원문이 필요하다.
 * 여기서 보는 것:
 *  1. BAD를 받으면 명령의 모양(atom 그대로, 섹션 괄호 원문대로)이 journal 경고로 남는다.
 *  2. 자격증명·개인정보는 남지 않는다 — 인자는 허용 목록의 명령만 남기고(모르는 명령·LOGIN·ACL·SEARCH는
 *     이름만), 그 안에서도 quoted·literal은 내용을 지운다.
 *  3. 세션당·리스너당 상한이 걸린다 — BAD 루프가 journal 증폭기가 되지 않는다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import type { SessionSummary } from "@ionosphere/core";
import { BadSampleBudget, ImapServer, type ImapBackend } from "../src/server.ts";

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
  request: async () => ({ kind: "no", message: "stub" }),
};

type Warn = { msg: string; fields: Record<string, unknown> };

async function start(opts: { badSamplesPerWindow?: number; logger?: boolean; backend?: ImapBackend } = {}): Promise<{ port: number; warns: Warn[]; summaries: SessionSummary[] }> {
  const warns: Warn[] = [];
  const summaries: SessionSummary[] = [];
  const server = new ImapServer({
    sessions: { report: (summary) => void summaries.push(summary) },
    hostname: "imap.test",
    backend: opts.backend ?? backend,
    allowInsecureAuth: true,
    ...(opts.logger === false ? {} : { logger: { warn: (msg: string, fields?: Record<string, unknown>) => void warns.push({ msg, fields: fields ?? {} }) } }),
    ...(opts.badSamplesPerWindow !== undefined ? { badSamplesPerWindow: opts.badSamplesPerWindow } : {}),
  });
  servers.push(server);
  return { port: await server.listen(0, "127.0.0.1"), warns, summaries };
}

/** 줄을 하나씩 보내고 그 태그의 완료 응답을 기다린다. */
async function session(port: number, lines: string[]): Promise<string> {
  const sock = connect(port, "127.0.0.1");
  sockets.push(sock);
  let buf = "";
  sock.on("data", (c: Buffer) => (buf += c.toString("latin1")));
  sock.on("error", () => {});
  const waitFor = async (re: RegExp): Promise<void> => {
    const until = Date.now() + 4000;
    while (!re.test(buf)) {
      if (Date.now() > until) throw new Error(`timeout waiting for ${re}; got ${JSON.stringify(buf)}`);
      await new Promise((r) => setTimeout(r, 5));
    }
  };
  await waitFor(/^\* OK/m);
  for (const line of lines) {
    sock.write(`${line}\r\n`);
    const tag = line.split(" ")[0]!;
    await waitFor(tag === "*" ? /^\* BAD /m : new RegExp(`^${tag} (OK|NO|BAD)`, "m"));
  }
  sock.destroy();
  return buf;
}

const samples = (warns: Warn[]): Warn[] => warns.filter((w) => w.msg === "imap BAD 표본");

describe("IMAP BAD 원문 표본", () => {
  test("★BAD를 받은 명령의 모양이 남는다 — FETCH 섹션 괄호도 원문대로", async () => {
    const { port, warns } = await start();
    const out = await session(port, ["a1 LOGIN u@imap.test pw", "a2 UID FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO)] BOGUS)"]);
    expect(out).toContain("a2 BAD ");
    expect(samples(warns)).toEqual([
      {
        msg: "imap BAD 표본",
        fields: {
          command: "UID FETCH",
          sample: "UID FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO)] BOGUS)",
          reply: "command requires a selected mailbox",
          ip: "127.0.0.1",
          accountId: "acct-1",
        },
      },
    ]);
  });

  test("★LOGIN·AUTHENTICATE는 인자를 남기지 않는다 — 비밀번호는 atom으로도 온다", async () => {
    const { port, warns } = await start();
    await session(port, ["p1 LOGIN hunter2-user", "p2 AUTHENTICATE PLAIN AGh1bnRlcjIAcHc= extra"]);
    const got = samples(warns);
    expect(got.map((w) => w.fields.sample)).toEqual(["LOGIN [인자 생략]", "AUTHENTICATE [인자 생략]"]);
    const text = JSON.stringify(got);
    expect(text).not.toContain("hunter2");
    expect(text).not.toContain("AGh1bnRlcjIAcHc");
  });

  test("★quoted·literal은 내용을 지우고 모양만 남긴다", async () => {
    const { port, warns } = await start();
    await session(port, ["a1 LOGIN u@imap.test pw", 'a2 STATUS "private words" (BOGUS)', "a3 STATUS {5+}\r\nworld (BOGUS)"]);
    expect(samples(warns).map((w) => w.fields.sample)).toEqual(['STATUS "…" (BOGUS)', "STATUS {5} (BOGUS)"]);
    expect(JSON.stringify(warns)).not.toContain("private");
    expect(JSON.stringify(warns)).not.toContain("world");
  });

  /**
   * ★리뷰가 재현한 누출들. 1차: 제외 목록이었을 때 `UID LOGIN user secret`이 비밀번호를 남겼다.
   * 2차: 모르는 명령의 **이름 자리**로도 샜다 — `UID "secret"`은 quoted 내용이 하위 이름으로 복원됐고,
   * 태그 없이 친 `user private-password`는 비밀번호가 명령 이름이 된다. 이제 모르는 명령은 "unknown"뿐이다.
   */
  test("★모르는 명령은 이름도 남기지 않는다 — 이름 자리에도 비밀이 올 수 있다", async () => {
    const { port, warns, summaries } = await start();
    await session(port, [
      "a1 LOGIN u@imap.test pw",
      "a2 UID LOGIN someone hunter2",
      'a3 UID "quoted-secret"',
      "user private-password",
    ]);
    await session(port, ["a1 LOGIN u@imap.test pw", "b1 UID {14+}\r\nliteral-secret", "b2 URLFETCH imap://x;URLAUTH=tok3n"]);
    expect(samples(warns).map((w) => w.fields.sample)).toEqual(Array(5).fill("unknown [인자 생략]"));
    // 세션 요약의 모르는 명령 표본(unknownCommands)도 quoted·literal을 되살리지 않는다.
    await new Promise((r) => setTimeout(r, 50));
    const text = JSON.stringify([warns, summaries]);
    for (const secret of ["hunter2", "someone", "quoted-secret", "QUOTED-SECRET", "literal-secret", "LITERAL-SECRET", "tok3n", "TOK3N"]) {
      expect(text).not.toContain(secret);
    }
  });

  /** 허용된 명령 이름이어도 확장 인자에 토큰이 실릴 수 있다 — APPEND CATENATE의 URLAUTH(2차 리뷰 재현). */
  test("★인자가 자유로운 명령(APPEND·STORE)은 이름만 남긴다", async () => {
    const { port, warns } = await start();
    await session(port, [
      "a1 LOGIN u@imap.test pw",
      "a2 APPEND INBOX CATENATE (URL imap://u@imap.test/INBOX/;UID=1;URLAUTH=submit+u:internal:s3cret)",
      "a3 STORE 1 +FLAGS (diagnosis-private)",
    ]);
    expect(samples(warns).map((w) => w.fields.sample)).toEqual(["APPEND [인자 생략]", "STORE [인자 생략]"]);
    const text = JSON.stringify(warns);
    expect(text).not.toContain("s3cret");
    expect(text).not.toContain("diagnosis-private");
  });

  test("★SASL 연속 줄의 비밀은 남지 않는다", async () => {
    const { port, warns } = await start();
    const sock = connect(port, "127.0.0.1");
    sockets.push(sock);
    let buf = "";
    sock.on("data", (c: Buffer) => (buf += c.toString("latin1")));
    const until = Date.now() + 4000;
    const wait = async (re: RegExp): Promise<void> => {
      while (!re.test(buf)) {
        if (Date.now() > until) throw new Error(`timeout ${re}: ${JSON.stringify(buf)}`);
        await new Promise((r) => setTimeout(r, 5));
      }
    };
    await wait(/^\* OK/m);
    sock.write("s1 AUTHENTICATE PLAIN\r\n");
    await wait(/^\+/m);
    sock.write("!!not-base64-sasl-secret!!\r\n");
    await wait(/^s1 BAD/m);
    expect(samples(warns).map((w) => w.fields.sample)).toEqual(["AUTHENTICATE [인자 생략]"]);
    expect(JSON.stringify(warns)).not.toContain("sasl-secret");
  });

  test("★계정 식별자(ACL)·검색어(SEARCH)를 싣는 명령도 이름만 남긴다", async () => {
    const { port, warns } = await start();
    await session(port, ["a1 LOGIN u@imap.test pw", "a2 SETACL INBOX friend@imap.test", "a3 SEARCH FROM boss@imap.test SUBJECT payroll"]);
    expect(samples(warns).map((w) => w.fields.sample)).toEqual(["SETACL [인자 생략]", "SEARCH [인자 생략]"]);
    const text = JSON.stringify(warns);
    for (const pii of ["friend@", "boss@", "payroll"]) expect(text).not.toContain(pii);
  });

  test("긴 인자는 자른다 — 거대한 시퀀스 집합이 journal 줄을 키우지 못한다", async () => {
    const { port, warns } = await start();
    const seq = Array.from({ length: 2000 }, (_, i) => i + 1).join(",");
    await session(port, ["a1 LOGIN u@imap.test pw", `a2 UID FETCH ${seq} (FLAGS)`]);
    const sample = String(samples(warns)[0]?.fields.sample);
    expect(sample.startsWith("UID FETCH 1,2,3,")).toBe(true);
    expect(sample.length).toBe(200);
    expect(sample.endsWith("…")).toBe(true);
  });

  test("깊은 중첩 목록도 같은 길이 예산을 나눠 쓴다", async () => {
    const { port, warns } = await start();
    const nested = `${"(".repeat(300)}FLAGS${")".repeat(300)}`;
    await session(port, ["a1 LOGIN u@imap.test pw", `a2 FETCH 1 ${nested}`]);
    const got = samples(warns);
    expect(got).toHaveLength(1);
    const sample = String(got[0]!.fields.sample);
    expect(sample.startsWith("FETCH 1 ((((")).toBe(true);
    expect(sample.length).toBeLessThanOrEqual(200);
  });

  test("파싱도 못 한 줄은 응답 문구만 남긴다", async () => {
    const { port, warns } = await start();
    await session(port, ["* (((("]);
    expect(samples(warns)).toEqual([{ msg: "imap BAD 표본", fields: { command: "unparsed", reply: "unterminated parenthesized list", ip: "127.0.0.1" } }]);
  });

  test("★세션당 3줄까지만 — 같은 클라이언트가 BAD를 반복해도 journal이 불지 않는다", async () => {
    const { port, warns } = await start();
    await session(port, ["a1 LOGIN u@imap.test pw", ...[2, 3, 4, 5, 6].map((n) => `a${n} STATUS INBOX (BOGUS${n})`)]);
    expect(samples(warns).map((w) => w.fields.sample)).toEqual(["STATUS INBOX (BOGUS2)", "STATUS INBOX (BOGUS3)", "STATUS INBOX (BOGUS4)"]);
  });

  test("★리스너당 상한 — 버린 수는 다음 창의 첫 줄에 suppressed로 싣는다", async () => {
    const { port, warns } = await start({ badSamplesPerWindow: 2 });
    await session(port, ["a1 STATUS INBOX (X1)", "a2 STATUS INBOX (X2)"]);
    await session(port, ["b1 STATUS INBOX (Y1)", "b2 STATUS INBOX (Y2)"]);
    // 창 안에서는 2줄만 — 두 번째 세션의 BAD 2건은 버려진다.
    expect(samples(warns).map((w) => w.fields.sample)).toEqual(["STATUS INBOX (X1)", "STATUS INBOX (X2)"]);
    expect(samples(warns).some((w) => "suppressed" in w.fields)).toBe(false);
  });

  test("OK·NO는 표본을 남기지 않는다", async () => {
    const { port, warns } = await start();
    const out = await session(port, ["a1 LOGIN u@imap.test pw", "a2 NOOP", "a3 SELECT INBOX"]);
    expect(out).toContain("a3 NO");
    expect(samples(warns)).toEqual([]);
  });

  /**
   * logger를 넘기면서 백엔드 예외 경고도 처음 켜진다. 장애 중 요청을 반복하는 세션이 줄을 쏟지 않게
   * 상한을 두고, 외부 응답 본문이 섞일 수 있는 예외 문구는 자른다(1차 리뷰).
   */
  test("백엔드 예외 경고도 상한과 길이 제한이 걸린다", async () => {
    const failing: ImapBackend = { ...backend, request: async () => Promise.reject(new Error(`boom ${"x".repeat(500)}`)) };
    const { port, warns } = await start({ backend: failing });
    await session(port, ["a1 LOGIN u@imap.test pw", ...Array.from({ length: 35 }, (_, i) => `s${i} SELECT INBOX`)]);
    const errors = warns.filter((w) => w.msg === "imap backend error");
    expect(errors).toHaveLength(30);
    expect(String(errors[0]!.fields.error).length).toBe(200);
  });

  test("로거가 없어도 BAD 응답은 그대로 나간다", async () => {
    const { port } = await start({ logger: false });
    expect(await session(port, ["a1 FROB"])).toContain("a1 BAD ");
  });
});

describe("BAD 표본 리스너당 예산", () => {
  test("★창 안에서 상한을 넘긴 줄은 버리고, 다음 창의 첫 줄이 버린 수를 알린다", () => {
    const budget = new BadSampleBudget(2);
    const t0 = 1_000_000;
    expect(budget.take(t0)).toBe(0);
    expect(budget.take(t0 + 1)).toBe(0);
    expect(budget.take(t0 + 2)).toBe(null);
    expect(budget.take(t0 + 3)).toBe(null);
    // 10분 창이 지나면 다시 쓸 수 있고, 첫 줄이 직전에 버린 2건을 싣는다 — 조용히 사라지면 "멎었다"로 읽힌다.
    expect(budget.take(t0 + 10 * 60 * 1000)).toBe(2);
    expect(budget.take(t0 + 10 * 60 * 1000 + 1)).toBe(0);
  });
});
