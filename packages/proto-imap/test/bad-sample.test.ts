/**
 * BAD 원문 표본 — 어댑터 수준(command-sample.ts·server.ts).
 *
 * ★이 파일이 있는 이유(2026-10-05 v2026.10.05 배포 뒤 실측). UID FETCH BAD가 5분마다 2건씩 꾸준히
 * 쌓였는데 지표는 "UID FETCH가 BAD"까지만 말했다. 무엇을 물었기에 BAD인지 알려면 원문이 필요하다.
 * 여기서 보는 것:
 *  1. BAD를 받으면 명령의 모양(atom 그대로, 섹션 괄호 원문대로)이 journal 경고로 남는다.
 *  2. 자격증명은 남지 않는다 — LOGIN·AUTHENTICATE는 인자를 통째로 빼고, quoted·literal은 내용을 지운다.
 *  3. 세션당·서버 전체 상한이 걸린다 — BAD 루프가 journal 증폭기가 되지 않는다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
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

async function start(opts: { badSamplesPerWindow?: number; logger?: boolean } = {}): Promise<{ port: number; warns: Warn[] }> {
  const warns: Warn[] = [];
  const server = new ImapServer({
    hostname: "imap.test",
    backend,
    allowInsecureAuth: true,
    ...(opts.logger === false ? {} : { logger: { warn: (msg: string, fields?: Record<string, unknown>) => void warns.push({ msg, fields: fields ?? {} }) } }),
    ...(opts.badSamplesPerWindow !== undefined ? { badSamplesPerWindow: opts.badSamplesPerWindow } : {}),
  });
  servers.push(server);
  return { port: await server.listen(0, "127.0.0.1"), warns };
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
    await session(port, ["a1 LOGIN u@imap.test pw", 'a2 FROB "private words" {5+}\r\nworld']);
    expect(samples(warns).map((w) => w.fields.sample)).toEqual(['FROB "…" {5}']);
    expect(JSON.stringify(warns)).not.toContain("private");
    expect(JSON.stringify(warns)).not.toContain("world");
  });

  test("파싱도 못 한 줄은 응답 문구만 남긴다", async () => {
    const { port, warns } = await start();
    await session(port, ["* (((("]);
    expect(samples(warns)).toEqual([{ msg: "imap BAD 표본", fields: { command: "unparsed", reply: "unterminated parenthesized list", ip: "127.0.0.1" } }]);
  });

  test("★세션당 3줄까지만 — 같은 클라이언트가 BAD를 반복해도 journal이 불지 않는다", async () => {
    const { port, warns } = await start();
    await session(port, ["a1 LOGIN u@imap.test pw", ...[2, 3, 4, 5, 6].map((n) => `a${n} FROB ${n}`)]);
    expect(samples(warns).map((w) => w.fields.sample)).toEqual(["FROB 2", "FROB 3", "FROB 4"]);
  });

  test("★서버 전체 상한 — 버린 수는 다음 창의 첫 줄에 suppressed로 싣는다", async () => {
    const { port, warns } = await start({ badSamplesPerWindow: 2 });
    await session(port, ["a1 FROB 1", "a2 FROB 2"]);
    await session(port, ["b1 FROB 1", "b2 FROB 2"]);
    // 창 안에서는 2줄만 — 두 번째 세션의 BAD 2건은 버려진다.
    expect(samples(warns).map((w) => w.fields.sample)).toEqual(["FROB 1", "FROB 2"]);
    expect(samples(warns).some((w) => "suppressed" in w.fields)).toBe(false);
  });

  test("OK·NO는 표본을 남기지 않는다", async () => {
    const { port, warns } = await start();
    const out = await session(port, ["a1 LOGIN u@imap.test pw", "a2 NOOP", "a3 SELECT INBOX"]);
    expect(out).toContain("a3 NO");
    expect(samples(warns)).toEqual([]);
  });

  test("로거가 없어도 BAD 응답은 그대로 나간다", async () => {
    const { port } = await start({ logger: false });
    expect(await session(port, ["a1 FROB"])).toContain("a1 BAD ");
  });
});

describe("BAD 표본 서버 전체 예산", () => {
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
