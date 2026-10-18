/**
 * 열린 연결의 계정 재확인 — 어댑터 관문의 갈래를 스텁으로 고정한다.
 *
 * 실제 DB로 정지를 반영하는 경로는 apps/server/test/session-account-recheck.test.ts가 본다.
 * 여기서는 거기서 만들기 어려운 갈래를 본다: **상태 조회가 실패하면 명령을 실행하지 않는다**
 * (fail closed). 연결은 끊지 않는다 — DB가 잠깐 흔들렸다고 모든 메일 연결을 끊으면 안 된다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { ImapServer, type ImapBackend } from "../src/server.ts";

let servers: ImapServer[] = [];
let sockets: Socket[] = [];
afterEach(async () => {
  for (const s of sockets) s.destroy();
  sockets = [];
  await Promise.all(servers.map((s) => s.close()));
  servers = [];
});

/** 상태 응답을 테스트가 고른다. 백엔드 요청이 실제로 실행됐는지 센다. */
function stubBackend(status: () => Promise<boolean>): { backend: ImapBackend; requests: () => number } {
  let requests = 0;
  const backend: ImapBackend = {
    authenticate: async (user, pass) => (user === "u@imap.test" && pass === "pw" ? { accountId: "acct-1" } : null),
    request: async () => {
      requests++;
      return { kind: "no", message: "stub" };
    },
    accountActive: status,
  };
  return { backend, requests: () => requests };
}

async function start(backend: ImapBackend): Promise<number> {
  const server = new ImapServer({ hostname: "imap.test", backend, allowInsecureAuth: true });
  servers.push(server);
  return await server.listen(0, "127.0.0.1");
}

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

describe("IMAP 계정 재확인 관문", () => {
  test("비활성이면 BYE로 닫고 백엔드 요청을 실행하지 않는다", async () => {
    const { backend, requests } = stubBackend(async () => false);
    const c = client(await start(backend));
    await c.waitFor("* OK");
    c.send("a1 LOGIN u@imap.test pw\r\n");
    await c.waitFor("a1 OK");
    c.send("a2 SELECT INBOX\r\n");
    await c.closed;
    expect(c.text()).toContain("* BYE account unavailable");
    expect(c.text()).not.toContain("a2 ");
    expect(requests()).toBe(0);
  });

  test("★상태 조회가 실패하면 그 명령은 NO이고 실행되지 않으며, 연결은 유지된다", async () => {
    let fail = true;
    const { backend, requests } = stubBackend(async () => {
      if (fail) throw new Error("db down");
      return true;
    });
    const c = client(await start(backend));
    await c.waitFor("* OK");
    c.send("a1 LOGIN u@imap.test pw\r\n");
    await c.waitFor("a1 OK");
    c.send("a2 SELECT INBOX\r\n");
    await c.waitFor("a2 NO SELECT internal error");
    expect(requests()).toBe(0);

    // DB가 돌아오면 같은 연결에서 다음 명령은 백엔드까지 간다.
    fail = false;
    c.send("a3 SELECT INBOX\r\n");
    await c.waitFor("a3 NO SELECT stub");
    expect(requests()).toBe(1);
  });
});
