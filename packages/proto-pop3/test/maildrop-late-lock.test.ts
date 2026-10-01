/**
 * maildrop 잠금을 **늦게** 얻은 세션이 잠금을 흘리지 않는가 — 어댑터 수준.
 *
 * ★이 파일이 있는 이유(2026-09-30 독립 리뷰가 찾은 블로커). `openMaildrop`이 잠금을 기다리는
 * 사이 세션이 끝나면(인증 전 마감 발동 또는 클라이언트 종료) `release()`가 **먼저** 돌아
 * `released=true`·`accountId=null`이 된다. 그때는 아직 잠금이 없어 풀 것도 없다. 그 뒤 잠금
 * 확보가 성공하면 "늦게 성공했으니 바로 푼다"는 분기가 다시 `release()`를 부르는데, 이미
 * `released`라 **아무것도 하지 않았다.** 잠금과 갱신 타이머가 남아 그 계정은 프로세스가
 * 재시작할 때까지 POP3에서 `maildrop already locked`로 막혔다.
 *
 * 기존 어댑터 테스트는 백엔드가 즉시 성공해서 이 순서를 한 번도 만들지 못했다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { Pop3Server, type Pop3Backend } from "../src/server.ts";

let servers: Pop3Server[] = [];
let sockets: Socket[] = [];
afterEach(async () => {
  for (const s of sockets) s.destroy();
  sockets = [];
  await Promise.all(servers.map((s) => s.close()));
  servers = [];
});

/**
 * 잠금 확보를 **밖에서 풀어 줄 때까지** 미루는 백엔드. 잠금 상태를 실제처럼 들고 있어서,
 * 잡기 전에 온 해제는 아무 효과가 없다(실제 DbMaildropLock도 그렇다 — 없는 잠금은 못 푼다).
 */
function slowLockBackend(): {
  backend: Pop3Backend;
  held: () => boolean;
  openStarted: Promise<void>;
  /** 잠금 확보를 허락하고, 백엔드가 **실제로 잡을 때까지** 기다린다. */
  grant: () => Promise<void>;
} {
  let held = false;
  let grant!: () => void;
  const granted = new Promise<void>((r) => (grant = r));
  let markStarted!: () => void;
  const openStarted = new Promise<void>((r) => (markStarted = r));
  let markAcquired!: () => void;
  const acquired = new Promise<void>((r) => (markAcquired = r));
  const backend: Pop3Backend = {
    authenticate: async (u, p) => (u === "alice" && p === "secret" ? { accountId: "acc-1" } : null),
    openMaildrop: async () => {
      markStarted();
      await granted;
      held = true;
      markAcquired();
      return { ok: true, messages: [] };
    },
    retrieve: async () => new Uint8Array(),
    commitDeletions: async () => {},
    releaseMaildrop: async (id) => {
      // 다른 계정 id로 푸는 버그를 통과시키지 않도록 id를 본다.
      if (id === "acc-1") held = false;
    },
  };
  // ★잡힌 뒤에 검사해야 한다. grant 직후 바로 보면 백엔드가 아직 잡기 전이라 "안 잡힘"을
  //   보고 통과해 버린다 — 이 파일의 첫 판이 그렇게 결함을 놓쳤다.
  return { backend, held: () => held, openStarted, grant: async () => (grant(), acquired) };
}

async function start(backend: Pop3Backend, preauthDeadlineMs: number): Promise<number> {
  const server = new Pop3Server({ hostname: "pop3.test", backend, allowInsecureAuth: true, preauthDeadlineMs });
  servers.push(server);
  return server.listen(0, "127.0.0.1");
}

function client(port: number): { send: (s: string) => void; sock: Socket; closed: Promise<void>; waitFor: (n: string) => Promise<void> } {
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
  return { send: (s) => sock.write(s), sock, closed, waitFor };
}

/** 잠금 해제는 비동기라 잠시 기다린다 — 끝내 안 풀리면 누수다. */
async function settle(held: () => boolean): Promise<boolean> {
  const until = Date.now() + 1000;
  while (held() && Date.now() < until) await new Promise((r) => setTimeout(r, 10));
  return held();
}

describe("POP3 — 늦게 얻은 maildrop 잠금", () => {
  test("★잠금을 기다리는 사이 인증 전 마감이 발동해도 잠금이 남지 않는다", async () => {
    const lock = slowLockBackend();
    const port = await start(lock.backend, 300);
    const c = client(port);
    await c.waitFor("+OK");
    c.send("USER alice\r\nPASS secret\r\n");
    await lock.openStarted;
    // 잠금 확보가 멈춘 사이 마감(300ms)이 발동하고 연결이 닫힌다.
    await c.closed;
    await lock.grant();
    expect(await settle(lock.held)).toBe(false);
  });

  test("★잠금을 기다리는 사이 클라이언트가 끊어도 잠금이 남지 않는다", async () => {
    const lock = slowLockBackend();
    const port = await start(lock.backend, 60_000);
    const c = client(port);
    await c.waitFor("+OK");
    c.send("USER alice\r\nPASS secret\r\n");
    await lock.openStarted;
    c.sock.destroy();
    await c.closed;
    // 서버 쪽 close 처리가 먼저 돌도록 한 틱 준다 — 그래야 결함이 나던 순서가 재현된다.
    await new Promise((r) => setTimeout(r, 50));
    await lock.grant();
    expect(await settle(lock.held)).toBe(false);
  });

  test("정상 경로 — 잠금을 늦게 얻어도 살아 있는 세션은 그대로 쓴다", async () => {
    const lock = slowLockBackend();
    const port = await start(lock.backend, 60_000);
    const c = client(port);
    await c.waitFor("+OK");
    c.send("USER alice\r\nPASS secret\r\n");
    await lock.openStarted;
    await new Promise((r) => setTimeout(r, 50));
    await lock.grant();
    await c.waitFor("maildrop");
    expect(lock.held()).toBe(true);
    c.send("QUIT\r\n");
    await c.closed;
    expect(await settle(lock.held)).toBe(false);
  });
});

/**
 * 실제 백엔드처럼 **계정 id 하나에 세션 하나**를 두는 공유 잠금. 해제는 소유자를 가리지 않는다
 * (apps/server backend.ts의 `sessions`가 accountId로 키를 잡는 것과 같다). 그래서 어댑터가
 * 자기가 잡지 않은 잠금에 대해 `releaseMaildrop`을 부르면 **남의 잠금이 풀린다.**
 */
function sharedLockBackend(): {
  backend: Pop3Backend;
  owner: () => string | undefined;
  /** 다음 열기를 멈춘다. `afterAcquire`면 잠금을 **잡은 뒤** 멈춘다(실제 백엔드의 DB 조회 구간). */
  pauseNextOpen: (afterAcquire?: boolean) => { started: Promise<void>; resume: () => void };
} {
  let holder: string | undefined;
  let seq = 0;
  let pause: { gate: Promise<void>; started: () => void; afterAcquire: boolean } | null = null;
  const backend: Pop3Backend = {
    authenticate: async (u, p) => (u === "alice" && p === "secret" ? { accountId: "acc-1" } : null),
    openMaildrop: async () => {
      const me = `s${++seq}`;
      const p = pause;
      pause = null;
      if (p && !p.afterAcquire) {
        p.started();
        await p.gate;
      }
      if (holder !== undefined) return { ok: false, inUse: true };
      holder = me;
      if (p && p.afterAcquire) {
        p.started();
        await p.gate;
      }
      return { ok: true, messages: [] };
    },
    retrieve: async () => new Uint8Array(),
    commitDeletions: async () => {},
    releaseMaildrop: async () => {
      holder = undefined;
    },
  };
  return {
    backend,
    owner: () => holder,
    pauseNextOpen: (afterAcquire = false) => {
      let resume!: () => void;
      const gate = new Promise<void>((r) => (resume = r));
      let started!: () => void;
      const startedP = new Promise<void>((r) => (started = r));
      pause = { gate, started, afterAcquire };
      return { started: startedP, resume };
    },
  };
}

describe("POP3 — 잠금을 기다리다 끊긴 세션이 남의 잠금을 풀지 않는다", () => {
  /**
   * ★세션 B가 잠금을 들고 있는데, 같은 계정의 세션 A가 잠금을 기다리는 사이 끊긴다.
   * 예전엔 A의 close가 `releaseMaildrop`을 불러 **B의 잠금이 풀렸다** — B가 배타성을 잃어
   * 두 세션이 같은 maildrop에 동시에 expunge할 수 있었다(2026-09-30 코드 검수).
   */
  test("★기다리는 중 끊긴 세션의 close가 다른 세션의 잠금을 풀지 않는다", async () => {
    const lock = sharedLockBackend();
    const port = await start(lock.backend, 60_000);
    const b = client(port);
    await b.waitFor("+OK");
    b.send("USER alice\r\nPASS secret\r\n");
    await b.waitFor("maildrop");
    const heldBy = lock.owner();
    expect(heldBy).toBeDefined();

    const paused = lock.pauseNextOpen();
    const a = client(port);
    await a.waitFor("+OK");
    a.send("USER alice\r\nPASS secret\r\n");
    await paused.started;
    a.sock.destroy();
    await a.closed;
    await new Promise((r) => setTimeout(r, 50));
    paused.resume();
    await new Promise((r) => setTimeout(r, 50));
    expect(lock.owner()).toBe(heldBy);
  });

  /**
   * 잠금을 **잡은 뒤** 멈춘 사이 끊기는 경우 — 이 세션이 잠금을 끝까지 쥐고 있다가 열기가 끝나면
   * 자기 잠금을 푼다. 그 사이 다른 세션은 [IN-USE]를 받는다(남의 잠금을 빼앗지도, 풀지도 않는다).
   */
  test("잠금을 잡은 뒤 기다리다 끊기면 자기 잠금만 풀고, 그 사이 다른 세션은 IN-USE", async () => {
    const lock = sharedLockBackend();
    const port = await start(lock.backend, 60_000);
    const paused = lock.pauseNextOpen(true);
    const a = client(port);
    await a.waitFor("+OK");
    a.send("USER alice\r\nPASS secret\r\n");
    await paused.started;
    const heldByA = lock.owner();
    expect(heldByA).toBeDefined();
    a.sock.destroy();
    await a.closed;
    await new Promise((r) => setTimeout(r, 50));
    // A의 close가 잠금을 풀지 않았다 — 아직 열기 중이라 결과를 보고 풀어야 한다.
    expect(lock.owner()).toBe(heldByA);

    const c = client(port);
    await c.waitFor("+OK");
    c.send("USER alice\r\nPASS secret\r\n");
    await c.waitFor("-ERR");
    paused.resume();
    await new Promise((r) => setTimeout(r, 50));
    expect(lock.owner()).toBeUndefined();
  });
});
