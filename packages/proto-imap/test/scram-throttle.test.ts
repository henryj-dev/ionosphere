/**
 * SCRAM 대입이 **스로틀에 걸리는가** — 어댑터 수준.
 *
 * ★이 파일이 있는 이유. SCRAM 증명 검증은 순수 계산이라 백엔드 왕복이 없다. 그래서 실패가
 * `auth`도 `authVerified`도 거치지 않고 엔진이 거절 응답만 내고 끝났고, 어댑터의
 * `authThrottle.recordFailure`는 `authVerified` 케이스 안에 있어서 **실행되지 않았다**.
 * 결과는 SCRAM으로 **무제한 비밀번호 추측**이 가능한 상태였고, 라이브 IMAP 993이 SCRAM을
 * 광고하므로 실제로 열려 있었다.
 *
 * `scram-auth.test.ts`는 엔진이 `authFailed` 액션을 내는지 본다. 여기서 보는 것은 그 액션이
 * **실제로 스로틀을 움직이는가**다 — 감사 로그가 남는 것과 공격이 막히는 것은 다른 사실이다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { AuthFailureThrottle, deriveScramKeys, type ScramStoredKeys } from "@ionosphere/core";
import { ImapServer, type ImapBackend } from "../src/server.ts";

const PASS = "correct-horse-battery";
const USER = "victim@test.local";

let servers: ImapServer[] = [];
let sockets: Socket[] = [];
afterEach(async () => {
  for (const s of sockets) s.destroy();
  sockets = [];
  await Promise.all(servers.map((s) => s.close()));
  servers = [];
});

/** SCRAM을 제공하는 최소 백엔드. `authenticate`는 항상 실패시킨다(여기서 볼 것은 SCRAM뿐). */
function backendWith(keys: ScramStoredKeys): ImapBackend {
  return {
    authenticate: async () => null,
    scramKeys: async (user) => (user === USER ? keys : null),
    scramAuthorize: async (user) => (user === USER ? { accountId: "acct-1" } : null),
    request: async () => {
      throw new Error("이 테스트는 인증을 통과하지 않는다");
    },
  };
}

/** 줄 단위 클라이언트 — 한 연결에서 SCRAM 한 판을 돌린다. */
function lineClient(port: number): {
  send: (s: string) => void;
  read: (until?: (l: string) => boolean) => Promise<string[]>;
} {
  const socket = connect(port, "127.0.0.1");
  sockets.push(socket);
  let buffer = "";
  const lines: string[] = [];
  const waiters: { until: (l: string) => boolean; resolve: (ls: string[]) => void }[] = [];
  const tryResolve = (): void => {
    while (waiters.length > 0) {
      const w = waiters[0]!;
      const i = lines.findIndex((l) => w.until(l));
      if (i < 0) return;
      waiters.shift();
      w.resolve(lines.splice(0, i + 1));
    }
  };
  socket.on("data", (chunk) => {
    buffer += chunk.toString("latin1");
    let idx: number;
    while ((idx = buffer.indexOf("\r\n")) >= 0) {
      lines.push(buffer.slice(0, idx));
      buffer = buffer.slice(idx + 2);
    }
    tryResolve();
  });
  socket.on("error", () => {
    /* 스로틀에 걸려 서버가 끊는 것도 정상 경로다 */
  });
  return {
    send: (s) => socket.write(s),
    read: (until = () => true) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("read timeout")), 4000);
        waiters.push({
          until,
          resolve: (ls) => {
            clearTimeout(timer);
            resolve(ls);
          },
        });
        tryResolve();
      }),
  };
}

/**
 * SCRAM 교환을 **틀린 증명으로** 한 판 돌린다. 반환은 마지막 태그 응답.
 *
 * proof를 계산하지 않는 이유: 실패만 만들면 되므로 어떤 바이트든 된다. 성공 경로는
 * `apps/server/test/scram-e2e.test.ts`가 실제 계산으로 덮는다.
 */
async function oneBadAttempt(port: number, nonce: string): Promise<string> {
  const c = lineClient(port);
  await c.read((l) => l.startsWith("* OK"));
  c.send(`a1 AUTHENTICATE SCRAM-SHA-256 ${Buffer.from(`n,,n=${USER},r=${nonce}`).toString("base64")}\r\n`);
  const first = await c.read((l) => l.startsWith("+ ") || l.startsWith("a1 "));
  const last = first.at(-1)!;
  // 스로틀에 걸려 server-first조차 오지 않으면 그 응답이 답이다.
  if (!last.startsWith("+ ")) return last;

  const serverFirst = Buffer.from(last.slice(2), "base64").toString();
  const full = /r=([^,]+)/.exec(serverFirst)![1]!;
  const bogus = Buffer.alloc(32, 13).toString("base64");
  c.send(`${Buffer.from(`c=biws,r=${full},p=${bogus}`).toString("base64")}\r\n`);
  return (await c.read((l) => l.startsWith("a1 "))).at(-1)!;
}

describe("IMAP SCRAM — 대입 스로틀", () => {
  test("★틀린 증명이 스로틀에 세어진다 — 예전에는 무제한이었다", async () => {
    const keys = (await deriveScramKeys(PASS, { iterations: 4096 })) as ScramStoredKeys;
    // 한도를 3으로 낮춰 테스트를 빠르게 — 기본 10을 쓰면 같은 것을 열 번 확인한다.
    const throttle = new AuthFailureThrottle({ limit: 3, windowMs: 60_000 });
    const server = new ImapServer({
      hostname: "imap.test",
      backend: backendWith(keys),
      allowInsecureAuth: true,
      authThrottle: throttle,
    });
    servers.push(server);
    const port = await server.listen(0, "127.0.0.1");

    // 세 번 틀린다 → 한도에 도달.
    for (let i = 0; i < 3; i++) {
      expect(await oneBadAttempt(port, `nonce-${i}`)).toContain("NO");
    }
    /**
     * ★네 번째는 **차단**이어야 한다. 여기가 결함의 핵심이었다 — 실패가 세어지지 않으면
     * 이 값이 영원히 false이고, 공격자는 초당 수십 번 SCRAM 교환을 돌릴 수 있다.
     */
    expect(throttle.blocked("127.0.0.1")).toBe(true);
  });

  test("성공 경로를 막지 않는다 — 스로틀 발동 전에는 교환이 정상 진행된다", async () => {
    const keys = (await deriveScramKeys(PASS, { iterations: 4096 })) as ScramStoredKeys;
    const throttle = new AuthFailureThrottle({ limit: 3, windowMs: 60_000 });
    const server = new ImapServer({
      hostname: "imap.test",
      backend: backendWith(keys),
      allowInsecureAuth: true,
      authThrottle: throttle,
    });
    servers.push(server);
    const port = await server.listen(0, "127.0.0.1");

    // 한 번 틀려도 아직 차단은 아니다 — 오타 한 번에 잠기면 안 된다.
    await oneBadAttempt(port, "nonce-single");
    expect(throttle.blocked("127.0.0.1")).toBe(false);
  });

  test("★없는 계정에 대한 대입도 세어진다 — 열거 방어가 스로틀 우회로 쓰이면 안 된다", async () => {
    // 없는 계정은 가짜 salt로 교환이 끝까지 진행된다(열거 방어). 그 갈래가 무기록·무계수면
    // 공격자는 존재하지 않는 사용자명으로 한도를 소진 없이 서버를 계속 두드릴 수 있다.
    const keys = (await deriveScramKeys(PASS, { iterations: 4096 })) as ScramStoredKeys;
    const throttle = new AuthFailureThrottle({ limit: 2, windowMs: 60_000 });
    const server = new ImapServer({
      hostname: "imap.test",
      backend: backendWith(keys),
      allowInsecureAuth: true,
      authThrottle: throttle,
    });
    servers.push(server);
    const port = await server.listen(0, "127.0.0.1");

    for (let i = 0; i < 2; i++) {
      const c = lineClient(port);
      await c.read((l) => l.startsWith("* OK"));
      c.send(`a1 AUTHENTICATE SCRAM-SHA-256 ${Buffer.from(`n,,n=ghost@x.test,r=g${i}`).toString("base64")}\r\n`);
      const first = await c.read((l) => l.startsWith("+ ") || l.startsWith("a1 "));
      const last = first.at(-1)!;
      if (!last.startsWith("+ ")) continue;
      const serverFirst = Buffer.from(last.slice(2), "base64").toString();
      const full = /r=([^,]+)/.exec(serverFirst)![1]!;
      c.send(
        `${Buffer.from(`c=biws,r=${full},p=${Buffer.alloc(32, 17).toString("base64")}`).toString("base64")}\r\n`,
      );
      await c.read((l) => l.startsWith("a1 "));
    }

    expect(throttle.blocked("127.0.0.1")).toBe(true);
  });
});
