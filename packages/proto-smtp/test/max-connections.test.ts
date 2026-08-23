/**
 * 리스너 동시 연결 수 상한.
 *
 * 과거 결함: 어느 리스너에도 상한이 없어 소켓·파일디스크립터가 고갈될 때까지 받아들였다.
 * 그 지점에서는 **정상 사용자도 접속하지 못하고**, 프로세스 전체가 같은 fd 풀을 쓰므로
 * 다른 프로토콜(IMAP·POP3·JMAP)까지 함께 죽는다. 초과분을 즉시 끊으면 이미 붙은 세션은 산다.
 *
 * 여기서는 상한이 **실제로 적용되는지**만 본다(기본값 1024로 테스트하면 fd를 많이 써서
 * 환경에 따라 불안정하므로, node의 maxConnections 자체가 걸렸는지를 낮은 값으로 확인한다).
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { MAX_LISTENER_CONNECTIONS } from "@ionosphere/core";
import { SmtpServer, type SmtpBackend } from "../src/server.ts";

let servers: SmtpServer[] = [];
let clients: Socket[] = [];

afterEach(async () => {
  for (const c of clients) c.destroy();
  clients = [];
  await Promise.all(servers.map((s) => s.close()));
  servers = [];
});

function makeBackend(): SmtpBackend {
  return { verifyRecipient: async () => ({ ok: true }), deliver: async () => ({ ok: true }) };
}

/** 접속해서 배너를 받으면 true, 그 전에 끊기면 false. */
function tryBanner(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = connect(port, "127.0.0.1");
    clients.push(sock);
    let settled = false;
    const done = (v: boolean): void => {
      if (settled) return;
      settled = true;
      resolve(v);
    };
    sock.once("data", () => done(true));
    sock.once("close", () => done(false));
    sock.once("error", () => done(false));
    setTimeout(() => done(false), 2000);
  });
}

describe("리스너 연결 수 상한", () => {
  test("상한을 넘는 연결은 배너를 받지 못하고 끊긴다", async () => {
    const server = new SmtpServer({ hostname: "srv.test", maxSizeBytes: 1_000_000, backend: makeBackend() });
    servers.push(server);
    const port = await server.listen(0, "127.0.0.1");
    const raw = (server as unknown as { server: { maxConnections: number } }).server;

    // ① 배선 확인 — listen 시점에 상한이 실제로 설정됐는가(이 줄이 빠지면 여기서 잡힌다).
    expect(raw.maxConnections).toBe(MAX_LISTENER_CONNECTIONS);

    // ② 동작 확인 — 기본값(1024)으로 재현하면 fd를 많이 써 환경에 따라 흔들리므로 낮춰서 본다.
    raw.maxConnections = 2;

    expect(await tryBanner(port)).toBe(true);
    expect(await tryBanner(port)).toBe(true);
    // 세 번째는 상한 초과 — node가 수락 즉시 끊으므로 배너가 오지 않는다.
    expect(await tryBanner(port)).toBe(false);
  });
});
