/**
 * 발신 클라이언트가 상대 서버로부터 받는 바이트에 상한이 있는가.
 *
 * 과거 결함: `ReplyReader.buf`가 무제한 문자열 누적이었다(`+=`라 O(n²)까지). 악의적이거나
 * 고장난 MX가 CRLF를 영영 보내지 않으면 발송 워커가 메모리를 다 쓰고 죽는다 — 워커는
 * 한 프로세스라 거기서 죽으면 **큐 전체가 멈춘다.**
 *
 * 수신 쪽은 이미 같은 상한을 걸어 뒀는데(proto-smtp DATA 버퍼) 발신 쪽에만 없었다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { createServer, type Server, type Socket } from "node:net";
import { sendSmtp } from "../src/smtp-client.ts";

let servers: Server[] = [];
let sockets: Socket[] = [];
afterEach(async () => {
  // 소켓을 먼저 끊어야 close()가 완결된다 — 이 서버는 일부러 계속 쓰는 중이라 스스로 안 끝난다.
  for (const s of sockets) s.destroy();
  sockets = [];
  await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
  servers = [];
});

/** 배너를 CRLF 없이 계속 흘리는 서버 — "응답을 끝내지 않는" 상대. */
async function neverEndingBannerServer(): Promise<number> {
  const server = createServer((socket) => {
    sockets.push(socket);
    socket.write("220 "); // 코드만 보내고 줄을 끝내지 않는다
    const pump = (): void => {
      // 백프레셔를 존중하며 계속 밀어넣는다.
      while (socket.writable && socket.write("x".repeat(8192))) {
        /* drain될 때까지 */
      }
    };
    socket.on("drain", pump);
    socket.on("error", () => {
      /* 클라이언트가 끊는 것이 정상 경로 */
    });
    pump();
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  return typeof addr === "object" && addr !== null ? addr.port : 0;
}

describe("응답 버퍼 상한", () => {
  test("끝나지 않는 응답에 매달리거나 메모리를 다 쓰지 않고 실패로 끝낸다", async () => {
    const port = await neverEndingBannerServer();

    const res = await sendSmtp({
      host: "127.0.0.1",
      port,
      ehloName: "mx.test",
      mailFrom: "a@test.local",
      rcptTo: ["b@remote.test"],
      raw: new TextEncoder().encode("Subject: x\r\n\r\nbody\r\n"),
      tls: "never",
      timeoutMs: 15_000, // 타임아웃이 아니라 **상한**이 끝내는지 보려고 넉넉히 잡는다
    });

    expect(res.ok).toBe(false);
    expect(res.code).toBe(0); // 연결 실패로 수렴 → 재시도 대상(영구 실패로 굳히지 않는다)
    expect(res.message).toContain("reply too large");
  }, 20_000);
});
