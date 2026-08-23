/**
 * SMTP AUTH 시도 제한 배선.
 *
 * 과거 결함: 인증 실패 횟수 제한이 **아무 프로토콜에도 없었다.** 한 연결에서 자격증명을
 * 무제한으로 때려볼 수 있었고, 실패마다 scrypt(~40ms)가 돌아 브루트포스가 곧 CPU 소모
 * 공격이기도 했다. 그래서 여기서 확인하는 것은 "거절한다"가 아니라
 * **"차단 뒤에는 백엔드를 아예 부르지 않는다"** — 값을 검사하기 전에 끊는 게 요점이다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect } from "node:net";
import { SmtpServer, type SmtpBackend } from "../src/server.ts";

let activeServers: SmtpServer[] = [];
afterEach(async () => {
  await Promise.all(activeServers.map((s) => s.close()));
  activeServers = [];
});

function lineReader(socket: ReturnType<typeof connect>): () => Promise<string> {
  let buf = "";
  return () =>
    new Promise((resolve) => {
      const tryFlush = (): boolean => {
        const idx = buf.indexOf("\r\n");
        if (idx === -1) return false;
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        resolve(line);
        return true;
      };
      if (tryFlush()) return;
      const onData = (chunk: Buffer): void => {
        buf += chunk.toString("utf-8");
        if (tryFlush()) socket.off("data", onData);
      };
      socket.on("data", onData);
    });
}

/** authenticate 호출 횟수를 세는 백엔드 — 항상 실패시킨다. */
function countingBackend(): SmtpBackend & { calls: () => number } {
  let calls = 0;
  return {
    verifyRecipient: async () => ({ ok: true as const }),
    deliver: async () => ({ ok: true as const }),
    authenticate: async () => {
      calls++;
      return { ok: false };
    },
    calls: () => calls,
  };
}

describe("SMTP AUTH 시도 제한", () => {
  test("연속 실패가 한도를 넘으면 백엔드를 더 이상 호출하지 않는다", async () => {
    const backend = countingBackend();
    const server = new SmtpServer({
      hostname: "srv.test",
      maxSizeBytes: 1_000_000,
      backend,
      profile: "submission",
      allowInsecureAuth: true, // TLS 없이 AUTH 광고(테스트 전용 경로)
    });
    activeServers.push(server);
    const port = await server.listen(0, "127.0.0.1");

    const socket = connect(port, "127.0.0.1");
    try {
      const readLine = lineReader(socket);
      await new Promise<void>((resolve) => socket.once("connect", resolve));
      await readLine(); // banner
      socket.write("EHLO client.test\r\n");
      let line = await readLine();
      while (line.startsWith("250-")) line = await readLine();

      // 기본 한도는 60초 윈도우에 10회. 넉넉히 20회 시도한다.
      const creds = Buffer.from("\u0000user@test\u0000wrong", "utf8").toString("base64");
      let rejected = 0;
      for (let i = 0; i < 20; i++) {
        socket.write(`AUTH PLAIN ${creds}\r\n`);
        const resp = await readLine();
        expect(resp).toStartWith("535 ");
        rejected++;
      }
      expect(rejected).toBe(20);

      // 20회를 시도했지만 백엔드가 본 것은 한도까지뿐이어야 한다.
      expect(backend.calls()).toBeLessThanOrEqual(10);
      expect(backend.calls()).toBeGreaterThan(0);
    } finally {
      socket.destroy();
    }
  });
});
