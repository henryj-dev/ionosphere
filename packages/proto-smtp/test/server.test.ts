/**
 * SmtpServer 통합테스트 — 실제 net 소켓 + 가짜 백엔드로 어댑터 배선을 검증.
 * 엔진 로직 자체는 engine.test.ts에서 소켓 없이 검증하므로 여기서는 어댑터 경로만.
 */
import { connect, type Socket } from "node:net";
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { SmtpServer, type SmtpBackend } from "../src/server.ts";

interface Delivered {
  mailFrom: string;
  rcptTo: string[];
  raw: Uint8Array;
}

function makeBackend(overrides: Partial<SmtpBackend> = {}): { backend: SmtpBackend; delivered: Delivered[] } {
  const delivered: Delivered[] = [];
  const backend: SmtpBackend = {
    verifyRecipient: async (address) => ({ ok: true }),
    deliver: async (env) => {
      delivered.push(env);
      return { ok: true, queuedId: "q-1" };
    },
    ...overrides,
  };
  return { backend, delivered };
}

/** 소켓에서 CRLF 종결 응답 라인을 하나씩 읽는 작은 헬퍼. */
class LineReader {
  private buf = "";
  private waiters: ((line: string) => void)[] = [];

  constructor(socket: Socket) {
    socket.on("data", (chunk: Buffer) => {
      this.buf += chunk.toString("utf-8");
      this.flush();
    });
  }

  private flush(): void {
    while (this.waiters.length > 0) {
      const idx = this.buf.indexOf("\r\n");
      if (idx === -1) break;
      const line = this.buf.slice(0, idx);
      this.buf = this.buf.slice(idx + 2);
      const waiter = this.waiters.shift()!;
      waiter(line);
    }
  }

  readLine(): Promise<string> {
    return new Promise((resolve) => {
      this.waiters.push(resolve);
      this.flush();
    });
  }
}

let activeServers: SmtpServer[] = [];

afterEach(async () => {
  await Promise.all(activeServers.map((s) => s.close()));
  activeServers = [];
});

describe("SmtpServer — 소켓 통합", () => {
  test("connect → EHLO → 메시지 전송 → 백엔드가 정확한 raw 바이트를 받음", async () => {
    const { backend, delivered } = makeBackend();
    const server = new SmtpServer({ hostname: "srv.test", maxSizeBytes: 1_000_000, backend });
    activeServers.push(server);
    const port = await server.listen(0, "127.0.0.1");

    const socket = connect(port, "127.0.0.1");
    const reader = new LineReader(socket);
    await new Promise<void>((resolve) => socket.once("connect", resolve));

    expect(await reader.readLine()).toStartWith("220 ");
    socket.write("EHLO client.test\r\n");
    let line = await reader.readLine();
    while (line.startsWith("250-")) line = await reader.readLine();
    expect(line).toBe("250 SMTPUTF8");

    socket.write("MAIL FROM:<alice@example.test>\r\n");
    expect(await reader.readLine()).toBe("250 2.1.0 OK");

    socket.write("RCPT TO:<bob@example.test>\r\n");
    expect(await reader.readLine()).toBe("250 2.1.5 bob@example.test OK");

    socket.write("DATA\r\n");
    expect(await reader.readLine()).toStartWith("354 ");

    socket.write("Subject: test\r\n\r\nhello world\r\n.\r\n");
    expect(await reader.readLine()).toBe("250 2.6.0 queued as q-1");

    socket.write("QUIT\r\n");
    expect(await reader.readLine()).toStartWith("221 ");

    socket.end();
    expect(delivered).toHaveLength(1);
    expect(delivered[0]!.mailFrom).toBe("alice@example.test");
    expect(delivered[0]!.rcptTo).toEqual(["bob@example.test"]);
    expect(new TextDecoder().decode(delivered[0]!.raw)).toBe("Subject: test\r\n\r\nhello world\r\n");
  });

  test("수신자 거부 경로 — 백엔드가 rejects면 550, deliver는 호출되지 않음", async () => {
    const delivered: Delivered[] = [];
    const backend: SmtpBackend = {
      verifyRecipient: async () => ({ ok: false, code: 550, enhanced: "5.1.1", message: "No such user" }),
      deliver: async (env) => {
        delivered.push(env);
        return { ok: true };
      },
    };
    const server = new SmtpServer({ hostname: "srv.test", maxSizeBytes: 1_000_000, backend });
    activeServers.push(server);
    const port = await server.listen(0, "127.0.0.1");

    const socket = connect(port, "127.0.0.1");
    const reader = new LineReader(socket);
    await new Promise<void>((resolve) => socket.once("connect", resolve));

    await reader.readLine(); // banner
    socket.write("EHLO c\r\n");
    let line = await reader.readLine();
    while (line.startsWith("250-")) line = await reader.readLine();

    socket.write("MAIL FROM:<a@b.test>\r\n");
    expect(await reader.readLine()).toBe("250 2.1.0 OK");

    socket.write("RCPT TO:<nouser@b.test>\r\n");
    expect(await reader.readLine()).toBe("550 5.1.1 No such user");

    socket.end();
    expect(delivered).toHaveLength(0);
  });
});
