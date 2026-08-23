import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import * as net from "node:net";
import {
  InProcessMaildropLock,
  Pop3Server,
  type Pop3Backend,
  type Pop3MaildropMessage,
} from "../src/server.ts";

const enc = new TextEncoder();

/** 소켓 데이터를 라인/마커 단위로 읽어내는 최소 테스트용 리더. */
class SocketReader {
  private chunks: Buffer[] = [];
  private waiters: Array<() => void> = [];
  private ended = false;

  constructor(socket: net.Socket) {
    socket.on("data", (chunk: Buffer) => {
      this.chunks.push(chunk);
      this.flush();
    });
    socket.on("close", () => {
      this.ended = true;
      this.flush();
    });
  }

  private buf(): Buffer {
    return Buffer.concat(this.chunks);
  }

  private flush(): void {
    const waiters = this.waiters.splice(0);
    for (const w of waiters) w();
  }

  private async waitForData(): Promise<void> {
    await new Promise<void>((resolve) => this.waiters.push(resolve));
  }

  async readLine(): Promise<string> {
    for (;;) {
      const buf = this.buf();
      const idx = buf.indexOf("\r\n");
      if (idx !== -1) {
        const line = buf.subarray(0, idx).toString("utf8");
        this.chunks = [buf.subarray(idx + 2)];
        return line;
      }
      if (this.ended) throw new Error("소켓이 라인을 못 받고 닫힘");
      await this.waitForData();
    }
  }

  async readUntil(marker: Buffer): Promise<Buffer> {
    for (;;) {
      const buf = this.buf();
      const idx = buf.indexOf(marker);
      if (idx !== -1) {
        const result = buf.subarray(0, idx + marker.length);
        this.chunks = [buf.subarray(idx + marker.length)];
        return Buffer.from(result);
      }
      if (this.ended) throw new Error("소켓이 마커를 못 받고 닫힘");
      await this.waitForData();
    }
  }
}

function connect(port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(port, "127.0.0.1");
    socket.once("connect", () => resolve(socket));
    socket.once("error", reject);
  });
}

function send(socket: net.Socket, line: string): void {
  socket.write(`${line}\r\n`);
}

/** 이 페이크는 프로세스 안 단일 세션만 흉내내므로 owner 하나로 충분하다. */
const OWNER = "fake-session";

class FakeBackend implements Pop3Backend {
  readonly lock = new InProcessMaildropLock();
  readonly released: string[] = [];
  readonly committed: Array<{ accountId: string; messages: Pop3MaildropMessage[] }> = [];
  private readonly accounts = new Map([["alice", { pass: "secret", accountId: "acc-1" }]]);
  private readonly maildrops = new Map<string, Pop3MaildropMessage[]>();
  private readonly content = new Map<string, Uint8Array>();

  constructor(messages: Pop3MaildropMessage[], content: Map<string, Uint8Array>) {
    this.maildrops.set("acc-1", messages);
    this.content = content;
  }

  async authenticate(user: string, pass: string): Promise<{ accountId: string } | null> {
    const acc = this.accounts.get(user);
    if (!acc || acc.pass !== pass) return null;
    return { accountId: acc.accountId };
  }

  async openMaildrop(
    accountId: string,
  ): Promise<{ ok: true; messages: Pop3MaildropMessage[] } | { ok: false; inUse: boolean }> {
    if (!(await this.lock.acquire(accountId, OWNER))) return { ok: false, inUse: true };
    return { ok: true, messages: this.maildrops.get(accountId) ?? [] };
  }

  async retrieve(_accountId: string, msg: Pop3MaildropMessage): Promise<Uint8Array> {
    const bytes = this.content.get(msg.ref as string);
    if (!bytes) throw new Error("not found");
    return bytes;
  }

  async commitDeletions(accountId: string, msgs: Pop3MaildropMessage[]): Promise<void> {
    this.committed.push({ accountId, messages: msgs });
  }

  async releaseMaildrop(accountId: string): Promise<void> {
    this.released.push(accountId);
    await this.lock.release(accountId, OWNER);
  }
}

function buildBackend(): FakeBackend {
  const messageA = enc.encode("Subject: A\r\n\r\nbodyA\r\n");
  const messageB = enc.encode("Subject: B\r\n\r\nbodyB\r\n");
  const content = new Map<string, Uint8Array>([
    ["msgA", messageA],
    ["msgB", messageB],
  ]);
  const messages: Pop3MaildropMessage[] = [
    { uidl: "u1", sizeBytes: messageA.length, ref: "msgA" },
    { uidl: "u2", sizeBytes: messageB.length, ref: "msgB" },
  ];
  return new FakeBackend(messages, content);
}

describe("Pop3Server — 소켓 어댑터 통합", () => {
  let server: Pop3Server | undefined;
  const sockets: net.Socket[] = [];

  afterEach(async () => {
    for (const s of sockets.splice(0)) if (!s.destroyed) s.destroy();
    if (server) {
      await server.close();
      server = undefined;
    }
  });

  test("전체 세션: 인증 → LIST → RETR → DELE → QUIT, release는 항상 호출", async () => {
    const backend = buildBackend();
    server = new Pop3Server({ allowInsecureAuth: true, hostname: "pop.test", backend });
    const port = await server.listen(0, "127.0.0.1");
    const socket = await connect(port);
    sockets.push(socket);
    const reader = new SocketReader(socket);

    expect(await reader.readLine()).toStartWith("+OK");

    send(socket, "USER alice");
    expect(await reader.readLine()).toStartWith("+OK");

    send(socket, "PASS secret");
    expect(await reader.readLine()).toStartWith("+OK");

    send(socket, "LIST");
    const listReply = (await reader.readUntil(Buffer.from("\r\n.\r\n"))).toString("utf8");
    expect(listReply).toContain("1 ");
    expect(listReply).toContain("2 ");

    send(socket, "RETR 1");
    const retrReply = (await reader.readUntil(Buffer.from("\r\n.\r\n"))).toString("utf8");
    expect(retrReply).toContain("bodyA");

    send(socket, "DELE 1");
    expect(await reader.readLine()).toStartWith("+OK");

    send(socket, "QUIT");
    expect(await reader.readLine()).toStartWith("+OK");

    await new Promise((resolve) => socket.once("close", resolve));

    expect(backend.committed).toHaveLength(1);
    expect(backend.committed[0]?.accountId).toBe("acc-1");
    expect(backend.committed[0]?.messages.map((m) => m.ref)).toEqual(["msgA"]);
    expect(backend.released).toEqual(["acc-1"]);
  });

  test("동시 연결: 두 번째 접속은 [IN-USE], 첫 연결 종료 후 잠금 해제 확인", async () => {
    const backend = buildBackend();
    server = new Pop3Server({ allowInsecureAuth: true, hostname: "pop.test", backend });
    const port = await server.listen(0, "127.0.0.1");

    const socket1 = await connect(port);
    sockets.push(socket1);
    const reader1 = new SocketReader(socket1);
    await reader1.readLine(); // greeting
    send(socket1, "USER alice");
    await reader1.readLine();
    send(socket1, "PASS secret");
    expect(await reader1.readLine()).toStartWith("+OK"); // 로그인 성공, maildrop 잠금 획득

    const socket2 = await connect(port);
    sockets.push(socket2);
    const reader2 = new SocketReader(socket2);
    await reader2.readLine(); // greeting
    send(socket2, "USER alice");
    await reader2.readLine();
    send(socket2, "PASS secret");
    const secondLogin = await reader2.readLine();
    expect(secondLogin).toBe("-ERR [IN-USE] maildrop locked");

    // 첫 연결 종료 → releaseMaildrop → 잠금 해제
    send(socket1, "QUIT");
    await reader1.readLine();
    await new Promise((resolve) => socket1.once("close", resolve));
    expect(backend.released).toEqual(["acc-1"]);

    // 세 번째 연결은 잠금이 풀렸으므로 성공해야 함
    const socket3 = await connect(port);
    sockets.push(socket3);
    const reader3 = new SocketReader(socket3);
    await reader3.readLine(); // greeting
    send(socket3, "USER alice");
    await reader3.readLine();
    send(socket3, "PASS secret");
    expect(await reader3.readLine()).toStartWith("+OK");
  });

  test("에러 없이 연결이 끊겨도(QUIT 없이 destroy) release는 호출됨", async () => {
    const backend = buildBackend();
    server = new Pop3Server({ allowInsecureAuth: true, hostname: "pop.test", backend });
    const port = await server.listen(0, "127.0.0.1");
    const socket = await connect(port);
    const reader = new SocketReader(socket);
    await reader.readLine(); // greeting
    send(socket, "USER alice");
    await reader.readLine();
    send(socket, "PASS secret");
    expect(await reader.readLine()).toStartWith("+OK");

    socket.destroy();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(backend.released).toEqual(["acc-1"]);
  });
});
