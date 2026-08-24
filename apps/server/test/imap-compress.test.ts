/**
 * IMAP COMPRESS=DEFLATE (RFC 4978) — **실 소켓** e2e.
 *
 * ★단위테스트로는 이 기능의 핵심 버그를 못 잡는다. `Z_SYNC_FLUSH`를 빠뜨리면 압축 스트림이
 * 블록이 찰 때까지 출력을 모으는데, IMAP은 서버가 한 줄 보내고 클라이언트 응답을 기다리는
 * 대화형이라 그 버퍼링이 곧 **양쪽이 서로를 기다리는 교착**이 된다. 실제로 왕복을 해 봐야
 * 드러나므로 소켓을 연다.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as net from "node:net";
import * as zlib from "node:zlib";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

let app: IonosphereApp;
let blobRoot: string;

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-compress-"));
  app = new IonosphereApp({
    hostname: "test.local",
    dbPath: ":memory:",
    blobRoot,
    smtpPort: 0,
    pop3Port: 0,
    imapPort: 0,
    resolver: offlineResolver(),
  });
  await app.start();
  await app.createUser("you@test.local", "pw-comp");
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

/** 평문 IMAP 세션 하나. `waitFor`는 그 문자열이 올 때까지 모은다. */
async function connect(): Promise<{
  send: (line: string) => void;
  waitFor: (needle: string, timeoutMs?: number) => Promise<string>;
  startCompress: () => void;
  end: () => void;
}> {
  const sock = net.connect({ port: app.imapPort, host: "127.0.0.1" });
  await new Promise<void>((resolve, reject) => {
    sock.once("connect", () => resolve());
    sock.once("error", reject);
  });

  let buf = "";
  let deflate: zlib.DeflateRaw | null = null;
  let inflate: zlib.InflateRaw | null = null;
  sock.on("data", (chunk: Buffer) => {
    if (inflate) inflate.write(chunk);
    else buf += chunk.toString("latin1");
  });

  return {
    send: (line: string): void => {
      const bytes = Buffer.from(line, "latin1");
      if (deflate) {
        deflate.write(bytes);
        deflate.flush(zlib.constants.Z_SYNC_FLUSH);
      } else sock.write(bytes);
    },
    waitFor: async (needle: string, timeoutMs = 5000): Promise<string> => {
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        if (buf.includes(needle)) return buf;
        if (Date.now() > deadline) throw new Error(`timeout waiting for ${needle}; got: ${buf.slice(0, 400)}`);
        await new Promise((r) => setTimeout(r, 10));
      }
    },
    startCompress: (): void => {
      const d = zlib.createDeflateRaw();
      const i = zlib.createInflateRaw();
      d.on("data", (c: Buffer) => sock.write(c));
      i.on("data", (c: Buffer) => {
        buf += c.toString("latin1");
      });
      deflate = d;
      inflate = i;
    },
    end: (): void => {
      sock.destroy();
      deflate?.destroy();
      inflate?.destroy();
    },
  };
}

describe("COMPRESS=DEFLATE", () => {
  /** 인증 전 압축은 자원만 쓰게 하는 무료 증폭 수단이다 — 광고도 하지 않고 받지도 않는다. */
  test("인증 전에는 광고하지 않고 받지도 않는다", async () => {
    const c = await connect();
    await c.waitFor("* OK");
    c.send("a1 CAPABILITY\r\n");
    const caps = await c.waitFor("a1 OK");
    expect(caps.includes("COMPRESS=DEFLATE")).toBe(false);

    c.send("a2 COMPRESS DEFLATE\r\n");
    expect(await c.waitFor("a2 ")).toContain("a2 BAD");
    c.end();
  });

  test("인증 후에는 광고한다", async () => {
    const c = await connect();
    await c.waitFor("* OK");
    c.send("a1 LOGIN you@test.local pw-comp\r\n");
    await c.waitFor("a1 OK");
    c.send("a2 CAPABILITY\r\n");
    expect(await c.waitFor("a2 OK")).toContain("COMPRESS=DEFLATE");
    c.end();
  });

  /**
   * ★이 파일의 핵심. OK가 **평문으로** 나온 뒤부터 양방향이 압축이고, 그 상태에서 왕복이
   * 실제로 돌아야 한다. flush를 빠뜨리면 여기서 타임아웃이 난다.
   */
  test("압축을 켠 뒤에도 명령이 오간다", async () => {
    const c = await connect();
    await c.waitFor("* OK");
    c.send("a1 LOGIN you@test.local pw-comp\r\n");
    await c.waitFor("a1 OK");

    c.send("a2 COMPRESS DEFLATE\r\n");
    expect(await c.waitFor("a2 OK")).toContain("DEFLATE active");
    c.startCompress(); // 이 줄 이후가 압축 구간이다

    c.send("a3 NOOP\r\n");
    expect(await c.waitFor("a3 OK")).toContain("a3 OK");

    // 여러 왕복이 이어져야 한다 — 한 번만 되고 막히는 형태를 잡는다.
    c.send("a4 SELECT INBOX\r\n");
    const sel = await c.waitFor("a4 OK");
    expect(sel).toContain("EXISTS");

    c.send("a5 LIST \"\" *\r\n");
    expect(await c.waitFor("a5 OK")).toContain("* LIST");
    c.end();
  });

  /** RFC 4978 §3 — 두 번 켤 수 없다. 켜진 뒤에는 광고에서도 빠진다. */
  test("두 번 켜면 NO [COMPRESSIONACTIVE]", async () => {
    const c = await connect();
    await c.waitFor("* OK");
    c.send("a1 LOGIN you@test.local pw-comp\r\n");
    await c.waitFor("a1 OK");
    c.send("a2 COMPRESS DEFLATE\r\n");
    await c.waitFor("a2 OK");
    c.startCompress();

    c.send("a3 COMPRESS DEFLATE\r\n");
    expect(await c.waitFor("a3 ")).toContain("[COMPRESSIONACTIVE]");

    c.send("a4 CAPABILITY\r\n");
    const caps = await c.waitFor("a4 OK");
    expect(caps.slice(caps.indexOf("a4")).includes("COMPRESS=DEFLATE")).toBe(false);
    c.end();
  });

  test("모르는 알고리즘은 BAD", async () => {
    const c = await connect();
    await c.waitFor("* OK");
    c.send("a1 LOGIN you@test.local pw-comp\r\n");
    await c.waitFor("a1 OK");
    c.send("a2 COMPRESS LZW\r\n");
    expect(await c.waitFor("a2 ")).toContain("a2 BAD");
    c.end();
  });
});
