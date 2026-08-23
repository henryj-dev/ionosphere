/**
 * STARTTLS 통합테스트 — test/fixtures/{cert,key}.pem(자체서명, CN=localhost, 100년)로
 * 어댑터 배선을 검증. 픽스처는 `openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem
 * -out cert.pem -days 36500 -subj "/CN=localhost"`로 1회 생성.
 *
 * ★편차 (실행 요약에 기재): 실제 TLS 핸드셰이크 완주(tls.connect → secureConnect)까지 도는
 * 풀 라운드트립은 여기서 검증하지 않는다. Bun의 usocket이 서버 사이드 소켓의 TLS 업그레이드를
 * 지원하지 않아(node:tls의 `new TLSSocket(existingSocket, {isServer:true})` 경로) Bun
 * 런타임에서 `secure`/`secureConnect`가 영영 발생하지 않는, 현재 미해결인 업스트림 버그다
 * (oven-sh/bun#21541, 근본원인은 oven-sh/bun#25044). 동일 코드가 Node에서는 정상 동작함을
 * 스크립트로 별도 확인함(node --experimental-strip-types) — PLAN.md §6 리스크에 명시된
 * "Bun TLS/소켓 엣지케이스 → 문제 시 해당 컴포넌트만 Node 실행"이 정확히 이 케이스.
 * 스펙의 폴백 지침("최소한 STARTTLS 광고 + engine이 startTls emit + 상태 리셋만이라도 검증")을
 * 따른다 — 엔진 레벨 검증(광고/emit/리셋)은 engine.test.ts에 이미 있고, 여기서는 어댑터가
 * STARTTLS 커맨드에 220으로 응답하고 업그레이드 시도를 트리거하는 배선만 소켓으로 확인한다.
 */
import { readFileSync } from "node:fs";
import { connect } from "node:net";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { SmtpServer, type SmtpBackend } from "../src/server.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const cert = readFileSync(path.join(here, "fixtures/cert.pem"));
const key = readFileSync(path.join(here, "fixtures/key.pem"));

function makeBackend(): SmtpBackend {
  return {
    verifyRecipient: async () => ({ ok: true }),
    deliver: async () => ({ ok: true }),
  };
}

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

let activeServers: SmtpServer[] = [];

afterEach(async () => {
  await Promise.all(activeServers.map((s) => s.close()));
  activeServers = [];
});

describe("STARTTLS 어댑터 배선", () => {
  test("tls 설정 시 EHLO에 STARTTLS 광고, STARTTLS 커맨드는 220 응답", async () => {
    const server = new SmtpServer({
      hostname: "srv.test",
      maxSizeBytes: 1_000_000,
      backend: makeBackend(),
      tls: { key, cert },
    });
    activeServers.push(server);
    const port = await server.listen(0, "127.0.0.1");

    const socket = connect(port, "127.0.0.1");
    const readLine = lineReader(socket);
    await new Promise<void>((resolve) => socket.once("connect", resolve));

    expect(await readLine()).toStartWith("220 ");
    socket.write("EHLO client.test\r\n");
    let line = await readLine();
    let sawStartTls = false;
    while (line.startsWith("250-")) {
      if (line.includes("STARTTLS")) sawStartTls = true;
      line = await readLine();
    }
    if (line.includes("STARTTLS")) sawStartTls = true;
    expect(sawStartTls).toBe(true);

    socket.write("STARTTLS\r\n");
    expect(await readLine()).toBe("220 2.0.0 Ready to start TLS");

    socket.destroy();
  });

  test("tls 미설정이면 STARTTLS 미광고 및 502", async () => {
    const server = new SmtpServer({ hostname: "srv.test", maxSizeBytes: 1_000_000, backend: makeBackend() });
    activeServers.push(server);
    const port = await server.listen(0, "127.0.0.1");

    const socket = connect(port, "127.0.0.1");
    const readLine = lineReader(socket);
    await new Promise<void>((resolve) => socket.once("connect", resolve));

    await readLine(); // banner
    socket.write("EHLO c\r\n");
    let line = await readLine();
    while (line.startsWith("250-")) {
      expect(line).not.toContain("STARTTLS");
      line = await readLine();
    }
    expect(line).not.toContain("STARTTLS");

    socket.write("STARTTLS\r\n");
    expect(await readLine()).toStartWith("502 ");

    socket.destroy();
  });
});
