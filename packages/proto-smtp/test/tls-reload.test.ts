/**
 * 인증서 핫리로드 회귀 테스트.
 *
 * 왜 이 파일이 필요한가: 갱신 배선이 끊겨도 **갱신 직후에는 증상이 없다.** 90일 뒤 만료
 * 시점에야 25/587이 만료 인증서를 제시해 MTA-STS enforce 상대의 수신이 끊긴다. 실제로
 * `upgradeTls()`가 `opts.tls`(생성 시점 값)를 읽고 있어 STARTTLS 경로는 갱신이 영원히
 * 반영되지 않았고, `app.reloadAllTls()`는 25/587을 아예 호출하지도 않았다.
 *
 * 검증 범위: 465(암시적 TLS)는 소켓 왕복으로 **교체된 인증서를 실제로 확인**한다.
 * STARTTLS(25/587)는 서버측 업그레이드가 Bun에서 동작하지 않아(oven-sh/bun#25044,
 * starttls.test.ts 상단 주석) 핸드셰이크 완주를 볼 수 없으므로, 같은 `currentTls`를 읽는
 * 배선이 리로드 후에도 온전한지(광고·220 응답)와 **평문 리스너가 리로드로 TLS를 켜지 않는지**를
 * 확인한다. 후자가 중요한 이유: 런타임 미지원으로 의도적으로 끈 STARTTLS가 갱신 한 번에
 * 되살아나면 발신자가 광고를 보고 핸드셰이크에서 멈춰 수신이 깨진다.
 */
import { readFileSync } from "node:fs";
import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { SmtpServer, type SmtpBackend } from "../src/server.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const cert = readFileSync(path.join(here, "fixtures/cert.pem")); // CN=localhost
const key = readFileSync(path.join(here, "fixtures/key.pem"));
const cert2 = readFileSync(path.join(here, "fixtures/cert2.pem")); // CN=rotated.test
const key2 = readFileSync(path.join(here, "fixtures/key2.pem"));

function makeBackend(): SmtpBackend {
  return {
    verifyRecipient: async () => ({ ok: true }),
    deliver: async () => ({ ok: true }),
  };
}

let activeServers: SmtpServer[] = [];

afterEach(async () => {
  await Promise.all(activeServers.map((s) => s.close()));
  activeServers = [];
});

/** CRLF 단위 라인 리더(starttls.test.ts와 동형). */
function lineReader(socket: ReturnType<typeof netConnect>): () => Promise<string> {
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

/** 암시적 TLS 리스너에 접속해 제시된 인증서의 CN을 읽는다. */
async function peerCommonName(port: number): Promise<string> {
  const socket = tlsConnect({ host: "127.0.0.1", port, rejectUnauthorized: false });
  try {
    await new Promise<void>((resolve, reject) => {
      socket.once("secureConnect", resolve);
      socket.once("error", reject);
    });
    const subject = socket.getPeerCertificate().subject as { CN?: string } | undefined;
    return subject?.CN ?? "";
  } finally {
    socket.destroy();
  }
}

/** 평문 접속 후 EHLO 응답 전체를 모아 STARTTLS 광고 여부를 본다. */
async function ehloAdvertisesStartTls(port: number): Promise<boolean> {
  const socket = netConnect(port, "127.0.0.1");
  try {
    let buf = "";
    const collected = new Promise<string>((resolve) => {
      socket.on("data", (chunk: Buffer) => {
        buf += chunk.toString("utf-8");
        // 배너(220) + EHLO 멀티라인의 마지막 줄("250 ")까지 도착하면 종료
        if (/^250 /m.test(buf)) resolve(buf);
      });
    });
    await new Promise<void>((resolve) => socket.once("connect", resolve));
    socket.write("EHLO client.test\r\n");
    return (await collected).includes("STARTTLS");
  } finally {
    socket.destroy();
  }
}

describe("TLS 인증서 핫리로드", () => {
  test("암시적 TLS(465): reloadTls 후 새 연결이 교체된 인증서를 받는다", async () => {
    const server = new SmtpServer({
      hostname: "srv.test",
      maxSizeBytes: 1_000_000,
      backend: makeBackend(),
      tls: { key, cert },
      implicitTls: true,
    });
    activeServers.push(server);
    const port = await server.listen(0, "127.0.0.1");

    expect(await peerCommonName(port)).toBe("localhost");

    await server.reloadTls({ key: key2, cert: cert2 });

    expect(await peerCommonName(port)).toBe("rotated.test");
  });

  test("STARTTLS(25/587): 업그레이드가 reloadTls한 자료를 실제로 읽는다", async () => {
    const server = new SmtpServer({
      hostname: "srv.test",
      maxSizeBytes: 1_000_000,
      backend: makeBackend(),
      tls: { key, cert },
    });
    activeServers.push(server);
    const port = await server.listen(0, "127.0.0.1");
    expect(await ehloAdvertisesStartTls(port)).toBe(true);

    // ★관측 트릭: Bun에서는 서버측 핸드셰이크 완주를 볼 수 없어(oven-sh/bun#25044) "어느 인증서를
    // 제시했는지"를 직접 확인할 수 없다. 대신 **서로 어긋난 key/cert 쌍**으로 교체한다 —
    // 업그레이드가 새 자료를 읽으면 TLSSocket 생성이 동기 throw하고 어댑터가 연결을 끊는다.
    // 옛 자료(opts.tls)를 읽으면 쌍이 맞아 연결이 살아 있다. 즉 연결 종료 여부가 곧 판별식이다.
    await server.reloadTls({ key: key2, cert });

    const socket = netConnect(port, "127.0.0.1");
    try {
      const readLine = lineReader(socket);
      await new Promise<void>((resolve) => socket.once("connect", resolve));
      expect(await readLine()).toStartWith("220 ");
      socket.write("EHLO client.test\r\n");
      let line = await readLine();
      while (line.startsWith("250-")) line = await readLine();

      const closed = new Promise<boolean>((resolve) => {
        const timer = setTimeout(() => resolve(false), 3000);
        socket.once("close", () => {
          clearTimeout(timer);
          resolve(true);
        });
      });
      socket.write("STARTTLS\r\n");
      expect(await readLine()).toStartWith("220 ");

      expect(await closed).toBe(true);
    } finally {
      socket.destroy();
    }
  });

  test("평문 리스너: reloadTls는 no-op — STARTTLS를 켜지 않는다", async () => {
    const server = new SmtpServer({ hostname: "srv.test", maxSizeBytes: 1_000_000, backend: makeBackend() });
    activeServers.push(server);
    const port = await server.listen(0, "127.0.0.1");

    expect(await ehloAdvertisesStartTls(port)).toBe(false);

    await server.reloadTls({ key, cert });

    // 여기서 true가 되면 "미지원 런타임에서 STARTTLS를 광고해 수신이 멈추는" 사고가 부활한 것.
    expect(await ehloAdvertisesStartTls(port)).toBe(false);
  });
});
