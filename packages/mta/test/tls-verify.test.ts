/**
 * 발신 TLS 신뢰 검증.
 *
 * 과거 결함: tls 모드가 required/implicit이어도 `rejectUnauthorized: false`였다. 즉
 *  - MTA-STS enforce(RFC 8461 §4.1)가 정책 조회·MX 매칭·다운그레이드 금지를 다 해놓고
 *    **마지막 한 줄에서 능동적 MITM 방어가 사라졌다**(암호화만 하고 상대는 확인 안 함).
 *  - 스마트호스트는 AUTH PLAIN으로 자격증명을 실어 보내는데 그게 검증 없는 TLS 위로 나갔다.
 *
 * 픽스처는 proto-smtp 테스트의 자체서명 인증서를 그대로 읽는다(import가 아니라 파일 읽기라
 * 패키지 의존 방향에 영향이 없다). CN=localhost라 **호스트명은 맞고 신뢰 사슬만 없는** 상태 —
 * 검증 실패가 호스트명 불일치가 아니라 "자체서명"에서 나오도록 조건을 분리한다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:tls";
import { createServer as netCreateServer, type Server as NetServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sendSmtp } from "../src/smtp-client.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "../../proto-smtp/test/fixtures");
const cert = readFileSync(join(fixtures, "cert.pem")); // CN=localhost, 자체서명
const key = readFileSync(join(fixtures, "key.pem"));

let servers: Server[] = [];
let plainServers: NetServer[] = [];
afterEach(async () => {
  await Promise.all([
    ...servers.map((s) => new Promise<void>((r) => s.close(() => r()))),
    ...plainServers.map((s) => new Promise<void>((r) => s.close(() => r()))),
  ]);
  servers = [];
  plainServers = [];
});

/** 자체서명 인증서로 도는 최소 암시적 TLS SMTP 서버(배너 → EHLO → 무엇이든 250). */
async function selfSignedSmtpServer(): Promise<number> {
  const server = createServer({ key, cert }, (socket) => {
    socket.write("220 self-signed.test ESMTP\r\n");
    socket.on("data", (chunk: Buffer) => {
      for (const line of chunk.toString("utf8").split("\r\n").filter(Boolean)) {
        if (/^EHLO/i.test(line)) socket.write("250 self-signed.test\r\n");
        else if (/^QUIT/i.test(line)) socket.end("221 bye\r\n");
        else socket.write("250 ok\r\n");
      }
    });
    socket.on("error", () => {
      /* 검증 실패로 클라이언트가 끊는 것이 정상 경로다 */
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  return typeof addr === "object" && addr !== null ? addr.port : 0;
}

/** STARTTLS를 광고하지 않는 평문 SMTP 서버. */
async function plaintextSmtpServer(): Promise<number> {
  const server = netCreateServer((socket) => {
    socket.write("220 plain.test ESMTP\r\n");
    socket.on("data", (chunk: Buffer) => {
      for (const line of chunk.toString("utf8").split("\r\n").filter(Boolean)) {
        if (/^EHLO/i.test(line)) socket.write("250 plain.test\r\n"); // 확장 없음
        else if (/^QUIT/i.test(line)) socket.end("221 bye\r\n");
        else socket.write("250 ok\r\n");
      }
    });
    socket.on("error", () => {
      /* 클라이언트가 끊는 것이 정상 경로 */
    });
  });
  plainServers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  return typeof addr === "object" && addr !== null ? addr.port : 0;
}

const baseOpts = {
  ehloName: "mx.test",
  mailFrom: "a@test.local",
  rcptTo: ["b@remote.test"],
  raw: new TextEncoder().encode("Subject: hi\r\n\r\nbody\r\n"),
  timeoutMs: 5000,
};

describe("발신 TLS 신뢰 검증", () => {
  test("implicit: 자체서명 상대는 거절한다(자격증명 보호)", async () => {
    const port = await selfSignedSmtpServer();
    const res = await sendSmtp({ ...baseOpts, host: "localhost", port, tls: "implicit" });

    expect(res.ok).toBe(false);
    // 연결 자체가 성립하지 않음 = code 0. 영구 실패로 굳히지 않아 재시도 대상으로 남는다.
    expect(res.code).toBe(0);
    expect(res.permanent).toBe(false);
    expect(res.message).toMatch(/self.?signed|unable to (verify|get local issuer)|certificate/i);
  });

  test("required: STARTTLS 미광고 상대에게 평문으로 흘리지 않는다", async () => {
    // 검증 강화가 "TLS를 아예 안 쓰는 경로"를 열어주지 않는지 함께 확인한다.
    const port = await plaintextSmtpServer();
    const res = await sendSmtp({ ...baseOpts, host: "127.0.0.1", port, tls: "required" });

    expect(res.ok).toBe(false);
    expect(res.permanent).toBe(false); // 설정·상대 문제 → 재시도 대상
    expect(res.message).toContain("STARTTLS required");
  });
});
