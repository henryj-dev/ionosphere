/**
 * node 전용 크래시 회귀 프로브(테스트 러너가 아니라 **하위 프로세스**로 실행된다).
 *
 * 왜 별도 프로세스인가: 이 결함은 node에서만 재현된다(bun은 Content-Length 초과분을 조용히
 * 자른다). 테스트 러너는 bun이라 같은 프로세스 안에서는 고정할 수 없다. 라이브가 node이므로
 * (`deploy/systemd/ionosphere.service`의 ExecStart) node에서 반드시 잡혀 있어야 한다.
 *
 * upstream이 선언한 Content-Length보다 많이 보내면 `ur.pipe(res)`가 이미 끝난 res에 쓰면서
 * ERR_STREAM_WRITE_AFTER_END를 던진다. res에 'error' 리스너가 없으면 unhandled가 되고
 * main.ts는 uncaughtException에서 프로세스를 종료한다 — 443 하나가 25·587·993을 함께 내린다.
 *
 * 정상이면 exit 0, 방어가 빠지면 node 기본 동작으로 exit 1(uncaughtException).
 */
import * as net from "node:net";
import * as tls from "node:tls";
import { generateSelfSigned } from "@ionosphere/tls";
import { HttpsFrontServer } from "../src/https-front.ts";

// 선언(2바이트)보다 많이(5바이트) 보내는 고장난 upstream.
const socks: net.Socket[] = [];
const up = net.createServer((sock) => {
  socks.push(sock);
  sock.on("error", () => {});
  let sent = false;
  sock.on("data", () => {
    if (sent) return;
    sent = true;
    sock.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhello");
  });
});
await new Promise<void>((r) => up.listen(0, "127.0.0.1", () => r()));
const upAddr = up.address();
const upPort = typeof upAddr === "object" && upAddr !== null ? upAddr.port : 0;

const cert = generateSelfSigned({ commonName: "mx.ionosphere.test" });
const front = new HttpsFrontServer({
  tls: { key: cert.keyPem, cert: cert.certPem },
  routes: [{ hosts: ["mx.ionosphere.test"], port: upPort, exposure: "public" }],
});
const port = await front.listen(0, "127.0.0.1");

await new Promise<void>((resolve) => {
  const s = tls.connect({ host: "127.0.0.1", port, rejectUnauthorized: false, servername: "mx.ionosphere.test" }, () => {
    s.write("GET /a HTTP/1.1\r\nHost: mx.ionosphere.test\r\n\r\n");
  });
  s.on("error", () => resolve());
  setTimeout(() => {
    s.destroy();
    resolve();
  }, 500);
});
// unhandled 'error'가 터졌다면 여기까지 오지 못한다.
await new Promise((r) => setTimeout(r, 300));

await front.close();
for (const s of socks) s.destroy();
await new Promise<void>((r) => up.close(() => r()));
process.exit(0);
