/**
 * node 전용 ManageSieve STARTTLS 프로브(테스트 러너가 아니라 **하위 프로세스**로 실행된다).
 *
 * 왜 별도 프로세스인가: 서버측 TLS 업그레이드는 bun ≤1.3.14에서 완료되지 않는다
 * (oven-sh/bun#25044 — 실측: 핸드셰이크가 그대로 멈춘다). 테스트 러너는 bun이라 같은
 * 프로세스에서는 이 경로를 돌릴 수 없고, 조건부 skip으로 두면 **기본 `bun test`에서 통째로
 * 건너뛰어 회귀 방어가 되지 않는다.** 라이브 런타임이 node이므로
 * (운영 저장소의 systemd 유닛의 ExecStart) node에서 반드시 잡혀 있어야 한다.
 *
 * 고정하는 것(감사 L-5): 4190에서 STARTTLS 광고 → 업그레이드 → SASL PLAIN 인증 →
 * PUTSCRIPT → SETACTIVE 가 **끝까지** 동작한다. 이 경로가 죽으면 평문 AUTH는 fail closed라
 * 라이브에서 Sieve 관리가 불가능해진다(L-5의 원래 증상).
 *
 * 정상이면 exit 0, 어긋나면 사유를 stderr에 남기고 exit 1.
 */
import { connect, type Socket } from "node:net";
import * as tls from "node:tls";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSignedCertSource } from "@ionosphere/tls";
import { IonosphereApp } from "../src/app.ts";
// helpers.ts는 `bun:` import가 없어 node에서도 그대로 로드된다 — 리졸버를 복제하지 않는다.
import { offlineResolver } from "./helpers.ts";

const NUL = String.fromCharCode(0);
const USER = "u@sieve.test.local";
const PASS = "pw-sieve";

function fail(msg: string): never {
  process.stderr.write(`프로브 실패: ${msg}\n`);
  process.exit(1);
}

/** 완결 응답(리터럴 밖의 OK/NO/BYE 라인)까지 모아 돌려주는 최소 클라이언트. */
class Client {
  private socket: Socket | tls.TLSSocket;
  private buffer = "";
  private waiter: { resolve: (s: string) => void; timer: NodeJS.Timeout } | null = null;

  constructor(port: number) {
    this.socket = connect(port, "127.0.0.1");
    this.attach(this.socket);
  }

  private attach(s: Socket | tls.TLSSocket): void {
    s.on("data", (c: Buffer) => {
      this.buffer += c.toString("latin1");
      this.tryComplete();
    });
    s.on("error", () => {
      /* 종료로 수렴 */
    });
  }

  private tryComplete(): void {
    if (!this.waiter) return;
    const lines = this.buffer.split("\r\n");
    let i = 0;
    let literal = 0;
    while (i < lines.length - 1) {
      const line = lines[i]!;
      if (literal > 0) {
        literal -= Buffer.byteLength(line, "latin1") + 2;
        i++;
        continue;
      }
      const m = /\{(\d+)\+?\}$/.exec(line);
      if (m) {
        literal = Number(m[1]);
        i++;
        continue;
      }
      if (/^(OK|NO|BYE)\b/.test(line)) {
        const w = this.waiter;
        this.waiter = null;
        clearTimeout(w.timer);
        const consumed = lines.slice(0, i + 1).join("\r\n") + "\r\n";
        this.buffer = this.buffer.slice(consumed.length);
        w.resolve(consumed);
        return;
      }
      i++;
    }
  }

  read(what: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`응답 타임아웃: ${what}`)), 8000);
      this.waiter = { resolve, timer };
      this.tryComplete();
    });
  }

  send(s: string): void {
    this.socket.write(s);
  }

  async upgrade(): Promise<string | null> {
    const plain = this.socket as Socket;
    plain.removeAllListeners("data");
    const sec = tls.connect({ socket: plain, rejectUnauthorized: false, servername: "sieve.test.local" });
    await new Promise<void>((resolve, reject) => {
      sec.once("secureConnect", () => resolve());
      sec.once("error", reject);
    });
    this.socket = sec;
    this.buffer = "";
    this.attach(sec);
    return sec.getProtocol();
  }

  close(): void {
    this.socket.destroy();
  }
}

const blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-sieve-probe-"));
const tlsDir = mkdtempSync(join(tmpdir(), "ionosphere-sieve-probe-tls-"));
const app = new IonosphereApp({
  hostname: "sieve.test.local",
  dbPath: ":memory:",
  blobRoot,
  manageSievePort: 0,
  // 라이브와 같은 형태: certSource만 채우고 전역 tls는 비운다.
  // smtpStartTls는 **주지 않는다** — 4190 STARTTLS가 그 옵트인과 독립이어야 한다(라이브 env에 없다).
  certSource: selfSignedCertSource({ commonName: "sieve.test.local", sans: ["sieve.test.local"], dir: tlsDir }),
  resolver: offlineResolver(),
  runMtaWorker: false,
  runWebhookWorker: false,
  runReaper: false,
  blobGcMode: "off",
});
await app.start();
const created = await app.createUser(USER, PASS);

const c = new Client(app.manageSievePort);
const greeting = await c.read("greeting");
if (!greeting.includes('"STARTTLS"')) fail(`node에서 STARTTLS를 광고하지 않았다: ${JSON.stringify(greeting)}`);
if (!greeting.includes('"SASL" ""')) fail(`평문 회선에서 SASL을 열었다: ${JSON.stringify(greeting)}`);

c.send("STARTTLS\r\n");
const stlsResp = await c.read("STARTTLS");
if (!stlsResp.startsWith("OK")) fail(`STARTTLS가 거절됐다(광고=구현 위반): ${JSON.stringify(stlsResp)}`);

const proto = await c.upgrade();
if (proto === null || !/^TLSv1\.[23]$/.test(proto)) fail(`업그레이드가 성립하지 않았다: proto=${String(proto)}`);

// RFC 5804 §2.2: 업그레이드 직후 능력 목록 재전송 — 여기서 PLAIN이 보여야 클라이언트가 인증한다.
const recaps = await c.read("업그레이드 후 능력 목록");
if (!recaps.includes('"SASL" "PLAIN"')) fail(`업그레이드 후 SASL PLAIN이 열리지 않았다: ${JSON.stringify(recaps)}`);
if (recaps.includes('"STARTTLS"')) fail("이미 TLS인데 STARTTLS를 계속 광고한다(RFC 5804 §1.7)");

c.send(`AUTHENTICATE "PLAIN" "${Buffer.from(`${NUL}${USER}${NUL}${PASS}`, "utf8").toString("base64")}"\r\n`);
const authResp = await c.read("AUTHENTICATE");
if (!authResp.startsWith("OK")) fail(`TLS 위 인증이 실패했다(L-5 인증 경로 없음): ${JSON.stringify(authResp)}`);

const script = 'require ["fileinto"];\r\nif header :contains "subject" "bill" { fileinto "Bills"; }\r\n';
c.send(`PUTSCRIPT "probe" {${Buffer.byteLength(script, "utf8")}+}\r\n${script}\r\n`);
const putResp = await c.read("PUTSCRIPT");
if (!putResp.startsWith("OK")) fail(`PUTSCRIPT 실패: ${JSON.stringify(putResp)}`);

c.send(`SETACTIVE "probe"\r\n`);
const setResp = await c.read("SETACTIVE");
if (!setResp.startsWith("OK")) fail(`SETACTIVE 실패: ${JSON.stringify(setResp)}`);

const active = await app.store.getActiveSieveScript(created.accountId);
if (active === null || !active.includes("fileinto")) fail(`활성 스크립트가 스토어에 없다: ${String(active)}`);

c.close();
await app.stop();
rmSync(blobRoot, { recursive: true, force: true });
rmSync(tlsDir, { recursive: true, force: true });
process.exit(0);
