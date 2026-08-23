/**
 * 4190 ManageSieve STARTTLS — 라이브 인증 경로 e2e (감사 L-5).
 *
 * L-5의 원래 결함은 "STARTTLS를 광고하고 거부"였다. 광고만 지워 불일치는 없앴지만 그러면
 * **인증 경로가 아예 없어진다** — 평문 AUTH는 fail closed로 막혀 있고 TLS로 갈 방법이 없어
 * 라이브에서 Sieve 관리가 불가능했다. 그래서 STARTTLS를 구현했고, 여기서 **실제 소켓으로
 * 인증부터 스크립트 활성화까지** 끝까지 확인한다. 이 경로가 죽으면 Sieve 관리가 죽는다.
 *
 * 런타임: bun ≤1.3.14는 서버측 업그레이드를 완료하지 못하므로(oven-sh/bun#25044) 조립층이
 * 인증서를 넘기지 않는다 — 그 런타임에서는 "광고하지 않음"만 확인한다(광고=구현 불변식).
 * 판정을 여기서 다시 쓰지 않고 startTlsSupport를 호출하는 이유: 판정을 복제하면 한쪽만 낡는다.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { spawnSync } from "node:child_process";
import { connect, type Socket } from "node:net";
import * as tls from "node:tls";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSignedCertSource } from "@ionosphere/tls";
import { IonosphereApp } from "../src/app.ts";
import { startTlsSupport } from "../src/starttls-support.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver, PROBE_OK, probeVerdict } from "./helpers.ts";

let app: IonosphereApp;
let blobRoot: string;
let tlsDir: string;
let accountId: string;

const NUL = String.fromCharCode(0);
function plainB64(user: string, pass: string): string {
  return Buffer.from(`${NUL}${user}${NUL}${pass}`, "utf8").toString("base64");
}

/**
 * 줄 단위 리더 — 평문 소켓으로 시작해 STARTTLS 후 TLSSocket으로 교체할 수 있다.
 * 완결 판정은 리터럴 밖의 OK/NO/BYE 라인(managesieve-e2e.test.ts와 같은 규칙).
 */
class SieveClient {
  private socket: Socket | tls.TLSSocket;
  private buffer = "";
  private waiter: { resolve: (s: string) => void; timer: ReturnType<typeof setTimeout> } | null = null;

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
      /* 세션 종료로 수렴 */
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

  read(): Promise<string> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("read timeout")), 6000);
      this.waiter = { resolve, timer };
      this.tryComplete();
    });
  }

  send(s: string): void {
    this.socket.write(s);
  }

  /** STARTTLS OK를 받은 뒤 실제 TLS 핸드셰이크 — 협상된 프로토콜을 돌려준다. */
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

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-sieve-tls-"));
  tlsDir = mkdtempSync(join(tmpdir(), "ionosphere-sieve-tls-cert-"));
  app = new IonosphereApp({
    hostname: "sieve.test.local",
    dbPath: ":memory:",
    blobRoot,
    manageSievePort: 0,
    // 라이브와 같은 형태: certSource로 인증서를 구성한다(전역 tls는 비운다).
    // ⚠ smtpStartTls는 **일부러 주지 않는다** — 4190 STARTTLS가 그 옵트인과 무관하게
    //   켜져야 한다는 것이 이 테스트의 요점이다(라이브 env에 그 키가 없다).
    certSource: selfSignedCertSource({ commonName: "sieve.test.local", sans: ["sieve.test.local"], dir: tlsDir }),
    resolver: offlineResolver(),
    runMtaWorker: false,
    runWebhookWorker: false,
    runReaper: false,
    blobGcMode: "off",
  });
  await app.start();
  const created = await app.createUser("u@sieve.test.local", "pw-sieve");
  accountId = created.accountId;
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
  rmSync(tlsDir, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("4190 STARTTLS 인증 경로", () => {
  test("광고 여부가 런타임 지원과 정확히 일치한다 (L-5 불변식)", async () => {
    const c = new SieveClient(app.manageSievePort);
    const greeting = await c.read();
    expect(greeting.includes('"STARTTLS"')).toBe(startTlsSupport().supported);
    // 평문 회선에서는 어느 런타임이든 SASL을 열지 않는다.
    expect(greeting).toContain('"SASL" ""');
    c.close();
  });

  test("STARTTLS → 인증 → PUTSCRIPT → SETACTIVE 까지 실제로 동작한다", async () => {
    if (!startTlsSupport().supported) return; // 미지원 런타임: 위 테스트가 비광고를 고정한다
    const c = new SieveClient(app.manageSievePort);
    await c.read();

    c.send("STARTTLS\r\n");
    expect(await c.read()).toStartWith("OK");
    expect(await c.upgrade()).toMatch(/^TLSv1\.[23]$/);

    // RFC 5804 §2.2: 업그레이드 직후 서버가 능력 목록을 다시 보낸다 — 여기서 PLAIN이 보여야
    // 클라이언트가 인증을 시도한다(평문에서 본 목록은 폐기하므로).
    const recaps = await c.read();
    expect(recaps).toContain('"SASL" "PLAIN"');
    expect(recaps).not.toContain('"STARTTLS"');

    c.send(`AUTHENTICATE "PLAIN" "${plainB64("u@sieve.test.local", "pw-sieve")}"\r\n`);
    expect(await c.read()).toStartWith("OK");

    const script = 'require ["fileinto"];\r\nif header :contains "subject" "bill" { fileinto "Bills"; }\r\n';
    c.send(`PUTSCRIPT "tlsmain" {${Buffer.byteLength(script, "utf8")}+}\r\n${script}\r\n`);
    expect(await c.read()).toStartWith("OK");

    c.send(`SETACTIVE "tlsmain"\r\n`);
    expect(await c.read()).toStartWith("OK");

    c.send("LISTSCRIPTS\r\n");
    expect(await c.read()).toContain('"tlsmain" ACTIVE');

    c.send("LOGOUT\r\n");
    expect(await c.read()).toStartWith("OK");
    c.close();

    // 스토어까지 도달했는지 — 인증 경로가 끝까지 살아 있음을 확인한다.
    expect(await app.store.getActiveSieveScript(accountId)).toContain("fileinto");
  }, E2E_HOOK_TIMEOUT_MS);

  /**
   * ★위 테스트만으로는 라이브 경로가 고정되지 않는다: 기본 러너인 bun 1.3.14는 서버측
   * 업그레이드를 못 해(oven-sh/bun#25044) 업그레이드 테스트가 조건부로 빠진다. 라이브는 node라
   * (`deploy/systemd/ionosphere.service`) node 하위 프로세스로 실제 실행해 고정한다.
   * 프로브가 STARTTLS→인증→PUTSCRIPT→SETACTIVE를 끝까지 확인하고 어긋나면 exit 1.
   */
  test("[node] STARTTLS 인증 경로가 라이브 런타임에서 끝까지 동작한다", () => {
    const probe = new URL("./managesieve-starttls-probe.ts", import.meta.url).pathname;
    const r = spawnSync("node", [probe], { encoding: "utf8", timeout: 60_000 });
    expect(probeVerdict(r)).toBe(PROBE_OK);
  }, 60_000);

  test("업그레이드 없이는 여전히 인증이 거부된다 (fail closed 유지)", async () => {
    const c = new SieveClient(app.manageSievePort);
    await c.read();
    c.send(`AUTHENTICATE "PLAIN" "${plainB64("u@sieve.test.local", "pw-sieve")}"\r\n`);
    const r = await c.read();
    expect(r).toStartWith("NO");
    expect(r).toContain("TLS required");
    c.close();
  });
});
