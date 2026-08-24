/**
 * 회귀 테스트 — certSource.resolve()가 **throw할 때**의 기동 동작.
 *
 * 과거 결함 두 가지:
 *  ① app.ts에 try/catch가 없어 인증서 확보 실패 = **부팅 자체 실패**였다(25번 수신까지 정지).
 *     타입은 `Promise<TlsMaterial | null>`이라 "실패하면 null"로 읽히는데 url/acme 구현은 throw한다.
 *  ② 단순히 catch만 하면 tlsAvailable=false가 되어 `allowInsecureAuth`가 켜지고
 *     **143/587 평문 AUTH가 열리는 보안 강등**이 생긴다. 그래서 "TLS를 의도했는가"(tlsConfigured)로
 *     판정해 인증서가 없어도 평문 AUTH는 계속 차단한다(fail closed).
 */
import { afterAll, beforeAll, describe, expect, test, SOCKET_DEADLINE_MS } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CertSource } from "@ionosphere/tls";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

/** url 소스가 "원격 불가 + 캐시 없음"일 때와 동일하게 throw하는 소스. */
function failingCertSource(): CertSource {
  return {
    mode: "url",
    resolve() {
      return Promise.reject(new Error("url cert 페치 실패 + 캐시 없음"));
    },
    status() {
      return Promise.resolve({ mode: "url" as const, enabled: false, source: "http://unreachable.invalid/cert.pem" });
    },
  };
}

/** 한 줄 명령을 보내고 응답 첫 줄을 받는다. */
function lineExchange(port: number, greetingLines: number, send: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const sock: Socket = connect(port, "127.0.0.1");
    const lines: string[] = [];
    let buf = "";
    sock.setEncoding("utf8");
    sock.on("data", (chunk: string) => {
      buf += chunk;
      let i: number;
      while ((i = buf.indexOf("\r\n")) >= 0) {
        lines.push(buf.slice(0, i));
        buf = buf.slice(i + 2);
        if (lines.length === greetingLines) sock.write(send);
        if (lines.length >= greetingLines + 1) {
          sock.end();
          resolve(lines);
          return;
        }
      }
    });
    sock.on("error", reject);
    setTimeout(() => {
      sock.destroy();
      reject(new Error("timeout"));
    }, SOCKET_DEADLINE_MS);
  });
}

describe("certSource.resolve() 실패 시", () => {
  let app: IonosphereApp;
  let blobRoot: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-tlsfail-"));
    app = new IonosphereApp({
      hostname: "mx.test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      imapPort: 0, // 평문 143
      imapsPort: 0, // 993 — 자료가 없으므로 기동되지 않아야 함
      submissionPort: 0, // 평문 587
      certSource: failingCertSource(),
      resolver: offlineResolver(),
    });
    // ① 부팅이 죽지 않아야 한다
    await app.start();
    await app.createUser("u@test.local", "pw");
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("① 부팅에 성공하고 수신(25)은 계속 동작한다", () => {
    expect(app.smtpPort).toBeGreaterThan(0);
  });

  test("① TLS 자료가 없으므로 993 리스너는 기동되지 않는다", () => {
    expect(app.imapsPort).toBe(0);
  });

  test("② 143 평문 AUTH는 여전히 차단된다(LOGINDISABLED)", async () => {
    const lines = await lineExchange(app.imapPort, 1, "a1 LOGIN u@test.local pw\r\n");
    expect(lines[0]).toContain("LOGINDISABLED");
    expect(lines[1]).toMatch(/^a1 NO/);
    expect(lines[1]).toContain("PRIVACYREQUIRED");
  });

  test("② 587 평문 AUTH도 차단된다", async () => {
    const lines = await lineExchange(app.submissionPort, 1, "EHLO test\r\n");
    // EHLO 응답에 AUTH가 광고되지 않아야 한다(평문 경로 차단)
    const ehlo = lines.slice(1).join(" ");
    expect(ehlo).not.toContain("AUTH ");
  });
});
