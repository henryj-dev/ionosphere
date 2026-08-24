/**
 * SMTP STARTTLS(25/587) — 런타임 지원 판정 + 실제 업그레이드 검증.
 *
 * 배경: STARTTLS를 광고해놓고 업그레이드가 실패하면 **광고하지 않는 것보다 나쁘다**.
 * 발신 MTA가 220을 받고 핸드셰이크에서 멈춰 수신이 깨진다. bun 1.3.14 이하가 정확히 그 상태라
 * (oven-sh/bun#25044), 런타임 판정으로 자동 비활성한다. bun 1.4.0+(#29932)와 node는 지원.
 *
 * MTA-STS enforce는 25번 STARTTLS가 전제이므로 이 판정이 곧 enforce 가능 여부다.
 */
import { describe, expect, test, SOCKET_DEADLINE_MS } from "@ionosphere/testkit";
import { connect } from "node:net";
import * as tls from "node:tls";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSignedCertSource } from "@ionosphere/tls";
import { SmtpEngine, type SmtpAction } from "@ionosphere/proto-smtp";
import { IonosphereApp } from "../src/app.ts";
import { startTlsSupport, startTlsSupportFor } from "../src/starttls-support.ts";
import { offlineResolver } from "./helpers.ts";

describe("startTlsSupport — 런타임 판정", () => {
  test("node(bun 아님)는 지원", () => {
    expect(startTlsSupportFor(null).supported).toBe(true);
  });

  test("bun 1.3.14 이하는 미지원 — 켜면 수신이 깨지므로 막는다", () => {
    for (const v of ["1.3.14", "1.3.0", "1.2.9", "0.8.1"]) {
      const r = startTlsSupportFor(v);
      expect(r.supported).toBe(false);
      expect(r.reason).toContain("25044"); // 근거 이슈를 로그에 남긴다
    }
  });

  test("bun 1.4.0+는 지원(oven-sh/bun#29932)", () => {
    for (const v of ["1.4.0", "1.4.0-canary.1", "1.4.2", "2.0.0"]) {
      expect(startTlsSupportFor(v).supported).toBe(true);
    }
  });

  test("파싱 불가 버전은 안전하게 미지원", () => {
    expect(startTlsSupportFor("weird").supported).toBe(false);
  });
});

/** EHLO 능력 목록을 읽는다. */
function ehloCaps(port: number): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const sock = connect(port, "127.0.0.1");
    sock.setEncoding("utf8");
    let buf = "";
    const caps: string[] = [];
    let greeted = false;
    sock.on("data", (c: string) => {
      buf += c;
      let i: number;
      while ((i = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (!greeted) {
          greeted = true;
          sock.write("EHLO probe\r\n");
          continue;
        }
        caps.push(line.slice(4));
        if (line.startsWith("250 ")) {
          sock.end();
          resolve(caps);
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

describe("IonosphereApp STARTTLS 배선", () => {
  test("smtpStartTls=true — 지원 런타임이면 광고+업그레이드, 미지원이면 비광고", async () => {
    const blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-starttls-"));
    const tlsDir = mkdtempSync(join(tmpdir(), "ionosphere-starttls-tls-"));
    const app = new IonosphereApp({
      hostname: "mx.test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      smtpStartTls: true,
      certSource: selfSignedCertSource({ commonName: "mx.test.local", sans: ["mx.test.local"], dir: tlsDir }),
      resolver: offlineResolver(),
    });
    await app.start();
    try {
      const caps = await ehloCaps(app.smtpPort);
      const advertised = caps.some((c) => c.toUpperCase().startsWith("STARTTLS"));
      const support = startTlsSupport();
      // 광고 여부는 런타임 지원과 정확히 일치해야 한다 — 이게 어긋나면 수신이 깨진다.
      expect(advertised).toBe(support.supported);

      if (support.supported) {
        // 실제 업그레이드까지 성립하는지(광고만 하고 멈추면 안 됨)
        const proto = await new Promise<string | null>((resolve, reject) => {
          const sock = connect(app.smtpPort, "127.0.0.1");
          sock.setEncoding("utf8");
          let buf = "";
          let stage = 0;
          sock.on("data", (c: string) => {
            buf += c;
            let i: number;
            while ((i = buf.indexOf("\r\n")) >= 0) {
              const line = buf.slice(0, i);
              buf = buf.slice(i + 2);
              if (stage === 0) {
                stage = 1;
                sock.write("EHLO probe\r\n");
              } else if (stage === 1 && line.startsWith("250 ")) {
                stage = 2;
                sock.write("STARTTLS\r\n");
              } else if (stage === 2 && line.startsWith("220")) {
                stage = 3;
                const sec = tls.connect({ socket: sock, servername: "mx.test.local", rejectUnauthorized: false }, () => {
                  const p = sec.getProtocol();
                  sec.destroy();
                  resolve(p);
                });
                sec.on("error", reject);
                return;
              }
            }
          });
          sock.on("error", reject);
          setTimeout(() => {
            sock.destroy();
            reject(new Error("STARTTLS 업그레이드 타임아웃"));
          }, SOCKET_DEADLINE_MS);
        });
        expect(proto).toMatch(/^TLSv1\.[23]$/);
      }
    } finally {
      await app.stop();
      rmSync(blobRoot, { recursive: true, force: true });
      rmSync(tlsDir, { recursive: true, force: true });
    }
  });

  test("smtpStartTls 미지정이면 STARTTLS 비광고(기본값 유지)", async () => {
    const blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-nostarttls-"));
    const tlsDir = mkdtempSync(join(tmpdir(), "ionosphere-nostarttls-tls-"));
    const app = new IonosphereApp({
      hostname: "mx.test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      certSource: selfSignedCertSource({ commonName: "mx.test.local", sans: ["mx.test.local"], dir: tlsDir }),
      resolver: offlineResolver(),
    });
    await app.start();
    try {
      const caps = await ehloCaps(app.smtpPort);
      expect(caps.some((c) => c.toUpperCase().startsWith("STARTTLS"))).toBe(false);
    } finally {
      await app.stop();
      rmSync(blobRoot, { recursive: true, force: true });
      rmSync(tlsDir, { recursive: true, force: true });
    }
  });
});

describe("STARTTLS 명령 주입 — 업그레이드 전 평문 버퍼 폐기 (감사 I-1 회귀)", () => {
  // 고전적 STARTTLS 명령 주입(CVE-2011-0411 계열): 공격자가 `STARTTLS`와 **같은 세그먼트**에
  // 평문 명령을 덧붙이면, 서버가 그 바이트를 버리지 않을 경우 업그레이드 후에 **TLS 세션의
  // 명령인 것처럼** 실행된다. proto-smtp engine.ts의 `handleStartTls`가 버퍼를 비우는 한 줄과
  // `tlsUpgraded()`의 상태 초기화가 이걸 막는데, 그 한 줄을 지워도 통과하는 테스트뿐이었다.
  // 여기서는 **성질**을 고정한다: 주입된 명령이 업그레이드 전후 어디서도 실행되지 않는다.
  //
  // 엔진 레벨로 짠 이유: 실제 리스너로 재현하려면 STARTTLS 업그레이드가 되는 런타임이어야
  // 하는데(bun 1.3.14 이하는 미지원 — 위 describe 참조) 그러면 기본 `bun test`에서 통째로
  // 건너뛰어 회귀 방어가 되지 않는다. 엔진은 양 런타임에서 결정적으로 돈다.

  const enc = new TextEncoder();
  const VICTIM = "victim@evil.test";

  function tlsEngine(): SmtpEngine {
    const e = new SmtpEngine({ hostname: "mx.test.local", maxSizeBytes: 1024 * 1024, tlsAvailable: true });
    e.greeting();
    e.feed(enc.encode("EHLO probe\r\n"));
    return e;
  }

  function texts(actions: SmtpAction[]): string[] {
    return actions.filter((a): a is { kind: "reply"; text: string } => a.kind === "reply").map((a) => a.text);
  }

  test("STARTTLS와 같은 세그먼트로 온 평문 트랜잭션은 업그레이드 후에도 실행되지 않는다", () => {
    const e = tlsEngine();

    // 한 번의 write로 도착 = 엔진 buffer에 STARTTLS 뒤 바이트가 그대로 남는 상황.
    const injected = e.feed(enc.encode(`STARTTLS\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<${VICTIM}>\r\n`));

    // 업그레이드 전: 220과 startTls 액션뿐. 주입된 MAIL FROM/RCPT는 응답조차 나오면 안 된다.
    expect(injected.map((a) => a.kind)).toEqual(["reply", "startTls"]);
    expect(texts(injected)[0]).toStartWith("220 ");

    // 업그레이드 후: 주입분이 살아 있었다면 여기서 MAIL FROM 250과 rcpt 액션이 튀어나온다.
    e.tlsUpgraded();
    const after = e.feed(enc.encode("EHLO probe\r\n"));
    expect(after.filter((a) => a.kind === "rcpt")).toEqual([]);
    expect(texts(after)[0]).toStartWith("250"); // 첫 응답은 우리 EHLO의 것이어야 한다
    expect(JSON.stringify(after)).not.toContain(VICTIM);
  });

  test("업그레이드 후 정상 트랜잭션은 그대로 동작한다 (상한이 기능을 막지 않는지)", () => {
    const e = tlsEngine();
    e.feed(enc.encode("STARTTLS\r\n"));
    e.tlsUpgraded();
    e.feed(enc.encode("EHLO probe\r\n"));
    expect(texts(e.feed(enc.encode("MAIL FROM:<a@b.test>\r\n")))[0]).toStartWith("250");
    const rcpt = e.feed(enc.encode("RCPT TO:<user@b.test>\r\n"));
    expect(rcpt).toEqual([{ kind: "rcpt", address: "user@b.test" }]);
  });
});
