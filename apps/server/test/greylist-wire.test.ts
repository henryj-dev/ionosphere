/**
 * greylist 조립 검증: relay 수신에서 첫 대면 defer(451) → 지연 경과 후 재시도 accept.
 * greylist는 옵션이라 별도 앱에서 켜서 확인 (기본 앱은 off).
 * SPF-pass 면제는 spam 패키지 단위테스트가 커버 — 여기선 미인증(none) 발신자로 defer를 본다.
 */
import { afterAll, beforeAll, describe, expect, test, SOCKET_DEADLINE_MS } from "@ionosphere/testkit";
import { E2E_HOOK_TIMEOUT_MS } from "./helpers.ts";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DnsNotFoundError, type DnsResolver } from "@ionosphere/mail-auth";
import { IonosphereApp } from "../src/app.ts";

function offline(): DnsResolver {
  const nf = (): never => { throw new DnsNotFoundError("none"); };
  return { txt: async () => nf(), mx: async () => nf(), a: async () => nf(), aaaa: async () => nf(), ptr: async () => nf() };
}

function relaySend(port: number, from: string, to: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect(port, "127.0.0.1");
    const msg = `From: ${from}\r\nTo: ${to}\r\nSubject: gl\r\n\r\nhi\r\n.\r\n`;
    const steps = [`EHLO t\r\n`, `MAIL FROM:<${from}>\r\n`, `RCPT TO:<${to}>\r\n`, `DATA\r\n`, msg];
    let stage = -1; let buf = "";
    const t = setTimeout(() => { s.destroy(); reject(new Error("timeout")); }, SOCKET_DEADLINE_MS);
    s.on("data", (d) => {
      buf += d.toString("latin1");
      let nl: number;
      while ((nl = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 2);
        if (line.startsWith("250-")) continue;
        if (line.startsWith("4") || line.startsWith("5")) { clearTimeout(t); s.write("QUIT\r\n"); s.destroy(); resolve(line); return; }
        if (stage === steps.length - 1) { clearTimeout(t); s.write("QUIT\r\n"); s.destroy(); resolve(line); return; }
        stage++; s.write(steps[stage]!);
      }
    });
    s.on("error", reject);
  });
}

describe("greylist 조립", () => {
  let app: IonosphereApp;
  let blobRoot: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-gl-"));
    app = new IonosphereApp({
      hostname: "mx.test", dbPath: ":memory:", blobRoot, smtpPort: 0, pop3Port: 0,
      resolver: offline(),
      greylist: { delayMs: 200, expireMs: 3_600_000 }, // 짧은 지연으로 테스트
    });
    await app.start();
    await app.createUser("rcpt@mx.test", "pw");
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("첫 시도 451 defer → 지연 후 재시도 250", async () => {
    const c1 = await relaySend(app.smtpPort, "stranger@ext.test", "rcpt@mx.test");
    expect(c1).toStartWith("451"); // 첫 대면 defer

    await new Promise((r) => setTimeout(r, 260)); // delayMs 경과

    const c2 = await relaySend(app.smtpPort, "stranger@ext.test", "rcpt@mx.test");
    expect(c2).toStartWith("250"); // 재시도 accept
  });
});
