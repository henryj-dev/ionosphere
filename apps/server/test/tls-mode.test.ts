/** TLS 모드 조립 — IonosphereApp이 certSource(selfsigned)로 993 TLS 제공 + 143 평문 AUTH 차단. */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import * as tls from "node:tls";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSignedCertSource } from "@ionosphere/tls";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

describe("TLS 모드 조립 (certSource=selfsigned)", () => {
  let app: IonosphereApp;
  let blobRoot: string;
  let tlsDir: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-tlsmode-"));
    tlsDir = mkdtempSync(join(tmpdir(), "ionosphere-tlsdir-"));
    app = new IonosphereApp({
      hostname: "mx.test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      imapPort: 0, // 평문 143
      imapsPort: 0, // 암시적 TLS 993
      certSource: selfSignedCertSource({ commonName: "mx.test.local", sans: ["mx.test.local"], dir: tlsDir }),
      resolver: offlineResolver(),
    });
    await app.start();
    await app.createUser("u@test.local", "pw");
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
    rmSync(tlsDir, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("993이 certSource 자기서명 인증서로 TLS 핸드셰이크", async () => {
    const cn = await new Promise<string>((resolve, reject) => {
      const c = tls.connect({ host: "127.0.0.1", port: app.imapsPort, rejectUnauthorized: false }, () => {
        // node 타입에서 CN은 string | string[]다(다중 CN 인증서). 첫 값만 본다.
        const rawCn = c.getPeerCertificate().subject?.CN;
        const n = Array.isArray(rawCn) ? (rawCn[0] ?? "") : (rawCn ?? "");
        c.end();
        resolve(n);
      });
      c.on("error", reject);
    });
    expect(cn).toBe("mx.test.local");
  });

  test("143 평문 AUTH 차단(certSource가 TLS 경로 제공 → LOGINDISABLED)", async () => {
    const line = await new Promise<string>((resolve) => {
      const sock = connect(app.imapPort, "127.0.0.1");
      let buf = "";
      sock.on("data", (d) => {
        buf += d.toString("latin1");
        const i = buf.indexOf("\r\n");
        if (i >= 0) {
          sock.end();
          resolve(buf.slice(0, i));
        }
      });
    });
    expect(line).toContain("LOGINDISABLED");
  });
});
