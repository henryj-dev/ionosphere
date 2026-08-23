/**
 * 4190 평문 AUTH 차단 배선 — 143/110/587과 **같은 판정**을 써야 한다.
 *
 * 과거 결함: 여기만 `allowInsecureAuth: !this.opts.tls`였다. 운영 표준 경로(certSource 또는
 * imapsTls로 TLS를 구성하고 전역 `tls`는 비우는 구성)에서는 `opts.tls`가 undefined이므로
 * **다른 모든 리스너가 평문 AUTH를 막는 동안 ManageSieve만 AUTHENTICATE PLAIN을 열어 뒀다.**
 * ManageSieve는 TLS 리스너도 STARTTLS도 없어서 비밀번호가 그대로 평문으로 흐른다.
 *
 * 판정은 `tlsConfigured`("TLS를 의도했는가")여야 한다 — 인증서 확보 실패가 평문 AUTH 개방으로
 * 이어지지 않게 하려고 자료 유무와 분리해 둔 값이다(tls-resolve-failure.test.ts 참조).
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect } from "node:net";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "../../../packages/proto-smtp/test/fixtures");
// 993 전용 인증서만 구성한 라이브 형태 — certSource(acme/file) 경로도 tlsConfigured만 켜고
// opts.tls는 비우므로 이 테스트가 재현하는 조건과 동일하다.
const imapsTls = { key: readFileSync(join(fixtures, "key.pem")), cert: readFileSync(join(fixtures, "cert.pem")) };

/** 그리팅(OK로 끝남)을 읽고, 명령 하나를 보내 완결 라인(OK/NO/BYE)까지 수집. */
async function sieveExchange(port: number, command: string): Promise<{ greeting: string[]; response: string }> {
  const sock = connect(port, "127.0.0.1");
  const lines: string[] = [];
  let buf = "";
  const waiters: ((l: string) => void)[] = [];
  sock.on("data", (c) => {
    buf += c.toString("latin1");
    let i: number;
    while ((i = buf.indexOf("\r\n")) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 2);
      lines.push(line);
      waiters.shift()?.(line);
    }
  });
  const readUntil = (pred: (l: string) => boolean): Promise<string> =>
    new Promise<string>((resolve) => {
      const check = (l: string): void => {
        if (pred(l)) resolve(l);
        else waiters.push(check);
      };
      waiters.push(check);
    });

  await readUntil((l) => /^(OK|NO|BYE)\b/.test(l));
  const greeting = [...lines];
  sock.write(command + "\r\n");
  const response = await readUntil((l) => /^(OK|NO|BYE)\b/.test(l));
  sock.end();
  await new Promise<void>((r) => sock.on("close", () => r()));
  return { greeting, response };
}

describe("4190 평문 AUTH 차단 (TLS 구성 시)", () => {
  let app: IonosphereApp;
  let blobRoot: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-sieveauth-"));
    app = new IonosphereApp({
      hostname: "test.local",
      dbPath: ":memory:",
      blobRoot,
      manageSievePort: 0,
      imapsTls, // ← TLS를 구성한 라이브 형태. 이게 있으면 4190 평문 AUTH도 차단돼야 한다.
      resolver: offlineResolver(),
      runMtaWorker: false,
      runWebhookWorker: false,
      runReaper: false,
      blobGcMode: "off",
    });
    await app.start();
    await app.createUser("u@test.local", "pw-sieve");
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("CAPABILITY가 SASL PLAIN을 광고하지 않는다", async () => {
    const { greeting } = await sieveExchange(app.manageSievePort, "NOOP");
    const sasl = greeting.find((l) => l.startsWith('"SASL"'));
    expect(sasl).toBe('"SASL" ""');
  });

  test("평문 AUTHENTICATE PLAIN → NO 거부", async () => {
    // SASL PLAIN: authzid NUL authcid NUL passwd
    // 값은 리터럴 제어문자가 아니라 escape여야 한다(CLAUDE.md 규약).
    const creds = Buffer.from("\u0000u@test.local\u0000pw-sieve", "utf8").toString("base64");
    const { response } = await sieveExchange(app.manageSievePort, `AUTHENTICATE "PLAIN" "${creds}"`);
    expect(response).toStartWith("NO");
    expect(response).toContain("TLS required");
  });
});
