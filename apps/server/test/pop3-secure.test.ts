/**
 * POP3 평문 인증 차단(110) + POP3S(995) — RFC 8314 §4.1.
 *
 * 실측으로 드러난 사고: 110이 공인망에 열린 채 **TLS 없이 USER/PASS를 받고 있었다**.
 * CAPA에 `USER`와 `SASL PLAIN`을 광고하고, 비밀번호를 실제로 평가해 `-ERR authentication failed`를
 * 돌려줬다. 즉 POP3를 쓰는 사용자의 비밀번호가 평문으로 인터넷을 지나갔다.
 * IMAP 143(LOGINDISABLED)·SMTP 587은 이미 같은 정책을 쓰고 있었는데 **POP3만 빠져 있었다**.
 *
 * 여기서 고정하는 계약:
 *  ① 평문 110은 인증을 거부하고, CAPA에서 인증 수단을 **광고조차 하지 않는다**
 *     (광고해놓고 거부하면 클라이언트가 "비밀번호가 틀렸다"고 오해한다)
 *  ② 995(암시적 TLS)에서는 정상 인증된다 — 차단이 "POP3 폐지"가 아니라 "안전한 경로로 이동"
 *  ③ TLS를 아예 확보하지 못한 구성에서는 110 인증이 살아 있다(자체 폐쇄망·dev 회귀 방지)
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCredential } from "@ionosphere/store";
import { selfSignedCertSource } from "@ionosphere/tls";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

const PASS = "pop3-secure-pw";

/** POP3 대화 — 인사말 후 주어진 명령들을 순서대로 보내고 각 응답을 모은다. */
function talk(port: number, useTls: boolean, cmds: string[]): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const sock = useTls
      ? tlsConnect({ port, host: "127.0.0.1", rejectUnauthorized: false })
      : netConnect(port, "127.0.0.1");
    sock.setEncoding("utf8");
    const out: string[] = [];
    let buf = "";
    let sent = 0;
    let inMultiline = false;
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error("timeout"));
    }, 15_000);
    const next = (): void => {
      if (sent < cmds.length) sock.write(cmds[sent++] + "\r\n");
      else {
        clearTimeout(timer);
        sock.end();
        resolve(out);
      }
    };
    sock.on("data", (c: string) => {
      buf += c;
      let i: number;
      while ((i = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        out.push(line);
        if (inMultiline) {
          if (line === ".") {
            inMultiline = false;
            next();
          }
          continue;
        }
        // CAPA 성공 응답은 멀티라인(마지막이 ".")
        if (sent > 0 && cmds[sent - 1] === "CAPA" && line.startsWith("+OK")) {
          inMultiline = true;
          continue;
        }
        next();
      }
    });
    sock.on("error", (e: Error) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

describe("POP3 — TLS 확보된 구성", () => {
  let app: IonosphereApp;
  let blobRoot: string;
  let tlsDir: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-pop3sec-"));
    tlsDir = mkdtempSync(join(tmpdir(), "ionosphere-pop3sec-tls-"));
    app = new IonosphereApp({
      hostname: "mx.test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      pop3sPort: 0,
      certSource: selfSignedCertSource({ commonName: "mx.test.local", sans: ["mx.test.local"], dir: tlsDir }),
      runMtaWorker: false,
      resolver: offlineResolver(),
    });
    await app.start();
    const { tenantId } = await app.store.createTenant("t");
    const { accountId } = await app.store.createAccount({ tenantId, email: "u@test.local" });
    await createCredential(app.db, { accountId, password: PASS });
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
    rmSync(tlsDir, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("995(POP3S)가 열린다", () => {
    expect(app.pop3sPort).toBeGreaterThan(0);
    expect(app.pop3sPort).not.toBe(app.pop3Port);
  });

  test("★110 평문: CAPA가 인증 수단을 광고하지 않는다", async () => {
    const lines = await talk(app.pop3Port, false, ["CAPA"]);
    const caps = lines.join("\n");
    expect(caps).toContain("UIDL"); // 다른 능력은 그대로
    expect(caps).not.toContain("USER");
    expect(caps).not.toContain("SASL");
  });

  test("★110 평문: USER/PASS가 거부된다 — 비밀번호가 평문으로 흐르지 않는다", async () => {
    const lines = await talk(app.pop3Port, false, ["USER u@test.local", "PASS " + PASS]);
    expect(lines.some((l) => l.startsWith("-ERR") && l.includes("TLS required"))).toBe(true);
    // 인증 성공(+OK)이 절대 나오면 안 된다
    expect(lines.filter((l) => l.startsWith("+OK")).length).toBeLessThanOrEqual(1); // 인사말뿐
  });

  test("★110 평문: SASL AUTH도 거부된다", async () => {
    const lines = await talk(app.pop3Port, false, ["AUTH PLAIN"]);
    expect(lines.some((l) => l.includes("TLS required"))).toBe(true);
  });

  test("995: 정상 인증된다 — 차단은 폐지가 아니라 안전한 경로로의 이동", async () => {
    const lines = await talk(app.pop3sPort, true, ["USER u@test.local", "PASS " + PASS, "STAT"]);
    expect(lines.some((l) => l.startsWith("+OK") && l.includes("0 0"))).toBe(true); // STAT 성공
  });

  test("995: CAPA가 인증 수단을 광고한다", async () => {
    const caps = (await talk(app.pop3sPort, true, ["CAPA"])).join("\n");
    expect(caps).toContain("USER");
    // SASL 줄에 PLAIN이 있어야 한다. ★부분 문자열 `"SASL PLAIN"`으로 보지 않는다 —
    // 메커니즘이 추가되면(SCRAM-SHA-256) 줄이 `SASL SCRAM-SHA-256 PLAIN`이 되어
    // 광고가 멀쩡한데도 깨진다. 검사 대상은 "그 메커니즘이 있는가"이지 줄의 생김새가 아니다.
    const saslLine = caps.split("\n").find((l) => l.startsWith("SASL")) ?? "";
    expect(saslLine).toContain("PLAIN");
    expect(saslLine).toContain("SCRAM-SHA-256");
  });
});

describe("POP3 — TLS 미확보 구성(자체 폐쇄망·dev)", () => {
  let app: IonosphereApp;
  let blobRoot: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-pop3plain-"));
    app = new IonosphereApp({
      hostname: "mx.test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      runMtaWorker: false,
      resolver: offlineResolver(),
    }); // 인증서 없음
    await app.start();
    const { tenantId } = await app.store.createTenant("t");
    const { accountId } = await app.store.createAccount({ tenantId, email: "u@test.local" });
    await createCredential(app.db, { accountId, password: PASS });
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("TLS를 아예 확보 못 하면 110 인증이 살아 있다(기존 동작 보존)", async () => {
    const lines = await talk(app.pop3Port, false, ["USER u@test.local", "PASS " + PASS, "STAT"]);
    expect(lines.some((l) => l.startsWith("+OK") && l.includes("0 0"))).toBe(true);
  });
});
