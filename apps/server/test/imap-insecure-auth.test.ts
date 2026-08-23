/**
 * 143 평문 AUTH 차단 배선(Phase 5 보안) — imapsTls가 구성되면(라이브 구성) 평문 143에서
 * LOGINDISABLED 광고 + LOGIN/AUTHENTICATE를 NO [PRIVACYREQUIRED]로 거부해야 한다.
 * tls/imapsTls 둘 다 없는 dev/테스트에선 종전대로 평문 AUTH 허용(하위호환)은 imap-e2e가 커버.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { E2E_HOOK_TIMEOUT_MS } from "./helpers.ts";
import { connect } from "node:net";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { IonosphereApp } from "../src/app.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "../../../packages/proto-smtp/test/fixtures");
const imapsTls = { key: readFileSync(join(fixtures, "key.pem")), cert: readFileSync(join(fixtures, "cert.pem")) };

/** 평문 IMAP 한 명령 왕복 — 태그 응답 라인까지 수집. */
async function imapCmd(port: number, lines: string[]): Promise<string[]> {
  const sock = connect(port, "127.0.0.1");
  const out: string[] = [];
  let buf = "";
  const waiters: ((l: string) => void)[] = [];
  sock.on("data", (c) => {
    buf += c.toString("latin1");
    let i: number;
    while ((i = buf.indexOf("\r\n")) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 2);
      out.push(line);
      waiters.shift()?.(line);
    }
  });
  const readUntil = (pred: (l: string) => boolean) =>
    new Promise<void>((resolve) => {
      const check = (l: string) => (pred(l) ? resolve() : waiters.push(check));
      waiters.push(check);
    });
  await readUntil((l) => l.startsWith("* OK")); // greeting
  for (const cmd of lines) {
    const tag = cmd.split(" ")[0]!;
    sock.write(cmd + "\r\n");
    await readUntil((l) => l.startsWith(tag + " "));
  }
  sock.end();
  await new Promise<void>((r) => sock.on("close", () => r()));
  return out;
}

describe("143 평문 AUTH 차단 (imapsTls 구성 시)", () => {
  let app: IonosphereApp;
  let blobRoot: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-imapauth-"));
    app = new IonosphereApp({
      hostname: "test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      imapPort: 0, // 평문 143
      imapsTls, // ← 라이브 구성 재현(993 전용 TLS). 이게 있으면 143 평문 AUTH 차단돼야 함
    });
    await app.start();
    await app.createUser("u@test.local", "pw-imap");
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("CAPABILITY에 LOGINDISABLED 광고", async () => {
    const out = await imapCmd(app.imapPort, ["a CAPABILITY"]);
    const capLine = out.find((l) => l.includes("CAPABILITY"));
    expect(capLine).toContain("LOGINDISABLED");
  });

  test("평문 LOGIN → NO [PRIVACYREQUIRED] 거부", async () => {
    const out = await imapCmd(app.imapPort, ["a LOGIN u@test.local pw-imap"]);
    const resp = out.find((l) => l.startsWith("a "))!;
    expect(resp).toContain("NO");
    expect(resp).toContain("PRIVACYREQUIRED");
  });

  test("평문 AUTHENTICATE PLAIN → NO [PRIVACYREQUIRED] 거부", async () => {
    const out = await imapCmd(app.imapPort, ["a AUTHENTICATE PLAIN"]);
    const resp = out.find((l) => l.startsWith("a "))!;
    expect(resp).toContain("NO");
    expect(resp).toContain("PRIVACYREQUIRED");
  });
});
