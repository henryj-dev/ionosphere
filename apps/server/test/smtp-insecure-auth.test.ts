/**
 * 587 submission 평문 AUTH 차단(Phase 5 보안) — 보안 submission 경로(465 smtpsTls=imapsTls 또는
 * 전역 tls)가 구성되면 587 평문 회선에서 AUTH를 광고하지 않고(502) 거부해야 한다(RFC 4954).
 * tls/imapsTls 둘 다 없는 dev/테스트는 종전대로 평문 AUTH 허용(기존 submission 테스트가 커버).
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

/** 평문 SMTP 왕복 — 각 명령 후 응답 라인(멀티라인은 "NNN " 종결까지) 수집. */
async function smtp(port: number, cmds: string[]): Promise<string[]> {
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
  const readFinal = () =>
    new Promise<void>((resolve) => {
      const check = (l: string) => (/^\d{3} /.test(l) ? resolve() : waiters.push(check));
      waiters.push(check);
    });
  await readFinal(); // 220 greeting
  for (const cmd of cmds) {
    sock.write(cmd + "\r\n");
    await readFinal();
  }
  sock.end();
  await new Promise<void>((r) => sock.on("close", () => r()));
  return out;
}

describe("587 평문 AUTH 차단 (imapsTls/465 보안 경로 구성 시)", () => {
  let app: IonosphereApp;
  let blobRoot: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-smtpauth-"));
    app = new IonosphereApp({
      hostname: "test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      submissionPort: 0, // 평문 587
      imapsTls, // ← 465 smtpsTls로 이어짐 = 보안 submission 경로 존재 → 587 평문 AUTH 차단
      runMtaWorker: false,
    });
    await app.start();
    await app.createUser("u@test.local", "pw-smtp");
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("EHLO가 평문 587에서 AUTH를 광고하지 않음", async () => {
    const out = await smtp(app.submissionPort, ["EHLO client.test"]);
    expect(out.some((l) => l.toUpperCase().includes("AUTH"))).toBe(false);
  });

  test("평문 AUTH 명령 → 502 거부", async () => {
    const out = await smtp(app.submissionPort, ["EHLO client.test", "AUTH LOGIN"]);
    const resp = out[out.length - 1]!;
    expect(resp).toStartWith("502");
  });
});
