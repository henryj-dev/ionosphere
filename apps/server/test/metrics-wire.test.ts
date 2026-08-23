/** 관측성 조립 배선 — 실제 수신 배달 → /metrics에 received 증가 + 큐 깊이 수집기 동작. */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

/** 최소 SMTP 송신 — 한 통을 로컬 수신자에게 배달(응답 프리픽스만 확인). */
async function sendOne(port: number, from: string, to: string, data: string): Promise<void> {
  const sock = connect(port, "127.0.0.1");
  let buf = "";
  const pending: ((line: string) => void)[] = [];
  sock.on("data", (c) => {
    buf += c.toString("latin1");
    let i: number;
    while ((i = buf.indexOf("\r\n")) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 2);
      pending.shift()?.(line);
    }
  });
  const expect2 = (prefix: string) =>
    new Promise<void>((resolve, reject) => {
      pending.push((line) => (line.startsWith(prefix) ? resolve() : reject(new Error(`기대 ${prefix}, 실제 ${line}`))));
    });
  const send = (s: string) => sock.write(s);
  await expect2("220");
  send("EHLO client.test\r\n");
  // EHLO 멀티라인 — "250 "(마지막)까지 소비
  await new Promise<void>((resolve) => {
    const onLine = (line: string) => {
      if (line.startsWith("250 ")) resolve();
      else pending.unshift(onLine);
    };
    pending.push(onLine);
  });
  send(`MAIL FROM:<${from}>\r\n`);
  await expect2("250");
  send(`RCPT TO:<${to}>\r\n`);
  await expect2("250");
  send("DATA\r\n");
  await expect2("354");
  send(data.replace(/\r?\n/g, "\r\n") + "\r\n.\r\n");
  await expect2("250");
  send("QUIT\r\n");
  sock.end();
  await new Promise<void>((resolve) => sock.on("close", () => resolve()));
}

describe("metrics 조립 배선", () => {
  let app: IonosphereApp;
  let blobRoot: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-metrics-"));
    app = new IonosphereApp({
      hostname: "test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      metricsPort: 0,
      resolver: offlineResolver(),
    });
    await app.start();
    await app.createUser("rcpt@test.local", "pw-metrics");
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("메트릭 패밀리 노출 + 큐 깊이 수집기(0)", async () => {
    const res = await fetch(`http://127.0.0.1:${app.metricsPort}/metrics`);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("# TYPE ionosphere_received_messages_total counter");
    expect(body).toContain("# TYPE ionosphere_delivery_total counter");
    expect(body).toContain("ionosphere_queue_depth 0"); // 수집기가 실제 mta_queue 질의
  });

  test("수신 배달 → ionosphere_received_messages_total 증가", async () => {
    await sendOne(app.smtpPort, "sender@remote.test", "rcpt@test.local", "Subject: hi\r\n\r\nbody\r\n");
    const body = await (await fetch(`http://127.0.0.1:${app.metricsPort}/metrics`)).text();
    // "ionosphere_received_messages_total N" — N >= 1
    const m = body.match(/^ionosphere_received_messages_total (\d+)$/m);
    expect(m).not.toBeNull();
    expect(Number(m![1])).toBeGreaterThanOrEqual(1);
  });
});
