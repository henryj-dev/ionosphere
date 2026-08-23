/**
 * 내부 전용 모드(`IONOSPHERE_LOCAL_ONLY=1`) — 외부 도메인 발송을 **즉시** 거절한다.
 *
 * 왜 필요한가: 아웃바운드 25가 막혔고 스마트호스트도 없으면, 외부 수신자는 큐에 적재된 뒤
 * 재시도만 반복하다 몇 시간 뒤에야 바운스된다. 그동안 사용자는 "보냈다"고 믿는다 —
 * 조용한 실패다. 어차피 나갈 수 없다면 보낸 순간 알려주는 게 낫다.
 *
 * ★여기서 가장 중요한 계약: **SMTP와 JMAP이 같은 판정을 한다**. 발송 정책을 갈래마다 손으로
 * 재작성하면 한쪽만 빠지고, 그게 과거 JMAP만 레이트리밋을 우회했던 사고와 같은 종류다.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ulid } from "@ionosphere/core";
import { createCredential } from "@ionosphere/store";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

let app: IonosphereApp;
let blobRoot: string;
const PASS = "pw-local-only";

/** RCPT TO 응답까지만 진행해 코드를 돌려준다(제출 프로파일, AUTH 후). */
function rcptCode(port: number, rcpt: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = connect(port, "127.0.0.1");
    sock.setEncoding("utf8");
    let buf = "";
    let stage = 0;
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error("timeout"));
    }, 15_000);
    const auth = Buffer.from(`\0user@test.local\0${PASS}`).toString("base64");
    sock.on("data", (c: string) => {
      buf += c;
      let i: number;
      while ((i = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (stage === 0) {
          stage = 1;
          sock.write("EHLO c\r\n");
        } else if (stage === 1 && line.startsWith("250 ")) {
          stage = 2;
          sock.write(`AUTH PLAIN ${auth}\r\n`);
        } else if (stage === 2) {
          if (!line.startsWith("235")) {
            clearTimeout(timer);
            sock.destroy();
            reject(new Error("auth failed: " + line));
            return;
          }
          stage = 3;
          sock.write("MAIL FROM:<user@test.local>\r\n");
        } else if (stage === 3) {
          stage = 4;
          sock.write(`RCPT TO:<${rcpt}>\r\n`);
        } else if (stage === 4) {
          clearTimeout(timer);
          sock.write("QUIT\r\n");
          sock.end();
          resolve(line);
          return;
        }
      }
    });
    sock.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-localonly-"));
  app = new IonosphereApp({
    hostname: "test.local",
    dbPath: ":memory:",
    blobRoot,
    smtpPort: 0,
    pop3Port: 0,
    submissionPort: 0,
    localOnly: true,
    runMtaWorker: false,
    resolver: offlineResolver(),
  });
  await app.start();
  const { tenantId } = await app.store.createTenant("t");
  const { accountId } = await app.store.createAccount({ tenantId, email: "user@test.local" });
  await createCredential(app.db, { accountId, password: PASS });
  // 발신 도메인 게이트(§8 ②)를 통과하려면 검증된 도메인이 있어야 한다.
  await app.db.batch([
    {
      sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, ?, 1, ?, ?)",
      params: [ulid(), tenantId, "test.local", Date.now(), Date.now()],
    },
  ]);
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("내부 전용 모드 — SMTP submission", () => {
  test("로컬 수신자는 RCPT 통과", async () => {
    expect(await rcptCode(app.submissionPort, "user@test.local")).toStartWith("250");
  });

  test("외부 수신자는 RCPT에서 즉시 550 — 큐에 쌓아두지 않는다", async () => {
    const code = await rcptCode(app.submissionPort, "someone@gmail.com");
    expect(code).toStartWith("550");
    // DATA까지 가지 않았으므로 큐에도 아무것도 없어야 한다
    const { rows } = await app.db.query({ sql: "SELECT COUNT(*) AS n FROM mta_queue" });
    expect(Number(rows[0]!.n)).toBe(0);
  });
});

describe("내부 전용 모드 — enqueue 게이트(모든 갈래의 정본)", () => {
  test("외부 도메인은 적재 자체가 거부된다(external-disabled)", async () => {
    const { enqueueMessage, OutboundRejectedError } = await import("@ionosphere/mta");
    const { rows } = await app.db.query({ sql: "SELECT id FROM tenants LIMIT 1" });
    const tenantId = String(rows[0]!.id);
    let err: unknown;
    try {
      await enqueueMessage(
        app.db,
        {
          tenantId,
          blobId: "b".repeat(64),
          sizeBytes: 10,
          envFrom: "user@test.local",
          rcpts: ["out@example.com"],
        },
        { localOnly: true },
      );
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(OutboundRejectedError);
    expect((err as InstanceType<typeof OutboundRejectedError>).reason).toBe("external-disabled");
  });

  test("시스템 발송(internal)은 게이트를 우회한다 — 막으면 바운스 반송조차 사라진다", async () => {
    const { enqueueMessage } = await import("@ionosphere/mta");
    const { rows } = await app.db.query({ sql: "SELECT id FROM tenants LIMIT 1" });
    const r = await enqueueMessage(
      app.db,
      {
        tenantId: String(rows[0]!.id),
        blobId: "c".repeat(64),
        sizeBytes: 10,
        envFrom: "bounce@origin.example",
        rcpts: ["victim@origin.example"],
        system: { relayPerHour: 100, envFrom: "srs" },
      },
      { localOnly: true },
    );
    expect(r.queuedIds).toHaveLength(1);
  });

  test("localOnly가 꺼져 있으면 외부 도메인도 정상 적재된다(기본 동작 불변)", async () => {
    const { enqueueMessage } = await import("@ionosphere/mta");
    const { rows } = await app.db.query({ sql: "SELECT id FROM tenants LIMIT 1" });
    const r = await enqueueMessage(app.db, {
      tenantId: String(rows[0]!.id),
      blobId: "d".repeat(64),
      sizeBytes: 10,
      envFrom: "user@test.local",
      rcpts: ["out@example.com"],
    });
    expect(r.queuedIds).toHaveLength(1);
  });
});
