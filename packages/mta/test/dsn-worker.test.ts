/**
 * 워커의 DSN 발송 배선 — **언제 보내고 언제 보내지 않는가**가 전부다.
 *
 * 잘못 보내면 이중 바운스 루프이거나 "아직 배달될 수 있는 메일에 실패 통보"가 되고,
 * 안 보내면 발신자가 실패를 영영 모른다(이 기능이 생긴 이유).
 *
 * 상대는 worker.test.ts와 같이 실제 `SmtpServer`를 쓴다 — 가짜 소켓을 새로 만들면
 * 프로토콜 왕복이 실제와 갈라진다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { ulid } from "@ionosphere/core";
import { MTA_QUEUE_STATUS, type DbDriver } from "@ionosphere/db";
import { parseMessage } from "@ionosphere/mime";
import { SmtpServer, type SmtpBackend } from "@ionosphere/proto-smtp";
import { MtaWorker, type MxRecord } from "../src/worker.ts";
import { freshDb } from "./helpers.ts";

const RAW = new TextEncoder().encode(
  "From: sender@x.test\r\nTo: r@remote.test\r\nSubject: hi\r\nMessage-ID: <o@x.test>\r\n\r\nbody\r\n",
);
const BLOB_ID = "b".repeat(64);

let servers: SmtpServer[] = [];
afterEach(async () => {
  await Promise.all(servers.map((s) => s.close()));
  servers = [];
});

/** 수신자 검증 결과를 지정할 수 있는 상대 서버. */
async function startPeer(rcpt: { ok: true } | { ok: false; code: number; enhanced: string; message: string }): Promise<number> {
  const backend: SmtpBackend = {
    verifyRecipient: async () => rcpt,
    deliver: async () => ({ ok: true }),
  };
  const server = new SmtpServer({ hostname: "mx.test", maxSizeBytes: 10_000_000, backend });
  servers.push(server);
  return server.listen(0, "127.0.0.1");
}

const mxToLocalhost = (): ((d: string) => Promise<MxRecord[]>) => async () => [{ exchange: "127.0.0.1", priority: 10 }];

async function seedQueue(db: DbDriver, opts: { envFrom: string; attempts?: number }): Promise<string> {
  const id = ulid();
  const now = Date.now();
  await db.batch([
    {
      sql: `INSERT INTO mta_queue (id, tenant_id, account_id, submission_id, blob_id, env_from, verp_token,
              rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, last_error, created_at)
            VALUES (?, ?, NULL, NULL, ?, ?, ?, 'r@remote.test', 'remote.test', ?, ?, ?, NULL, NULL, ?)`,
      params: [id, ulid(), BLOB_ID, opts.envFrom, "0".repeat(16), MTA_QUEUE_STATUS.queued, opts.attempts ?? 0, now, now],
    },
  ]);
  return id;
}

interface Sent {
  tenantId: string;
  to: string;
  message: Uint8Array;
}

function worker(db: DbDriver, port: number, sent: Sent[] | null, maxAttempts = 8): MtaWorker {
  return new MtaWorker({
    db,
    blobs: { get: async () => RAW },
    resolveMx: mxToLocalhost(),
    ehloName: "mx.x.test",
    port,
    maxAttempts,
    ...(sent
      ? {
          dsn: {
            send: async (input) => {
              sent.push(input);
            },
          },
        }
      : {}),
  });
}

async function statusOf(db: DbDriver, id: string): Promise<number> {
  const { rows } = await db.query({ sql: "SELECT status FROM mta_queue WHERE id = ?", params: [id] });
  return Number(rows[0]!.status);
}

const REJECT = { ok: false as const, code: 550, enhanced: "5.1.1", message: "no such user" };
const DEFER = { ok: false as const, code: 451, enhanced: "4.3.0", message: "try later" };

describe("워커 DSN 발송", () => {
  test("영구 거절(5xx) → 발신자에게 바운스", async () => {
    const db = await freshDb();
    const id = await seedQueue(db, { envFrom: "sender@x.test" });
    const sent: Sent[] = [];
    await worker(db, await startPeer(REJECT), sent).tick();

    expect(sent).toHaveLength(1);
    expect(sent[0]!.to).toBe("sender@x.test");
    const p = parseMessage(sent[0]!.message);
    expect(p.subject).toBe("Undelivered Mail Returned to Sender");
    const body = Buffer.from(sent[0]!.message).toString("latin1");
    expect(body).toContain("Final-Recipient: rfc822; r@remote.test");
    expect(body).toContain("Action: failed");
    expect(body).toContain("no such user"); // 원격 사유가 전달돼야 진단이 된다
    expect(await statusOf(db, id)).toBe(MTA_QUEUE_STATUS.bounced);
  });

  /**
   * ★이중 바운스 차단. 봉투 발신자가 null이면 그 메시지 자체가 이미 바운스이거나 시스템
   * 발송이다(`enqueue.ts` SystemRelay.envFrom:"null-sender") — 거기에 또 바운스를 보내면
   * 무한 반사가 된다.
   */
  test("null 발신자(`<>`)에는 보내지 않는다 — 이중 바운스 차단", async () => {
    const db = await freshDb();
    const id = await seedQueue(db, { envFrom: "" });
    const sent: Sent[] = [];
    await worker(db, await startPeer(REJECT), sent).tick();

    expect(sent).toHaveLength(0);
    expect(await statusOf(db, id)).toBe(MTA_QUEUE_STATUS.bounced); // 큐 행은 그래도 닫힌다
  });

  /** 아직 배달될 수 있는 메일에 실패 통보를 보내면 사용자가 두 번 보낸다. */
  test("일시 실패(4xx) 재시도 중에는 보내지 않는다", async () => {
    const db = await freshDb();
    const id = await seedQueue(db, { envFrom: "sender@x.test" });
    const sent: Sent[] = [];
    await worker(db, await startPeer(DEFER), sent).tick();

    expect(sent).toHaveLength(0);
    expect(await statusOf(db, id)).toBe(MTA_QUEUE_STATUS.deferred);
  });

  test("재시도 상한을 소진하면 보낸다", async () => {
    const db = await freshDb();
    await seedQueue(db, { envFrom: "sender@x.test", attempts: 7 });
    const sent: Sent[] = [];
    await worker(db, await startPeer(DEFER), sent, 8).tick();

    expect(sent).toHaveLength(1);
    expect(Buffer.from(sent[0]!.message).toString("latin1")).toContain("max attempts exhausted");
  });

  test("성공 배달에는 보내지 않는다", async () => {
    const db = await freshDb();
    const id = await seedQueue(db, { envFrom: "sender@x.test" });
    const sent: Sent[] = [];
    await worker(db, await startPeer({ ok: true }), sent).tick();

    expect(sent).toHaveLength(0);
    expect(await statusOf(db, id)).toBe(MTA_QUEUE_STATUS.done);
  });

  /** 훅을 안 주면 예전 동작 그대로 — 기존 배포·테스트와 하위호환. */
  test("dsn 훅 미지정이면 아무것도 하지 않는다", async () => {
    const db = await freshDb();
    const id = await seedQueue(db, { envFrom: "sender@x.test" });
    await worker(db, await startPeer(REJECT), null).tick(); // 던지지 않아야 한다
    expect(await statusOf(db, id)).toBe(MTA_QUEUE_STATUS.bounced);
  });

  /**
   * ★DSN 적재가 실패해도 큐 행은 **이미** 닫혀 있어야 한다. 순서가 뒤바뀌면 훅 실패가
   * 발송 결과 기록을 막아 행이 열린 채 남고, 리스 만료 후 통째로 재처리된다.
   */
  test("훅이 던져도 발송 결과 기록은 남는다", async () => {
    const db = await freshDb();
    const id = await seedQueue(db, { envFrom: "sender@x.test" });
    const w = new MtaWorker({
      db,
      blobs: { get: async () => RAW },
      resolveMx: mxToLocalhost(),
      ehloName: "mx.x.test",
      port: await startPeer(REJECT),
      dsn: {
        send: async () => {
          throw new Error("blob store down");
        },
      },
    });
    await w.tick();
    expect(await statusOf(db, id)).toBe(MTA_QUEUE_STATUS.bounced);
  });
});
