/**
 * 워커 동시 발송 — **느린 상대 하나가 tick 전체를 붙잡지 않는가**, 그리고
 * **같은 도메인에 여러 연결을 동시에 열지 않는가**.
 *
 * 예전엔 그룹을 완전 직렬로 돌았다. 연결 타임아웃이 30초라 느린 상대 10곳이면 5분이고,
 * 리스(5분) 안에 못 끝내면 `runTick` 주석이 적은 대로 "진행이 통째로 날아간다".
 *
 * 반대 방향의 사고도 막아야 한다: 전부 병렬로 열면 같은 상대에게 동시 연결이 쌓여
 * 레이트리밋으로 되받는다 — 그러면 큐가 오히려 느려진다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { ulid } from "@ionosphere/core";
import { MTA_QUEUE_STATUS, type DbDriver } from "@ionosphere/db";
import { SmtpServer, type SmtpBackend } from "@ionosphere/proto-smtp";
import { MtaWorker, type MxRecord } from "../src/worker.ts";
import { freshDb } from "./helpers.ts";

const RAW = new TextEncoder().encode("From: s@x.test\r\nSubject: hi\r\n\r\nbody\r\n");

let servers: SmtpServer[] = [];
afterEach(async () => {
  await Promise.all(servers.map((s) => s.close()));
  servers = [];
});

/** 동시 접속 수를 관측하는 상대 서버. `delayMs`로 느린 상대를 흉내낸다. */
async function startPeer(delayMs: number): Promise<{ port: number; peakConcurrent: () => number }> {
  let live = 0;
  let peak = 0;
  const backend: SmtpBackend = {
    verifyRecipient: async () => ({ ok: true }),
    deliver: async () => {
      live++;
      peak = Math.max(peak, live);
      if (delayMs > 0) await new Promise((r) => setTimeout(r, delayMs));
      live--;
      return { ok: true };
    },
  };
  const server = new SmtpServer({ hostname: "mx.test", maxSizeBytes: 10_000_000, backend });
  servers.push(server);
  const port = await server.listen(0, "127.0.0.1");
  return { port, peakConcurrent: () => peak };
}

async function seed(db: DbDriver, domain: string, count: number): Promise<void> {
  const now = Date.now();
  await db.batch(
    Array.from({ length: count }, (_, i) => ({
      sql: `INSERT INTO mta_queue (id, tenant_id, account_id, submission_id, blob_id, env_from, verp_token,
              rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, last_error, created_at)
            VALUES (?, 't1', NULL, NULL, ?, 'f@x.test', ?, ?, ?, ?, 0, ?, NULL, NULL, ?)`,
      // blob_id를 도메인마다 다르게 둬야 그룹이 갈린다(groupKey는 blob_id를 포함한다).
      params: [ulid(), `b-${domain}-${i}`, "0".repeat(16), `r${i}@${domain}`, domain, MTA_QUEUE_STATUS.queued, now, now],
    })),
  );
}

function worker(db: DbDriver, port: number, concurrency?: number): MtaWorker {
  return new MtaWorker({
    db,
    blobs: { get: async () => RAW },
    resolveMx: (async () => [{ exchange: "127.0.0.1", priority: 10 }]) as (d: string) => Promise<MxRecord[]>,
    ehloName: "mx.x.test",
    port,
    ...(concurrency !== undefined ? { concurrency } : {}),
  });
}

describe("워커 동시 발송", () => {
  /**
   * 서로 다른 도메인 8개 × 각 100ms. 직렬이면 800ms, 병렬이면 그 한참 아래다.
   * 값을 빡빡하게 잡으면 CI에서 흔들리므로 "직렬보다 확실히 빠르다"만 본다.
   */
  test("서로 다른 도메인은 병렬로 처리한다", async () => {
    const db = await freshDb();
    const peer = await startPeer(100);
    for (let d = 0; d < 8; d++) await seed(db, `d${d}.test`, 1);

    const started = Date.now();
    const n = await worker(db, peer.port, 8).tick();
    const elapsed = Date.now() - started;

    expect(n).toBe(8);
    expect(elapsed < 500).toBe(true); // 직렬이면 800ms 이상이다
    await db.close();
  });

  /**
   * ★반대 방향 — 같은 도메인의 그룹은 **순차**여야 한다. 한 상대에게 동시 연결을 쌓으면
   * 정중하지 않고, 상대가 레이트리밋으로 되받으면 큐가 더 느려진다.
   */
  test("같은 도메인에는 연결을 하나만 연다", async () => {
    const db = await freshDb();
    const peer = await startPeer(40);
    await seed(db, "same.test", 6); // 같은 도메인, blob_id가 달라 그룹은 6개

    const n = await worker(db, peer.port, 8).tick();
    expect(n).toBe(6);
    expect(peer.peakConcurrent()).toBe(1);
    await db.close();
  });

  test("concurrency=1이면 예전처럼 완전 직렬이다", async () => {
    const db = await freshDb();
    const peer = await startPeer(30);
    for (let d = 0; d < 4; d++) await seed(db, `s${d}.test`, 1);

    const started = Date.now();
    await worker(db, peer.port, 1).tick();
    expect(Date.now() - started >= 120).toBe(true); // 4 × 30ms
    expect(peer.peakConcurrent()).toBe(1);
    await db.close();
  });

  test("모든 행이 처리된다(병렬이어도 빠뜨리지 않는다)", async () => {
    const db = await freshDb();
    const peer = await startPeer(5);
    for (let d = 0; d < 5; d++) await seed(db, `m${d}.test`, 3);

    await worker(db, peer.port, 4).tick();
    const { rows } = await db.query({
      sql: `SELECT COUNT(*) AS n FROM mta_queue WHERE status = ${MTA_QUEUE_STATUS.done}`,
      params: [],
    });
    expect(Number(rows[0]!.n)).toBe(15);
    await db.close();
  });
});
