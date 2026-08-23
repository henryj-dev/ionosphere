/** WebhookWorker — 가짜 fetch로 배달 성공/재시도/실패·HMAC 서명·리스 경합 검증. */
import { describe, expect, test } from "@ionosphere/testkit";
import { createHmac } from "node:crypto";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { WebhookWorker, type FetchFn } from "../src/worker.ts";

async function freshDb(): Promise<DbDriver> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  return db;
}

let seq = 0;
async function seedDelivery(db: DbDriver, over: { url?: string; secret?: string; payload?: string; nextAttempt?: number; createdAt?: number } = {}): Promise<string> {
  const id = `D${String(++seq).padStart(25, "0")}`;
  await db.batch([
    {
      sql: `INSERT INTO webhook_deliveries (id, account_id, endpoint_id, url, secret, payload, status, attempts, next_attempt, lease_until, last_error, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, NULL, NULL, ?)`,
      params: [id, "acc", "ep", over.url ?? "https://hook.test/in", over.secret ?? "", over.payload ?? '{"event":"inbound"}', over.nextAttempt ?? 0, over.createdAt ?? 0],
    },
  ]);
  return id;
}
async function status(db: DbDriver, id: string): Promise<{ status: number; attempts: number }> {
  const { rows } = await db.query({ sql: "SELECT status, attempts FROM webhook_deliveries WHERE id = ?", params: [id] });
  return { status: Number(rows[0]!.status), attempts: Number(rows[0]!.attempts) };
}
/** 배달 행의 시크릿 사본 — 없는 행은 null(정리된 행과 비워진 행을 구분하기 위함). */
async function secretOf(db: DbDriver, id: string): Promise<string | null> {
  const { rows } = await db.query({ sql: "SELECT secret FROM webhook_deliveries WHERE id = ?", params: [id] });
  const row = rows[0];
  return row ? String(row.secret) : null;
}

describe("WebhookWorker — 처리량 상한과 동시 배달", () => {
  /** 회귀: SELECT에 LIMIT이 없어 큐 전량을 한 tick에 메모리로 올렸다. */
  test("batchSize를 넘는 행은 다음 tick으로 넘긴다", async () => {
    const db = await freshDb();
    for (let i = 0; i < 5; i++) await seedDelivery(db);
    const worker = new WebhookWorker({ db, fetch: async () => ({ status: 200 }), batchSize: 2 });

    expect(await worker.tick()).toBe(2);
    expect(await worker.tick()).toBe(2);
    expect(await worker.tick()).toBe(1);

    await db.close();
  });

  /**
   * 회귀: 배달이 완전 순차라 **응답이 느린 엔드포인트 하나가 뒤의 전부를 막았다**.
   * 타임아웃이 10초이므로 그런 대상 10개면 한 tick이 100초이고, 그 사이 리스(60초)가 만료된다.
   */
  test("느린 엔드포인트가 뒤를 막지 않는다(제한된 동시 배달)", async () => {
    const db = await freshDb();
    const DELAY_MS = 60;
    const COUNT = 8;
    for (let i = 0; i < COUNT; i++) await seedDelivery(db);

    let inFlight = 0;
    let peak = 0;
    const fetchFn: FetchFn = async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, DELAY_MS));
      inFlight--;
      return { status: 200 };
    };
    const worker = new WebhookWorker({ db, fetch: fetchFn, concurrency: 4 });

    expect(await worker.tick()).toBe(COUNT);

    // ★판정은 **동시 실행 수**로 한다. 경과 시간으로 재면 CI 부하에 따라 흔들려 플레이크가 된다
    // (이 저장소가 이미 한 번 겪은 종류의 사고다). peak > 1이면 겹쳐 돌았다는 직접 증거이고,
    // 속도는 거기서 따라온다.
    expect(peak).toBeGreaterThan(1); // 순차였다면 항상 1이다
    expect(peak).toBeLessThanOrEqual(4); // 상한을 넘지 않았는가
    expect(inFlight).toBe(0); // 전부 회수됐는가

    await db.close();
  });
});

/**
 * 회귀(감사 §8-10): 적재 시점 스냅샷이라 배달 행에는 엔드포인트 시크릿의 **평문 사본**이 남는다.
 * 정리 주체가 없으면 무한히 쌓이므로, 종료 상태에 닿는 순간 비우고 보존 기간이 지나면 행을 지운다.
 * ★핵심 회귀는 반대 방향이다 — 재시도가 남은 행의 시크릿을 비우면 다음 발송이 서명 없이 나간다.
 */
describe("WebhookWorker — 시크릿 사본 수명", () => {
  test("배달 성공(done) 시 시크릿 사본을 비운다", async () => {
    const db = await freshDb();
    const id = await seedDelivery(db, { secret: "s3cr3t" });
    await new WebhookWorker({ db, fetch: async () => ({ status: 200 }) }).tick();

    expect((await status(db, id)).status).toBe(2); // done
    expect(await secretOf(db, id)).toBe(""); // 행은 남고(관측용) 시크릿만 사라진다
    await db.close();
  });

  test("영구실패(maxAttempts 도달) 시 시크릿 사본을 비운다", async () => {
    const db = await freshDb();
    const id = await seedDelivery(db, { secret: "s3cr3t" });
    await new WebhookWorker({ db, fetch: async () => ({ status: 500 }), maxAttempts: 1 }).tick();

    expect((await status(db, id)).status).toBe(3); // failed
    expect(await secretOf(db, id)).toBe("");
    await db.close();
  });

  /** ★이걸 깨면 재시도가 서명 없이 나가 수신측이 거절한다 = 배달 실패. */
  test("재시도 대기(deferred) 중인 배달의 시크릿은 남아 있고 다음 시도에 서명된다", async () => {
    const db = await freshDb();
    const id = await seedDelivery(db, { secret: "s3cr3t", payload: '{"x":1}' });

    // 1차 시도 실패 → queued로 되돌아간다(재시도 여지 있음)
    await new WebhookWorker({ db, fetch: async () => ({ status: 503 }) }).tick();
    expect((await status(db, id)).status).toBe(0); // queued
    expect(await secretOf(db, id)).toBe("s3cr3t"); // 비우지 않았는가

    // next_attempt가 미래로 밀렸으니 due로 되돌린 뒤 2차 시도 — 서명이 붙어야 한다
    await db.batch([{ sql: "UPDATE webhook_deliveries SET next_attempt = 0 WHERE id = ?", params: [id] }]);
    let seen: Record<string, string> = {};
    await new WebhookWorker({ db, fetch: async (_u, init) => { seen = init.headers; return { status: 200 }; } }).tick();

    const expected = "sha256=" + createHmac("sha256", "s3cr3t").update('{"x":1}').digest("hex");
    expect(seen["x-mailer-signature"]).toBe(expected);
    await db.close();
  });

  test("차단된 URL(즉시 failed)도 시크릿 사본을 비운다", async () => {
    const db = await freshDb();
    const id = await seedDelivery(db, { url: "http://169.254.169.254/latest/meta-data/", secret: "s3cr3t" });
    await new WebhookWorker({ db, fetch: async () => ({ status: 200 }) }).tick();

    expect((await status(db, id)).status).toBe(3); // failed
    expect(await secretOf(db, id)).toBe("");
    await db.close();
  });
});

describe("WebhookWorker — 종료 배달 행 보존 기간", () => {
  test("보존 기간이 지난 종료 행은 지우고, 창 안의 행은 남긴다", async () => {
    const db = await freshDb();
    const now = 1_000_000_000_000;
    const retentionMs = 30 * 24 * 60 * 60 * 1000;
    const old = await seedDelivery(db, { createdAt: now - retentionMs - 1 });
    const recent = await seedDelivery(db, { createdAt: now - 1_000 });
    // 둘 다 done으로 닫는다 — 스윕 대상은 종료 상태뿐이다
    await db.batch([{ sql: `UPDATE webhook_deliveries SET status = 2 WHERE id IN (?, ?)`, params: [old, recent] }]);

    const worker = new WebhookWorker({ db, fetch: async () => ({ status: 200 }), retentionMs });
    expect(await worker.sweepRetention(now)).toBe(1);

    expect(await secretOf(db, old)).toBeNull(); // 지워졌는가
    expect(await secretOf(db, recent)).not.toBeNull(); // 창 안은 남았는가
    await db.close();
  });

  /** ★시각만으로 지우면 오래 deferred 중인(=살아 있는) 배달을 지워 이벤트를 유실시킨다. */
  test("보존 기간이 지났어도 재시도 대기 중인 행은 지우지 않는다", async () => {
    const db = await freshDb();
    const now = 1_000_000_000_000;
    const retentionMs = 1_000;
    const queued = await seedDelivery(db, { createdAt: now - retentionMs - 1 });
    // status는 seed 기본값 0(queued) 그대로 — 아직 재시도 대상이다

    const worker = new WebhookWorker({ db, fetch: async () => ({ status: 200 }), retentionMs });
    expect(await worker.sweepRetention(now)).toBe(0);
    expect(await secretOf(db, queued)).not.toBeNull();
    await db.close();
  });

  test("스윕 간격 안에서는 다시 돌지 않는다(tick마다 DELETE를 던지지 않는다)", async () => {
    const db = await freshDb();
    // 기동 직후 첫 tick은 스윕하지 않는다 — 밀린 큐를 배달할 시점에 DB를 잡지 않으려는 선택.
    const worker = new WebhookWorker({ db, fetch: async () => ({ status: 200 }), retentionMs: 0, sweepIntervalMs: 3_600_000 });
    const done = await seedDelivery(db, { createdAt: 0 });
    await db.batch([{ sql: "UPDATE webhook_deliveries SET status = 2 WHERE id = ?", params: [done] }]);

    await worker.tick();
    expect(await secretOf(db, done)).not.toBeNull(); // 간격 전이라 아직 살아 있다
    await db.close();
  });
});

describe("WebhookWorker", () => {
  test("2xx → done, HMAC 서명 헤더 부착", async () => {
    const db = await freshDb();
    const calls: { url: string; headers: Record<string, string>; body: string }[] = [];
    const fetchFn: FetchFn = async (url, init) => {
      calls.push({ url, headers: init.headers, body: init.body });
      return { status: 200 };
    };
    const id = await seedDelivery(db, { secret: "s3cr3t", payload: '{"x":1}' });
    const worker = new WebhookWorker({ db, fetch: fetchFn });
    expect(await worker.tick()).toBe(1);
    expect((await status(db, id)).status).toBe(2); // done
    expect(calls).toHaveLength(1);
    const expected = "sha256=" + createHmac("sha256", "s3cr3t").update('{"x":1}').digest("hex");
    expect(calls[0]!.headers["x-mailer-signature"]).toBe(expected);
    await db.close();
  });

  test("시크릿 없으면 서명 헤더 없음", async () => {
    const db = await freshDb();
    let seen: Record<string, string> = {};
    const id = await seedDelivery(db, { secret: "" });
    await new WebhookWorker({ db, fetch: async (_u, init) => { seen = init.headers; return { status: 204 }; } }).tick();
    expect(seen["x-mailer-signature"]).toBeUndefined();
    expect((await status(db, id)).status).toBe(2);
    await db.close();
  });

  test("5xx → 재시도(deferred), 상태 queued + attempts 증가", async () => {
    const db = await freshDb();
    const id = await seedDelivery(db);
    await new WebhookWorker({ db, fetch: async () => ({ status: 503 }) }).tick();
    const s = await status(db, id);
    expect(s.status).toBe(0); // queued(재시도 대기)
    expect(s.attempts).toBe(1);
    await db.close();
  });

  test("maxAttempts 도달 → failed", async () => {
    const db = await freshDb();
    const id = await seedDelivery(db);
    const worker = new WebhookWorker({ db, fetch: async () => ({ status: 500 }), maxAttempts: 1 });
    await worker.tick();
    expect((await status(db, id)).status).toBe(3); // failed
    await db.close();
  });

  test("fetch 예외(네트워크) → 재시도", async () => {
    const db = await freshDb();
    const id = await seedDelivery(db);
    await new WebhookWorker({ db, fetch: async () => { throw new Error("ECONNREFUSED"); } }).tick();
    const s = await status(db, id);
    expect(s.status).toBe(0);
    expect(s.attempts).toBe(1);
    await db.close();
  });

  test("due 아닌 건(next_attempt 미래)은 건너뜀", async () => {
    const db = await freshDb();
    const id = await seedDelivery(db, { nextAttempt: Date.now() + 3_600_000 });
    let called = 0;
    expect(await new WebhookWorker({ db, fetch: async () => { called++; return { status: 200 }; } }).tick()).toBe(0);
    expect(called).toBe(0);
    expect((await status(db, id)).status).toBe(0);
    await db.close();
  });
});
