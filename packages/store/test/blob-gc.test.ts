/**
 * 블롭 2단계 GC (SCHEMA.md §9-5).
 *
 * 여기서 고정하는 것은 "지운다"가 아니라 **"지우면 안 되는 것을 안 지운다"** 쪽이다.
 * 블롭 파일이 사라지면 메일 본문이 사라진다 — 되돌릴 수 없다. 그래서 참조 있는 블롭,
 * 발송 대기 중인 블롭, 유예가 안 지난 블롭, 그리고 부활한 블롭이 살아남는지를 먼저 본다.
 */
import { afterEach, beforeEach, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { allMigrations, BLOB_STATUS, migrate, MTA_QUEUE_STATUS, openSqlite, REF_KIND, type DbDriver } from "@ionosphere/db";
import { ulid } from "@ionosphere/core";
import { FsBlobStore, putBlob, runBlobGc } from "../src/index.ts";

const HOUR = 3600_000;

let db: DbDriver;
let root: string;
let blobs: FsBlobStore;

/** blobs.id 경로(hash/generation) — 파일 존재 확인용. */
function filePath(blobId: string, generation: number): string {
  return join(root, blobId.slice(0, 2), blobId, String(generation));
}

async function ledger(blobId: string): Promise<{ status: number; generation: number } | null> {
  const { rows } = await db.query({ sql: "SELECT status, generation FROM blobs WHERE id = ?", params: [blobId] });
  const r = rows[0];
  return r ? { status: Number(r.status), generation: Number(r.generation) } : null;
}

/** 원장 행 + 참조를 직접 심는다(스토어 전체 경로를 태우지 않고 GC만 보기 위해). */
async function seedBlob(
  content: string,
  ref: { kind: number; refId: string; accountId?: string } | null,
  createdAt = Date.now(),
): Promise<string> {
  const bytes = new TextEncoder().encode(content);
  const { blobId, size, generation } = await putBlob(db, blobs, bytes);
  const stmts = [
    {
      sql: db.insertIgnore("blobs", ["id", "size_bytes", "backend", "status", "generation", "created_at"]),
      params: [blobId, size, 0, BLOB_STATUS.live, generation, createdAt],
    },
  ];
  if (ref) {
    stmts.push({
      sql: db.insertIgnore("blob_refs", ["blob_id", "account_id", "ref_kind", "ref_id", "created_at"]),
      params: [blobId, ref.accountId ?? "acct", ref.kind, ref.refId, createdAt],
    });
  }
  await db.batch(stmts);
  return blobId;
}

async function insertQueueRow(id: string, blobId: string, status: number): Promise<void> {
  await db.batch([
    {
      sql: `INSERT INTO mta_queue (id, tenant_id, account_id, submission_id, blob_id, env_from, verp_token, rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, last_error, created_at)
            VALUES (?, ?, NULL, NULL, ?, ?, NULL, ?, ?, ?, 0, ?, NULL, NULL, ?)`,
      params: [id, ulid(), blobId, "s@x.test", "r@y.test", "y.test", status, Date.now(), Date.now()],
    },
  ]);
}

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), "ionosphere-blobgc-"));
  blobs = new FsBlobStore(root);
  db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
});

afterEach(async () => {
  await db.close();
  rmSync(root, { recursive: true, force: true });
});

describe("블롭 GC — 지우면 안 되는 것", () => {
  test("메시지 참조가 있으면 doomed로 찍지 않는다", async () => {
    const id = await seedBlob("kept", { kind: REF_KIND.message, refId: ulid() });
    const r = await runBlobGc(db, blobs, "sweep", { graceMs: 0 });
    expect(r.doomed).toBe(0);
    expect(r.swept).toBe(0);
    expect((await ledger(id))!.status).toBe(BLOB_STATUS.live);
    expect(existsSync(filePath(id, 0))).toBe(true);
  });

  test("발송 대기 중(queued)인 큐 블롭은 참조가 유지된다", async () => {
    const queueId = ulid();
    const id = await seedBlob("in-flight", { kind: REF_KIND.queue, refId: queueId });
    await insertQueueRow(queueId, id, MTA_QUEUE_STATUS.queued);

    const r = await runBlobGc(db, blobs, "sweep", { graceMs: 0 });
    expect(r.releasedQueue).toBe(0);
    expect(r.swept).toBe(0);
    expect(existsSync(filePath(id, 0))).toBe(true);
  });

  test("유예가 안 지난 doomed 블롭은 파일을 지우지 않는다", async () => {
    const id = await seedBlob("young", null);
    const first = await runBlobGc(db, blobs, "sweep", { graceMs: HOUR });
    expect(first.doomed).toBe(1);
    expect(first.swept).toBe(0); // 방금 doomed — 유예 안 지남
    expect(existsSync(filePath(id, 0))).toBe(true);
    expect((await ledger(id))!.status).toBe(BLOB_STATUS.doomed);
  });

  test("mark 수위는 파일을 절대 지우지 않는다(기본값)", async () => {
    const id = await seedBlob("marked", null, Date.now() - 48 * HOUR);
    await runBlobGc(db, blobs, "mark", { graceMs: 0, now: Date.now() - HOUR });
    const after = await runBlobGc(db, blobs, "mark", { graceMs: 0 });
    expect(after.swept).toBe(0);
    expect(existsSync(filePath(id, 0))).toBe(true);
  });

  test("업로드 참조는 TTL 안이면 살아남는다", async () => {
    const id = await seedBlob("fresh-upload", { kind: REF_KIND.upload, refId: "u" }, Date.now());
    const r = await runBlobGc(db, blobs, "sweep", { graceMs: 0, uploadTtlMs: HOUR });
    expect(r.expiredUploads).toBe(0);
    expect(existsSync(filePath(id, 0))).toBe(true);
  });
});

describe("블롭 GC — 회수", () => {
  test("참조 0 → doomed → 유예 후 파일 삭제 + swept 툼스톤(행은 남는다)", async () => {
    const id = await seedBlob("orphan", null);

    const marked = await runBlobGc(db, blobs, "sweep", { graceMs: HOUR });
    expect(marked.doomed).toBe(1);

    // 유예가 지난 시점으로 이동
    const swept = await runBlobGc(db, blobs, "sweep", { graceMs: HOUR, now: Date.now() + 2 * HOUR });
    expect(swept.swept).toBe(1);
    expect(existsSync(filePath(id, 0))).toBe(false);

    const row = await ledger(id);
    expect(row).not.toBeNull(); // ★툼스톤: 행을 지우면 라이터가 gen 0에 다시 써서 레이스가 살아난다
    expect(row!.status).toBe(BLOB_STATUS.swept);
  });

  test("배달이 끝난 큐 항목은 참조를 놓아준다 — 단 큐 행 자체는 남는다(과금·레이트리밋 근거)", async () => {
    const queueId = ulid();
    const id = await seedBlob("delivered", { kind: REF_KIND.queue, refId: queueId });
    await insertQueueRow(queueId, id, MTA_QUEUE_STATUS.done);

    const r = await runBlobGc(db, blobs, "sweep", { graceMs: HOUR });
    expect(r.releasedQueue).toBe(1);
    expect(r.doomed).toBe(1);

    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM mta_queue WHERE id = ?", params: [queueId] });
    expect(Number(rows[0]!.n)).toBe(1); // 큐 행은 보존
  });

  test("TTL이 지난 업로드는 참조가 만료돼 회수 대상이 된다", async () => {
    const id = await seedBlob("stale-upload", { kind: REF_KIND.upload, refId: "u2" }, Date.now() - 48 * HOUR);
    const r = await runBlobGc(db, blobs, "sweep", { graceMs: 0, uploadTtlMs: HOUR });
    expect(r.expiredUploads).toBe(1);
    expect(r.doomed).toBe(1);
  });
});

describe("블롭 GC — 부활(라이터 레이스)", () => {
  test("doomed 블롭에 같은 내용이 다시 들어오면 다음 세대에 쓰고, GC는 옛 세대만 지운다", async () => {
    const content = new TextEncoder().encode("resurrect me");
    const id = await seedBlob("resurrect me", null);

    // 1단계: 참조 0 → doomed
    await runBlobGc(db, blobs, "mark", {});
    expect((await ledger(id))!.status).toBe(BLOB_STATUS.doomed);

    // 라이터가 같은 내용을 다시 저장 — putBlob이 doomed를 보고 gen 1을 고른다
    const again = await putBlob(db, blobs, content);
    expect(again.generation).toBe(1);
    expect(existsSync(filePath(id, 1))).toBe(true);

    // 라이터의 배치(appendMessage/enqueueMessage와 동형) — 행을 live로 되돌리고 참조를 만든다
    await db.batch([
      {
        sql: "UPDATE blobs SET status = ?, doomed_at = NULL, generation = ? WHERE id = ? AND generation <= ?",
        params: [BLOB_STATUS.live, 1, id, 1],
      },
      {
        sql: db.insertIgnore("blob_refs", ["blob_id", "account_id", "ref_kind", "ref_id", "created_at"]),
        params: [id, "acct", REF_KIND.message, ulid(), Date.now()],
      },
    ]);

    // GC가 다시 돌아도 부활한 블롭은 건드리지 않는다
    const r = await runBlobGc(db, blobs, "sweep", { graceMs: 0, now: Date.now() + 48 * HOUR });
    expect(r.swept).toBe(0);
    expect(existsSync(filePath(id, 1))).toBe(true);
    expect((await ledger(id))!.status).toBe(BLOB_STATUS.live);
  });

  test("판정과 삭제 사이에 참조가 생기면 파일을 지우지 않는다(check-and-set 가드)", async () => {
    const id = await seedBlob("late-ref", null);
    await runBlobGc(db, blobs, "mark", {}); // doomed

    // GC 2단계 직전에 참조가 생긴 상황(부활 없이 참조만)
    await db.batch([
      {
        sql: db.insertIgnore("blob_refs", ["blob_id", "account_id", "ref_kind", "ref_id", "created_at"]),
        params: [id, "acct", REF_KIND.message, ulid(), Date.now()],
      },
    ]);

    const r = await runBlobGc(db, blobs, "sweep", { graceMs: 0, now: Date.now() + 48 * HOUR });
    expect(r.swept).toBe(0);
    expect(existsSync(filePath(id, 0))).toBe(true);
  });

  test("off 수위는 아무것도 하지 않는다", async () => {
    const id = await seedBlob("untouched", null);
    const r = await runBlobGc(db, blobs, "off", { graceMs: 0 });
    expect(r).toEqual({ releasedQueue: 0, expiredUploads: 0, doomed: 0, swept: 0, bytesFreed: 0 });
    expect((await ledger(id))!.status).toBe(BLOB_STATUS.live);
  });
});
