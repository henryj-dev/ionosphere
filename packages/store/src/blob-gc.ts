/**
 * 블롭 2단계 GC (SCHEMA.md §9-5) — 참조가 사라진 블롭 파일을 회수한다.
 *
 * 이게 없던 동안 블롭 파일은 **한 번 쓰면 영원히 남았다**. 메일을 지워도, 포워딩 사본을
 * 보내고 나서도, 업로드만 하고 버려도 디스크에서 사라지지 않았다. 정확성 문제는 아니지만
 * 디스크가 차면 결국 수신이 멈추므로 운영 문제다.
 *
 * ★단계를 나누는 이유(TOCTOU 제거):
 * 블롭 id는 내용의 sha256이고 전역 dedup이라 "지운 내용이 다시 들어오는" 일이 흔하다.
 * 단일 경로(hash 하나 = 파일 하나)라면 "GC가 참조 0을 확인 → 파일 unlink" 사이에 라이터가
 * 같은 내용을 저장하는 창이 항상 남는다. 그래서 **저장 경로에 generation을 넣고**,
 * 라이터는 doomed 상태를 보면 generation+1 경로에 쓴다(putBlob). GC는 자기가 판정한
 * generation 이하만 지운다 — 두 쪽이 같은 경로를 다투는 일 자체가 없어진다.
 *
 * ★툼스톤을 남기는 이유: 파일을 지운 뒤에도 blobs 행을 status=swept로 남긴다. 행을 지우면
 * 라이터가 "처음 보는 블롭"으로 알고 generation 0에 쓰는데, 그 경로는 방금 GC가 지운 경로라
 * 레이스가 되살아난다. 수십 바이트로 그걸 막는다.
 */
import { BLOB_STATUS, REF_KIND, TERMINAL_QUEUE_STATUSES, type DbDriver, type Statement } from "@ionosphere/db";
import type { BlobStore } from "./blob.ts";

/**
 * GC 동작 수위.
 *  - `off`   : 아무것도 하지 않는다.
 *  - `mark`  : 참조 해제 + doomed 표시까지만. **파일을 지우지 않는다** — 기본값.
 *  - `sweep` : 유예가 지난 doomed 블롭의 파일까지 지운다.
 *
 * 기본이 `mark`인 이유: 파일 삭제는 되돌릴 수 없고 실수의 대가가 메일 유실이다. 반대로
 * 미실행의 대가는 디스크 누수(복구 가능). 먼저 `mark`로 돌려 doomed 건수를 관측하고,
 * 납득한 뒤 `sweep`으로 올리는 단계적 활성화를 기본 경로로 삼는다(보안은 fail closed).
 */
export type BlobGcMode = "off" | "mark" | "sweep";

export function isBlobGcMode(v: string): v is BlobGcMode {
  return v === "off" || v === "mark" || v === "sweep";
}

export interface BlobGcOptions {
  /** doomed로 찍힌 뒤 파일을 지우기까지의 유예. 기본 24시간. */
  graceMs?: number;
  /** 메시지로 승격되지 않은 업로드 참조의 수명. 기본 24시간(RFC 8620은 서버 재량). */
  uploadTtlMs?: number;
  /** 한 회차에 처리할 블롭 수 상한. 기본 500. */
  batchSize?: number;
  /** 테스트 결정성용 시각 주입. */
  now?: number;
}

export interface BlobGcResult {
  /** 배달이 끝난 큐 항목에서 놓아준 참조 수. */
  releasedQueue: number;
  /** TTL이 지나 만료시킨 업로드 참조 수. */
  expiredUploads: number;
  /** live → doomed로 찍은 블롭 수. */
  doomed: number;
  /** 파일까지 지운 블롭 수. */
  swept: number;
  /** 회수한 바이트(원장에 기록된 size_bytes 합 — 백필된 legacy 행은 0). */
  bytesFreed: number;
}

const DEFAULT_GRACE_MS = 24 * 60 * 60 * 1000;
const DEFAULT_UPLOAD_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_BATCH = 500;

/** `IN (?, ?, ...)` 자리표시자. */
function placeholders(n: number): string {
  return new Array(n).fill("?").join(", ");
}

/**
 * GC 한 회차. `mode`가 `off`면 아무 일도 하지 않는다.
 *
 * 순서에 의미가 있다: 참조를 먼저 놓아주고(1·2) → 참조 0을 doomed로 찍고(3) → 유예가 지난
 * 것만 파일을 지운다(4). 같은 회차에서 방금 doomed가 된 블롭이 곧바로 지워지는 일은 없다
 * (doomed_at + grace 조건 때문) — 유예는 "판정이 틀렸을 때 되돌릴 시간"이므로 반드시 필요하다.
 */
export async function runBlobGc(
  db: DbDriver,
  blobs: BlobStore,
  mode: BlobGcMode,
  opts: BlobGcOptions = {},
): Promise<BlobGcResult> {
  const result: BlobGcResult = { releasedQueue: 0, expiredUploads: 0, doomed: 0, swept: 0, bytesFreed: 0 };
  if (mode === "off") return result;

  const now = opts.now ?? Date.now();
  const graceMs = opts.graceMs ?? DEFAULT_GRACE_MS;
  const uploadTtlMs = opts.uploadTtlMs ?? DEFAULT_UPLOAD_TTL_MS;
  const batchSize = opts.batchSize ?? DEFAULT_BATCH;

  result.releasedQueue = await releaseTerminalQueueRefs(db);
  result.expiredUploads = await expireUploadRefs(db, now - uploadTtlMs);
  result.doomed = await markDoomed(db, now, batchSize);
  if (mode === "sweep") {
    const swept = await sweepDoomed(db, blobs, now - graceMs, batchSize);
    result.swept = swept.count;
    result.bytesFreed = swept.bytes;
  }
  return result;
}

/**
 * 1) 배달이 끝난 큐 항목의 블롭 참조를 놓아준다.
 *
 * mta_queue 행 자체는 지우지 않는다 — 레이트리밋 윈도우·바운스율 집계·사용량 과금이 그 행을
 * 읽기 때문이다. 놓아주는 건 **본문에 대한 참조**뿐이고, 종료 상태(done/bounced/canceled)에
 * 도달했다면 본문을 다시 읽을 경로가 없다. 실제 파일 삭제는 여기서 일어나지 않고
 * doomed + 유예를 거치므로, 판정이 틀렸어도 되돌릴 시간이 있다.
 */
async function releaseTerminalQueueRefs(db: DbDriver): Promise<number> {
  const [res] = await db.batch([
    {
      sql: `DELETE FROM blob_refs
             WHERE ref_kind = ${REF_KIND.queue}
               AND ref_id IN (SELECT id FROM mta_queue WHERE status IN (${placeholders(TERMINAL_QUEUE_STATUSES.length)}))`,
      params: [...TERMINAL_QUEUE_STATUSES],
    },
  ]);
  return res?.changes ?? 0;
}

/** 2) 메시지로 승격되지 않은 업로드 참조를 TTL로 만료시킨다(RFC 8620 §6.1 — 서버 재량). */
async function expireUploadRefs(db: DbDriver, cutoff: number): Promise<number> {
  const [res] = await db.batch([
    {
      sql: `DELETE FROM blob_refs WHERE ref_kind = ${REF_KIND.upload} AND created_at < ?`,
      params: [cutoff],
    },
  ]);
  return res?.changes ?? 0;
}

/**
 * 3) GC 1단계 — 참조가 0인 live 블롭을 doomed로 찍는다.
 *
 * 후보를 먼저 읽고 id별 **단일 문장 check-and-set**으로 갱신한다(§9-5 2단계 규율).
 * 후보 선정과 갱신 사이에 참조가 생겼으면 `NOT EXISTS` 가드가 그 행만 통과시키지 않는다 —
 * 영향 행 수가 곧 승인 신호다. 서브쿼리에 LIMIT을 넣지 않는 건 방언 호환(MySQL) 때문이다.
 */
async function markDoomed(db: DbDriver, now: number, limit: number): Promise<number> {
  const { rows } = await db.query({
    sql: `SELECT id FROM blobs
           WHERE status = ${BLOB_STATUS.live}
             AND NOT EXISTS (SELECT 1 FROM blob_refs r WHERE r.blob_id = blobs.id)
           LIMIT ${limit}`,
  });
  if (rows.length === 0) return 0;

  const stmts: Statement[] = rows.map((r) => ({
    sql: `UPDATE blobs SET status = ${BLOB_STATUS.doomed}, doomed_at = ?
           WHERE id = ? AND status = ${BLOB_STATUS.live}
             AND NOT EXISTS (SELECT 1 FROM blob_refs r WHERE r.blob_id = blobs.id)`,
    params: [now, String(r.id)],
  }));
  const results = await db.batch(stmts);
  return results.reduce((n, r) => n + r.changes, 0);
}

/**
 * 4) GC 2단계 — 유예가 지난 doomed 블롭의 파일을 지운다.
 *
 * **툼스톤 표시가 먼저, 파일 삭제가 나중**인 순서가 핵심이다. status=swept로 바꾸는 가드된
 * UPDATE가 원자적 관문 역할을 한다 — 통과했다면 그 시점 이후의 라이터는 putBlob에서
 * generation+1 경로를 고르므로, 우리가 generation 이하 파일을 지우는 동안 라이터와 부딪히지
 * 않는다. 반대 순서(삭제 먼저)로 하면 삭제와 표시 사이에 부활한 블롭의 파일을 지우게 된다.
 *
 * 알려진 대가: 표시 직후 프로세스가 죽으면 파일이 남는다(원장은 swept). 다음 회차가 그 행을
 * 다시 보지 않으므로 그 파일은 누수로 남는다 — 유실보다 누수를 택한 의도적 트레이드오프다.
 */
async function sweepDoomed(
  db: DbDriver,
  blobs: BlobStore,
  cutoff: number,
  limit: number,
): Promise<{ count: number; bytes: number }> {
  const { rows } = await db.query({
    sql: `SELECT id, generation, size_bytes FROM blobs
           WHERE status = ${BLOB_STATUS.doomed} AND doomed_at IS NOT NULL AND doomed_at < ?
           LIMIT ${limit}`,
    params: [cutoff],
  });
  let count = 0;
  let bytes = 0;
  for (const row of rows) {
    const id = String(row.id);
    const generation = Number(row.generation);
    const [res] = await db.batch([
      {
        sql: `UPDATE blobs SET status = ${BLOB_STATUS.swept}
               WHERE id = ? AND status = ${BLOB_STATUS.doomed} AND generation = ?
                 AND NOT EXISTS (SELECT 1 FROM blob_refs r WHERE r.blob_id = blobs.id)`,
        params: [id, generation],
      },
    ]);
    if ((res?.changes ?? 0) === 0) continue; // 부활했거나 세대가 올라갔다 — 건드리지 않는다
    // 이 세대 **이하** 전부. 부활을 거친 블롭은 중간 세대 파일이 남아 있을 수 있다.
    for (let g = 0; g <= generation; g++) await blobs.remove(id, g);
    count++;
    bytes += Number(row.size_bytes);
  }
  return { count, bytes };
}
