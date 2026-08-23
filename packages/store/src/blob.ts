import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { BLOB_STATUS, lookupBlob, type DbDriver } from "@ionosphere/db";

// 원장 조회는 스키마 소유 패키지(@ionosphere/db)가 갖는다 — @ionosphere/mta도 같은 정본을 쓴다.
// 기존 호출부 호환을 위해 여기서 재수출한다.
export { lookupBlob, type BlobLedgerRow } from "@ionosphere/db";

/** BlobStore — 원본 메시지 바이트 저장 추상화 (PLAN.md §4, SCHEMA.md §1-6: 블롭은 DB 밖). */
export interface BlobPutResult {
  /** sha256 hex 64자 — blobs.id / messages.blob_id로 그대로 쓰임 (SCHEMA.md §2). */
  blobId: string;
  size: number;
  /** 실제로 기록된 세대. 읽을 때 이 값을 그대로 넘겨야 한다. */
  generation: number;
}

export interface BlobStore {
  /** `generation` 생략 시 0(신규). 부활 경로만 0이 아닌 값을 넘긴다 — putBlob() 참조. */
  put(content: Uint8Array, generation?: number): Promise<BlobPutResult>;
  get(blobId: string, generation?: number): Promise<Uint8Array>;
  /** 해당 세대의 파일을 지운다(없으면 무시). GC 2단계 전용. */
  remove(blobId: string, generation: number): Promise<void>;
}

/** 블롭 id = 내용의 sha256 hex (전역 dedup — SCHEMA.md §9-5 / 트레이드오프 §11). */
export function blobHash(content: Uint8Array): string {
  return createHash("sha256").update(content).digest("hex");
}

/** blobs.id는 언제나 서버측 `blobHash()` 출력 = sha256 소문자 hex 64자다. */
const BLOB_ID_PATTERN = /^[0-9a-f]{64}$/;

/**
 * 저장 경로 = hash/generation (SCHEMA.md §9-5) — 라이터와 GC가 파일 경로를 절대
 * 공유하지 않게 하는 세대 분리. 앞 2자를 샤드 디렉터리로 분리(단일 디렉터리 파일 폭주 방지).
 *
 * **심층방어 가드**: id 형식을 여기서 확인한다. `join()`은 `..`를 정규화하므로
 * `"../../../../etc/passwd"` 같은 id가 들어오면 root 밖의 파일을 읽고 쓴다.
 * 지금은 도달 불가다 — 클라이언트 문자열이 경로에 닿는 경로는 모두 DB 존재 확인을
 * 선행하고 `blobs.id`는 항상 `blobHash()` 결과다. 그러나 그 안전성이 **흩어진 호출부**에
 * 있었다. 조립부에 가드를 두면 새 호출부가 생겨도 규율을 다시 지킬 필요가 없다.
 */
function blobPath(root: string, blobId: string, generation: number): string {
  if (!BLOB_ID_PATTERN.test(blobId)) {
    // 통째로 넣으면 공격자가 고른 긴 문자열이 로그로 흘러간다 — 앞부분만 남긴다.
    throw new Error(`blobId가 sha256 hex 64자가 아닙니다: ${JSON.stringify(blobId.slice(0, 80))}`);
  }
  if (!Number.isInteger(generation) || generation < 0) {
    throw new Error(`generation은 0 이상 정수여야 합니다: ${generation}`);
  }
  const shard = blobId.slice(0, 2);
  return join(root, shard, blobId, String(generation));
}

/** 로컬 FS BlobStore. 세대 경로 계약(§9-5)만 지키고 GC 정책은 모른다. */
export class FsBlobStore implements BlobStore {
  private readonly root: string;

  constructor(root: string) {
    this.root = root;
  }

  async put(content: Uint8Array, generation = 0): Promise<BlobPutResult> {
    const blobId = blobHash(content);
    const path = blobPath(this.root, blobId, generation);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, content);
    return { blobId, size: content.byteLength, generation };
  }

  async get(blobId: string, generation = 0): Promise<Uint8Array> {
    const path = blobPath(this.root, blobId, generation);
    const buf = await readFile(path);
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  async remove(blobId: string, generation: number): Promise<void> {
    await rm(blobPath(this.root, blobId, generation), { force: true });
  }
}

/**
 * 블롭 저장의 정본 경로 — **파일을 먼저 쓰고, 어느 세대에 썼는지 알려준다**(SCHEMA.md §9-5 라이터 규칙).
 *
 * 왜 `blobs.put()`을 직접 부르면 안 되는가: GC가 참조 0인 블롭을 doomed로 찍고 유예 후
 * 파일을 지운다. 그 사이에 같은 내용이 다시 들어오면(전역 dedup이라 흔하다) 라이터가
 * 같은 경로(generation 0)에 쓰고 GC가 그 파일을 지우는 레이스가 생긴다 —
 * "해시가 있으니 파일도 있겠지"가 깨지고, 메시지 행만 남아 본문을 못 읽는다.
 *
 * 그래서 doomed/swept 상태면 **다음 세대 경로**에 쓴다. GC는 자기가 판정한 세대 이하만
 * 지우므로 두 경로가 절대 겹치지 않는다. 반환된 generation은 호출자가 그대로
 * `appendMessage`/`enqueueMessage`에 넘겨 blobs 행을 같은 세대로 부활시켜야 한다.
 */
export async function putBlob(db: DbDriver, blobs: BlobStore, content: Uint8Array): Promise<BlobPutResult> {
  const blobId = blobHash(content);
  const ledger = await lookupBlob(db, blobId);
  const generation =
    ledger === null || ledger.status === BLOB_STATUS.live ? (ledger?.generation ?? 0) : ledger.generation + 1;
  return blobs.put(content, generation);
}
