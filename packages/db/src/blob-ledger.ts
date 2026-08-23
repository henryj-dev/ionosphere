/**
 * `blobs` 원장 조회 — **세대 해석의 정본**.
 *
 * 왜 db 패키지인가: 블롭을 읽는 주체가 store만이 아니다. 아웃바운드 워커(@ionosphere/mta)도
 * 발송 전에 세대를 알아야 하는데, mta는 store에 의존하지 않아 같은 SQL을 손으로 복제하고 있었다.
 * 세대 해석 규칙이 바뀌면 한쪽만 고쳐져 조용히 깨지는 자리라, 스키마를 소유한 여기로 올린다
 * (CLAUDE.md 소유권 규약: 같은 변환이 두 곳에 복제되면 소유자를 정해 올린다).
 */
import type { DbDriver } from "./types.ts";

/** blobs 원장 행 — 읽기 경로가 "몇 세대를 읽어야 하는지" 알아내는 유일한 근거. */
export interface BlobLedgerRow {
  generation: number;
  status: number;
  sizeBytes: number;
}

/**
 * blobs 원장 조회. 행이 없으면 null — **파일이 있어도 원장에 없으면 없는 것으로 취급한다**
 * (GC가 보호할 수 없는 블롭이기 때문). 읽기 경로에서 generation을 0으로 가정하지 말 것:
 * GC가 doomed로 찍었다가 재수신으로 부활한 블롭은 generation+1 경로에 있다(SCHEMA.md §9-5).
 */
export async function lookupBlob(db: DbDriver, blobId: string): Promise<BlobLedgerRow | null> {
  const { rows } = await db.query({
    sql: "SELECT generation, status, size_bytes FROM blobs WHERE id = ?",
    params: [blobId],
  });
  const row = rows[0];
  return row ? { generation: Number(row.generation), status: Number(row.status), sizeBytes: Number(row.size_bytes) } : null;
}
