import type { Statement } from "@ionosphere/db";

/**
 * D1 최소 공통분모 한도: 문장당 파라미터 100개 (SCHEMA.md §1-3).
 * 다중행 INSERT 청크 수학(§7-6)의 기준값 — 컬럼 추가 시 rowsPerStatement가
 * 자동으로 재계산되도록 상수 하드코딩을 피한다.
 */
export const MAX_PARAMS_PER_STATEMENT = 100;

/** 컬럼 수로부터 문장당 최대 행 수를 유도 (SCHEMA.md §7-6: floor(100 / 컬럼수)). */
export function rowsPerStatement(columnCount: number): number {
  return Math.max(1, Math.floor(MAX_PARAMS_PER_STATEMENT / columnCount));
}

/** 배열을 size 크기로 청크. */
export function chunk<T>(items: readonly T[], size: number): T[][] {
  if (items.length === 0) return [];
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    out.push(items.slice(i, i + size));
  }
  return out;
}

/**
 * 다중행 INSERT 문장 조립 (SCHEMA.md §7-6) — rows-per-statement는 컬럼 수로부터 유도.
 * insertIgnore(§1-5)가 필요한 테이블은 이 헬퍼를 쓸 수 없음(다이얼렉트별 단일행 SQL만
 * db.insertIgnore()가 생성) — 해당 테이블은 행마다 개별 문장으로 처리.
 */
export function multiRowInsertStatements(
  table: string,
  columns: readonly string[],
  rows: readonly (readonly unknown[])[],
): Statement[] {
  if (rows.length === 0) return [];
  const size = rowsPerStatement(columns.length);
  const rowPlaceholder = `(${columns.map(() => "?").join(", ")})`;
  return chunk(rows, size).map((rowChunk) => ({
    sql: `INSERT INTO ${table} (${columns.join(", ")}) VALUES ${rowChunk.map(() => rowPlaceholder).join(", ")}`,
    params: rowChunk.flat(),
  }));
}
