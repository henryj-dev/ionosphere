import type { DbDriver, Statement } from "@ionosphere/db";

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

/**
 * `IN (…)` 리스트를 쓰는 **읽기 질의**를 파라미터 한도 안에서 나눠 돌리고 행을 합친다.
 *
 * ★왜 필요한가(2026-08-23 검수): 이 파일이 정한 한도(문장당 100개)를 **쓰기 경로는 지키고
 * 읽기 경로는 지키지 않았다.** `db.batch()`로 가는 문장은 전부 `chunk()`를 타는데,
 * `db.query()`로 가는 `IN` 리스트는 `uids.map(() => "?")`로 손수 조립돼 개수 제한이 없었다.
 * 같은 한도가 읽기에도 똑같이 적용되는데도 그랬다:
 *   · D1  — 문장당 100개 초과 시 실패. 메시지 100통 넘는 메일함에서 IMAP이 통째로 깨진다
 *   · PG  — 바인드 메시지의 파라미터 수가 int16이라 65535개가 상한
 * `UID FETCH 1:*`·`SEARCH`·`UID STORE 1:*`이 메일함 메시지 수만큼 파라미터를 만들었다.
 *
 * ★헬퍼로 만드는 것이 요점이다. 호출부마다 `map(() => "?")`를 손으로 쓰면 새 호출자도 같은
 * 실수를 한다 — 이 결함이 생긴 방식이 정확히 그것이다.
 *
 * `sql`은 자리표시자 목록을 받아 문장을 만드는 함수다. 고정 파라미터(mailbox_id 등)는
 * `fixed`로 앞에 붙이고, 그만큼 청크 크기에서 뺀다.
 *
 * ⚠ 청크마다 별도 질의라 **한 스냅샷이 아니다**. 이 헬퍼를 쓰는 곳은 이미 그 성질을 가진
 * 경로다(IMAP 세션 뷰는 SELECT 시점 스냅샷이고, 그 사이 변경은 EXPUNGE·FETCH 흐름이 따로
 * 다룬다). 원자성이 필요한 읽기에는 쓰지 말 것.
 */
export async function queryInChunks(
  db: DbDriver,
  items: readonly unknown[],
  sql: (placeholders: string) => string,
  fixed: readonly unknown[] = [],
): Promise<Record<string, unknown>[]> {
  if (items.length === 0) return [];
  const size = Math.max(1, MAX_PARAMS_PER_STATEMENT - fixed.length);
  const out: Record<string, unknown>[] = [];
  for (const part of chunk(items, size)) {
    const { rows } = await db.query({
      sql: sql(part.map(() => "?").join(", ")),
      params: [...fixed, ...part],
    });
    out.push(...rows);
  }
  return out;
}
