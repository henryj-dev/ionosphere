/** DB 추상화 — SCHEMA.md §1/§3 계약의 코드 표면. */

export type Dialect = "sqlite" | "postgres" | "mysql" | "d1";

export interface Statement {
  sql: string;
  params?: readonly unknown[];
}

export interface StatementResult {
  /** 영향 행 수 — 리스 획득 판정의 승인 메커니즘 (SCHEMA.md §9-4). */
  changes: number;
}

export interface QueryResult {
  rows: Record<string, unknown>[];
}

/**
 * 제약 위반(PK/UNIQUE)으로 배치 전체가 롤백됐음을 나타냄.
 * 스토어 레이어의 낙관 잠금 재시도(SCHEMA.md §3-3)가 이 타입으로 판별한다.
 */
export class BatchConflictError extends Error {
  override readonly cause: unknown;

  constructor(message: string, cause: unknown) {
    super(message);
    this.name = "BatchConflictError";
    this.cause = cause;
  }
}

export interface DbDriver {
  readonly dialect: Dialect;

  /** 단일 읽기 질의. */
  query(stmt: Statement): Promise<QueryResult>;

  /**
   * 단일 원자 배치 (SCHEMA.md §1-1): 전부 성공하거나, 에러 시 전부 롤백.
   * 제약 위반은 BatchConflictError로 정규화해 던진다.
   * 0행 UPDATE는 에러가 아님 — 호출자는 changes로 판정할 것.
   */
  batch(stmts: readonly Statement[]): Promise<StatementResult[]>;

  /**
   * "INSERT 없으면 무시" — 유일하게 승인된 다이얼렉트 분기 (SCHEMA.md §1-5).
   * columns/values로 다이얼렉트별 SQL을 생성한다.
   */
  insertIgnore(table: string, columns: readonly string[]): string;

  close(): Promise<void>;
}
