import {
  BatchConflictError,
  type DbDriver,
  type QueryResult,
  type Statement,
  type StatementResult,
} from "./types.ts";
import { isAddColumn } from "./ddl.ts";

/**
 * Cloudflare D1 상한 (출처: developers.cloudflare.com/d1/platform/limits, 2026-07).
 * 초과 시 왕복 전에 조기 에러로 실패시킨다.
 */
const MAX_SQL_BYTES = 100_000; // 문장 길이 100KB
const MAX_PARAMS_PER_STATEMENT = 100; // 문장당 바인딩 파라미터 수
const MAX_STATEMENTS_PER_BATCH = 1000; // 바인딩 호출당 쿼리 수(Paid)

const DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4";

export interface D1Options {
  accountId: string;
  databaseId: string;
  apiToken: string;
  /** 기본 https://api.cloudflare.com/client/v4 — 테스트/셀프호스팅 오버라이드용. */
  baseUrl?: string;
  /** fetch 주입(테스트) — 미지정 시 전역 fetch. */
  fetch?: typeof fetch;
}

/** CF REST 표준 봉투. */
interface D1Envelope {
  result: D1StatementResult[];
  success: boolean;
  errors: { code?: number; message: string }[];
  messages: unknown[];
}

interface D1StatementResult {
  results?: Record<string, unknown>[];
  success?: boolean;
  meta?: { changes?: number; last_row_id?: number };
}

/**
 * D1 제약 위반 판별 — D1은 SQLite 기반이라 에러 메시지가 SQLite와 동일 계열.
 * sqlite.ts의 isConstraintViolation과 같은 패턴.
 */
/** 이미 있는 컬럼을 다시 추가 — SQLite 원문 메시지가 D1 오류로 그대로 실려 온다. */
function isDuplicateColumn(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return msg.includes("duplicate column name");
}

function isConstraintViolation(message: string): boolean {
  return (
    message.includes("UNIQUE constraint failed") ||
    message.includes("PRIMARY KEY constraint failed") ||
    message.includes("constraint failed")
  );
}

/**
 * 파라미터를 D1 wire 허용 타입(number | string | null | number[])으로 정규화.
 * JSON wire는 boolean/바이너리 충실 인코딩이 없으므로 bool→1/0, 바이트열→number[]로
 * 변환한다(D1의 네이티브 변환·BLOB 읽기 표현과 일치, DESIGN.md §9-4).
 */
function normalizeParam(value: unknown): number | string | null | number[] {
  if (value === null || value === undefined) return null; // undefined→null (D1는 undefined 금지)
  if (typeof value === "boolean") return value ? 1 : 0;
  if (typeof value === "number") return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return Array.from(value);
  if (value instanceof ArrayBuffer) return Array.from(new Uint8Array(value));
  if (Array.isArray(value)) return value as number[]; // 이미 바이트 배열
  throw new Error(`D1: 지원하지 않는 파라미터 타입: ${typeof value}`);
}

function validateStatement(stmt: Statement): { sql: string; params: (number | string | null | number[])[] } {
  const bytes = new TextEncoder().encode(stmt.sql).length;
  if (bytes > MAX_SQL_BYTES) {
    throw new Error(`D1: SQL 길이 ${bytes}B가 상한 ${MAX_SQL_BYTES}B를 초과`);
  }
  const params = (stmt.params ?? []).map(normalizeParam);
  if (params.length > MAX_PARAMS_PER_STATEMENT) {
    throw new Error(`D1: 파라미터 ${params.length}개가 상한 ${MAX_PARAMS_PER_STATEMENT}개를 초과`);
  }
  return { sql: stmt.sql, params };
}

class D1Driver implements DbDriver {
  readonly dialect = "d1" as const;
  private readonly endpoint: string;
  private readonly headers: Record<string, string>;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: D1Options) {
    const base = opts.baseUrl ?? DEFAULT_BASE_URL;
    // /query는 행-객체 배열(results)을 반환 → QueryResult.rows에 그대로 매핑.
    this.endpoint = `${base}/accounts/${opts.accountId}/d1/database/${opts.databaseId}/query`;
    this.headers = {
      Authorization: `Bearer ${opts.apiToken}`,
      "Content-Type": "application/json",
    };
    this.fetchImpl = opts.fetch ?? fetch;
  }

  /** 봉투를 받아 HTTP/에러 상태를 정규화. 제약 위반은 BatchConflictError로 승격. */
  private async send(body: unknown): Promise<D1Envelope> {
    const res = await this.fetchImpl(this.endpoint, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify(body),
    });
    let env: D1Envelope;
    try {
      env = (await res.json()) as D1Envelope;
    } catch {
      throw new Error(`D1: 응답 파싱 실패 (HTTP ${res.status})`);
    }
    if (!res.ok || !env.success) {
      const messages = (env.errors ?? []).map((e) => e.message).join("; ") || `HTTP ${res.status}`;
      if (isConstraintViolation(messages)) {
        throw new BatchConflictError("batch rolled back: constraint violation", env.errors);
      }
      throw new Error(`D1: ${messages}`);
    }
    return env;
  }

  async query(stmt: Statement): Promise<QueryResult> {
    const { sql, params } = validateStatement(stmt);
    const env = await this.send({ sql, params });
    return { rows: env.result[0]?.results ?? [] };
  }

  async batch(stmts: readonly Statement[]): Promise<StatementResult[]> {
    if (stmts.length > MAX_STATEMENTS_PER_BATCH) {
      throw new Error(`D1: 배치 문장 ${stmts.length}개가 상한 ${MAX_STATEMENTS_PER_BATCH}개를 초과`);
    }
    // {batch:[{sql,params}...]} 1급 폼 = 단일 요청 원자 실행 (DESIGN.md §9-2 실측 확정).
    const batch = stmts.map(validateStatement);
    try {
      const env = await this.send({ batch });
      return env.result.map((r) => ({ changes: r.meta?.changes ?? 0 }));
    } catch (err) {
      /**
       * ADD COLUMN 재적용은 멱등 no-op으로 흡수한다(D1=SQLite라 IF NOT EXISTS가 없다).
       *
       * D1은 배치를 한 요청으로 보내 문장별 오류를 구분할 수 없다. 그래서 **배치가 전부
       * ADD COLUMN일 때만** 흡수한다 — 마이그레이션 러너가 문장당 배치 하나로 보내므로
       * (migrate.ts) 실제로 걸리는 경우가 그 형태다. 섞인 배치를 삼키면 다른 문장의 실패까지
       * 성공으로 보고하게 된다.
       */
      if (stmts.length > 0 && stmts.every((st) => isAddColumn(st.sql)) && isDuplicateColumn(err)) {
        return stmts.map(() => ({ changes: 0 }));
      }
      throw err;
    }
  }

  insertIgnore(table: string, columns: readonly string[]): string {
    // D1 = SQLite 기반 → INSERT OR IGNORE.
    const placeholders = columns.map(() => "?").join(", ");
    return `INSERT OR IGNORE INTO ${table} (${columns.join(", ")}) VALUES (${placeholders})`;
  }

  async close(): Promise<void> {
    // D1은 상태 없는 HTTP 전송 — 유지 리소스 없음.
  }
}

/** Cloudflare D1 REST 어댑터 (의존성 제로, fetch 기반). */
export function openD1(opts: D1Options): DbDriver {
  return new D1Driver(opts);
}
