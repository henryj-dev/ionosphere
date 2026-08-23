import { Pool, types, type PoolClient } from "pg";
import {
  BatchConflictError,
  type DbDriver,
  type QueryResult,
  type Statement,
  type StatementResult,
} from "./types.ts";
import { isAddColumn } from "./ddl.ts";

/** PG unique_violation 에러 코드 (SCHEMA.md §1-5 / §3-2 낙관 잠금 판별용). */
const UNIQUE_VIOLATION_CODE = "23505";

/**
 * PG는 int8(OID 20, BIGINT)을 기본 문자열로 반환.
 * SCHEMA.md §2 규약("2^53 미만 유지")에 따라 number로 안전하게 강제 변환한다.
 * 전역 pg.types를 건드리지 않고 풀 단위 커스텀 파서로 국한.
 */
const INT8_OID = types.builtins.INT8;
const int8AsNumber = (value: string): number => Number(value);
const poolTypes = {
  getTypeParser: (oid: number, format?: "text" | "binary") =>
    oid === INT8_OID ? int8AsNumber : types.getTypeParser(oid, format),
};

/**
 * `?` 위치 파라미터를 PG `$1..$n`로 변환.
 * 우리 SQL에는 문자열 리터럴 안에 `?`가 등장하지 않지만(SCHEMA.md 규약),
 * 안전을 위해 단일따옴표 문자열 구간은 스캔에서 건너뛴다('' 이스케이프도 처리).
 */
function translatePlaceholders(sql: string): string {
  let result = "";
  let paramIndex = 0;
  let inString = false;
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    if (inString) {
      result += ch;
      if (ch === "'") {
        if (sql[i + 1] === "'") {
          result += sql[i + 1];
          i++;
        } else {
          inString = false;
        }
      }
      continue;
    }
    if (ch === "'") {
      inString = true;
      result += ch;
      continue;
    }
    if (ch === "?") {
      paramIndex++;
      result += `$${paramIndex}`;
      continue;
    }
    result += ch;
  }
  return result;
}

/**
 * `ADD COLUMN` → `ADD COLUMN IF NOT EXISTS`.
 *
 * 다른 드라이버는 "이미 있음" 오류를 흡수하지만 PostgreSQL에서는 그럴 수 없다 —
 * 문장 하나가 실패하면 트랜잭션 전체가 중단 상태가 되어 이후 명령이 전부 거부된다.
 * PG는 이 구문을 지원하므로 **애초에 오류를 만들지 않는 쪽**이 맞다.
 */
function addColumnIfNotExists(sql: string): string {
  return isAddColumn(sql) && !/ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS/i.test(sql)
    ? sql.replace(/ADD\s+COLUMN\s+/i, "ADD COLUMN IF NOT EXISTS ")
    : sql;
}

function isUniqueViolation(err: unknown): boolean {
  return typeof err === "object" && err !== null && "code" in err && err.code === UNIQUE_VIOLATION_CODE;
}

class PostgresDriver implements DbDriver {
  readonly dialect = "postgres" as const;
  private readonly pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
  }

  async query(stmt: Statement): Promise<QueryResult> {
    const result = await this.pool.query(translatePlaceholders(stmt.sql), (stmt.params ?? []) as unknown[]);
    return { rows: result.rows };
  }

  async batch(stmts: readonly Statement[]): Promise<StatementResult[]> {
    const client: PoolClient = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const results: StatementResult[] = [];
      try {
        for (const stmt of stmts) {
          const r = await client.query(translatePlaceholders(addColumnIfNotExists(stmt.sql)), (stmt.params ?? []) as unknown[]);
          results.push({ changes: r.rowCount ?? 0 });
        }
        await client.query("COMMIT");
        return results;
      } catch (err) {
        await client.query("ROLLBACK");
        if (isUniqueViolation(err)) {
          throw new BatchConflictError("batch rolled back: constraint violation", err);
        }
        throw err;
      }
    } finally {
      client.release();
    }
  }

  insertIgnore(table: string, columns: readonly string[]): string {
    // 다른 드라이버와 동일하게 `?` 자리표시자로 생성 — batch()/query()에서 일괄 변환된다.
    const placeholders = columns.map(() => "?").join(", ");
    return `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

/**
 * 연결 획득 타임아웃 — 안 걸면 DB가 죽었을 때 요청이 **영원히 매달린다**.
 * 빨리 실패해야 SMTP가 4xx로 정직하게 지연시키고 발신측이 재시도한다.
 */
const CONNECT_TIMEOUT_MS = 10_000;

/**
 * 커넥션 풀 크기. pg 기본값은 10인데, 프로토콜 리스너 여럿이 한 프로세스에서 같은 풀을 쓰므로
 * 느린 질의 몇 개가 전체를 막을 수 있다. 기본값은 그대로 두고(DB 부하 특성을 임의로 바꾸지
 * 않는다) 조정 수단만 연다 — `IONOSPHERE_DB_POOL_MAX`.
 *
 * ⚠ `statement_timeout`은 **일부러 걸지 않는다.** 마이그레이션이 같은 풀을 쓰는데, 대형
 * 재빌드(003·006류)가 그 시간을 넘기면 DDL이 중간에 잘려 스키마가 반쯤 적용된 상태로 남는다.
 * 느린 질의 대응은 풀 크기와 질의 자체로 해결할 문제다.
 */
function poolMaxFromEnv(): number | undefined {
  const raw = Number(process.env.IONOSPHERE_DB_POOL_MAX);
  return Number.isInteger(raw) && raw > 0 ? raw : undefined;
}

/** connectionString 기반 PG 어댑터 (PLAN.md 결정: 프로덕션 기본 백엔드). */
export async function openPostgres(connectionString: string): Promise<DbDriver> {
  const max = poolMaxFromEnv();
  const pool = new Pool({
    connectionString,
    types: poolTypes,
    connectionTimeoutMillis: CONNECT_TIMEOUT_MS,
    ...(max !== undefined ? { max } : {}),
  });
  /**
   * ★필수. node-postgres는 **유휴 클라이언트**에서 오류가 나면 Pool에 'error'를 emit하는데,
   * 리스너가 없으면 unhandled error가 되어 **프로세스가 죽는다**. DB 재시작·네트워크 순단 한 번에
   * 올인원 서버(SMTP·IMAP·POP3·JMAP 전부)가 통째로 내려간다는 뜻이다.
   *
   * 삼켜도 되는 이유: 유휴 클라이언트는 이미 풀에서 제거되고, 진행 중인 질의의 오류는 그 질의의
   * Promise로 따로 전달된다. 여기서 할 일은 "죽지 않기"와 진단 흔적을 남기는 것뿐이다.
   * (db 패키지는 로거를 주입받지 않으므로 stderr에 한 줄만 남긴다.)
   */
  pool.on("error", (err: Error) => {
    process.stderr.write(`[db:postgres] 유휴 클라이언트 오류(무시하고 계속): ${err.message}\n`);
  });
  return new PostgresDriver(pool);
}
