import type { EventEmitter } from "node:events";
import { createPool, type Pool, type PoolConnection } from "mysql2/promise";
import {
  BatchConflictError,
  type DbDriver,
  type QueryResult,
  type Statement,
  type StatementResult,
} from "./types.ts";
import { isAddColumn } from "./ddl.ts";

/** MySQL 에러 코드 (mysql2 err.errno) — 낙관 잠금/멱등 DDL 판별용. */
const ER_DUP_ENTRY = 1062; // UNIQUE/PK 위반 → BatchConflictError
const ER_DUP_KEYNAME = 1061; // 인덱스 중복 생성 → CREATE INDEX 멱등 no-op
const ER_DUP_FIELDNAME = 1060; // 컬럼 중복 추가 → ADD COLUMN 멱등 no-op (MySQL엔 IF NOT EXISTS가 없다)

/**
 * SCHEMA v2.1 식별자 중 MySQL 예약어와 충돌하는 것들.
 * SQLite/PG에서는 예약어가 아니라 무따옴표로 통과하지만, MySQL에서는 백틱 인용이 필요하다.
 * 현재 스키마에서 유일한 충돌은 background_jobs.cursor (CURSOR는 MySQL 예약어).
 * 이 컬럼은 런타임 질의에서 쓰이지 않고 CREATE TABLE DDL에만 등장하지만,
 * 안전을 위해 드라이버를 통과하는 모든 SQL에 일관 적용한다(문자열/기존 백틱은 건너뜀).
 */
const MYSQL_RESERVED = new Set(["cursor"]);

/**
 * MySQL 방언 변환 (postgres.ts의 `?`→`$n`에 대응하는 위치).
 * 1) 예약어 식별자를 백틱으로 인용 — 문자열 리터럴('...')과 기존 백틱(`...`)은 스캔에서 제외.
 * 2) `CREATE [UNIQUE] INDEX IF NOT EXISTS`의 `IF NOT EXISTS` 제거 —
 *    MySQL은 인덱스에 IF NOT EXISTS를 지원하지 않으므로(테이블은 지원),
 *    제거 후 실행하고 ER_DUP_KEYNAME을 멱등 no-op으로 흡수한다(idempotentIndex 플래그).
 * `?` 자리표시자는 MySQL 네이티브라 변환하지 않는다.
 */
function translate(sql: string): { sql: string; idempotentIndex: boolean; idempotentColumn: boolean } {
  const quoted = quoteReserved(sql);
  const indexRe = /^(\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+)IF\s+NOT\s+EXISTS\s+/i;
  if (indexRe.test(quoted)) {
    return { sql: quoted.replace(/\s+IF\s+NOT\s+EXISTS\s+/i, " "), idempotentIndex: true, idempotentColumn: false };
  }
  // MySQL엔 ADD COLUMN IF NOT EXISTS가 없다(MariaDB에만 있다) — 실행하고 중복 오류를 흡수한다.
  return { sql: quoted, idempotentIndex: false, idempotentColumn: isAddColumn(quoted) };
}

/** 예약어 식별자를 백틱 인용. 단일따옴표 문자열과 백틱 구간은 원본 유지. */
function quoteReserved(sql: string): string {
  let result = "";
  let i = 0;
  while (i < sql.length) {
    const ch = sql[i]!;
    if (ch === "'") {
      // 문자열 리터럴 — '' 이스케이프 처리하며 통째로 복사
      result += ch;
      i++;
      while (i < sql.length) {
        result += sql[i];
        if (sql[i] === "'") {
          if (sql[i + 1] === "'") {
            result += sql[i + 1];
            i += 2;
            continue;
          }
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    if (ch === "`") {
      // 이미 백틱 인용된 식별자 — 통째로 복사
      result += ch;
      i++;
      while (i < sql.length) {
        result += sql[i];
        if (sql[i] === "`") {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      // 식별자/키워드 토큰 추출
      let word = "";
      while (i < sql.length && /[A-Za-z0-9_]/.test(sql[i]!)) {
        word += sql[i];
        i++;
      }
      result += MYSQL_RESERVED.has(word.toLowerCase()) ? `\`${word}\`` : word;
      continue;
    }
    result += ch;
    i++;
  }
  return result;
}

function isDupEntry(err: unknown): boolean {
  return typeof err === "object" && err !== null && "errno" in err && (err as { errno: number }).errno === ER_DUP_ENTRY;
}

function isDupFieldName(err: unknown): boolean {
  return typeof err === "object" && err !== null && "errno" in err && (err as { errno: number }).errno === ER_DUP_FIELDNAME;
}

function isDupKeyName(err: unknown): boolean {
  return typeof err === "object" && err !== null && "errno" in err && (err as { errno: number }).errno === ER_DUP_KEYNAME;
}

/** INSERT/UPDATE/DDL 결과에서 영향 행 수 추출(SELECT 결과 배열이면 0). */
function changesOf(result: unknown): number {
  if (result && typeof result === "object" && "affectedRows" in result) {
    return Number((result as { affectedRows: number }).affectedRows) || 0;
  }
  return 0;
}

class MysqlDriver implements DbDriver {
  readonly dialect = "mysql" as const;
  private readonly pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
  }

  async query(stmt: Statement): Promise<QueryResult> {
    const [rows] = await this.pool.query(translate(stmt.sql).sql, (stmt.params ?? []) as unknown[]);
    return { rows: (Array.isArray(rows) ? rows : []) as Record<string, unknown>[] };
  }

  async batch(stmts: readonly Statement[]): Promise<StatementResult[]> {
    const conn: PoolConnection = await this.pool.getConnection();
    try {
      // DML은 InnoDB 트랜잭션으로 원자화. (DDL은 MySQL에서 암묵 커밋되지만
      // migrate.ts가 문장당 단일 배치로 보내므로 원자성 요구가 없다.)
      await conn.beginTransaction();
      const results: StatementResult[] = [];
      try {
        for (const stmt of stmts) {
          const t = translate(stmt.sql);
          try {
            const [res] = await conn.query(t.sql, (stmt.params ?? []) as unknown[]);
            results.push({ changes: changesOf(res) });
          } catch (err) {
            // CREATE INDEX(IF NOT EXISTS 제거본)가 이미 존재 → 멱등 no-op
            if (t.idempotentIndex && isDupKeyName(err)) {
              results.push({ changes: 0 });
              continue;
            }
            // ADD COLUMN이 이미 적용됨 → 멱등 no-op (마이그레이션 재개)
            if (t.idempotentColumn && isDupFieldName(err)) {
              results.push({ changes: 0 });
              continue;
            }
            throw err;
          }
        }
        await conn.commit();
        return results;
      } catch (err) {
        await conn.rollback();
        if (isDupEntry(err)) {
          throw new BatchConflictError("batch rolled back: constraint violation", err);
        }
        throw err;
      }
    } finally {
      conn.release();
    }
  }

  insertIgnore(table: string, columns: readonly string[]): string {
    const placeholders = columns.map(() => "?").join(", ");
    const key = columns[0]!;
    return `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${placeholders}) ON DUPLICATE KEY UPDATE ${key} = ${key}`;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

/**
 * connectionString(mysql://user:pass@host:port/db) 기반 MySQL/MariaDB 어댑터.
 *
 * 설계 결정:
 * - 정수 정규화: typeCast로 정수 계열(BIGINT/INT/SMALLINT/TINYINT)을 항상 JS number로 반환.
 *   PG의 int8AsNumber에 대응(SCHEMA §2: 2^53 미만 규약). SMALLINT 불리언 0/1도 number 왕복.
 *   NULL은 number 강제 없이 null 유지(Number(null)=0 버그 회피).
 * - changes 판정: node-mysql 계열 기본 플래그에 이미 CLIENT_FOUND_ROWS가 포함돼 UPDATE
 *   affectedRows가 "매칭 행 수"(값 변화 무관)로 나온다 — SQLite `changes`/PG `rowCount`와 동일 의미.
 *   리스 규율(§9-4)이 changes로 판정하므로 이 의미 일치가 중요. FOUND_ROWS를 명시 지정해
 *   서버/버전 차이와 무관하게 고정한다(기존 기본 플래그에 병합, 제거 아님).
 * - charset utf8mb4: 다국어 로컬파트/이름 지원. VARCHAR(255) PK/인덱스는 utf8mb4에서
 *   1020바이트 < InnoDB 대형 프리픽스 상한(3072, MySQL 5.7.7+/8.0·MariaDB 10.2+ 기본)이라 안전.
 */
export async function openMysql(connectionString: string): Promise<DbDriver> {
  const u = new URL(connectionString);
  const pool = createPool({
    host: u.hostname,
    port: u.port ? Number(u.port) : 3306,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: u.pathname.replace(/^\//, ""),
    charset: "utf8mb4",
    flags: ["FOUND_ROWS"],
    supportBigNumbers: true,
    bigNumberStrings: false,
    typeCast(field: { type: string; string(): string | null }, next: () => unknown): unknown {
      if (
        field.type === "LONGLONG" ||
        field.type === "LONG" ||
        field.type === "INT24" ||
        field.type === "SHORT" ||
        field.type === "TINY" ||
        field.type === "YEAR"
      ) {
        const s = field.string();
        return s === null ? null : Number(s);
      }
      return next();
    },
  });
  // postgres.ts와 같은 이유 — 풀에서 올라온 오류에 리스너가 없으면 프로세스가 죽는다.
  // 진행 중인 질의의 오류는 그 질의의 Promise로 따로 전달되므로 여기서는 흔적만 남긴다.
  // mysql2의 타입은 'enqueue' 이벤트만 선언해 두어 EventEmitter로 좁혀서 등록한다.
  (pool as unknown as EventEmitter).on("error", (err: Error) => {
    process.stderr.write(`[db:mysql] 풀 오류(무시하고 계속): ${err.message}\n`);
  });
  return new MysqlDriver(pool);
}
