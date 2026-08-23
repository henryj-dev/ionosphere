import {
  BatchConflictError,
  type DbDriver,
  type QueryResult,
  type Statement,
  type StatementResult,
} from "./types.ts";
import { isAddColumn } from "./ddl.ts";

/** bun:sqlite와 node:sqlite를 하나의 동기 핸들로 정규화. */
interface RawSqlite {
  run(sql: string, params: readonly unknown[]): { changes: number };
  all(sql: string, params: readonly unknown[]): Record<string, unknown>[];
  close(): void;
}

/**
 * node:sqlite로 연다.
 *
 * ★예전엔 `process.versions.bun` 분기로 `bun:sqlite`도 지원했다. 지웠는데, 분기가 런타임에
 * 도달하지 않아도 **node의 ESM 로더가 `import("bun:sqlite")`를 해석하려다 던진다**
 * (`Only URLs with a scheme in: file, data, and node are supported ... Received protocol 'bun:'`).
 * 그 예외가 `app.start()`를 조용히 실패시켜 e2e 테스트 31건이 취소됐다 — 러너를 node:test로
 * 옮기면서 드러났다. 이 저장소는 node 전용이므로 분기 자체가 필요 없다.
 */
async function openRaw(path: string): Promise<RawSqlite> {
  const { DatabaseSync } = await import("node:sqlite");
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA foreign_keys = OFF;");
  return {
    run(sql, params) {
      const r = db.prepare(sql).run(...(params as never[]));
      return { changes: Number(r.changes) };
    },
    all(sql, params) {
      return db.prepare(sql).all(...(params as never[])) as Record<string, unknown>[];
    },
    close() {
      db.close();
    },
  };
}

/** 이미 있는 컬럼을 다시 추가 — 마이그레이션 재개 시 흡수할 멱등 no-op. */
function isDuplicateColumn(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  // bun:sqlite / node:sqlite 모두 sqlite 원문: "duplicate column name: x"
  return msg.includes("duplicate column name");
}

function isConstraintViolation(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  // bun:sqlite: "UNIQUE constraint failed: t.c" / node:sqlite: 동일 sqlite 메시지
  return msg.includes("UNIQUE constraint failed") || msg.includes("PRIMARY KEY constraint failed");
}

class SqliteDriver implements DbDriver {
  readonly dialect = "sqlite" as const;
  private readonly raw: RawSqlite;

  constructor(raw: RawSqlite) {
    this.raw = raw;
  }

  async query(stmt: Statement): Promise<QueryResult> {
    return { rows: this.raw.all(stmt.sql, stmt.params ?? []) };
  }

  async batch(stmts: readonly Statement[]): Promise<StatementResult[]> {
    // SQLite는 단일 프로세스 단일 라이터 전제 (SCHEMA.md §3-3) — IMMEDIATE로 라이터 잠금 선점
    this.raw.run("BEGIN IMMEDIATE", []);
    const results: StatementResult[] = [];
    try {
      for (const stmt of stmts) {
        try {
          results.push(this.raw.run(stmt.sql, stmt.params ?? []));
        } catch (err) {
          // SQLite엔 ADD COLUMN IF NOT EXISTS가 없다 — 이미 있으면 성공으로 친다.
          // (PostgreSQL과 달리 SQLite는 문장 오류로 트랜잭션이 중단 상태가 되지 않아 계속할 수 있다.)
          if (isAddColumn(stmt.sql) && isDuplicateColumn(err)) {
            results.push({ changes: 0 });
            continue;
          }
          throw err;
        }
      }
      this.raw.run("COMMIT", []);
      return results;
    } catch (err) {
      this.raw.run("ROLLBACK", []);
      if (isConstraintViolation(err)) {
        throw new BatchConflictError("batch rolled back: constraint violation", err);
      }
      throw err;
    }
  }

  insertIgnore(table: string, columns: readonly string[]): string {
    const placeholders = columns.map(() => "?").join(", ");
    return `INSERT OR IGNORE INTO ${table} (${columns.join(", ")}) VALUES (${placeholders})`;
  }

  async close(): Promise<void> {
    this.raw.close();
  }
}

/** path 기본값 ":memory:" — dev/테스트 기본 백엔드 (PLAN.md 결정). */
export async function openSqlite(path = ":memory:"): Promise<DbDriver> {
  return new SqliteDriver(await openRaw(path));
}
