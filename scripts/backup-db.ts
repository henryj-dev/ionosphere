/**
 * SQLite 온라인 백업 — VACUUM INTO로 WAL까지 포함한 일관된 단일 파일 스냅샷을 만든다.
 * 라이브 DB가 열려 있어도 안전(읽기 트랜잭션). 듀얼 런타임: `bun`/`node` 모두 실행 가능(erasableSyntaxOnly).
 * 사용: bun scripts/backup-db.ts <src.db> <dest.db>
 */
import { openSqlite } from "@ionosphere/db";

const src = process.argv[2];
const dest = process.argv[3];
if (!src || !dest) {
  console.error("usage: backup-db.ts <src.db> <dest.db>");
  process.exit(1);
}

// VACUUM은 트랜잭션 밖에서만 가능 → query()(단문)로 실행. 경로의 작은따옴표는 SQL 이스케이프.
const escaped = dest.replace(/'/g, "''");
const db = await openSqlite(src);
await db.query({ sql: `VACUUM INTO '${escaped}'` });
await db.close();
console.log(`BACKUP OK: ${dest}`);
