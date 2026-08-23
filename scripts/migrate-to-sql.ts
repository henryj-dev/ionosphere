/**
 * SQLite → PostgreSQL/MySQL 데이터 이관 (일회성 운영 도구).
 *
 * 왜 필요한가: 스키마는 `migrate()`가 어느 방언에나 적용하지만, **기존 행을 옮기는 코드가
 * 저장소에 없었다.** SQLite 단일 인스턴스에서 시작한 배포가 멀티 인스턴스로 가려면 반드시
 * 한 번은 거쳐야 하는 길인데, 그때마다 손으로 SQL을 짜면 조용히 빠지는 테이블이 생긴다.
 *
 * 사용:
 *   IONOSPHERE_DB=/var/lib/ionosphere/ionosphere.db \
 *   IONOSPHERE_TARGET_URL='postgres://user:pw@host:5432/ionosphere' \
 *     node scripts/migrate-to-sql.ts [--dry-run] [--truncate]
 *
 *   --dry-run  읽기만 하고 대상에 쓰지 않는다(행 수·타입 점검용).
 *   --truncate 대상 테이블을 비우고 넣는다. 없으면 **비어 있어야만** 진행한다(아래 참조).
 *
 * ★설계상 지키는 것들:
 *
 * 1) **비어 있지 않은 대상에는 기본적으로 쓰지 않는다.** 이관은 보통 한 번뿐이고, 두 번째
 *    실행이 부분 중복을 만들면 원인을 찾기 어렵다. 덮어쓰려면 `--truncate`로 의도를 밝힌다.
 *
 * 2) **끝나고 행 수를 대조한다.** "오류 없이 끝났다"와 "다 옮겨졌다"는 다르다. 한 테이블이
 *    통째로 빠져도 INSERT는 아무 불평을 하지 않는다 — 이 저장소는 배포에서 패키지 하나가
 *    몇 주 동안 조용히 빠져 있던 적이 있고, 그때 배운 것이 "옮겼다고 믿지 말고 세어 보라"다.
 *
 * 3) **스키마는 우리 `migrate()`로 만든다.** SQLite의 DDL을 번역하지 않는다 — 번역기는
 *    방언 차이(AUTOINCREMENT·타입 어피니티)에서 어긋나고, 그 결과가 운영 DB에 남는다.
 *
 * 4) **본문 블롭은 대상이 아니다.** 메일 본문은 파일시스템(또는 S3)에 있고 DB엔 참조만 있다.
 *    이 스크립트는 DB만 옮기므로, 블롭 저장소는 별도로 같은 위치를 가리키게 해야 한다.
 */
import { openDatabase, openSqlite, migrate, allMigrations, describeDbSpec, type DbDriver, type Statement } from "../packages/db/src/index.ts";

const DRY_RUN = process.argv.includes("--dry-run");
const TRUNCATE = process.argv.includes("--truncate");

/** 한 번에 보내는 행 수. 너무 크면 파라미터 상한에, 너무 작으면 왕복 비용에 걸린다. */
const CHUNK = 200;

function requiredEnv(key: string): string {
  const v = process.env[key];
  if (!v) throw new Error(`${key}가 필요하다`);
  return v;
}

/** 원본(SQLite)의 사용자 테이블 목록 — sqlite 내부 테이블은 제외. */
function sourceTables(src: DbDriver): Promise<string[]> {
  return src
    .query({ sql: "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name" })
    .then((r) => r.rows.map((row) => String(row.name)));
}

async function columnsOf(src: DbDriver, table: string): Promise<string[]> {
  const r = await src.query({ sql: `PRAGMA table_info("${table}")` });
  return r.rows.map((row) => String(row.name));
}

async function countOf(db: DbDriver, table: string): Promise<number> {
  const r = await db.query({ sql: `SELECT COUNT(*) AS c FROM ${table}` });
  // ★PG는 COUNT를 int8로 돌려주고 int8은 **문자열**로 온다(postgres.ts 주석). Number로 좁힌다.
  return Number(r.rows[0]?.c ?? 0);
}

async function main(): Promise<void> {
  const srcPath = process.env.IONOSPHERE_DB ?? "ionosphere.db";
  const targetUrl = requiredEnv("IONOSPHERE_TARGET_URL");
  if (/^(file:|sqlite:)/i.test(targetUrl) || !/^[a-z][a-z0-9+.-]*:/i.test(targetUrl)) {
    throw new Error("IONOSPHERE_TARGET_URL이 SQLite를 가리킨다 — 이 스크립트는 SQLite→PG/MySQL 전용이다");
  }

  console.log(`원본  : ${srcPath}`);
  console.log(`대상  : ${describeDbSpec(targetUrl)}`);
  console.log(`모드  : ${DRY_RUN ? "dry-run(쓰지 않음)" : TRUNCATE ? "truncate 후 이관" : "빈 대상에만 이관"}`);

  const src = await openSqlite(srcPath);
  const dst = await openDatabase(targetUrl);

  try {
    // 1) 대상 스키마 — 우리 마이그레이션으로 만든다(SQLite DDL을 번역하지 않는다).
    if (!DRY_RUN) {
      const applied = await migrate(dst, allMigrations);
      console.log(`\n[1/3] 대상 스키마 준비 — 마이그레이션 ${applied}개 적용`);
    } else {
      console.log("\n[1/3] (dry-run) 스키마 적용 생략");
    }

    const tables = await sourceTables(src);
    // schema_migrations는 위 migrate()가 이미 자기 손으로 채운다. 여기서 또 넣으면 충돌한다.
    const targets = tables.filter((t) => t !== "schema_migrations");

    // 2) 행 복사
    console.log(`\n[2/3] 데이터 이관 — 테이블 ${targets.length}개`);
    const copied = new Map<string, number>();
    for (const table of targets) {
      const cols = await columnsOf(src, table);
      const { rows } = await src.query({ sql: `SELECT ${cols.map((c) => `"${c}"`).join(", ")} FROM "${table}"` });
      if (rows.length === 0) {
        copied.set(table, 0);
        continue;
      }

      if (!DRY_RUN) {
        const existing = await countOf(dst, table);
        if (existing > 0) {
          if (!TRUNCATE) {
            throw new Error(
              `대상 ${table}에 이미 ${existing}행이 있다 — 부분 중복을 만들지 않으려고 멈춘다. ` +
                "의도한 재실행이면 --truncate를 붙일 것",
            );
          }
          await dst.batch([{ sql: `DELETE FROM ${table}` }]);
        }
        const placeholders = `(${cols.map(() => "?").join(", ")})`;
        for (let i = 0; i < rows.length; i += CHUNK) {
          const slice = rows.slice(i, i + CHUNK);
          const stmts: Statement[] = slice.map((row) => ({
            sql: `INSERT INTO ${table} (${cols.join(", ")}) VALUES ${placeholders}`,
            params: cols.map((c) => row[c] ?? null),
          }));
          await dst.batch(stmts);
        }
      }
      copied.set(table, rows.length);
      console.log(`  ${table.padEnd(24)} ${rows.length}행${DRY_RUN ? " (읽기만)" : ""}`);
    }

    // 3) 대조 — "오류 없이 끝났다"를 "다 옮겨졌다"로 읽지 않기 위해 **다시 센다**.
    console.log("\n[3/3] 행 수 대조");
    if (DRY_RUN) {
      const total = [...copied.values()].reduce((a, b) => a + b, 0);
      console.log(`  (dry-run) 원본 총 ${total}행 — 대상 대조는 실제 실행에서 한다`);
      return;
    }
    const mismatch: string[] = [];
    for (const [table, n] of copied) {
      const got = await countOf(dst, table);
      if (got !== n) mismatch.push(`${table}: 원본 ${n} → 대상 ${got}`);
    }
    if (mismatch.length) {
      console.error("\n행 수가 맞지 않는다:");
      for (const m of mismatch) console.error(`  ${m}`);
      throw new Error(`이관 검증 실패 ${mismatch.length}건`);
    }
    const total = [...copied.values()].reduce((a, b) => a + b, 0);
    console.log(`  전 테이블 일치 — 총 ${total}행`);
    console.log("\n이관 완료. 다음: IONOSPHERE_DB_URL을 대상으로 바꾸고 기동할 것.");
    console.log("⚠ 블롭 저장소(메일 본문)는 DB 밖이다 — 같은 위치를 가리키는지 따로 확인할 것.");
  } finally {
    await src.close();
    await dst.close();
  }
}

await main();
