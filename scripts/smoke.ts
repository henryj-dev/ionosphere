/**
 * 듀얼 런타임 스모크: `bun scripts/smoke.ts` 와 `node scripts/smoke.ts` 모두 통과해야 함.
 * (Node는 타입 스트리핑으로 .ts 직접 실행 — 코드가 erasableSyntaxOnly인 이유)
 */
import { ulid } from "@ionosphere/core";
import { allMigrations, BatchConflictError, migrate, openSqlite } from "@ionosphere/db";

const runtime = `node ${process.versions.node}`;

const db = await openSqlite();
const applied = await migrate(db, allMigrations);

const acct = ulid();
await db.batch([
  { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [acct, 1] },
]);

let conflictOk = false;
try {
  await db.batch([
    { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [acct, 1] },
  ]);
} catch (err) {
  conflictOk = err instanceof BatchConflictError;
}

await db.close();

if (applied !== allMigrations.length || !conflictOk) {
  console.error(`SMOKE FAIL on ${runtime}: applied=${applied} conflictOk=${conflictOk}`);
  process.exit(1);
}
console.log(`SMOKE OK on ${runtime}: migrations=${applied}, optimistic-lock conflict detected`);
