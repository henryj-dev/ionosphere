/**
 * 적재 처리량 벤치 — 라이터 큐 코얼레싱(SCHEMA.md §3-1)의 이득을 재현 가능하게 재기 위한 것.
 *
 * ★반드시 리눅스(실제 배포 대상)에서 재라. macOS의 fsync는 진짜 배리어가 아니라
 * 커밋 비용이 20배 이상 싸게 나오고, 그러면 이 최적화는 "이득 없음"으로 잘못 판정된다.
 * 실측(라이브 Vultr, node 24, SQLite WAL):
 *   코얼레싱 전: 200건 203ms(1.02ms/건) · 500건 538ms(1.08ms/건)
 *   코얼레싱 후: 200건  49ms(0.25ms/건) · 500건 160ms(0.32ms/건)   → 3.4~4.1배
 * 커밋 1회 오버헤드는 같은 장비에서 0.40ms(macOS는 0.018ms).
 *
 * 사용: node apps/server/bench/append-throughput.ts [건수]
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { FsBlobStore, putBlob, Store, type AppendMessageInput } from "@ionosphere/store";

const N = Number(process.argv[2] ?? 200);
const dir = mkdtempSync(join(tmpdir(), "bench-append-"));
const db = await openSqlite(join(dir, "mail.db"));
await migrate(db, allMigrations);
const store = new Store(db);
const blobs = new FsBlobStore(join(dir, "blobs"));

const { tenantId } = await store.createTenant("t");
const { accountId } = await store.createAccount({ tenantId, email: "u@test.local" });
const inbox = (await store.getMailboxByRole(accountId, "inbox"))!;

const inputs: AppendMessageInput[] = [];
for (let i = 0; i < N; i++) {
  const raw = new TextEncoder().encode(`Subject: msg ${i}\r\n\r\nbody ${i}\r\n${"x".repeat(500)}`);
  const { blobId, size, generation } = await putBlob(db, blobs, raw);
  inputs.push({
    accountId,
    mailboxIds: [inbox.id],
    blobId,
    blobGeneration: generation,
    sizeBytes: size,
    receivedAt: Date.now(),
    envelope: {
      subject: `msg ${i}`,
      subjectBase: `msg ${i}`,
      msgidHash: `h${i}`,
      sentAt: Date.now(),
      preview: "body",
      hasAttachment: false,
      addresses: [],
      threadRefHashes: [],
    },
    keywords: [],
  });
}

// 동시 제출 = 실제 버스트 형태. 라이터 큐가 직렬화하면서 호환 작업을 합친다.
const t0 = performance.now();
await Promise.all(inputs.map((i) => store.appendMessage(i)));
const elapsed = performance.now() - t0;

// 실제로 몇 배치로 커밋됐는지 — 코얼레싱이 없으면 N과 같다.
const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM modseq_claims WHERE account_id = ?", params: [accountId] });
const batches = Number(rows[0]!.n);

console.log(
  JSON.stringify({
    n: N,
    totalMs: Math.round(elapsed),
    perMsgMs: +(elapsed / N).toFixed(3),
    batches,
    avgGroupSize: +(N / batches).toFixed(1),
  }),
);

await db.close();
rmSync(dir, { recursive: true, force: true });
