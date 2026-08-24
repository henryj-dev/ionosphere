/**
 * 헤더 리스트 증폭 회귀 — **저장 경로까지** 확인한다.
 *
 * 파서 상한(`packages/mime/test/header-list-limits.test.ts`)만으로는 부족하다: 이 결함이
 * 실제로 아팠던 지점은 `appendMessage()`가 만드는 **DB 행 수와 한 배치의 문장 수**였다.
 *
 * 수정 전 실측(SQLite, 메시지 한 통 701KB):
 *   append 407ms · thread_refs 20,001행 · message_addresses 20,000행
 * 407ms는 `db.batch()`가 동기로 도는 시간이라 그동안 전 프로토콜이 함께 멈춘다.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { MAX_ADDRESSES_PER_HEADER, MAX_THREAD_REFS } from "@ionosphere/core";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { parseMessage } from "@ionosphere/mime";
import { FsBlobStore, putBlob, Store } from "@ionosphere/store";
import { toAppendAddresses } from "../src/addresses.ts";

test("References·To가 2만 개여도 append가 폭주하지 않는다", async () => {
  const db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
  const store = new Store(db);
  const blobs = new FsBlobStore(mkdtempSync(join(tmpdir(), "ion-amp-")));
  const { tenantId } = await store.createTenant("t");
  const { accountId, mailboxId } = await store.createAccount({ tenantId, email: "a@x.test" });

  const n = 20_000;
  const refs = Array.from({ length: n }, (_, i) => `<r${i}@x.test>`).join(" ");
  const to = Array.from({ length: n }, (_, i) => `u${i}@x.test`).join(", ");
  const raw = new Uint8Array(
    Buffer.from(
      `From: a@x.test\r\nTo: ${to}\r\nMessage-ID: <m@x.test>\r\n` +
        `References: ${refs}\r\nSubject: t\r\n\r\nbody\r\n`,
    ),
  );
  const parsed = parseMessage(raw);
  const { blobId, size, generation } = await putBlob(db, blobs, raw);

  const started = Date.now();
  await store.appendMessage({
    accountId,
    mailboxIds: [mailboxId],
    blobId,
    blobGeneration: generation,
    sizeBytes: size,
    receivedAt: Date.now(),
    envelope: {
      subject: parsed.subject,
      subjectBase: parsed.subjectBase,
      msgidHash: parsed.msgidHash,
      sentAt: parsed.sentAt,
      preview: parsed.preview,
      hasAttachment: false,
      addresses: toAppendAddresses(parsed),
      threadRefHashes: parsed.threadRefHashes,
    },
    keywords: [],
  });
  const elapsed = Date.now() - started;

  const { rows: tr } = await db.query({ sql: "SELECT COUNT(*) AS n FROM thread_refs", params: [] });
  const { rows: ma } = await db.query({ sql: "SELECT COUNT(*) AS n FROM message_addresses", params: [] });

  expect(Number(tr[0]!.n) <= MAX_THREAD_REFS).toBe(true);
  // From(1) + To(상한) — 헤더별로 적용되므로 합이 상한을 조금 넘는 것은 정상이다.
  expect(Number(ma[0]!.n) <= MAX_ADDRESSES_PER_HEADER + 8).toBe(true);
  // 수정 전 407ms. 100ms는 느린 CI에서도 여유가 있으면서 회귀는 잡는 값이다.
  expect(elapsed < 100).toBe(true);

  await db.close();
});
