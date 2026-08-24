/**
 * 메시지 파기 시 검색 부산물(message_text · search_index)도 함께 지워지는가.
 *
 * ★왜 이게 회귀 테스트인가: `message_text`에는 **제목과 본문 텍스트**가 들어가는데
 * (`searchIndexBody` 기본 true) 파기 경로가 `messages`·`message_keywords`·
 * `message_addresses`·`blob_refs`만 지웠다. 블롭(본문 바이트)은 GC가 치우는데 **그 본문의
 * 텍스트 사본은 남았다** — 사용자가 EXPUNGE한 메일이 DB와 백업에 영구히 남는다는 뜻이고,
 * 저장소 낭비 이전에 삭제 계약이 깨진 것이다(2026-08-23 검수 §5).
 *
 * 파기 경로가 넷이라 넷 다 확인한다 — 한 곳만 고치면 나머지가 그대로 남는다.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { FsBlobStore, putBlob, Store } from "@ionosphere/store";

async function setup() {
  const db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
  const store = new Store(db);
  const blobs = new FsBlobStore(mkdtempSync(join(tmpdir(), "ion-sac-")));
  const { tenantId } = await store.createTenant("t");
  const { accountId, mailboxId } = await store.createAccount({ tenantId, email: "a@x.test" });
  return { db, store, blobs, accountId, mailboxId };
}

async function append(
  db: DbDriver,
  store: Store,
  blobs: FsBlobStore,
  accountId: string,
  mailboxIds: string[],
  body: string,
): Promise<{ messageId: string; uids: Map<string, number> }> {
  const raw = new Uint8Array(Buffer.from(`From: a@x.test\r\nSubject: hello\r\n\r\n${body}\r\n`));
  const { blobId, size, generation } = await putBlob(db, blobs, raw);
  const r = await store.appendMessage({
    accountId,
    mailboxIds,
    blobId,
    blobGeneration: generation,
    sizeBytes: size,
    receivedAt: Date.now(),
    envelope: {
      subject: "hello",
      subjectBase: "hello",
      msgidHash: null,
      sentAt: null,
      preview: body,
      hasAttachment: false,
      addresses: [{ kind: 0, pos: 0, name: null, email: "a@x.test" }],
      threadRefHashes: [],
    },
    keywords: [],
    searchText: { subject: "hello", body },
  });
  return { messageId: r.messageId, uids: r.uids };
}

async function counts(db: DbDriver, messageId: string): Promise<{ text: number; index: number }> {
  const { rows: t } = await db.query({
    sql: "SELECT COUNT(*) AS n FROM message_text WHERE message_id = ?",
    params: [messageId],
  });
  const { rows: i } = await db.query({
    sql: "SELECT COUNT(*) AS n FROM search_index WHERE message_id = ?",
    params: [messageId],
  });
  return { text: Number(t[0]!.n), index: Number(i[0]!.n) };
}

describe("파기 시 검색 부산물 정리", () => {
  test("EXPUNGE — 마지막 membership이면 함께 지운다", async () => {
    const { db, store, blobs, accountId, mailboxId } = await setup();
    const { messageId } = await append(db, store, blobs, accountId, [mailboxId], "corpus alpha");
    const before = await counts(db, messageId);
    expect(before.text > 0).toBe(true);
    expect(before.index > 0).toBe(true);

    const { rows } = await db.query({
      sql: "SELECT uid FROM message_mailbox WHERE message_id = ?",
      params: [messageId],
    });
    await store.setDeleted({ accountId, mailboxId, uids: [Number(rows[0]!.uid)], deleted: true });
    await store.expunge({ accountId, mailboxId });

    expect(await counts(db, messageId)).toEqual({ text: 0, index: 0 });
    await db.close();
  });

  /** 다른 메일함에 남아 있으면 메시지가 사는 것이므로 색인도 **남아야** 한다. */
  test("EXPUNGE — 다른 메일함에 살아남으면 색인도 남는다", async () => {
    const { db, store, blobs, accountId, mailboxId } = await setup();
    const { mailboxId: other } = await store.createMailbox({ accountId, name: "Keep" });
    const { messageId } = await append(db, store, blobs, accountId, [mailboxId, other], "corpus beta");

    const { rows } = await db.query({
      sql: "SELECT uid FROM message_mailbox WHERE message_id = ? AND mailbox_id = ?",
      params: [messageId, mailboxId],
    });
    await store.setDeleted({ accountId, mailboxId, uids: [Number(rows[0]!.uid)], deleted: true });
    await store.expunge({ accountId, mailboxId });

    const after = await counts(db, messageId);
    expect(after.text > 0).toBe(true);
    expect(after.index > 0).toBe(true);
    await db.close();
  });

  test("메일함 리퍼(2단계) — 툼스톤 수거 시 함께 지운다", async () => {
    const { db, store, blobs, accountId } = await setup();
    const { mailboxId: tmp } = await store.createMailbox({ accountId, name: "Temp" });
    const { messageId } = await append(db, store, blobs, accountId, [tmp], "corpus gamma");

    await store.deleteMailbox({ accountId, mailboxId: tmp });
    await store.reapMailbox(accountId, tmp);

    expect(await counts(db, messageId)).toEqual({ text: 0, index: 0 });
    await db.close();
  });

  test("단일 membership 제거(JMAP Email/set) — 마지막이면 함께 지운다", async () => {
    const { db, store, blobs, accountId, mailboxId } = await setup();
    const { messageId } = await append(db, store, blobs, accountId, [mailboxId], "corpus delta");

    const r = await store.removeMessageFromMailbox(accountId, messageId, mailboxId);
    expect(r.destroyed).toBe(true);
    expect(await counts(db, messageId)).toEqual({ text: 0, index: 0 });
    await db.close();
  });

  /** 지워진 메시지가 검색 결과에 남지 않는지 — 고아 포스팅이 없으면 조인 필터에 기대지 않아도 된다. */
  test("파기 후 검색에서 사라진다", async () => {
    const { db, store, blobs, accountId, mailboxId } = await setup();
    const { messageId } = await append(db, store, blobs, accountId, [mailboxId], "zzunique");
    expect(await store.search(accountId, "zzunique")).toHaveLength(1);

    await store.removeMessageFromMailbox(accountId, messageId, mailboxId);
    expect(await store.search(accountId, "zzunique")).toHaveLength(0);
    await db.close();
  });
});
