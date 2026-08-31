import { describe, expect, test } from "@ionosphere/testkit";
import { projectHeaders } from "../src/header-projection.ts";
import type { Store } from "../src/store.ts";
import type { DbDriver } from "@ionosphere/db";
import { makeAppendInput, setupFixture } from "./helpers.ts";

const raw = new TextEncoder().encode("From: Alice <alice@example.test>\r\nSubject: lifecycle\r\nDate: Tue, 01 Jan 2030 00:00:00 +0000\r\n\r\nbody");

async function appendProjected(store: Store, accountId: string, mailboxIds: readonly string[]): Promise<string> {
  const result = await store.appendMessage(makeAppendInput({
    accountId,
    mailboxIds,
    headerProjections: projectHeaders(raw),
  }));
  return result.messageId;
}

async function projectionCount(db: DbDriver, messageId: string): Promise<number> {
  const { rows } = await db.query({
    sql: "SELECT COUNT(*) AS n FROM message_header_projection WHERE message_id = ?",
    params: [messageId],
  });
  return Number(rows[0]!.n);
}

describe("header projection ingest lifecycle", () => {
  test("append는 여러 projection을 message와 같은 원자 배치에 저장한다", async () => {
    const { db, store, accountId, inboxId } = await setupFixture();
    const messageId = await appendProjected(store, accountId, [inboxId]);

    const { rows } = await db.query({
      sql: "SELECT name, display_value FROM message_header_projection WHERE message_id = ? ORDER BY name",
      params: [messageId],
    });
    expect(rows.map((row) => [row.name, row.display_value])).toEqual([
      ["date", "Tue, 01 Jan 2030 00:00:00 +0000"],
      ["from", "Alice <alice@example.test>"],
      ["subject", "lifecycle"],
    ]);
    await db.close();
  });

  test("projection 제약 위반은 message까지 롤백한다", async () => {
    const { db, store, accountId, inboxId } = await setupFixture();
    const projection = projectHeaders("Subject: duplicate\r\n\r\n")[0]!;

    await expect(store.appendMessage(makeAppendInput({
      accountId,
      mailboxIds: [inboxId],
      headerProjections: [projection, projection],
    }))).rejects.toThrow();
    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM messages", params: [] });
    expect(Number(rows[0]!.n)).toBe(0);
    await db.close();
  });

  test("COPY는 새 message id에 projection을 원자 복제한다", async () => {
    const { db, store, accountId, inboxId } = await setupFixture();
    const { mailboxId: archiveId } = await store.createMailbox({ accountId, name: "Archive" });
    const sourceId = await appendProjected(store, accountId, [inboxId]);

    await store.copyOrMoveMessages({
      accountId,
      messageIds: [sourceId],
      fromMailboxId: inboxId,
      toMailboxId: archiveId,
      op: "copy",
    });
    const { rows } = await db.query({
      sql: "SELECT message_id FROM message_mailbox WHERE mailbox_id = ?",
      params: [archiveId],
    });
    const copyId = String(rows[0]!.message_id);
    expect(copyId).not.toBe(sourceId);
    expect(await projectionCount(db, copyId)).toBe(await projectionCount(db, sourceId));
    await db.close();
  });

  test("EXPUNGE는 마지막 membership일 때만 projection을 지운다", async () => {
    const { db, store, accountId, inboxId } = await setupFixture();
    const { mailboxId: keepId } = await store.createMailbox({ accountId, name: "Keep" });
    const messageId = await appendProjected(store, accountId, [inboxId, keepId]);

    await store.setDeleted({ accountId, mailboxId: inboxId, uids: [1], deleted: true });
    await store.expunge({ accountId, mailboxId: inboxId });
    expect(await projectionCount(db, messageId)).toBeGreaterThan(0);
    await store.setDeleted({ accountId, mailboxId: keepId, uids: [1], deleted: true });
    await store.expunge({ accountId, mailboxId: keepId });
    expect(await projectionCount(db, messageId)).toBe(0);
    await db.close();
  });

  test("메일함 reap의 최종 파기는 projection을 지운다", async () => {
    const { db, store, accountId } = await setupFixture();
    const { mailboxId } = await store.createMailbox({ accountId, name: "Temporary" });
    const messageId = await appendProjected(store, accountId, [mailboxId]);

    await store.deleteMailbox({ accountId, mailboxId });
    await store.reapMailbox(accountId, mailboxId);
    expect(await projectionCount(db, messageId)).toBe(0);
    await db.close();
  });

  test("마지막 membership 제거는 projection을 지운다", async () => {
    const { db, store, accountId, inboxId } = await setupFixture();
    const messageId = await appendProjected(store, accountId, [inboxId]);

    await store.removeMessageFromMailbox(accountId, messageId, inboxId);
    expect(await projectionCount(db, messageId)).toBe(0);
    await db.close();
  });

  test("Email destroy는 projection을 지운다", async () => {
    const { db, store, accountId, inboxId } = await setupFixture();
    const messageId = await appendProjected(store, accountId, [inboxId]);

    await store.destroyMessage(accountId, messageId);
    expect(await projectionCount(db, messageId)).toBe(0);
    await db.close();
  });
});
