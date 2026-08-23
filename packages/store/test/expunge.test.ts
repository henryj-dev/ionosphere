import { describe, expect, test } from "@ionosphere/testkit";
import { makeAppendInput, setupFixture } from "./helpers.ts";

describe("Expunge (SCHEMA.md §7-4)", () => {
  test("deleted=1 대상만 툼스톤 기록 + modseq 정확", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();
    const { messageId: m1 } = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] }));
    await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] })); // uid 2, 삭제 안 함

    await store.setDeleted({ accountId, mailboxId: inboxId, uids: [1], deleted: true });
    const beforeModseq = (await db.query({ sql: "SELECT modseq FROM accounts WHERE id=?", params: [accountId] })).rows[0]!.modseq;

    const result = await store.expunge({ accountId, mailboxId: inboxId });
    expect(result.expunged).toHaveLength(1);
    expect(result.expunged[0]!.uid).toBe(1);
    expect(result.expunged[0]!.modseq).toBe(Number(beforeModseq) + 1);

    const { rows: expungedRows } = await db.query({ sql: "SELECT uid, modseq FROM expunged WHERE mailbox_id = ?", params: [inboxId] });
    expect(expungedRows).toHaveLength(1);
    expect(Number(expungedRows[0]?.uid)).toBe(1);

    // uid 2는 남아있어야 함
    const list = await store.listMessages(inboxId);
    expect(list.map((m) => m.uid)).toEqual([2]);

    // last membership → messages/message_keywords/message_addresses/blob_refs 삭제 + change_log destroyed
    const { rows: msgRows } = await db.query({ sql: "SELECT id FROM messages WHERE id = ?", params: [m1] });
    expect(msgRows).toHaveLength(0);
    const { rows: refRows } = await db.query({ sql: "SELECT blob_id FROM blob_refs WHERE ref_id = ?", params: [m1] });
    expect(refRows).toHaveLength(0);
    const { rows: destroyedRows } = await db.query({
      sql: "SELECT kind FROM change_log WHERE account_id = ? AND entity = 0 AND object_id = ?",
      params: [accountId, m1],
    });
    expect(destroyedRows.some((r) => Number(r.kind) === 2)).toBe(true);

    await db.close();
  });

  test("last-membership 아니면 change_log는 updated (destroyed 아님) — 다른 메일함엔 남아있음", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();
    const { mailboxId: archiveId } = await store.createMailbox({ accountId, name: "Archive" });
    const { messageId } = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId, archiveId] }));

    await store.setDeleted({ accountId, mailboxId: inboxId, uids: [1], deleted: true });
    await store.expunge({ accountId, mailboxId: inboxId });

    // archive에는 여전히 존재
    const archiveList = await store.listMessages(archiveId);
    expect(archiveList.map((m) => m.messageId)).toContain(messageId);

    const { rows: msgRows } = await db.query({ sql: "SELECT id FROM messages WHERE id = ?", params: [messageId] });
    expect(msgRows).toHaveLength(1); // 메시지 자체는 살아있음

    const { rows: logRows } = await db.query({
      sql: "SELECT kind FROM change_log WHERE account_id = ? AND entity = 0 AND object_id = ? ORDER BY modseq DESC LIMIT 1",
      params: [accountId, messageId],
    });
    expect(Number(logRows[0]?.kind)).toBe(1); // updated, not destroyed

    await db.close();
  });

  test("deleted 플래그 없는 메일함 → no-op (빈 결과)", async () => {
    const { store, accountId, inboxId } = await setupFixture();
    await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] }));
    const result = await store.expunge({ accountId, mailboxId: inboxId });
    expect(result.expunged).toHaveLength(0);
  });
});
