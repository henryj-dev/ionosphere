import { describe, expect, test } from "@ionosphere/testkit";
import { makeAppendInput, setupFixture } from "./helpers.ts";

describe("MoveMessage (SCHEMA.md §7-3)", () => {
  test("원본 메일함 expunged 툼스톤 + Email change_log는 updated(NOT destroyed)", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();
    const { mailboxId: archiveId } = await store.createMailbox({ accountId, name: "Archive" });
    const { messageId } = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] }));

    const result = await store.moveMessage({ accountId, messageId, fromMailboxId: inboxId, toMailboxId: archiveId });
    expect(result.uid).toBe(1);

    // 원본에서 사라짐, 대상에 새 UID로 존재
    expect(await store.listMessages(inboxId)).toHaveLength(0);
    const archiveList = await store.listMessages(archiveId);
    expect(archiveList).toHaveLength(1);
    expect(archiveList[0]!.uid).toBe(result.uid);

    const { rows: expungedRows } = await db.query({ sql: "SELECT uid FROM expunged WHERE mailbox_id = ?", params: [inboxId] });
    expect(expungedRows).toHaveLength(1);
    expect(Number(expungedRows[0]?.uid)).toBe(1);

    // 메시지 자체는 살아있음
    const { rows: msgRows } = await db.query({ sql: "SELECT id FROM messages WHERE id = ?", params: [messageId] });
    expect(msgRows).toHaveLength(1);

    const { rows: logRows } = await db.query({
      sql: "SELECT kind FROM change_log WHERE account_id = ? AND entity = 0 AND object_id = ? ORDER BY modseq DESC LIMIT 1",
      params: [accountId, messageId],
    });
    expect(Number(logRows[0]?.kind)).toBe(1); // updated

    await db.close();
  });

  test("메일함 카운터 이동: 원본 -1, 대상 +1", async () => {
    const { store, accountId, inboxId } = await setupFixture();
    const { mailboxId: archiveId } = await store.createMailbox({ accountId, name: "Archive" });
    const { messageId } = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId], sizeBytes: 77 }));

    await store.moveMessage({ accountId, messageId, fromMailboxId: inboxId, toMailboxId: archiveId });

    const mailboxes = await store.listMailboxes(accountId);
    const inbox = mailboxes.find((m) => m.id === inboxId)!;
    const archive = mailboxes.find((m) => m.id === archiveId)!;
    expect(inbox.totalCount).toBe(0);
    expect(inbox.totalBytes).toBe(0);
    expect(archive.totalCount).toBe(1);
    expect(archive.totalBytes).toBe(77);
  });

  test("이미 대상에 존재하면 no-op (COPY 계약과 동일 no-op 선검사)", async () => {
    const { store, accountId, inboxId } = await setupFixture();
    const { mailboxId: archiveId } = await store.createMailbox({ accountId, name: "Archive" });
    const { messageId } = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId, archiveId] }));

    const result = await store.moveMessage({ accountId, messageId, fromMailboxId: inboxId, toMailboxId: archiveId });
    // 이미 archive에 있었으므로 그대로 유지 — no-op
    expect(result.uid).toBe(1);
    const archiveList = await store.listMessages(archiveId);
    expect(archiveList).toHaveLength(1);
  });
});
