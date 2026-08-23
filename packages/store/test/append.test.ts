import { describe, expect, test } from "@ionosphere/testkit";
import { StoreQuotaError } from "../src/errors.ts";
import { makeAppendInput, setupFixture } from "./helpers.ts";

describe("appendMessage → listMessages (SCHEMA.md §7-1)", () => {
  test("연속 append → UID 1,2,3... + 카운터 반영", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();

    for (let i = 1; i <= 3; i++) {
      const result = await store.appendMessage(
        makeAppendInput({ accountId, mailboxIds: [inboxId], sizeBytes: 50 * i, keywords: [] }),
      );
      expect(result.uids.get(inboxId)).toBe(i);
      expect(result.modseq).toBe(i);
    }

    const list = await store.listMessages(inboxId);
    expect(list.map((m) => m.uid)).toEqual([1, 2, 3]);
    expect(list.every((m) => !m.deleted)).toBe(true);

    const mbx = await store.listMailboxes(accountId);
    const inbox = mbx.find((m) => m.id === inboxId)!;
    expect(inbox.totalCount).toBe(3);
    expect(inbox.unreadCount).toBe(3); // $seen 없음 → 전부 안읽음
    expect(inbox.totalBytes).toBe(50 + 100 + 150);
    expect(inbox.highestmodseq).toBe(3);

    const { rows } = await db.query({ sql: "SELECT modseq, message_count, used_bytes FROM accounts WHERE id = ?", params: [accountId] });
    expect(Number(rows[0]?.modseq)).toBe(3);
    expect(Number(rows[0]?.message_count)).toBe(3);
    expect(Number(rows[0]?.used_bytes)).toBe(300);

    await db.close();
  });

  test("여러 메일함에 동시 append: 메일함별 독립 UID 공간", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();
    const { mailboxId: otherId } = await store.createMailbox({ accountId, name: "Archive" });

    const r1 = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId, otherId] }));
    expect(r1.uids.get(inboxId)).toBe(1);
    expect(r1.uids.get(otherId)).toBe(1);

    const r2 = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] }));
    expect(r2.uids.get(inboxId)).toBe(2);

    await db.close();
  });

  test("쿼터 초과 → StoreQuotaError, 상태 변경 없음", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();
    await db.batch([{ sql: "UPDATE accounts SET quota_bytes = 100 WHERE id = ?", params: [accountId] }]);

    await expect(
      store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId], sizeBytes: 200 })),
    ).rejects.toBeInstanceOf(StoreQuotaError);

    const list = await store.listMessages(inboxId);
    expect(list).toHaveLength(0);
    const { rows } = await db.query({ sql: "SELECT modseq, used_bytes FROM accounts WHERE id = ?", params: [accountId] });
    expect(Number(rows[0]?.modseq)).toBe(0);
    expect(Number(rows[0]?.used_bytes)).toBe(0);

    await db.close();
  });

  test("쿼터 이내: 정확히 한도까지는 성공", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();
    await db.batch([{ sql: "UPDATE accounts SET quota_bytes = 100 WHERE id = ?", params: [accountId] }]);

    await expect(
      store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId], sizeBytes: 100 })),
    ).resolves.toBeTruthy();

    await db.close();
  });
});
