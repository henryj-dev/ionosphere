import { describe, expect, test } from "@ionosphere/testkit";
import { makeAppendInput, setupFixture } from "./helpers.ts";

describe("$seen 키워드 (SCHEMA.md §7-1/§7-2)", () => {
  test("append with $seen → unread_count는 증가하지 않음", async () => {
    const { store, accountId, inboxId } = await setupFixture();
    await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId], keywords: ["$Seen"] }));

    const mbx = (await store.listMailboxes(accountId)).find((m) => m.id === inboxId)!;
    expect(mbx.unreadCount).toBe(0);
    expect(mbx.totalCount).toBe(1);
  });

  test("setKeywords add $seen → unread_count 1 감소", async () => {
    const { store, accountId, inboxId } = await setupFixture();
    const { messageId } = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] }));

    let mbx = (await store.listMailboxes(accountId)).find((m) => m.id === inboxId)!;
    expect(mbx.unreadCount).toBe(1);

    await store.setKeywords({ accountId, messageId, add: ["$seen"], remove: [] });

    mbx = (await store.listMailboxes(accountId)).find((m) => m.id === inboxId)!;
    expect(mbx.unreadCount).toBe(0);
  });

  test("setKeywords remove $seen → unread_count 1 증가", async () => {
    const { store, accountId, inboxId } = await setupFixture();
    const { messageId } = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId], keywords: ["$seen"] }));

    let mbx = (await store.listMailboxes(accountId)).find((m) => m.id === inboxId)!;
    expect(mbx.unreadCount).toBe(0);

    await store.setKeywords({ accountId, messageId, add: [], remove: ["$SEEN"] });

    mbx = (await store.listMailboxes(accountId)).find((m) => m.id === inboxId)!;
    expect(mbx.unreadCount).toBe(1);
  });

  test("이미 보유한 키워드 재추가는 no-op — modseq 소모 없음", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();
    const { messageId } = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId], keywords: ["$seen"] }));

    const before = (await db.query({ sql: "SELECT modseq FROM accounts WHERE id = ?", params: [accountId] })).rows[0]?.modseq;
    await store.setKeywords({ accountId, messageId, add: ["$seen"], remove: [] });
    const after = (await db.query({ sql: "SELECT modseq FROM accounts WHERE id = ?", params: [accountId] })).rows[0]?.modseq;

    expect(after).toBe(before);
  });

  test("키워드는 소문자로 정규화 저장 (§5-3)", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();
    const { messageId } = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] }));
    await store.setKeywords({ accountId, messageId, add: ["Important"], remove: [] });

    const { rows } = await db.query({ sql: "SELECT keyword FROM message_keywords WHERE message_id = ?", params: [messageId] });
    expect(rows.map((r) => r.keyword)).toContain("important");
  });
});
