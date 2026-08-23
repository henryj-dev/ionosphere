/** removeMessageFromMailbox / destroyMessage 레시피 — 멤버십·카운터·파기 불변식. */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { Store } from "@ionosphere/store";

async function setup(): Promise<{ db: DbDriver; store: Store; accountId: string; inbox: string }> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const store = new Store(db);
  const { tenantId } = await store.createTenant("t");
  const { accountId } = await store.createAccount({ tenantId, email: "u@x.test" });
  const inbox = (await store.getMailboxByRole(accountId, "inbox"))!.id;
  return { db, store, accountId, inbox };
}

const enc = new TextEncoder();
async function append(store: Store, accountId: string, mailboxId: string): Promise<string> {
  const r = await store.appendMessage({
    accountId,
    mailboxIds: [mailboxId],
    blobId: "b".repeat(64),
    sizeBytes: 100,
    receivedAt: Date.now(),
    envelope: { subject: "s", subjectBase: "s", msgidHash: null, sentAt: null, preview: "p", hasAttachment: false, addresses: [], threadRefHashes: [] },
    keywords: [],
  });
  return r.messageId;
}
void enc;

async function accountCounts(db: DbDriver, accountId: string): Promise<{ messageCount: number; usedBytes: number }> {
  const { rows } = await db.query({ sql: "SELECT message_count, used_bytes FROM accounts WHERE id = ?", params: [accountId] });
  return { messageCount: Number(rows[0]!.message_count), usedBytes: Number(rows[0]!.used_bytes) };
}

describe("removeMessageFromMailbox", () => {
  test("2개 멤버십 중 하나 제거 → destroyed:false, 메시지 잔존", async () => {
    const { db, store, accountId, inbox } = await setup();
    const other = (await store.createMailbox({ accountId, name: "Other" })).mailboxId;
    const msgId = await append(store, accountId, inbox);
    await store.copyMessage({ accountId, messageId: msgId, toMailboxId: other });

    const r = await store.removeMessageFromMailbox(accountId, msgId, inbox);
    expect(r.destroyed).toBe(false);
    // 메시지는 여전히 존재(other에), 계정 카운트 유지
    const metas = await store.getEmailsForJmap(accountId, [msgId]);
    expect(metas).toHaveLength(1);
    expect(metas[0]!.mailboxIds).toEqual([other]);
    expect((await accountCounts(db, accountId)).messageCount).toBe(1);
    await db.close();
  });

  test("마지막 멤버십 제거 → destroyed:true, 메시지·카운터 소멸 + change_log destroyed", async () => {
    const { db, store, accountId, inbox } = await setup();
    const msgId = await append(store, accountId, inbox);
    expect((await accountCounts(db, accountId)).messageCount).toBe(1);

    const r = await store.removeMessageFromMailbox(accountId, msgId, inbox);
    expect(r.destroyed).toBe(true);
    expect(await store.getEmailsForJmap(accountId, [msgId])).toHaveLength(0);
    const c = await accountCounts(db, accountId);
    expect(c.messageCount).toBe(0);
    expect(c.usedBytes).toBe(0);
    const { rows } = await db.query({ sql: "SELECT kind FROM change_log WHERE entity = 0 AND object_id = ?", params: [msgId] });
    expect(rows.some((x) => Number(x.kind) === 2)).toBe(true); // destroyed
    await db.close();
  });

  test("없는 멤버십 → StoreError", async () => {
    const { db, store, accountId, inbox } = await setup();
    void inbox;
    await expect(store.removeMessageFromMailbox(accountId, "Z".repeat(26), "Y".repeat(26))).rejects.toThrow();
    await db.close();
  });
});

describe("destroyMessage", () => {
  test("여러 메일함 소속 메시지 전체 파기 → 전 멤버십·메시지 소멸, 각 메일함 카운터 감소", async () => {
    const { db, store, accountId, inbox } = await setup();
    const other = (await store.createMailbox({ accountId, name: "Other" })).mailboxId;
    const msgId = await append(store, accountId, inbox);
    await store.copyMessage({ accountId, messageId: msgId, toMailboxId: other });

    await store.destroyMessage(accountId, msgId);
    expect(await store.getEmailsForJmap(accountId, [msgId])).toHaveLength(0);
    expect((await accountCounts(db, accountId)).messageCount).toBe(0);
    // 두 메일함 total_count 모두 0
    const { rows } = await db.query({ sql: "SELECT total_count FROM mailboxes WHERE id IN (?, ?)", params: [inbox, other] });
    expect(rows.every((r) => Number(r.total_count) === 0)).toBe(true);
    await db.close();
  });

  test("없는 메시지 → StoreError", async () => {
    const { db, store, accountId } = await setup();
    await expect(store.destroyMessage(accountId, "Z".repeat(26))).rejects.toThrow();
    await db.close();
  });
});
