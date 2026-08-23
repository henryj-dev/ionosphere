/** 메일함 삭제 2단계 리퍼 — 툼스톤 메일함의 고아 메시지 완전파기 / 다중소속 detach / 활성 no-op. */
import { describe, expect, test } from "@ionosphere/testkit";
import { setupFixture, makeAppendInput } from "./helpers.ts";

async function counters(db: Awaited<ReturnType<typeof setupFixture>>["db"], accountId: string) {
  const { rows } = await db.query({ sql: "SELECT used_bytes, message_count FROM accounts WHERE id = ?", params: [accountId] });
  return { usedBytes: Number(rows[0]!.used_bytes), messageCount: Number(rows[0]!.message_count) };
}
async function messageExists(db: Awaited<ReturnType<typeof setupFixture>>["db"], id: string) {
  const { rows } = await db.query({ sql: "SELECT 1 FROM messages WHERE id = ?", params: [id] });
  return rows.length > 0;
}
async function mailboxRow(db: Awaited<ReturnType<typeof setupFixture>>["db"], id: string) {
  const { rows } = await db.query({ sql: "SELECT status FROM mailboxes WHERE id = ?", params: [id] });
  return rows[0] ? { status: Number(rows[0].status) } : null;
}

describe("reapMailbox", () => {
  test("툼스톤 메일함의 단독 소속 메시지 → 완전 파기 + 메일함 행 하드삭제 + 계정 카운터 차감", async () => {
    const { db, store, accountId } = await setupFixture();
    const { mailboxId } = await store.createMailbox({ accountId, name: "Junk" });
    const { messageId } = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [mailboxId], sizeBytes: 500 }));
    const before = await counters(db, accountId);
    expect(before.messageCount).toBe(1);

    await store.deleteMailbox({ accountId, mailboxId }); // 1단계: 툼스톤
    expect((await mailboxRow(db, mailboxId))?.status).toBe(2);

    const r = await store.reapMailbox(accountId, mailboxId);
    expect(r).toEqual({ purged: 1, detached: 0 });
    expect(await messageExists(db, messageId)).toBe(false); // 완전 파기
    expect(await mailboxRow(db, mailboxId)).toBeNull(); // 하드삭제
    const after = await counters(db, accountId);
    expect(after.messageCount).toBe(0);
    expect(after.usedBytes).toBe(before.usedBytes - 500);
  });

  test("다른 메일함에도 있는 메시지는 detach만(생존) — 카운터 유지", async () => {
    const { db, store, accountId, inboxId } = await setupFixture();
    const { mailboxId } = await store.createMailbox({ accountId, name: "Work" });
    const { messageId } = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId, mailboxId], sizeBytes: 300 }));
    const before = await counters(db, accountId);

    await store.deleteMailbox({ accountId, mailboxId });
    const r = await store.reapMailbox(accountId, mailboxId);
    expect(r).toEqual({ purged: 0, detached: 1 });
    expect(await messageExists(db, messageId)).toBe(true); // INBOX에 생존
    expect(await mailboxRow(db, mailboxId)).toBeNull();
    const after = await counters(db, accountId);
    expect(after.messageCount).toBe(before.messageCount); // 파기 아님 → 유지
    expect(after.usedBytes).toBe(before.usedBytes);
    // 남은 membership은 INBOX 하나
    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS c FROM message_mailbox WHERE message_id = ?", params: [messageId] });
    expect(Number(rows[0]!.c)).toBe(1);
  });

  test("활성(status=1) 메일함은 절대 건드리지 않음(no-op)", async () => {
    const { db, store, accountId } = await setupFixture();
    const { mailboxId } = await store.createMailbox({ accountId, name: "Keep" });
    await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [mailboxId] }));
    const r = await store.reapMailbox(accountId, mailboxId);
    expect(r).toEqual({ purged: 0, detached: 0 });
    expect((await mailboxRow(db, mailboxId))?.status).toBe(1); // 여전히 활성
  });

  test("빈 툼스톤 메일함 → 메일함 행만 삭제", async () => {
    const { db, store, accountId } = await setupFixture();
    const { mailboxId } = await store.createMailbox({ accountId, name: "Empty" });
    await store.deleteMailbox({ accountId, mailboxId });
    const r = await store.reapMailbox(accountId, mailboxId);
    expect(r).toEqual({ purged: 0, detached: 0 });
    expect(await mailboxRow(db, mailboxId)).toBeNull();
  });

  test("listReapableMailboxes: 툼스톤만 반환", async () => {
    const { store, accountId } = await setupFixture();
    const { mailboxId: a } = await store.createMailbox({ accountId, name: "A" });
    await store.createMailbox({ accountId, name: "B" });
    await store.deleteMailbox({ accountId, mailboxId: a });
    const reapable = await store.listReapableMailboxes();
    expect(reapable.map((m) => m.id)).toEqual([a]);
  });
});
