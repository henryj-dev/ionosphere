/** JMAP Email/query FTS 필터 — text/subject/body/from/to를 search_index로 배선. */
import { describe, expect, test } from "@ionosphere/testkit";
import { makeAppendInput, setupFixture } from "./helpers.ts";

async function seed() {
  const fx = await setupFixture();
  const { store, accountId, inboxId } = fx;
  const a = await store.appendMessage(
    makeAppendInput({ accountId, mailboxIds: [inboxId], searchText: { subject: "회의 안내", body: "내일 오후 3시", from: "boss@corp.com", to: "me@x.test" } }),
  );
  const b = await store.appendMessage(
    makeAppendInput({ accountId, mailboxIds: [inboxId], searchText: { subject: "점심 메뉴", body: "김치찌개 어때요", from: "friend@x.test", to: "me@x.test" } }),
  );
  return { ...fx, aId: a.messageId, bId: b.messageId };
}

describe("queryEmails FTS", () => {
  test("text: 전 필드 검색(subject/body/from)", async () => {
    const { store, db, accountId, aId } = await seed();
    expect((await store.queryEmails(accountId, { text: "회의" }, false, 0, 50)).ids).toEqual([aId]); // subject
    expect((await store.queryEmails(accountId, { text: "오후" }, false, 0, 50)).ids).toEqual([aId]); // body
    expect((await store.queryEmails(accountId, { text: "boss" }, false, 0, 50)).ids).toEqual([aId]); // from
    await db.close();
  });

  test("subject 필터는 subject 필드만 매칭", async () => {
    const { store, db, accountId, aId } = await seed();
    expect((await store.queryEmails(accountId, { subject: "회의" }, false, 0, 50)).ids).toEqual([aId]);
    // '오후'는 body에만 → subject 필터로는 매치 없음
    expect((await store.queryEmails(accountId, { subject: "오후" }, false, 0, 50)).ids).toEqual([]);
    await db.close();
  });

  test("text 다중 토큰 AND", async () => {
    const { store, db, accountId, aId } = await seed();
    expect((await store.queryEmails(accountId, { text: "회의 안내" }, false, 0, 50)).ids).toEqual([aId]);
    // '회의'(a) + '메뉴'(b) 공존 메시지 없음
    expect((await store.queryEmails(accountId, { text: "회의 메뉴" }, false, 0, 50)).ids).toEqual([]);
    await db.close();
  });

  test("매치 없음 → 빈 결과 + total 0", async () => {
    const { store, db, accountId } = await seed();
    const r = await store.queryEmails(accountId, { text: "존재하지않는단어" }, false, 0, 50);
    expect(r.ids).toEqual([]);
    expect(r.total).toBe(0);
    await db.close();
  });

  test("FTS + inMailbox/keyword 결합(AND)", async () => {
    const { store, db, accountId, inboxId, aId, bId } = await seed();
    // 둘 다 to=me → text 'me'는 둘 다, inMailbox INBOX도 둘 다 → 2건
    const both = await store.queryEmails(accountId, { text: "me", inMailbox: inboxId }, false, 0, 50);
    expect(both.ids.sort()).toEqual([aId, bId].sort());
    // subject '점심' + inMailbox → b만
    const one = await store.queryEmails(accountId, { subject: "점심", inMailbox: inboxId }, false, 0, 50);
    expect(one.ids).toEqual([bId]);
    await db.close();
  });
});
