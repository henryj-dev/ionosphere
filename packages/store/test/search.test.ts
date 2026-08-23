import { describe, expect, test } from "@ionosphere/testkit";
import { makeAppendInput, setupFixture } from "./helpers.ts";

describe("Store.search (SCHEMA.md §8: search_index 색인·질의)", () => {
  test("append(searchText) → search 라운드트립: subject/body/from 필드 매칭", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();

    const { messageId } = await store.appendMessage(
      makeAppendInput({
        accountId,
        mailboxIds: [inboxId],
        searchText: { subject: "회의 안내", body: "내일 오후 3시 회의입니다", from: "boss@corp.com" },
      }),
    );

    const bySubject = await store.search(accountId, "회의");
    expect(bySubject.map((h) => h.messageId)).toContain(messageId);

    const byBody = await store.search(accountId, "오후");
    expect(byBody.map((h) => h.messageId)).toContain(messageId);

    const byFrom = await store.search(accountId, "boss");
    expect(byFrom.map((h) => h.messageId)).toContain(messageId);

    const noMatch = await store.search(accountId, "없는단어");
    expect(noMatch).toEqual([]);

    await db.close();
  });

  test("AND 시맨틱: 두 토큰이 공존하는 메시지만 반환", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();

    const { messageId: m1 } = await store.appendMessage(
      makeAppendInput({ accountId, mailboxIds: [inboxId], searchText: { subject: "회의 안내" } }),
    );
    await store.appendMessage(
      makeAppendInput({ accountId, mailboxIds: [inboxId], searchText: { subject: "회의 취소" } }),
    );

    // "안내"와 "회의"는 m1에만 공존 (m2는 "취소"만 공존)
    const hits = await store.search(accountId, "회의 안내");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.messageId).toBe(m1);

    await db.close();
  });

  test("searchIndexBody:false → body는 검색 불가, subject/from은 계속 가능", async () => {
    const { store, db, accountId, inboxId } = await setupFixture({ searchIndexBody: false });

    const { messageId } = await store.appendMessage(
      makeAppendInput({
        accountId,
        mailboxIds: [inboxId],
        searchText: { subject: "분기 보고서", body: "매출이 증가했습니다", from: "cfo@corp.com" },
      }),
    );

    const byBody = await store.search(accountId, "매출");
    expect(byBody).toEqual([]);

    const bySubject = await store.search(accountId, "보고서");
    expect(bySubject.map((h) => h.messageId)).toContain(messageId);

    const byFrom = await store.search(accountId, "cfo");
    expect(byFrom.map((h) => h.messageId)).toContain(messageId);

    await db.close();
  });

  test("고아 포스팅: messages 행 삭제 후 조인 필터로 결과에서 제외", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();

    const { messageId } = await store.appendMessage(
      makeAppendInput({ accountId, mailboxIds: [inboxId], searchText: { subject: "삭제될 메시지" } }),
    );

    expect((await store.search(accountId, "삭제될")).map((h) => h.messageId)).toContain(messageId);

    // search_index를 남겨둔 채 messages 행만 직접 제거(§7-4 지연 정리 시나리오 재현)
    await db.batch([{ sql: "DELETE FROM messages WHERE id = ?", params: [messageId] }]);

    const hits = await store.search(accountId, "삭제될");
    expect(hits.map((h) => h.messageId)).not.toContain(messageId);

    await db.close();
  });

  test("searchText 생략 → append는 성공하지만 색인되지 않음", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();

    const result = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] }));
    expect(result.messageId).toBeTruthy();

    const hits = await store.search(accountId, "아무거나");
    expect(hits).toEqual([]);

    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS cnt FROM search_index WHERE account_id = ?", params: [accountId] });
    expect(Number(rows[0]?.cnt)).toBe(0);

    await db.close();
  });

  test("빈 질의 → 빈 결과", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();
    await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId], searchText: { subject: "아무거나" } }));

    expect(await store.search(accountId, "")).toEqual([]);
    expect(await store.search(accountId, "   ")).toEqual([]);

    await db.close();
  });
});
