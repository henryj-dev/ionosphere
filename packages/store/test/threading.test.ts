import { describe, expect, test } from "@ionosphere/testkit";
import { makeAppendInput, setupFixture } from "./helpers.ts";

describe("스레딩 (SCHEMA.md §5-3, no-merge)", () => {
  test("ref hash를 공유하는 두 메시지는 같은 thread_id", async () => {
    const { store, accountId, inboxId } = await setupFixture();

    const first = await store.appendMessage(
      makeAppendInput({
        accountId,
        mailboxIds: [inboxId],
        envelope: {
          subject: "hi",
          subjectBase: "hi",
          msgidHash: "aaaa",
          sentAt: null,
          preview: null,
          hasAttachment: false,
          addresses: [],
          threadRefHashes: ["aaaa"],
        },
      }),
    );

    const reply = await store.appendMessage(
      makeAppendInput({
        accountId,
        mailboxIds: [inboxId],
        envelope: {
          subject: "re: hi",
          subjectBase: "hi",
          msgidHash: "bbbb",
          sentAt: null,
          preview: null,
          hasAttachment: false,
          addresses: [],
          threadRefHashes: ["aaaa", "bbbb"], // 원본 참조 + 자기 msgid
        },
      }),
    );

    expect(reply.threadId).toBe(first.threadId);
  });

  test("연관 없는 메시지는 새 thread_id를 받음", async () => {
    const { store, accountId, inboxId } = await setupFixture();

    const a = await store.appendMessage(
      makeAppendInput({
        accountId,
        mailboxIds: [inboxId],
        envelope: {
          subject: "a",
          subjectBase: "a",
          msgidHash: "hash-a",
          sentAt: null,
          preview: null,
          hasAttachment: false,
          addresses: [],
          threadRefHashes: ["hash-a"],
        },
      }),
    );

    const b = await store.appendMessage(
      makeAppendInput({
        accountId,
        mailboxIds: [inboxId],
        envelope: {
          subject: "unrelated",
          subjectBase: "unrelated",
          msgidHash: "hash-b",
          sentAt: null,
          preview: null,
          hasAttachment: false,
          addresses: [],
          threadRefHashes: ["hash-b"],
        },
      }),
    );

    expect(a.threadId).not.toBe(b.threadId);
  });

  test("threadRefHashes 없는 메시지도 각자 새 thread를 받음", async () => {
    const { store, accountId, inboxId } = await setupFixture();
    const a = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] }));
    const b = await store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] }));
    expect(a.threadId).not.toBe(b.threadId);
  });
});
