/** ESEARCH(RFC 4731) + LIST-STATUS(RFC 5819) 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapFetchData, type ImapMailbox } from "../src/engine.ts";

const enc = new TextEncoder();

function mailbox(over: Partial<ImapMailbox> & { name: string }): ImapMailbox {
  return { role: null, uidvalidity: 11, uidnext: 5, highestmodseq: 9, totalCount: 4, unreadCount: 2, totalBytes: 1234, ...over };
}

const BOX = mailbox({ name: "INBOX", role: "inbox" });

function authed(): ImapEngine {
  const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
  e.feed(enc.encode("a0 LOGIN u p\r\n"));
  e.authResult({ accountId: "acc" });
  return e;
}

function selected(): ImapEngine {
  const e = authed();
  e.feed(enc.encode("s SELECT INBOX\r\n"));
  e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: null });
  return e;
}

function replies(actions: ImapAction[]): string[] {
  return actions.filter((a): a is { kind: "reply"; text: string } => a.kind === "reply").map((a) => a.text);
}

function data(uid: number, flags: string[]): ImapFetchData {
  return { uid, flags, internalDateMs: 0, size: 10, modseq: 5 };
}

describe("ESEARCH", () => {
  test("UID SEARCH RETURN (MIN MAX COUNT ALL) — 압축 응답", () => {
    const e = selected();
    e.feed(enc.encode("s1 UID SEARCH RETURN (MIN MAX COUNT ALL) UNSEEN\r\n"));
    const out = replies(e.backendResult({ kind: "messages", messages: [data(3, []), data(7, ["\\Seen"]), data(9, [])] }));
    expect(out[0]).toBe('* ESEARCH (TAG "s1") UID MIN 3 MAX 9 ALL 3,9 COUNT 2');
    expect(out[1]).toBe("s1 OK UID SEARCH completed");
  });

  test("RETURN () == ALL, 매칭 없으면 MIN/MAX/ALL 생략·COUNT만", () => {
    const e = selected();
    e.feed(enc.encode("s1 SEARCH RETURN (COUNT) DELETED\r\n"));
    const out = replies(e.backendResult({ kind: "messages", messages: [data(3, []), data(7, []), data(9, [])] }));
    expect(out[0]).toBe('* ESEARCH (TAG "s1") COUNT 0');

    const e2 = selected();
    e2.feed(enc.encode("s2 SEARCH RETURN () ALL\r\n"));
    const out2 = replies(e2.backendResult({ kind: "messages", messages: [data(3, []), data(7, []), data(9, [])] }));
    expect(out2[0]).toBe('* ESEARCH (TAG "s2") ALL 1:3'); // seq 모드 — RETURN ()는 ALL과 동일
  });

  test("RETURN 없는 SEARCH는 고전 응답 유지 + 미지 옵션 BAD", () => {
    const e = selected();
    e.feed(enc.encode("s1 SEARCH ALL\r\n"));
    const out = replies(e.backendResult({ kind: "messages", messages: [data(3, []), data(7, []), data(9, [])] }));
    expect(out[0]).toBe("* SEARCH 1 2 3");
    expect(replies(selected().feed(enc.encode("s2 SEARCH RETURN (BOGUS) ALL\r\n")))[0]).toContain("s2 BAD");
  });
});

describe("LIST-STATUS / RETURN (SUBSCRIBED)", () => {
  const BOXES = [mailbox({ name: "INBOX", role: "inbox" }), mailbox({ name: "Work", subscribed: false, totalCount: 7 })];

  test('LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN)) — STATUS 인라인', () => {
    const e = authed();
    e.feed(enc.encode('l1 LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN))\r\n'));
    const out = replies(e.backendResult({ kind: "mailboxes", mailboxes: BOXES }));
    expect(out).toEqual([
      '* LIST (\\HasNoChildren) "/" "INBOX"',
      '* STATUS "INBOX" (MESSAGES 4 UNSEEN 2)',
      '* LIST (\\HasNoChildren) "/" "Work"',
      '* STATUS "Work" (MESSAGES 7 UNSEEN 2)',
      "l1 OK LIST completed",
    ]);
  });

  test("RETURN (SUBSCRIBED) — \\Subscribed 속성", () => {
    const e = authed();
    e.feed(enc.encode('l1 LIST "" "*" RETURN (SUBSCRIBED)\r\n'));
    const out = replies(e.backendResult({ kind: "mailboxes", mailboxes: BOXES }));
    expect(out[0]).toContain("\\Subscribed");
    expect(out[1]).not.toContain("\\Subscribed"); // Work는 unsubscribed
  });

  test("LSUB에 RETURN → BAD", () => {
    expect(replies(authed().feed(enc.encode('l1 LSUB "" "*" RETURN (SUBSCRIBED)\r\n')))[0]).toContain("l1 BAD");
  });
});
