/**
 * STATUS·LIST-STATUS의 DELETED 항목(RFC 9051 §6.3.11 — rev2 필수 항목).
 *
 * ★이 파일이 있는 이유(2026-10-05, #29 리뷰 후속). 우리는 IMAP4rev2를 광고하는데 STATUS의 DELETED를
 * 몰랐다. 그래서 `STATUS INBOX (DELETED)`는 **BAD**를 받았고 — 광고와 구현이 어긋난 BAD는 10-02에
 * NAMESPACE→LIST 루프를 만든 바로 그 모양이다 — LIST-STATUS(`RETURN (STATUS (... DELETED))`)는
 * 백엔드까지 갔다가 STATUS 줄을 **조용히 통째로** 빼먹었다. 클라이언트는 카운트를 못 받고 이유도 모른다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapMailbox } from "../src/engine.ts";

const enc = new TextEncoder();

function mailbox(over: Partial<ImapMailbox> & { name: string }): ImapMailbox {
  return { role: null, uidvalidity: 11, uidnext: 5, highestmodseq: 9, totalCount: 4, unreadCount: 2, totalBytes: 1234, ...over };
}

function authed(): ImapEngine {
  const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
  e.feed(enc.encode("a0 LOGIN u p\r\n"));
  e.authResult({ accountId: "acc" });
  return e;
}

function replies(actions: ImapAction[]): string[] {
  return actions.filter((a): a is { kind: "reply"; text: string } => a.kind === "reply").map((a) => a.text);
}

/** 명령 하나 — 백엔드 요청이 나가면 그 요청을 돌려주고 mailboxes로 답한다. */
function run(line: string, mailboxes: ImapMailbox[]): { request: unknown; out: string[] } {
  const e = authed();
  const first = e.feed(enc.encode(`${line}\r\n`));
  const backend = first.find((a) => a.kind === "backend") as { kind: "backend"; req: unknown } | undefined;
  if (!backend) return { request: null, out: replies(first) };
  return { request: backend.req, out: replies(e.backendResult({ kind: "mailboxes", mailboxes })) };
}

const BOXES = [mailbox({ name: "INBOX", role: "inbox", deletedCount: 3 }), mailbox({ name: "Sent", role: "sent", deletedCount: 0 })];

describe("STATUS DELETED", () => {
  test("★STATUS (DELETED)는 BAD가 아니라 삭제 표시 수를 돌려준다", () => {
    const { request, out } = run("s STATUS INBOX (MESSAGES DELETED)", BOXES);
    expect(request).toEqual({ kind: "listMailboxes", deletedCounts: true });
    expect(out).toEqual(['* STATUS "INBOX" (MESSAGES 4 DELETED 3)', "s OK STATUS completed"]);
  });

  test("★LIST-STATUS에 DELETED가 섞여도 STATUS 줄이 빠지지 않는다", () => {
    const { out } = run('l LIST "" "*" RETURN (STATUS (MESSAGES DELETED))', BOXES);
    expect(out).toEqual([
      '* LIST (\\HasNoChildren) "/" "INBOX"',
      '* STATUS "INBOX" (MESSAGES 4 DELETED 3)',
      '* LIST (\\Sent \\HasNoChildren) "/" "Sent"',
      '* STATUS "Sent" (MESSAGES 4 DELETED 0)',
      "l OK LIST completed",
    ]);
  });

  test("★모르는 항목은 백엔드를 부르기 전에 BAD — 조용히 줄을 빼지 않는다", () => {
    const status = run("s STATUS INBOX (MESSAGES BOGUS)", BOXES);
    expect(status.request).toBe(null);
    expect(status.out.at(-1)).toMatch(/^s BAD /);
    const list = run('l LIST "" "*" RETURN (STATUS (MESSAGES BOGUS))', BOXES);
    expect(list.request).toBe(null);
    expect(list.out.at(-1)).toMatch(/^l BAD /);
  });

  test("DELETED를 요청하지 않으면 백엔드에 세 달라고 하지 않는다(평소 LIST·STATUS 비용 그대로)", () => {
    expect(run("s STATUS INBOX (MESSAGES UNSEEN)", BOXES).request).toEqual({ kind: "listMailboxes" });
    expect(run('l LIST "" "*" RETURN (STATUS (MESSAGES))', BOXES).request).toEqual({ kind: "listMailboxes" });
    expect(run('l LIST "" "*"', BOXES).request).toEqual({ kind: "listMailboxes" });
  });
});
