/** SELECT/EXAMINE/UNSELECT/CLOSE — selected 상태 전이 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapBackendRequest, type ImapMailbox } from "../src/engine.ts";

const enc = new TextEncoder();

const BOX: ImapMailbox = {
  name: "INBOX",
  role: "inbox",
  uidvalidity: 1111,
  uidnext: 6,
  highestmodseq: 42,
  totalCount: 3,
  unreadCount: 1,
  totalBytes: 999,
};

function authedEngine(): ImapEngine {
  const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
  e.feed(enc.encode("a0 LOGIN u p\r\n"));
  e.authResult({ accountId: "acc" });
  return e;
}

function replies(actions: ImapAction[]): string[] {
  return actions.filter((a): a is { kind: "reply"; text: string } => a.kind === "reply").map((a) => a.text);
}

/** SELECT까지 완료된 엔진. */
function selectedEngine(readWrite = true): ImapEngine {
  const e = authedEngine();
  e.feed(enc.encode(`s ${readWrite ? "SELECT" : "EXAMINE"} INBOX\r\n`));
  e.backendResult({ kind: "selected", mailbox: BOX, uids: [2, 3, 5], firstUnseenSeq: 2 });
  return e;
}

describe("SELECT/EXAMINE", () => {
  test("SELECT — 필수 untagged 응답 세트 + READ-WRITE", () => {
    const e = authedEngine();
    const first = e.feed(enc.encode("a1 SELECT inbox\r\n"));
    expect(first).toEqual([{ kind: "backend", req: { kind: "selectMailbox", name: "INBOX" } }]);
    const out = replies(e.backendResult({ kind: "selected", mailbox: BOX, uids: [2, 3, 5], firstUnseenSeq: 2 }));
    expect(out).toEqual([
      "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
      "* 3 EXISTS",
      "* 0 RECENT",
      "* OK [UIDVALIDITY 1111] UIDs valid",
      "* OK [UIDNEXT 6] predicted next UID",
      "* OK [HIGHESTMODSEQ 42] modseq",
      "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] flags",
      "* OK [UNSEEN 2] first unseen",
      "a1 OK [READ-WRITE] SELECT completed",
    ]);
  });

  test("EXAMINE — READ-ONLY + 빈 PERMANENTFLAGS", () => {
    const e = authedEngine();
    e.feed(enc.encode("a1 EXAMINE INBOX\r\n"));
    const out = replies(e.backendResult({ kind: "selected", mailbox: BOX, uids: [], firstUnseenSeq: null }));
    expect(out).toContain("* 0 EXISTS");
    expect(out).toContain("* OK [PERMANENTFLAGS ()] read-only");
    expect(out[out.length - 1]).toBe("a1 OK [READ-ONLY] EXAMINE completed");
    expect(out.join("\n")).not.toContain("UNSEEN"); // firstUnseenSeq null이면 생략
  });

  test("SELECT 실패 — NO + 기존 선택도 해제(RFC 명시)", () => {
    const e = selectedEngine();
    e.feed(enc.encode("a2 SELECT Nope\r\n"));
    const out = replies(e.backendResult({ kind: "no", code: "NONEXISTENT", message: "no such mailbox" }));
    expect(out[0]).toBe("a2 NO [NONEXISTENT] SELECT no such mailbox");
    // selected 전용 명령이 거부되면 해제된 것
    expect(replies(e.feed(enc.encode("a3 UNSELECT\r\n")))[0]).toContain("a3 BAD");
  });

  test("인증 전 SELECT → BAD", () => {
    const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
    expect(replies(e.feed(enc.encode("a1 SELECT INBOX\r\n")))[0]).toContain("a1 BAD");
  });
});

describe("UNSELECT/CLOSE", () => {
  test("UNSELECT — expunge 없이 해제", () => {
    const e = selectedEngine();
    const out = e.feed(enc.encode("a1 UNSELECT\r\n"));
    expect(out).toEqual([{ kind: "reply", text: "a1 OK UNSELECT completed" }]); // backend 호출 없음
    expect(replies(e.feed(enc.encode("a2 CLOSE\r\n")))[0]).toContain("a2 BAD");
  });

  test("CLOSE(READ-WRITE) — expungeMailbox 요청 후 OK, 해제", () => {
    const e = selectedEngine(true);
    const first = e.feed(enc.encode("a1 CLOSE\r\n"));
    const backend = first.find((a): a is { kind: "backend"; req: ImapBackendRequest } => a.kind === "backend");
    expect(backend?.req).toEqual({ kind: "expungeMailbox", name: "INBOX" });
    expect(replies(e.backendResult({ kind: "ok" }))).toEqual(["a1 OK CLOSE completed"]);
    expect(replies(e.feed(enc.encode("a2 UNSELECT\r\n")))[0]).toContain("a2 BAD"); // 이미 해제됨
  });

  test("CLOSE(READ-ONLY) — expunge 없이 즉시 OK", () => {
    const e = selectedEngine(false);
    const out = e.feed(enc.encode("a1 CLOSE\r\n"));
    expect(out).toEqual([{ kind: "reply", text: "a1 OK CLOSE completed" }]);
  });

  test("selected 아닌 상태에서 CLOSE/UNSELECT → BAD", () => {
    const e = authedEngine();
    expect(replies(e.feed(enc.encode("a1 CLOSE\r\n")))[0]).toContain("a1 BAD");
    expect(replies(e.feed(enc.encode("a2 UNSELECT\r\n")))[0]).toContain("a2 BAD");
  });
});
