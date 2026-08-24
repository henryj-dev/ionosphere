/** CONDSTORE/QRESYNC (RFC 7162) — MODSEQ/CHANGEDSINCE/UNCHANGEDSINCE/VANISHED. */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapBackendRequest, type ImapFetchData, type ImapMailbox } from "../src/engine.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();
const BOX: ImapMailbox = { name: "INBOX", role: "inbox", uidvalidity: 100, uidnext: 10, highestmodseq: 50, totalCount: 3, unreadCount: 1, totalBytes: 100 };

function authed(): ImapEngine {
  const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
  e.feed(enc.encode("a0 LOGIN u p\r\n"));
  e.authResult({ accountId: "acc" });
  return e;
}

function selected(): ImapEngine {
  const e = authed();
  e.feed(enc.encode("s SELECT INBOX\r\n"));
  e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: 1 });
  return e;
}

function replies(actions: ImapAction[]): string[] {
  return actions.filter((a): a is { kind: "reply"; text: string } => a.kind === "reply").map((a) => a.text);
}

function allText(actions: ImapAction[]): string {
  let out = "";
  for (const a of actions) {
    if (a.kind === "reply") out += a.text + "\r\n";
    else if (a.kind === "replyBinary") out += dec.decode(a.bytes);
  }
  return out;
}

function backendReq(actions: ImapAction[]): ImapBackendRequest | null {
  return actions.find((a): a is { kind: "backend"; req: ImapBackendRequest } => a.kind === "backend")?.req ?? null;
}

function data(uid: number, modseq: number, flags: string[] = []): ImapFetchData {
  return { uid, flags, internalDateMs: 0, size: 10, modseq };
}

describe("CONDSTORE", () => {
  test("FETCH (MODSEQ) 항목", () => {
    const e = selected();
    e.feed(enc.encode("f1 FETCH 1 (FLAGS MODSEQ)\r\n"));
    const out = allText(e.backendResult({ kind: "messages", messages: [data(3, 42, ["\\Seen"])] }));
    expect(out).toContain("* 1 FETCH (FLAGS (\\Seen) MODSEQ (42))");
  });

  test("FETCH CHANGEDSINCE — 필터 + MODSEQ 자동 포함", () => {
    const e = selected();
    e.feed(enc.encode("f1 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 40)\r\n"));
    const out = allText(e.backendResult({ kind: "messages", messages: [data(3, 30), data(7, 45), data(9, 50)] }));
    expect(out).not.toContain("UID 3"); // modseq 30 ≤ 40 — 제외
    expect(out).toContain("* 2 FETCH (FLAGS () UID 7 MODSEQ (45))");
    expect(out).toContain("* 3 FETCH (FLAGS () UID 9 MODSEQ (50))");
  });

  test("STORE UNCHANGEDSINCE — MODIFIED 응답 코드 + 백엔드 관통", () => {
    const e = selected();
    const first = e.feed(enc.encode("s1 UID STORE 3,7 (UNCHANGEDSINCE 40) +FLAGS (\\Seen)\r\n"));
    expect(backendReq(first)).toMatchObject({ kind: "storeFlags", uids: [3, 7], unchangedSince: 40 });
    const out = replies(
      e.backendResult({ kind: "flagsUpdated", updated: [{ uid: 3, flags: ["\\Seen"], modseq: 51 }], failed: [7] }),
    );
    expect(out[0]).toBe("* 1 FETCH (FLAGS (\\Seen) UID 3 MODSEQ (51))");
    expect(out[1]).toBe("s1 OK [MODIFIED 7] conditional UID STORE failed for some messages");
  });

  test("SELECT (CONDSTORE) 파라미터 수용", () => {
    const e = authed();
    e.feed(enc.encode("s1 SELECT INBOX (CONDSTORE)\r\n"));
    const out = replies(e.backendResult({ kind: "selected", mailbox: BOX, uids: [3], firstUnseenSeq: null }));
    expect(out.some((l) => l.startsWith("* OK [HIGHESTMODSEQ 50]"))).toBe(true);
  });
});

describe("QRESYNC", () => {
  test("ENABLE QRESYNC → CONDSTORE 함의, EXPUNGE가 VANISHED로", () => {
    const e = authed();
    expect(replies(e.feed(enc.encode("e0 ENABLE QRESYNC\r\n")))[0]).toBe("* ENABLED QRESYNC");
    e.feed(enc.encode("s SELECT INBOX\r\n"));
    e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: null });
    e.feed(enc.encode("x1 EXPUNGE\r\n"));
    const out = replies(e.backendResult({ kind: "expunged", uids: [3, 9] }));
    expect(out).toEqual(["* VANISHED 3,9", "x1 OK EXPUNGE completed"]);
  });

  test("SELECT (QRESYNC (uv modseq)) — VANISHED (EARLIER) + FLAGS 델타", () => {
    const e = authed();
    e.feed(enc.encode("e0 ENABLE QRESYNC\r\n"));
    const first = e.feed(enc.encode("s1 SELECT INBOX (QRESYNC (100 40))\r\n"));
    // 1차: selectMailbox
    const selectOut = e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: null });
    const syncReq = backendReq(selectOut);
    expect(syncReq).toEqual({ kind: "syncSince", name: "INBOX", sinceModseq: 40 });
    expect(backendReq(first)).toEqual({ kind: "selectMailbox", name: "INBOX" });
    // 2차: syncSince
    const out = replies(e.backendResult({ kind: "sync", vanished: [4, 5], changed: [{ uid: 7, flags: ["\\Seen"], modseq: 45 }] }));
    expect(out).toContain("* VANISHED (EARLIER) 4:5");
    expect(out).toContain("* 2 FETCH (UID 7 FLAGS (\\Seen) MODSEQ (45))");
    expect(out[out.length - 1]).toContain("s1 OK [READ-WRITE]");
  });

  /**
   * ★세 번째 인자 known-uids는 예전엔 문법으로만 받고 **버렸다**. 툼스톤 보존창이 생긴 뒤로는
   * 이 값이 "보존창 밖 요청에도 정확히 답할 수 있는" 유일한 근거라(RFC 7162 §3.2.5.2)
   * 백엔드까지 흘러야 한다.
   */
  test("SELECT (QRESYNC (uv modseq known-uids)) — known-uids가 백엔드로 간다", () => {
    const e = authed();
    e.feed(enc.encode("e0 ENABLE QRESYNC\r\n"));
    const first = e.feed(enc.encode("s1 SELECT INBOX (QRESYNC (100 40 1:5,9))\r\n"));
    expect(backendReq(first)).toEqual({ kind: "selectMailbox", name: "INBOX" });
    const selectOut = e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: null });
    expect(backendReq(selectOut)).toEqual({
      kind: "syncSince",
      name: "INBOX",
      sinceModseq: 40,
      knownUids: [{ from: 1, to: 5 }, { from: 9, to: 9 }],
    });
  });

  test("known-uids가 없으면 요청에 실리지 않는다", () => {
    const e = authed();
    e.feed(enc.encode("e0 ENABLE QRESYNC\r\n"));
    e.feed(enc.encode("s1 SELECT INBOX (QRESYNC (100 40))\r\n"));
    const selectOut = e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: null });
    expect(backendReq(selectOut)).toEqual({ kind: "syncSince", name: "INBOX", sinceModseq: 40 });
  });

  test("QRESYNC 미ENABLE 상태의 SELECT 파라미터 → BAD", () => {
    const e = authed();
    expect(replies(e.feed(enc.encode("s1 SELECT INBOX (QRESYNC (100 40))\r\n")))[0]).toBe("s1 BAD QRESYNC not enabled");
  });

  test("uidvalidity 불일치 — 델타 생략(전체 재동기화 유도)", () => {
    const e = authed();
    e.feed(enc.encode("e0 ENABLE QRESYNC\r\n"));
    e.feed(enc.encode("s1 SELECT INBOX (QRESYNC (999 40))\r\n"));
    const out = replies(e.backendResult({ kind: "selected", mailbox: BOX, uids: [3], firstUnseenSeq: null }));
    expect(out.join("\n")).not.toContain("VANISHED");
    expect(out[out.length - 1]).toContain("s1 OK [READ-WRITE]");
  });
});
