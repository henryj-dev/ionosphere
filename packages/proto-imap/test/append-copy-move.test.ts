/** APPEND/COPY/MOVE(UIDPLUS)/IDLE 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapBackendRequest, type ImapMailbox } from "../src/engine.ts";
import { formatUidSet } from "../src/sequence-set.ts";
import { parseImapDateTime } from "../src/fetch-format.ts";

const enc = new TextEncoder();
const BOX: ImapMailbox = { name: "INBOX", role: "inbox", uidvalidity: 1, uidnext: 10, highestmodseq: 5, totalCount: 3, unreadCount: 1, totalBytes: 100 };

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

function backendReq(actions: ImapAction[]): ImapBackendRequest | null {
  return actions.find((a): a is { kind: "backend"; req: ImapBackendRequest } => a.kind === "backend")?.req ?? null;
}

describe("유틸", () => {
  test("formatUidSet — 연속 압축", () => {
    expect(formatUidSet([3, 4, 5, 9, 1])).toBe("1,3:5,9");
    expect(formatUidSet([7])).toBe("7");
  });

  test("parseImapDateTime — 타임존 반영", () => {
    expect(parseImapDateTime("01-Jan-2026 09:00:00 +0900")).toBe(Date.UTC(2026, 0, 1, 0, 0, 0));
    expect(parseImapDateTime(" 5-Feb-2026 00:30:00 -0130")).toBe(Date.UTC(2026, 1, 5, 2, 0, 0));
    expect(parseImapDateTime("bogus")).toBeNull();
  });
});

describe("APPEND", () => {
  test("flags + date-time + 리터럴 → 백엔드 요청 + APPENDUID", () => {
    const e = authed();
    const raw = "From: a@x\r\n\r\nbody\r\n";
    const first = e.feed(enc.encode(`p1 APPEND Drafts (\\Draft $x) "01-Jan-2026 09:00:00 +0900" {${raw.length}+}\r\n${raw}\r\n`));
    expect(backendReq(first)).toEqual({
      kind: "appendMessage",
      name: "Drafts",
      flags: ["\\Draft", "$x"],
      internalDateMs: Date.UTC(2026, 0, 1),
      raw: enc.encode(raw),
    });
    expect(replies(e.backendResult({ kind: "appended", uidvalidity: 55, uid: 42 }))).toEqual([
      "p1 OK [APPENDUID 55 42] APPEND completed",
    ]);
  });

  test("옵션 생략(리터럴만) + 대상 없음 TRYCREATE 관통", () => {
    const e = authed();
    const first = e.feed(enc.encode("p1 APPEND Nope {4+}\r\nabcd\r\n"));
    expect(backendReq(first)).toMatchObject({ flags: [], internalDateMs: null });
    expect(replies(e.backendResult({ kind: "no", code: "TRYCREATE", message: "no such mailbox" }))[0]).toBe(
      "p1 NO [TRYCREATE] APPEND no such mailbox",
    );
  });

  test("메시지 없음 → BAD", () => {
    expect(replies(authed().feed(enc.encode("p1 APPEND INBOX\r\n")))[0]).toContain("p1 BAD");
  });
});

describe("COPY/MOVE", () => {
  test("COPY — COPYUID 응답 코드", () => {
    const e = selected();
    const first = e.feed(enc.encode("c1 COPY 1:2 Archive\r\n"));
    expect(backendReq(first)).toEqual({ kind: "copyMessages", from: "INBOX", to: "Archive", uids: [3, 7] });
    expect(replies(e.backendResult({ kind: "copied", uidvalidity: 88, srcUids: [3, 7], dstUids: [101, 102] }))).toEqual([
      "c1 OK [COPYUID 88 3,7 101:102] COPY completed",
    ]);
  });

  test("UID MOVE — untagged OK [COPYUID] → EXPUNGE(내림차순) → tagged OK, 뷰 갱신", () => {
    const e = selected();
    const first = e.feed(enc.encode("m1 UID MOVE 3,9 Archive\r\n"));
    expect(backendReq(first)).toEqual({ kind: "moveMessages", from: "INBOX", to: "Archive", uids: [3, 9] });
    const out = replies(e.backendResult({ kind: "copied", uidvalidity: 88, srcUids: [3, 9], dstUids: [201, 202] }));
    expect(out).toEqual(["* OK [COPYUID 88 3,9 201:202] moved", "* 3 EXPUNGE", "* 1 EXPUNGE", "m1 OK UID MOVE completed"]);
    // 남은 건 uid 7 → seq 1
    const f = e.feed(enc.encode("f1 FETCH 1 FLAGS\r\n"));
    expect(backendReq(f)).toMatchObject({ uids: [7] });
  });

  test("MOVE on READ-ONLY → NO, 대상 없는 세트 → OK no-op", () => {
    const ro = authed();
    ro.feed(enc.encode("s EXAMINE INBOX\r\n"));
    ro.backendResult({ kind: "selected", mailbox: BOX, uids: [3], firstUnseenSeq: null });
    expect(replies(ro.feed(enc.encode("m1 MOVE 1 X\r\n")))[0]).toContain("NO [READ-ONLY]");
    expect(replies(selected().feed(enc.encode("m2 UID MOVE 999 X\r\n")))).toEqual(["m2 OK UID MOVE completed"]);
  });
});

describe("IDLE", () => {
  test("IDLE → + idling → DONE → OK, isIdling 플래그", () => {
    const e = selected();
    expect(e.isIdling()).toBe(false);
    expect(replies(e.feed(enc.encode("i1 IDLE\r\n")))).toEqual(["+ idling"]);
    expect(e.isIdling()).toBe(true);
    expect(replies(e.feed(enc.encode("DONE\r\n")))).toEqual(["i1 OK IDLE terminated"]);
    expect(e.isIdling()).toBe(false);
    // 이후 정상 명령 처리 — selected 상태의 NOOP은 재동기화(selectMailbox) 후 OK
    e.feed(enc.encode("n1 NOOP\r\n"));
    const out = replies(e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: null }));
    expect(out).toEqual(["n1 OK NOOP completed"]);
  });

  test("DONE 아닌 라인 → BAD + IDLE 종료", () => {
    const e = selected();
    e.feed(enc.encode("i1 IDLE\r\n"));
    expect(replies(e.feed(enc.encode("garbage\r\n")))[0]).toBe("i1 BAD expected DONE");
    expect(e.isIdling()).toBe(false);
  });
});
