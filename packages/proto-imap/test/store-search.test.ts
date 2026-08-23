/** STORE/EXPUNGE/SEARCH — 엔진 + 크라이테리어 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapBackendRequest, type ImapFetchData, type ImapMailbox } from "../src/engine.ts";
import { parseSearchProgram, evaluateSearch, parseSearchDate, type SearchMessage } from "../src/search-criteria.ts";
import { parseValues } from "../src/parser.ts";

const enc = new TextEncoder();

const BOX: ImapMailbox = { name: "INBOX", role: "inbox", uidvalidity: 1, uidnext: 10, highestmodseq: 5, totalCount: 3, unreadCount: 1, totalBytes: 100 };

function makeEngine(readWrite = true): ImapEngine {
  const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
  e.feed(enc.encode("a0 LOGIN u p\r\n"));
  e.authResult({ accountId: "acc" });
  e.feed(enc.encode(`s ${readWrite ? "SELECT" : "EXAMINE"} INBOX\r\n`));
  e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: 1 });
  return e;
}

function replies(actions: ImapAction[]): string[] {
  return actions.filter((a): a is { kind: "reply"; text: string } => a.kind === "reply").map((a) => a.text);
}

function backendReq(actions: ImapAction[]): ImapBackendRequest | null {
  return actions.find((a): a is { kind: "backend"; req: ImapBackendRequest } => a.kind === "backend")?.req ?? null;
}

describe("STORE", () => {
  test("+FLAGS — 백엔드 요청 + untagged FETCH FLAGS", () => {
    const e = makeEngine();
    const first = e.feed(enc.encode("s1 STORE 1:2 +FLAGS (\\Seen $Label)\r\n"));
    expect(backendReq(first)).toEqual({ kind: "storeFlags", name: "INBOX", uids: [3, 7], mode: "add", flags: ["\\Seen", "$Label"] });
    const out = replies(
      e.backendResult({
        kind: "flagsUpdated",
        updated: [
          { uid: 3, flags: ["\\Seen", "$Label"] },
          { uid: 7, flags: ["\\Seen", "$Label", "\\Flagged"] },
        ],
      }),
    );
    expect(out).toEqual([
      // 미공지 키워드($Label) 첫 사용 — * FLAGS 재공지 선행(imaptest 요구)
      "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft $Label)",
      "* 1 FETCH (FLAGS (\\Seen $Label))",
      "* 2 FETCH (FLAGS (\\Seen $Label \\Flagged))",
      "s1 OK STORE completed",
    ]);
  });

  test("FLAGS.SILENT — untagged 억제", () => {
    const e = makeEngine();
    e.feed(enc.encode("s1 STORE 1 FLAGS.SILENT (\\Deleted)\r\n"));
    const out = replies(e.backendResult({ kind: "flagsUpdated", updated: [{ uid: 3, flags: ["\\Deleted"] }] }));
    expect(out).toEqual(["s1 OK STORE completed"]);
  });

  test("UID STORE — untagged에 UID 포함, -FLAGS 모드", () => {
    const e = makeEngine();
    const first = e.feed(enc.encode("s1 UID STORE 7 -FLAGS (\\Seen)\r\n"));
    expect(backendReq(first)).toMatchObject({ mode: "remove", uids: [7] });
    const out = replies(e.backendResult({ kind: "flagsUpdated", updated: [{ uid: 7, flags: [] }] }));
    expect(out[0]).toBe("* 2 FETCH (FLAGS () UID 7)");
  });

  test("READ-ONLY 메일함 → NO", () => {
    const e = makeEngine(false);
    expect(replies(e.feed(enc.encode("s1 STORE 1 +FLAGS (\\Seen)\r\n")))[0]).toContain("NO [READ-ONLY]");
  });

  test("잘못된 항목/플래그 → BAD", () => {
    expect(replies(makeEngine().feed(enc.encode("s1 STORE 1 BOGUS (\\Seen)\r\n")))[0]).toContain("s1 BAD");
    expect(replies(makeEngine().feed(enc.encode("s1 STORE x +FLAGS (\\Seen)\r\n")))[0]).toContain("s1 BAD");
  });
});

describe("EXPUNGE", () => {
  test("EXPUNGE — 내림차순 untagged + 세션 뷰 갱신", () => {
    const e = makeEngine();
    const first = e.feed(enc.encode("e1 EXPUNGE\r\n"));
    expect(backendReq(first)).toEqual({ kind: "expunge", name: "INBOX", uids: null });
    const out = replies(e.backendResult({ kind: "expunged", uids: [3, 9] }));
    expect(out).toEqual(["* 3 EXPUNGE", "* 1 EXPUNGE", "e1 OK EXPUNGE completed"]);
    // 남은 메시지는 uid 7 하나 — seq 1로 재번호
    const f = e.feed(enc.encode("f1 FETCH 1 FLAGS\r\n"));
    expect(backendReq(f)).toMatchObject({ uids: [7] });
  });

  test("UID EXPUNGE — uid 집합 제한(UIDPLUS)", () => {
    const e = makeEngine();
    const first = e.feed(enc.encode("e1 UID EXPUNGE 3:7\r\n"));
    expect(backendReq(first)).toEqual({ kind: "expunge", name: "INBOX", uids: [3, 7] });
    const out = replies(e.backendResult({ kind: "expunged", uids: [3, 7] }));
    expect(out).toEqual(["* 2 EXPUNGE", "* 1 EXPUNGE", "e1 OK UID EXPUNGE completed"]);
  });

  test("READ-ONLY → NO", () => {
    expect(replies(makeEngine(false).feed(enc.encode("e1 EXPUNGE\r\n")))[0]).toContain("NO [READ-ONLY]");
  });
});

// ── SEARCH ────────────────────────────────────────────────────────────────────

function crlf(s: string): Uint8Array {
  return enc.encode(s.replaceAll("\n", "\r\n"));
}

const RAW = crlf(["Date: Mon, 20 Jul 2026 10:00:00 +0000", "From: alice@a.test", "Subject: Quarterly Report", "", "please find the numbers attached", ""].join("\n"));

function msg(over: Partial<SearchMessage> = {}): SearchMessage {
  return { seq: 1, uid: 3, flags: ["\\Seen"], size: 500, internalDateMs: Date.UTC(2026, 6, 20, 15, 0), raw: RAW, ...over };
}

function evalKey(criteria: string, m: SearchMessage = msg()): boolean {
  const program = parseSearchProgram(parseValues([{ kind: "text", text: criteria }]));
  if (!program.ok) throw new Error(`parse failed: ${criteria}`);
  return evaluateSearch(program.key, m, 10, 100);
}

describe("SEARCH 크라이테리어", () => {
  test("플래그 계열 — SEEN/UNSEEN/KEYWORD/UNKEYWORD/DELETED", () => {
    expect(evalKey("SEEN")).toBe(true);
    expect(evalKey("UNSEEN")).toBe(false);
    expect(evalKey("DELETED")).toBe(false);
    expect(evalKey("UNDELETED")).toBe(true);
    expect(evalKey("KEYWORD $x", msg({ flags: ["$x"] }))).toBe(true);
    expect(evalKey("UNKEYWORD $x")).toBe(true);
  });

  test("크기/uid/seq/ALL/RECENT", () => {
    expect(evalKey("LARGER 400")).toBe(true);
    expect(evalKey("SMALLER 400")).toBe(false);
    expect(evalKey("UID 1:5")).toBe(true);
    expect(evalKey("2:4", msg({ seq: 3 }))).toBe(true);
    expect(evalKey("ALL")).toBe(true);
    expect(evalKey("RECENT")).toBe(false); // rev2 — \Recent 미지원
    expect(evalKey("OLD")).toBe(true);
  });

  test("날짜 — BEFORE/ON/SINCE(INTERNALDATE) + SENTON(Date 헤더)", () => {
    expect(parseSearchDate("5-Jul-2026")).toBe(Date.UTC(2026, 6, 5));
    expect(evalKey("ON 20-Jul-2026")).toBe(true);
    expect(evalKey("BEFORE 20-Jul-2026")).toBe(false);
    expect(evalKey("SINCE 21-Jul-2026")).toBe(false);
    expect(evalKey("SENTON 20-Jul-2026")).toBe(true);
  });

  test("텍스트 — HEADER/FROM/SUBJECT/BODY/TEXT (대소문자 무관)", () => {
    expect(evalKey("FROM alice")).toBe(true);
    expect(evalKey("SUBJECT quarterly")).toBe(true);
    expect(evalKey("HEADER Subject report")).toBe(true);
    expect(evalKey("BODY numbers")).toBe(true);
    expect(evalKey("BODY quarterly")).toBe(false); // 헤더는 BODY 검색 제외
    expect(evalKey("TEXT quarterly")).toBe(true);
  });

  test("불리언 — NOT/OR/괄호 그룹", () => {
    expect(evalKey("NOT SEEN")).toBe(false);
    expect(evalKey("OR SEEN DELETED")).toBe(true);
    expect(evalKey("OR DELETED DRAFT")).toBe(false);
    expect(evalKey("(SEEN LARGER 400)")).toBe(true);
    expect(evalKey("(SEEN LARGER 900)")).toBe(false);
  });
});

describe("엔진 SEARCH", () => {
  test("UID SEARCH — 매칭 uid 목록 응답", () => {
    const e = makeEngine();
    const first = e.feed(enc.encode("s1 UID SEARCH UNSEEN\r\n"));
    expect(backendReq(first)).toMatchObject({ kind: "fetchMessages", uids: [3, 7, 9], needRaw: false, markSeen: false });
    const data = (uid: number, flags: string[]): ImapFetchData => ({ uid, flags, internalDateMs: 0, size: 10, modseq: 5 });
    const out = replies(e.backendResult({ kind: "messages", messages: [data(3, ["\\Seen"]), data(7, []), data(9, [])] }));
    expect(out).toEqual(["* SEARCH 7 9", "s1 OK UID SEARCH completed"]);
  });

  test("SEARCH(seq 모드) + 매칭 없음 + BADCHARSET", () => {
    const e = makeEngine();
    e.feed(enc.encode("s1 SEARCH DELETED\r\n"));
    const data = (uid: number): ImapFetchData => ({ uid, flags: [], internalDateMs: 0, size: 10, modseq: 5 });
    const out = replies(e.backendResult({ kind: "messages", messages: [data(3), data(7), data(9)] }));
    expect(out).toEqual(["* SEARCH", "s1 OK SEARCH completed"]);

    const e2 = makeEngine();
    expect(replies(e2.feed(enc.encode("s2 SEARCH CHARSET KOI8-R ALL\r\n")))[0]).toContain("NO [BADCHARSET");
  });
});
