/** FETCH — 항목 파서·포매터·엔진 통합 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapBackendRequest, type ImapFetchData, type ImapMailbox } from "../src/engine.ts";
import { parseFetchItems } from "../src/fetch-items.ts";
import { parseValues } from "../src/parser.ts";
import { extractSection, formatEnvelope, formatBodyStructure, formatInternalDate } from "../src/fetch-format.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();

function crlf(s: string): Uint8Array {
  return enc.encode(s.replaceAll("\n", "\r\n"));
}

const SIMPLE = crlf(
  ["Date: Mon, 20 Jul 2026 10:00:00 +0900", "From: Alice <alice@a.test>", "To: bob@b.test", "Subject: Hello", "Message-ID: <m1@a.test>", "Content-Type: text/plain", "", "line one", "line two", ""].join(
    "\n",
  ),
);

const MULTI = crlf(
  [
    "From: a@x.test",
    "Subject: mp",
    'Content-Type: multipart/mixed; boundary="B"',
    "",
    "--B",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "hello body",
    "--B",
    "Content-Type: application/pdf; name=f.pdf",
    "Content-Transfer-Encoding: base64",
    "Content-Disposition: attachment; filename=f.pdf",
    "",
    "QUJD",
    "--B--",
    "",
  ].join("\n"),
);

function itemsOf(line: string) {
  return parseFetchItems(parseValues([{ kind: "text", text: line }]));
}

describe("parseFetchItems", () => {
  test("매크로 확장 — ALL/FAST/FULL", () => {
    expect(itemsOf("ALL")!.map((i) => i.kind)).toEqual(["flags", "internaldate", "rfc822size", "envelope"]);
    expect(itemsOf("FULL")!.map((i) => i.kind)).toEqual(["flags", "internaldate", "rfc822size", "envelope", "body"]);
  });

  test("리스트 항목 + 섹션·partial", () => {
    const items = itemsOf("(FLAGS BODY.PEEK[1.2]<0.100> UID)")!;
    expect(items[0]).toEqual({ kind: "flags" });
    expect(items[1]).toMatchObject({ kind: "section", peek: true, partial: { start: 0, count: 100 }, label: "BODY[1.2]<0>" });
    if (items[1]?.kind === "section") expect(items[1].spec).toEqual({ path: [1, 2], sub: null, fields: [] });
  });

  test("HEADER.FIELDS 재조립(프래그먼트) + 정규화 라벨", () => {
    const items = itemsOf("(BODY.PEEK[HEADER.FIELDS (From To)])")!;
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ kind: "section", peek: true, label: "BODY[HEADER.FIELDS (FROM TO)]" });
    if (items[0]?.kind === "section") expect(items[0].spec.fields).toEqual(["FROM", "TO"]);
  });

  test("RFC822 별칭 — 라벨 원형 유지", () => {
    expect(itemsOf("RFC822.HEADER")![0]).toMatchObject({ kind: "section", peek: true, label: "RFC822.HEADER" });
  });

  test("불량 항목 → null", () => {
    expect(itemsOf("BOGUS")).toBeNull();
    expect(itemsOf("BODY[XYZ]")).toBeNull();
    expect(itemsOf("(FLAGS BODY[MIME])")).toBeNull(); // MIME은 파트 전용
  });
});

describe("포매터", () => {
  test("ENVELOPE — 주소·폴백(sender/reply-to=from)·message-id", () => {
    const env = formatEnvelope(SIMPLE);
    expect(env).toBe(
      '("Mon, 20 Jul 2026 10:00:00 +0900" "Hello" (("Alice" NIL "alice" "a.test")) (("Alice" NIL "alice" "a.test")) (("Alice" NIL "alice" "a.test")) ((NIL NIL "bob" "b.test")) NIL NIL NIL "<m1@a.test>")',
    );
  });

  test("BODYSTRUCTURE — multipart + 디스포지션 확장", () => {
    const bs = formatBodyStructure(MULTI, true);
    expect(bs).toContain('"TEXT" "PLAIN" ("charset" "utf-8")');
    expect(bs).toContain('"APPLICATION" "PDF"');
    expect(bs).toContain('("attachment" ("filename" "f.pdf"))');
    expect(bs).toContain('"MIXED"');
    // BODY(비확장)에는 디스포지션 없음
    expect(formatBodyStructure(MULTI, false)).not.toContain("attachment");
  });

  test("섹션 추출 — HEADER/TEXT/파트/HEADER.FIELDS", () => {
    expect(dec.decode(extractSection(SIMPLE, { path: [], sub: "TEXT", fields: [] })!)).toBe("line one\r\nline two\r\n");
    expect(dec.decode(extractSection(SIMPLE, { path: [], sub: "HEADER", fields: [] })!)).toEndWith("\r\n\r\n");
    expect(dec.decode(extractSection(MULTI, { path: [1], sub: null, fields: [] })!)).toBe("hello body");
    expect(dec.decode(extractSection(MULTI, { path: [2], sub: null, fields: [] })!)).toBe("QUJD");
    const hf = dec.decode(extractSection(SIMPLE, { path: [], sub: "HEADER.FIELDS", fields: ["SUBJECT"] })!);
    expect(hf).toBe("Subject: Hello\r\n\r\n");
    expect(extractSection(MULTI, { path: [9], sub: null, fields: [] })).toBeNull();
  });

  test("INTERNALDATE 형식", () => {
    expect(formatInternalDate(Date.UTC(2026, 0, 5, 3, 4, 5))).toBe("05-Jan-2026 03:04:05 +0000");
  });
});

// ── 엔진 통합 ──────────────────────────────────────────────────────────────────

const BOX: ImapMailbox = { name: "INBOX", role: "inbox", uidvalidity: 1, uidnext: 10, highestmodseq: 5, totalCount: 2, unreadCount: 1, totalBytes: 100 };

function selectedEngine(): ImapEngine {
  const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
  e.feed(enc.encode("a0 LOGIN u p\r\n"));
  e.authResult({ accountId: "acc" });
  e.feed(enc.encode("s SELECT INBOX\r\n"));
  e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7], firstUnseenSeq: 1 });
  return e;
}

function fetchData(uid: number, raw: Uint8Array, flags: string[] = ["\\Seen"]): ImapFetchData {
  return { uid, flags, internalDateMs: Date.UTC(2026, 6, 1), size: raw.length, modseq: 5, raw };
}

function binText(actions: ImapAction[]): string {
  let out = "";
  for (const a of actions) {
    if (a.kind === "reply") out += a.text + "\r\n";
    else if (a.kind === "replyBinary") out += dec.decode(a.bytes);
  }
  return out;
}

describe("엔진 FETCH", () => {
  test("FETCH 1:* (FLAGS UID) — seq 모드 + 백엔드 요청 형태", () => {
    const e = selectedEngine();
    const first = e.feed(enc.encode("f1 FETCH 1:* (FLAGS UID)\r\n"));
    const req = first.find((a): a is { kind: "backend"; req: ImapBackendRequest } => a.kind === "backend")!.req;
    expect(req).toEqual({ kind: "fetchMessages", name: "INBOX", uids: [3, 7], needRaw: false, markSeen: false });
    const out = binText(e.backendResult({ kind: "messages", messages: [fetchData(3, SIMPLE, ["\\Seen"]), fetchData(7, SIMPLE, [])] }));
    expect(out).toContain("* 1 FETCH (FLAGS (\\Seen) UID 3)\r\n");
    expect(out).toContain("* 2 FETCH (FLAGS () UID 7)\r\n");
    expect(out).toContain("f1 OK FETCH completed");
  });

  test("UID FETCH — UID 항목 자동 포함 + uid 집합 매칭", () => {
    const e = selectedEngine();
    const first = e.feed(enc.encode("f1 UID FETCH 7 FLAGS\r\n"));
    const req = first.find((a): a is { kind: "backend"; req: ImapBackendRequest } => a.kind === "backend")!.req;
    expect(req).toMatchObject({ uids: [7] });
    const out = binText(e.backendResult({ kind: "messages", messages: [fetchData(7, SIMPLE)] }));
    expect(out).toContain("* 2 FETCH (FLAGS (\\Seen) UID 7)\r\n");
    expect(out).toContain("f1 OK UID FETCH completed");
  });

  test("BODY[] — 리터럴 방출 + markSeen, BODY.PEEK는 markSeen 안 함", () => {
    const e = selectedEngine();
    const first = e.feed(enc.encode("f1 FETCH 1 (BODY[])\r\n"));
    const req = first.find((a): a is { kind: "backend"; req: ImapBackendRequest } => a.kind === "backend")!.req;
    expect(req).toMatchObject({ needRaw: true, markSeen: true, uids: [3] });
    const out = binText(e.backendResult({ kind: "messages", messages: [fetchData(3, SIMPLE)] }));
    expect(out).toContain(`BODY[] {${SIMPLE.length}}\r\n`);
    expect(out).toContain("line one\r\nline two");

    const e2 = selectedEngine();
    const first2 = e2.feed(enc.encode("f2 FETCH 1 (BODY.PEEK[HEADER])\r\n"));
    expect(first2.find((a): a is { kind: "backend"; req: ImapBackendRequest } => a.kind === "backend")!.req).toMatchObject({ markSeen: false });
  });

  test("partial <start.count> — 절단 + 라벨 <start>", () => {
    const e = selectedEngine();
    e.feed(enc.encode("f1 FETCH 1 (BODY.PEEK[TEXT]<2.4>)\r\n"));
    const out = binText(e.backendResult({ kind: "messages", messages: [fetchData(3, SIMPLE)] }));
    expect(out).toContain("BODY[TEXT]<2> {4}\r\nne o");
  });

  test("빈 대상(범위 밖) — 백엔드 호출 없이 OK", () => {
    const e = selectedEngine();
    const out = e.feed(enc.encode("f1 UID FETCH 99 FLAGS\r\n"));
    expect(out).toEqual([{ kind: "reply", text: "f1 OK UID FETCH completed" }]);
  });

  test("불량 인자/미선택 상태 → BAD", () => {
    const e = selectedEngine();
    expect(binText(e.feed(enc.encode("f1 FETCH abc FLAGS\r\n")))).toContain("f1 BAD");
    const e2 = new ImapEngine({ hostname: "t", allowInsecureAuth: true });
    e2.feed(enc.encode("a0 LOGIN u p\r\n"));
    e2.authResult({ accountId: "acc" });
    expect(binText(e2.feed(enc.encode("f1 FETCH 1 FLAGS\r\n")))).toContain("f1 BAD");
  });
});
