/**
 * IMAP4rev2(RFC 9051) 광고와 그 전제 확장 — SEARCHRES(RFC 5182) · BINARY(RFC 3516).
 *
 * ★rev2를 광고한다는 것은 **약속**이다. rev2가 본문에 흡수한 확장을 다 갖추지 않고 광고하면
 * 규격을 따르는 클라이언트가 있다고 믿고 쓴 기능에서 `BAD`를 받는다. 이 파일은 그 약속의
 * 세 조각을 고정한다: 광고 · `$` · `BINARY`.
 *
 * 그리고 rev2는 **응답 모양**을 바꾼다(SEARCH가 ESEARCH로, RECENT·UNSEEN 제거). 그래서
 * ENABLE 전에는 rev1 모양 그대로여야 한다 — 그게 아래 테스트의 절반이다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapFetchData, type ImapMailbox } from "../src/engine.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();
const BOX: ImapMailbox = { name: "INBOX", role: "inbox", uidvalidity: 100, uidnext: 10, highestmodseq: 50, totalCount: 3, unreadCount: 1, totalBytes: 100 };

function authed(): ImapEngine {
  const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
  e.feed(enc.encode("a0 LOGIN u p\r\n"));
  e.authResult({ accountId: "acc" });
  return e;
}

/** `rev2`면 SELECT 전에 ENABLE한다 — 선택 중 ENABLE은 이제 BAD다(RFC 5161 §3.1). */
function selected(rev2 = false): ImapEngine {
  const e = authed();
  if (rev2) e.feed(enc.encode("e0 ENABLE IMAP4rev2\r\n"));
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

function data(uid: number, raw?: string): ImapFetchData {
  return { uid, flags: [], internalDateMs: 0, size: raw?.length ?? 10, modseq: 1, ...(raw ? { raw: enc.encode(raw) } : {}) };
}

describe("IMAP4rev2 광고와 ENABLE", () => {
  test("CAPABILITY가 rev2와 그 전제 확장을 낸다", () => {
    const e = authed();
    const caps = replies(e.feed(enc.encode("c1 CAPABILITY\r\n")))[0] ?? "";
    for (const c of ["IMAP4rev1", "IMAP4rev2", "SEARCHRES", "BINARY", "ESEARCH"]) {
      expect(caps.split(" ").includes(c)).toBe(true);
    }
  });

  test("ENABLE IMAP4rev2 → ENABLED", () => {
    const e = authed();
    expect(replies(e.feed(enc.encode("e1 ENABLE IMAP4rev2\r\n")))[0]).toBe("* ENABLED IMAP4rev2");
  });

  /**
   * ★rev2는 응답 모양을 바꾸므로 세션 중간에 켜지면 안 된다 — 클라이언트는 SEARCH 응답이
   * 언제부터 ESEARCH인지 알 방법이 없다. RFC 5161 §3.1이 애초에 금지한 이유다.
   */
  test("선택 상태의 ENABLE은 BAD", () => {
    const e = selected();
    expect(replies(e.feed(enc.encode("e1 ENABLE IMAP4rev2\r\n")))[0]).toContain("BAD");
  });
});

describe("rev1과 rev2의 응답 모양 차이", () => {
  test("rev1 SELECT에는 RECENT와 UNSEEN이 있다", () => {
    const e = authed();
    e.feed(enc.encode("s SELECT INBOX\r\n"));
    const out = replies(e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: 1 }));
    expect(out).toContain("* 0 RECENT");
    expect(out.some((l) => l.includes("[UNSEEN 1]"))).toBe(true);
  });

  /** RFC 9051 §7.3 — rev2가 RECENT 응답과 `[UNSEEN]` 응답 코드를 없앴다. */
  test("rev2 SELECT에는 RECENT도 UNSEEN도 없다", () => {
    const e = authed();
    e.feed(enc.encode("e0 ENABLE IMAP4rev2\r\n"));
    e.feed(enc.encode("s SELECT INBOX\r\n"));
    const out = replies(e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: 1 }));
    expect(out.some((l) => l.includes("RECENT"))).toBe(false);
    expect(out.some((l) => l.includes("UNSEEN"))).toBe(false);
    expect(out.some((l) => l.includes("[UIDVALIDITY 100]"))).toBe(true); // 나머지는 그대로
  });

  test("rev1 SEARCH는 고전 응답", () => {
    const e = selected();
    e.feed(enc.encode("q1 SEARCH ALL\r\n"));
    const out = replies(e.backendResult({ kind: "messages", messages: [data(3), data(7), data(9)] }));
    expect(out[0]).toBe("* SEARCH 1 2 3");
  });

  /** RFC 9051 §6.4.4 — rev2에는 고전 `* SEARCH` 응답이 없다. RETURN이 없어도 ESEARCH다. */
  test("rev2 SEARCH는 RETURN 없이도 ESEARCH", () => {
    const e = selected(true);
    e.feed(enc.encode("q1 SEARCH ALL\r\n"));
    const out = replies(e.backendResult({ kind: "messages", messages: [data(3), data(7), data(9)] }));
    expect(out[0]).toBe('* ESEARCH (TAG "q1") ALL 1:3');
  });
});

describe("SEARCHRES — 검색 결과 변수 $ (RFC 5182)", () => {
  /** §2.2 — SAVE만 있으면 SEARCH 응답 자체를 내지 않는다. */
  test("RETURN (SAVE) 단독은 무응답 + OK", () => {
    const e = selected();
    e.feed(enc.encode("q1 UID SEARCH RETURN (SAVE) ALL\r\n"));
    const out = replies(e.backendResult({ kind: "messages", messages: [data(3), data(7), data(9)] }));
    expect(out).toEqual(["q1 OK UID SEARCH completed"]);
  });

  test("저장한 $를 UID FETCH가 쓴다", () => {
    const e = selected();
    e.feed(enc.encode("q1 UID SEARCH RETURN (SAVE) ALL\r\n"));
    e.backendResult({ kind: "messages", messages: [data(3), data(7), data(9)] });
    const req = e.feed(enc.encode("f1 UID FETCH $ (UID)\r\n")).find((a) => a.kind === "backend");
    expect(req).toEqual({ kind: "backend", req: { kind: "fetchMessages", name: "INBOX", uids: [3, 7, 9], needRaw: false, markSeen: false } });
  });

  /**
   * ★§2.4 — `UID SEARCH`로 저장한 `$`를 **비UID** FETCH에 쓸 수 있어야 한다.
   * 그래서 저장은 UID로 하고 쓰는 시점에 seq로 옮긴다.
   */
  test("UID로 저장한 $를 비UID FETCH가 seq로 읽는다", () => {
    const e = selected();
    e.feed(enc.encode("q1 UID SEARCH RETURN (SAVE) ALL\r\n"));
    e.backendResult({ kind: "messages", messages: [data(3), data(9)] });
    e.feed(enc.encode("f1 FETCH $ (UID)\r\n"));
    // uid 3,9 → seq 1,3 (뷰는 3,7,9)
    const out = allText(e.backendResult({ kind: "messages", messages: [data(3), data(9)] }));
    expect(out).toContain("* 1 FETCH (UID 3)");
    expect(out).toContain("* 3 FETCH (UID 9)");
    expect(out).not.toContain("* 2 FETCH");
  });

  /** §2.1 표 — SAVE가 MIN/MAX와만 오면 그 한두 통만 담는다. */
  test("RETURN (SAVE MIN)은 최솟값 하나만 담는다", () => {
    const e = selected();
    e.feed(enc.encode("q1 UID SEARCH RETURN (SAVE MIN) ALL\r\n"));
    const out = replies(e.backendResult({ kind: "messages", messages: [data(3), data(7), data(9)] }));
    expect(out[0]).toBe('* ESEARCH (TAG "q1") UID MIN 3');
    const req = e.feed(enc.encode("f1 UID FETCH $ (UID)\r\n")).find((a) => a.kind === "backend");
    expect(req).toEqual({ kind: "backend", req: { kind: "fetchMessages", name: "INBOX", uids: [3], needRaw: false, markSeen: false } });
  });

  test("RETURN (SAVE ALL)은 전부 담고 ALL도 응답한다", () => {
    const e = selected();
    e.feed(enc.encode("q1 UID SEARCH RETURN (SAVE ALL) ALL\r\n"));
    const out = replies(e.backendResult({ kind: "messages", messages: [data(3), data(7), data(9)] }));
    expect(out[0]).toBe('* ESEARCH (TAG "q1") UID ALL 3,7,9');
  });

  /**
   * ★이 테스트가 `$`를 UID로 담는 이유 그 자체다. seq로 담았다면 아래 STORE는 EXPUNGE로
   * 밀린 번호를 따라가 **엉뚱한 메일**에 \Deleted를 붙인다.
   */
  test("사라진 메시지는 $에서 조용히 빠진다", () => {
    const e = selected();
    e.feed(enc.encode("q1 UID SEARCH RETURN (SAVE) ALL\r\n"));
    e.backendResult({ kind: "messages", messages: [data(3), data(7), data(9)] });
    e.feed(enc.encode("x1 EXPUNGE\r\n"));
    e.backendResult({ kind: "expunged", uids: [7] });
    const req = e.feed(enc.encode("f1 UID FETCH $ (UID)\r\n")).find((a) => a.kind === "backend");
    expect(req).toEqual({ kind: "backend", req: { kind: "fetchMessages", name: "INBOX", uids: [3, 9], needRaw: false, markSeen: false } });
  });

  /** §2.1 — SELECT/EXAMINE 성공 시 리셋. 메일함이 바뀌면 그 번호들은 의미가 없다. */
  test("SELECT가 $를 비운다", () => {
    const e = selected();
    e.feed(enc.encode("q1 UID SEARCH RETURN (SAVE) ALL\r\n"));
    e.backendResult({ kind: "messages", messages: [data(3), data(7), data(9)] });
    e.feed(enc.encode("s2 SELECT INBOX\r\n"));
    e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: null });
    // 빈 $ → 대상이 없으니 백엔드 요청 없이 OK
    const out = e.feed(enc.encode("f1 UID FETCH $ (UID)\r\n"));
    expect(out.some((a) => a.kind === "backend")).toBe(false);
    expect(replies(out)[0]).toBe("f1 OK UID FETCH completed");
  });
});

// base64로 실은 "Hello\r\nWorld" 첨부가 든 2파트 메시지
const B64_BODY = "SGVsbG8NCldvcmxk"; // "Hello\r\nWorld"
const MULTI = [
  "From: a@x.test",
  "Content-Type: multipart/mixed; boundary=bb",
  "",
  "--bb",
  "Content-Type: text/plain",
  "",
  "plain part",
  "--bb",
  "Content-Type: application/octet-stream",
  "Content-Transfer-Encoding: base64",
  "",
  B64_BODY,
  "--bb--",
  "",
].join("\r\n");

describe("BINARY (RFC 3516)", () => {
  test("BINARY[2]는 base64를 푼 바이트를 리터럴로 낸다", () => {
    const e = selected();
    e.feed(enc.encode("f1 FETCH 1 (BINARY.PEEK[2])\r\n"));
    const out = allText(e.backendResult({ kind: "messages", messages: [data(3, MULTI)] }));
    expect(out).toContain("BINARY[2] {12}\r\nHello\r\nWorld");
  });

  test("BINARY.SIZE[2]는 푼 뒤의 크기다", () => {
    const e = selected();
    e.feed(enc.encode("f1 FETCH 1 (BINARY.SIZE[2])\r\n"));
    const out = allText(e.backendResult({ kind: "messages", messages: [data(3, MULTI)] }));
    // 인코딩된 원문은 16바이트, 푼 것은 12바이트 — 이 차이가 BINARY의 존재 이유다
    expect(out).toContain("BINARY.SIZE[2] 12");
    expect(out).not.toContain("BINARY.SIZE[2] 16");
  });

  /** ★partial은 **푼 뒤** 기준이다(§4.2). 인코딩된 바이트로 자르면 쓰레기가 나온다. */
  test("partial은 디코드된 데이터 기준", () => {
    const e = selected();
    e.feed(enc.encode("f1 FETCH 1 (BINARY.PEEK[2]<0.5>)\r\n"));
    const out = allText(e.backendResult({ kind: "messages", messages: [data(3, MULTI)] }));
    expect(out).toContain("BINARY[2]<0> {5}\r\nHello");
  });

  test("인코딩 없는 파트는 그대로", () => {
    const e = selected();
    e.feed(enc.encode("f1 FETCH 1 (BINARY.PEEK[1])\r\n"));
    const out = allText(e.backendResult({ kind: "messages", messages: [data(3, MULTI)] }));
    expect(out).toContain("BINARY[1] {10}\r\nplain part");
  });

  /** §4.2 — 풀 수 없는 인코딩은 **명령 전체가 실패**한다. 부분 성공으로 넘기지 않는다. */
  test("모르는 인코딩 → NO [UNKNOWN-CTE]", () => {
    const raw = ["From: a@x.test", "Content-Transfer-Encoding: x-uuencode", "", "garbage", ""].join("\r\n");
    const e = selected();
    e.feed(enc.encode("f1 FETCH 1 (BINARY.PEEK[])\r\n"));
    const out = replies(e.backendResult({ kind: "messages", messages: [data(3, raw)] }));
    expect(out[out.length - 1]).toBe("f1 NO [UNKNOWN-CTE] FETCH cannot decode section");
  });

  /**
   * ★`section-binary`는 `section-part`다(§5 ABNF) — 파트 번호만 온다. `BINARY[HEADER]`를
   * 관용으로 받아 주면 클라이언트가 `BODY[HEADER]`와 같은 것을 기대하는데, 헤더에는 전송
   * 인코딩이 없으니 "푼 내용"이라는 말 자체가 성립하지 않는다.
   */
  test("BINARY[HEADER]는 문법 오류", () => {
    const e = selected();
    expect(replies(e.feed(enc.encode("f1 FETCH 1 (BINARY[HEADER])\r\n")))[0]).toContain("BAD");
  });

  test("BINARY.SIZE에 partial은 문법 오류", () => {
    const e = selected();
    expect(replies(e.feed(enc.encode("f1 FETCH 1 (BINARY.SIZE[1]<0.5>)\r\n")))[0]).toContain("BAD");
  });

  test("없는 파트는 NIL", () => {
    const e = selected();
    e.feed(enc.encode("f1 FETCH 1 (BINARY.PEEK[9])\r\n"));
    const out = allText(e.backendResult({ kind: "messages", messages: [data(3, MULTI)] }));
    expect(out).toContain("BINARY[9] NIL");
  });

  /** BINARY는 BODY[]와 같이 \Seen을 세우고, .PEEK만 예외다(§4.1). */
  test("BINARY는 \\Seen을 세우고 BINARY.PEEK는 아니다", () => {
    const e = selected();
    const req = e.feed(enc.encode("f1 FETCH 1 (BINARY[1])\r\n")).find((a) => a.kind === "backend");
    expect(req).toEqual({ kind: "backend", req: { kind: "fetchMessages", name: "INBOX", uids: [3], needRaw: true, markSeen: true } });

    const e2 = selected();
    const req2 = e2.feed(enc.encode("f2 FETCH 1 (BINARY.PEEK[1])\r\n")).find((a) => a.kind === "backend");
    expect(req2).toEqual({ kind: "backend", req: { kind: "fetchMessages", name: "INBOX", uids: [3], needRaw: true, markSeen: false } });
  });

  /**
   * ★NUL이 든 데이터는 일반 리터럴로 실을 수 없다 — literal8(`~{n}`)이 그래서 있다.
   * 반대로 NUL이 없으면 일반 리터럴을 쓴다(옛 클라이언트가 `~{n}`을 못 읽는 경우가 있다).
   */
  test("NUL이 있으면 literal8(~{n})", () => {
    // base64 "AABB" → 0x00 0x00 0x41
    const raw = ["From: a@x.test", "Content-Transfer-Encoding: base64", "", "AABB", ""].join("\r\n");
    const e = selected();
    e.feed(enc.encode("f1 FETCH 1 (BINARY.PEEK[1])\r\n"));
    const out = allText(e.backendResult({ kind: "messages", messages: [data(3, raw)] }));
    expect(out).toContain("BINARY[1] ~{3}\r\n");
  });
});
