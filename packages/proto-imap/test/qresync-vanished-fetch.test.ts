/**
 * UID FETCH의 VANISHED 수정자 (RFC 7162 §3.2.6).
 *
 * ★이 파일이 있는 이유(2026-10-05). 우리는 QRESYNC를 광고하면서 `UID FETCH … (CHANGEDSINCE n VANISHED)`를
 * 몰라 BAD로 거절했다. v2026.10.05 배포 뒤 실측에서 UID FETCH BAD가 5분에 2건씩 꾸준히 쌓였고(누적 1802)
 * ok는 거의 없었다 — QRESYNC 클라이언트는 동기화할 때마다 같은 요청을 되풀이하고, 사라진 메시지를 영영
 * 알 수 없다. 광고와 구현이 어긋난 BAD라는 점에서 10-02 NAMESPACE→LIST 루프와 같은 유형이다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapBackendRequest, type ImapFetchData, type ImapMailbox } from "../src/engine.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();
const BOX: ImapMailbox = { name: "INBOX", role: "inbox", uidvalidity: 100, uidnext: 10, highestmodseq: 50, totalCount: 3, unreadCount: 0, totalBytes: 100 };

function selected(opts: { qresync: boolean }): ImapEngine {
  const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
  e.feed(enc.encode("a0 LOGIN u p\r\n"));
  e.authResult({ accountId: "acc" });
  if (opts.qresync) e.feed(enc.encode("e0 ENABLE QRESYNC\r\n"));
  e.feed(enc.encode("s SELECT INBOX\r\n"));
  e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: null });
  return e;
}

function text(actions: ImapAction[]): string[] {
  const out: string[] = [];
  for (const a of actions) {
    if (a.kind === "reply") out.push(a.text);
    else if (a.kind === "replyBinary") out.push(dec.decode(a.bytes).replace(/\r\n$/, ""));
  }
  return out;
}

function backendReq(actions: ImapAction[]): ImapBackendRequest | null {
  return actions.find((a): a is { kind: "backend"; req: ImapBackendRequest } => a.kind === "backend")?.req ?? null;
}

function data(uid: number, modseq: number): ImapFetchData {
  return { uid, flags: [], internalDateMs: 0, size: 10, modseq };
}

describe("UID FETCH (CHANGEDSINCE n VANISHED)", () => {
  test("★BAD가 아니라 VANISHED (EARLIER)를 먼저, 이어서 바뀐 메시지의 FETCH를 보낸다", () => {
    const e = selected({ qresync: true });
    const first = e.feed(enc.encode("f1 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 40 VANISHED)\r\n"));
    expect(text(first)).toEqual([]);
    expect(backendReq(first)).toEqual({ kind: "syncSince", name: "INBOX", sinceModseq: 40, knownUids: [{ from: 1, to: "*" }], vanishedOnly: true });

    const second = e.backendResult({ kind: "sync", vanished: [4, 5, 8], changed: [] });
    expect(text(second)).toEqual(["* VANISHED (EARLIER) 4:5,8"]);
    expect(backendReq(second)).toEqual({ kind: "fetchMessages", name: "INBOX", uids: [3, 7, 9], needRaw: false, markSeen: false });

    const third = e.backendResult({ kind: "messages", messages: [data(3, 30), data(7, 45), data(9, 50)] });
    expect(text(third)).toEqual([
      "* 2 FETCH (FLAGS () UID 7 MODSEQ (45))",
      "* 3 FETCH (FLAGS () UID 9 MODSEQ (50))",
      "f1 OK UID FETCH completed",
    ]);
  });

  test("요청한 UID 집합 밖의 사라진 uid는 싣지 않는다", () => {
    const e = selected({ qresync: true });
    e.feed(enc.encode("f1 UID FETCH 3:7 (FLAGS) (CHANGEDSINCE 40 VANISHED)\r\n"));
    const out = e.backendResult({ kind: "sync", vanished: [1, 4, 5, 8, 12], changed: [] });
    expect(text(out)[0]).toBe("* VANISHED (EARLIER) 4:5");
  });

  test("`*`는 상한 없이 본다 — 마지막 메시지가 지워졌으면 그 uid는 현재 최대 uid보다 크다", () => {
    const e = selected({ qresync: true });
    e.feed(enc.encode("f1 UID FETCH 8:* (FLAGS) (CHANGEDSINCE 40 VANISHED)\r\n"));
    const out = e.backendResult({ kind: "sync", vanished: [4, 8, 12], changed: [] });
    expect(text(out)[0]).toBe("* VANISHED (EARLIER) 8,12");
  });

  test("사라진 것이 없으면 VANISHED 줄을 내지 않는다", () => {
    const e = selected({ qresync: true });
    e.feed(enc.encode("f1 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 40 VANISHED)\r\n"));
    const out = e.backendResult({ kind: "sync", vanished: [], changed: [] });
    expect(text(out)).toEqual([]);
    expect(backendReq(out)?.kind).toBe("fetchMessages");
  });

  test("집합 안에 남은 메시지가 없어도 VANISHED를 보낸 뒤 OK로 끝난다", () => {
    const e = selected({ qresync: true });
    e.feed(enc.encode("f1 UID FETCH 4:6 (FLAGS) (CHANGEDSINCE 40 VANISHED)\r\n"));
    const out = e.backendResult({ kind: "sync", vanished: [4, 5], changed: [] });
    expect(text(out)).toEqual(["* VANISHED (EARLIER) 4:5", "f1 OK UID FETCH completed"]);
  });

  test("백엔드가 NO면 NO로 끝난다", () => {
    const e = selected({ qresync: true });
    e.feed(enc.encode("f1 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 40 VANISHED)\r\n"));
    const out = e.backendResult({ kind: "no", code: "NONEXISTENT", message: "no such mailbox" });
    expect(text(out)).toEqual(["f1 NO [NONEXISTENT] UID FETCH no such mailbox"]);
  });

  // RFC 7162 §3.2.6 — 수정자를 잘못 쓰면 BAD.
  test("QRESYNC를 켜지 않은 세션은 BAD", () => {
    const e = selected({ qresync: false });
    expect(text(e.feed(enc.encode("f1 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 40 VANISHED)\r\n")))).toEqual(["f1 BAD QRESYNC not enabled"]);
  });

  test("UID 없는 FETCH는 BAD", () => {
    const e = selected({ qresync: true });
    expect(text(e.feed(enc.encode("f1 FETCH 1:* (FLAGS) (CHANGEDSINCE 40 VANISHED)\r\n")))).toEqual(["f1 BAD VANISHED requires UID FETCH"]);
  });

  test("CHANGEDSINCE 없이 VANISHED만, 또는 모르는 수정자는 BAD", () => {
    const e = selected({ qresync: true });
    expect(text(e.feed(enc.encode("f1 UID FETCH 1:* (FLAGS) (VANISHED)\r\n"))).at(-1)).toMatch(/^f1 BAD /);
    expect(text(e.feed(enc.encode("f2 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 40 BOGUS)\r\n")))).toEqual(["f2 BAD UID FETCH invalid CHANGEDSINCE"]);
    expect(text(e.feed(enc.encode("f3 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 40 VANISHED X)\r\n")))).toEqual(["f3 BAD UID FETCH invalid CHANGEDSINCE"]);
  });

  test("VANISHED 없는 CHANGEDSINCE는 예전 그대로 — syncSince를 부르지 않는다", () => {
    const e = selected({ qresync: true });
    const first = e.feed(enc.encode("f1 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 40)\r\n"));
    expect(backendReq(first)?.kind).toBe("fetchMessages");
  });
});
