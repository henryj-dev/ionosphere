/** NOOP/CHECK 재동기화 — 타 세션 변경(EXISTS/EXPUNGE) 가시성 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapMailbox } from "../src/engine.ts";

const enc = new TextEncoder();
const BOX: ImapMailbox = { name: "INBOX", role: "inbox", uidvalidity: 1, uidnext: 10, highestmodseq: 5, totalCount: 3, unreadCount: 1, totalBytes: 100 };

function selected(): ImapEngine {
  const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
  e.feed(enc.encode("a0 LOGIN u p\r\n"));
  e.authResult({ accountId: "acc" });
  e.feed(enc.encode("s SELECT INBOX\r\n"));
  e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: null });
  return e;
}

function replies(actions: ImapAction[]): string[] {
  return actions.filter((a): a is { kind: "reply"; text: string } => a.kind === "reply").map((a) => a.text);
}

describe("NOOP/CHECK 재동기화", () => {
  test("타 세션 APPEND → EXISTS, 타 세션 EXPUNGE → EXPUNGE(내림차순)", () => {
    const e = selected();
    e.feed(enc.encode("n1 NOOP\r\n"));
    // 백엔드 스냅샷: uid 3 사라지고 12 추가
    const out = replies(e.backendResult({ kind: "selected", mailbox: BOX, uids: [7, 9, 12], firstUnseenSeq: null }));
    expect(out).toEqual(["* 1 EXPUNGE", "* 3 EXISTS", "n1 OK NOOP completed"]);
    // 뷰 갱신 확인: FETCH 3(= uid 12)
    const f = e.feed(enc.encode("f1 FETCH 3 (UID)\r\n"));
    const req = f.find((a) => a.kind === "backend");
    expect(req).toMatchObject({ req: { uids: [12] } });
  });

  test("변화 없음 → untagged 없이 OK, CHECK도 동일 경로", () => {
    const e = selected();
    e.feed(enc.encode("c1 CHECK\r\n"));
    const out = replies(e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: null }));
    expect(out).toEqual(["c1 OK CHECK completed"]);
  });

  test("비선택 상태 NOOP은 즉시 OK(백엔드 미호출)", () => {
    const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
    e.feed(enc.encode("a0 LOGIN u p\r\n"));
    e.authResult({ accountId: "acc" });
    expect(replies(e.feed(enc.encode("n1 NOOP\r\n")))).toEqual(["n1 OK NOOP completed"]);
  });

  test("idleTick — IDLE 중 폴링으로 EXISTS 푸시(tagged 없음), 비IDLE/펜딩 중엔 무동작", () => {
    const e = selected();
    expect(e.idleTick()).toEqual([]); // IDLE 아님 — 무동작
    e.feed(enc.encode("i1 IDLE\r\n"));
    expect(e.isIdling()).toBe(true);
    const first = e.idleTick();
    expect(first[0]).toMatchObject({ kind: "backend", req: { kind: "selectMailbox", name: "INBOX" } });
    expect(e.idleTick()).toEqual([]); // 백엔드 응답 대기 중 — 틱 스킵
    const out = replies(e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9, 12], firstUnseenSeq: null }));
    expect(out).toEqual(["* 4 EXISTS"]); // untagged만 — tagged OK 없음
    // 폴링 후에도 DONE 정상 종료
    expect(replies(e.feed(enc.encode("DONE\r\n")))).toEqual(["i1 OK IDLE terminated"]);
  });

  test("idleTick — 변화 없으면 침묵", () => {
    const e = selected();
    e.feed(enc.encode("i1 IDLE\r\n"));
    e.idleTick();
    const out = replies(e.backendResult({ kind: "selected", mailbox: BOX, uids: [3, 7, 9], firstUnseenSeq: null }));
    expect(out).toEqual([]);
  });

  test("선택 중 메일함으로 APPEND → 즉시 EXISTS", () => {
    const e = selected();
    e.feed(enc.encode("p1 APPEND INBOX {4+}\r\nabcd\r\n"));
    const out = replies(e.backendResult({ kind: "appended", uidvalidity: 1, uid: 10 }));
    expect(out).toEqual(["* 4 EXISTS", "p1 OK [APPENDUID 1 10] APPEND completed"]);
  });
});
