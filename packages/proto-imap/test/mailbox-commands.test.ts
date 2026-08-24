/** ImapEngine 메일함 명령(LIST/CREATE/DELETE/RENAME/STATUS/NAMESPACE) 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapBackendRequest, type ImapMailbox } from "../src/engine.ts";
import { matchesListPattern, normalizeMailboxName } from "../src/list-match.ts";

const enc = new TextEncoder();

function mailbox(over: Partial<ImapMailbox> & { name: string }): ImapMailbox {
  return {
    role: null,
    uidvalidity: 1111,
    uidnext: 5,
    highestmodseq: 42,
    totalCount: 4,
    unreadCount: 2,
    totalBytes: 1234,
    ...over,
  };
}

const FIXTURE: ImapMailbox[] = [
  mailbox({ name: "INBOX", role: "inbox" }),
  mailbox({ name: "Sent", role: "sent" }),
  mailbox({ name: "Work" }),
  mailbox({ name: "Work/2026", uidvalidity: 2222, totalCount: 9 }),
];

/** 인증 완료된 엔진 준비. */
function authedEngine(): ImapEngine {
  const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
  e.feed(enc.encode("a0 LOGIN u p\r\n"));
  e.authResult({ accountId: "acc" });
  return e;
}

function replies(actions: ImapAction[]): string[] {
  return actions.filter((a): a is { kind: "reply"; text: string } => a.kind === "reply").map((a) => a.text);
}

/** 명령 실행 — backend 액션이 나오면 fixture 목록으로 응답해 최종 리플라이를 얻는다. */
function run(e: ImapEngine, line: string, boxes: readonly ImapMailbox[] = FIXTURE): { req: ImapBackendRequest | null; out: string[] } {
  const first = e.feed(enc.encode(line));
  const backend = first.find((a): a is { kind: "backend"; req: ImapBackendRequest } => a.kind === "backend");
  if (!backend) return { req: null, out: replies(first) };
  const rest = e.backendResult({ kind: "mailboxes", mailboxes: boxes });
  return { req: backend.req, out: [...replies(first), ...replies(rest)] };
}

describe("LIST", () => {
  test('LIST "" "*" — 전체 + SPECIAL-USE/CHILDREN 속성', () => {
    const { req, out } = run(authedEngine(), 'a1 LIST "" "*"\r\n');
    expect(req).toEqual({ kind: "listMailboxes" });
    expect(out).toEqual([
      '* LIST (\\HasNoChildren) "/" "INBOX"',
      '* LIST (\\Sent \\HasNoChildren) "/" "Sent"',
      '* LIST (\\HasChildren) "/" "Work"',
      '* LIST (\\HasNoChildren) "/" "Work/2026"',
      "a1 OK LIST completed",
    ]);
  });

  test('LIST "" "%" — 최상위만(구분자 제외 와일드카드)', () => {
    const { out } = run(authedEngine(), 'a1 LIST "" "%"\r\n');
    expect(out.filter((l) => l.startsWith("* LIST"))).toHaveLength(3); // Work/2026 제외
  });

  test('LIST "Work" "*" — reference 결합', () => {
    const { out } = run(authedEngine(), 'a1 LIST "Work" "*"\r\n');
    expect(out.filter((l) => l.startsWith("* LIST"))).toEqual(['* LIST (\\HasNoChildren) "/" "Work/2026"']);
  });

  test('LIST "" "" — 계층 구분자 공지(백엔드 호출 없음)', () => {
    const { req, out } = run(authedEngine(), 'a1 LIST "" ""\r\n');
    expect(req).toBeNull();
    expect(out).toEqual(['* LIST (\\Noselect) "/" ""', "a1 OK LIST completed"]);
  });

  test("LSUB — LIST 미러(rev1 호환)", () => {
    const { out } = run(authedEngine(), 'a1 LSUB "" "*"\r\n');
    expect(out[0]).toStartWith("* LSUB (");
    expect(out[out.length - 1]).toBe("a1 OK LSUB completed");
  });

  test("inbox 소문자 패턴도 INBOX 매칭(대소문자 무관)", () => {
    const { out } = run(authedEngine(), 'a1 LIST "" "inbox"\r\n');
    expect(out.filter((l) => l.startsWith("* LIST"))).toEqual(['* LIST (\\HasNoChildren) "/" "INBOX"']);
  });

  /**
   * ★INBOX **말고는** 대소문자를 구분한다(RFC 9051). 예전엔 패턴 정규식에 `i` 플래그가 붙어
   * `LIST "" "work"`가 `Work`를 매치했다. INBOX 관용은 위 테스트대로
   * `normalizeMailboxName()`이 선두 세그먼트에서 처리하므로 매처가 관용일 이유가 없다.
   */
  test("INBOX 외 이름은 대소문자를 구분한다", () => {
    const { out } = run(authedEngine(), 'a1 LIST "" "work"\r\n');
    expect(out.filter((l) => l.startsWith("* LIST"))).toHaveLength(0);
    const exact = run(authedEngine(), 'a1 LIST "" "Work"\r\n');
    expect(exact.out.filter((l) => l.startsWith("* LIST"))).toEqual(['* LIST (\\HasChildren) "/" "Work"']);
  });

  test("인증 전 → BAD", () => {
    const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
    expect(replies(e.feed(enc.encode('a1 LIST "" "*"\r\n')))[0]).toContain("a1 BAD");
  });
});

describe("SUBSCRIBE/LSUB", () => {
  test("SUBSCRIBE/UNSUBSCRIBE — setSubscribed 백엔드 위임", () => {
    const e = authedEngine();
    const first = e.feed(enc.encode("s1 UNSUBSCRIBE Work\r\n"));
    expect(first).toEqual([{ kind: "backend", req: { kind: "setSubscribed", name: "Work", subscribed: false } }]);
    expect(replies(e.backendResult({ kind: "ok" }))).toEqual(["s1 OK UNSUBSCRIBE completed"]);
  });

  test("LSUB — subscribed=false 메일함 제외", () => {
    const boxes = [mailbox({ name: "INBOX", role: "inbox" }), mailbox({ name: "Muted", subscribed: false } as never)];
    const { out } = run(authedEngine(), 'a1 LSUB "" "*"\r\n', boxes.map((b, i) => ({ ...b, subscribed: i === 0 })));
    expect(out.filter((l) => l.startsWith("* LSUB"))).toHaveLength(1);
    expect(out[0]).toContain('"INBOX"');
  });
});

describe("CREATE/DELETE/RENAME", () => {
  test("CREATE — 정규화(끝 구분자 제거)된 이름으로 백엔드 호출, OK", () => {
    const e = authedEngine();
    const first = e.feed(enc.encode('a1 CREATE "Projects/2026/"\r\n'));
    expect(first).toEqual([{ kind: "backend", req: { kind: "createMailbox", name: "Projects/2026" } }]);
    expect(replies(e.backendResult({ kind: "ok" }))).toEqual(["a1 OK CREATE completed"]);
  });

  test("CREATE INBOX / 빈 이름 → NO/BAD (백엔드 미호출)", () => {
    expect(run(authedEngine(), "a1 CREATE inbox\r\n").out[0]).toContain("a1 NO");
    expect(run(authedEngine(), 'a1 CREATE "/"\r\n').out[0]).toContain("a1 NO");
    expect(run(authedEngine(), "a1 CREATE\r\n").out[0]).toContain("a1 BAD");
  });

  test("CREATE 중복 → 백엔드 no 응답 코드 전달", () => {
    const e = authedEngine();
    e.feed(enc.encode("a1 CREATE Work\r\n"));
    const out = replies(e.backendResult({ kind: "no", code: "ALREADYEXISTS", message: "mailbox exists" }));
    expect(out).toEqual(["a1 NO [ALREADYEXISTS] CREATE mailbox exists"]);
  });

  test("DELETE — INBOX 금지, 그 외 백엔드 위임", () => {
    expect(run(authedEngine(), "a1 DELETE INBOX\r\n").out[0]).toContain("a1 NO");
    const e = authedEngine();
    const first = e.feed(enc.encode("a1 DELETE Work\r\n"));
    expect(first).toEqual([{ kind: "backend", req: { kind: "deleteMailbox", name: "Work" } }]);
    expect(replies(e.backendResult({ kind: "no", code: "NONEXISTENT", message: "no such mailbox" }))[0]).toBe(
      "a1 NO [NONEXISTENT] DELETE no such mailbox",
    );
  });

  test("RENAME — from/to 전달, 대상 INBOX 금지", () => {
    const e = authedEngine();
    const first = e.feed(enc.encode('a1 RENAME Work "Archive/Old Work"\r\n'));
    expect(first).toEqual([{ kind: "backend", req: { kind: "renameMailbox", from: "Work", to: "Archive/Old Work" } }]);
    expect(replies(e.backendResult({ kind: "ok" }))).toEqual(["a1 OK RENAME completed"]);
    expect(run(authedEngine(), "a2 RENAME Work INBOX\r\n").out[0]).toContain("a2 NO");
  });
});

describe("STATUS/NAMESPACE", () => {
  test("STATUS — 요청 항목만 순서대로", () => {
    const { out } = run(authedEngine(), "a1 STATUS Work/2026 (MESSAGES UIDNEXT UIDVALIDITY UNSEEN SIZE HIGHESTMODSEQ RECENT)\r\n");
    expect(out).toEqual([
      '* STATUS "Work/2026" (MESSAGES 9 UIDNEXT 5 UIDVALIDITY 2222 UNSEEN 2 SIZE 1234 HIGHESTMODSEQ 42 RECENT 0)',
      "a1 OK STATUS completed",
    ]);
  });

  test("STATUS 없는 메일함 → NO [NONEXISTENT]", () => {
    const { out } = run(authedEngine(), "a1 STATUS Nope (MESSAGES)\r\n");
    expect(out[0]).toBe("a1 NO [NONEXISTENT] STATUS no such mailbox");
  });

  test("STATUS 미지원 항목/리스트 아님 → BAD", () => {
    expect(run(authedEngine(), "a1 STATUS Work (BOGUS)\r\n").out[0]).toContain("a1 BAD");
    expect(run(authedEngine(), "a1 STATUS Work MESSAGES\r\n").out[0]).toContain("a1 BAD");
  });

  test("NAMESPACE — 개인 네임스페이스만", () => {
    const { out } = run(authedEngine(), "a1 NAMESPACE\r\n");
    expect(out).toEqual(['* NAMESPACE (("" "/")) NIL NIL', "a1 OK NAMESPACE completed"]);
  });

  test("백엔드 대기 중 파이프라이닝 — 순서 보존", () => {
    const e = authedEngine();
    const first = e.feed(enc.encode('a1 LIST "" "*"\r\na2 NOOP\r\n'));
    expect(replies(first)).toEqual([]); // 둘 다 대기
    const out = replies(e.backendResult({ kind: "mailboxes", mailboxes: FIXTURE }));
    expect(out[out.length - 2]).toBe("a1 OK LIST completed");
    expect(out[out.length - 1]).toBe("a2 OK NOOP completed");
  });
});

describe("list-match 유틸", () => {
  test("와일드카드 시맨틱", () => {
    expect(matchesListPattern("*", "a/b/c")).toBe(true);
    expect(matchesListPattern("%", "a/b")).toBe(false);
    expect(matchesListPattern("a/%", "a/b")).toBe(true);
    expect(matchesListPattern("a/%", "a/b/c")).toBe(false);
    expect(matchesListPattern("a*c", "a/b/c")).toBe(true);
    expect(matchesListPattern("W.rk", "Work")).toBe(false); // 정규식 메타 이스케이프
  });

  test("INBOX 정규화 — 선두 세그먼트만", () => {
    expect(normalizeMailboxName("inbox")).toBe("INBOX");
    expect(normalizeMailboxName("Inbox/sub")).toBe("INBOX/sub");
    expect(normalizeMailboxName("My/inbox")).toBe("My/inbox");
  });
});
