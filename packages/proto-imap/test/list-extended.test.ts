/**
 * LIST-EXTENDED(RFC 5258) — 선택 옵션·여러 패턴·RETURN (SPECIAL-USE·CHILDREN).
 *
 * ★이 파일이 있는 이유(2026-10-02 사서함 호스트). 클라이언트 하나가 `NAMESPACE`(ok) → `LIST`(BAD)를
 * 초당 수 회씩 끝없이 반복했다 — 명령 계측(imap_commands_total)이 두 카운터가 1076으로 함께 오르는
 * 것을 보여 줬다. 우리는 CAPABILITY에 IMAP4rev2·SPECIAL-USE를 광고하는데, rev2(RFC 9051 §6.3.9)의
 * LIST 문법은 LIST-EXTENDED를 포함한다. 그런데 엔진은 `LIST (SPECIAL-USE) "" "*"`처럼 선택 옵션이
 * 앞에 붙거나 `RETURN (SPECIAL-USE)`·`RETURN (CHILDREN)`이 붙으면 BAD로 거절했다. 광고를 믿은
 * 클라이언트는 특수 메일함을 찾다 거절당하고 처음부터 다시 시도했다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapMailbox } from "../src/engine.ts";

const enc = new TextEncoder();

function mailbox(over: Partial<ImapMailbox> & { name: string }): ImapMailbox {
  return { role: null, uidvalidity: 11, uidnext: 5, highestmodseq: 9, totalCount: 4, unreadCount: 2, totalBytes: 1234, ...over };
}

const MAILBOXES: ImapMailbox[] = [
  mailbox({ name: "INBOX", role: "inbox" }),
  mailbox({ name: "Sent", role: "sent" }),
  mailbox({ name: "Trash", role: "trash" }),
  mailbox({ name: "Work", subscribed: false }),
  mailbox({ name: "Work/Reports" }),
];

function authed(): ImapEngine {
  const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
  e.feed(enc.encode("a0 LOGIN u p\r\n"));
  e.authResult({ accountId: "acc" });
  return e;
}

function replies(actions: ImapAction[]): string[] {
  return actions.filter((a): a is { kind: "reply"; text: string } => a.kind === "reply").map((a) => a.text);
}

/** LIST 한 번 — 백엔드가 불리면 MAILBOXES로 답한다. 태그 달린 마지막 줄까지 돌려준다. */
function list(line: string, mailboxes: ImapMailbox[] = MAILBOXES): string[] {
  const e = authed();
  const first = e.feed(enc.encode(`${line}\r\n`));
  const wantsBackend = first.some((a) => a.kind === "backend");
  return wantsBackend ? replies(e.backendResult({ kind: "mailboxes", mailboxes })) : replies(first);
}

describe("LIST-EXTENDED", () => {
  test("★선택 옵션 SPECIAL-USE — 특수 용도 메일함만, BAD가 아니다", () => {
    const out = list('l LIST (SPECIAL-USE) "" "*"');
    expect(out).toEqual([
      '* LIST (\\Sent \\HasNoChildren) "/" "Sent"',
      '* LIST (\\Trash \\HasNoChildren) "/" "Trash"',
      "l OK LIST completed",
    ]);
  });

  test("★RETURN (SPECIAL-USE)·RETURN (CHILDREN) — 받는다(이미 항상 내보내는 속성)", () => {
    for (const opt of ["SPECIAL-USE", "CHILDREN", "CHILDREN SPECIAL-USE"]) {
      const out = list(`l LIST "" "*" RETURN (${opt})`);
      expect(out.at(-1)).toBe("l OK LIST completed");
      expect(out).toContain('* LIST (\\HasChildren) "/" "Work"');
      expect(out).toContain('* LIST (\\Sent \\HasNoChildren) "/" "Sent"');
    }
  });

  test("★선택 옵션과 RETURN을 함께 — 클라이언트가 실제로 보내는 모양", () => {
    const out = list('l LIST (SPECIAL-USE) "" "*" RETURN (SPECIAL-USE CHILDREN)');
    expect(out).toEqual([
      '* LIST (\\Sent \\HasNoChildren) "/" "Sent"',
      '* LIST (\\Trash \\HasNoChildren) "/" "Trash"',
      "l OK LIST completed",
    ]);
  });

  test("★여러 패턴 — 괄호 목록 중 하나라도 맞으면 낸다", () => {
    const out = list('l LIST "" ("INBOX" "Sent")');
    expect(out).toEqual(['* LIST (\\HasNoChildren) "/" "INBOX"', '* LIST (\\Sent \\HasNoChildren) "/" "Sent"', "l OK LIST completed"]);
  });

  test("선택 옵션 SUBSCRIBED — 구독한 것만, \\Subscribed를 붙인다", () => {
    const out = list('l LIST (SUBSCRIBED) "" "*"');
    // 구독하지 않은 Work는 아예 나오지 않는다.
    expect(out.some((l) => l.endsWith('"/" "Work"'))).toBe(false);
    expect(out).toContain('* LIST (\\HasNoChildren \\Subscribed) "/" "Work/Reports"');
  });

  test("SUBSCRIBED + RECURSIVEMATCH — 구독 안 한 부모도 구독한 자식이 있으면 CHILDINFO로 낸다", () => {
    const out = list('l LIST (SUBSCRIBED RECURSIVEMATCH) "" "%"');
    // 부모 줄도 일반 줄과 같은 속성을 쓴다 — \Subscribed만 없다(구독하지 않았으므로).
    expect(out).toContain('* LIST (\\HasChildren) "/" "Work" ("CHILDINFO" ("SUBSCRIBED"))');
  });

  test("RECURSIVEMATCH 단독·모르는 선택 옵션·모르는 RETURN 옵션은 BAD(RFC 5258 §3)", () => {
    expect(list('l LIST (RECURSIVEMATCH) "" "*"').at(-1)).toMatch(/^l BAD /);
    expect(list('l LIST (BOGUS) "" "*"').at(-1)).toMatch(/^l BAD /);
    expect(list('l LIST "" "*" RETURN (BOGUS)').at(-1)).toMatch(/^l BAD /);
  });

  test("REMOTE는 받되 원격 메일함이 없으므로 결과가 같다", () => {
    expect(list('l LIST (REMOTE) "" "*"')).toEqual(list('l LIST "" "*"'));
  });

  test("기존 형태는 그대로 — 빈 패턴(구분자)·RETURN (STATUS)·LSUB", () => {
    expect(list('l LIST "" ""')).toEqual(['* LIST (\\Noselect) "/" ""', "l OK LIST completed"]);
    expect(list('l LIST "" "INBOX" RETURN (STATUS (MESSAGES))')).toContain('* STATUS "INBOX" (MESSAGES 4)');
    // LSUB에는 확장 문법이 없다(RFC 5258은 LIST만 확장한다).
    expect(list('l LSUB (SUBSCRIBED) "" "*"').at(-1)).toMatch(/^l BAD /);
  });

  test("★확장 LIST의 빈 패턴은 구분자 조회가 아니라 무시된다(RFC 5258 §3 MUST)", () => {
    // 기본 형태만 구분자 공지다 — 확장 형태 셋은 응답 줄 없이 OK만 낸다.
    for (const line of ['l LIST "" ("")', 'l LIST (SUBSCRIBED) "" ""', 'l LIST "" "" RETURN (CHILDREN)']) {
      expect(list(line)).toEqual(["l OK LIST completed"]);
    }
    // 빈 패턴이 다른 패턴과 섞이면 빈 것만 무시된다.
    expect(list('l LIST "" ("" "INBOX")')).toEqual(['* LIST (\\HasNoChildren) "/" "INBOX"', "l OK LIST completed"]);
    // 빈 괄호도 확장 형태다(RFC 5258 §3 — 문법 형태로 가른다).
    expect(list('l LIST () "" ""')).toEqual(["l OK LIST completed"]);
    expect(list('l LIST "" "" RETURN ()')).toEqual(["l OK LIST completed"]);
  });

  test("RECURSIVEMATCH — 패턴에 맞는 자손이 이미 나가면 **선택되지 않은** 부모를 CHILDINFO로 따로 내지 않는다(RFC 5258 §3.5)", () => {
    // `*`이면 Work/Reports가 자기 줄로 나가므로, 구독 안 한 Work를 따로 낼 이유가 없다.
    const out = list('l LIST (SUBSCRIBED RECURSIVEMATCH) "" "*"');
    expect(out).toContain('* LIST (\\HasNoChildren \\Subscribed) "/" "Work/Reports"');
    expect(out.some((l) => l.includes('"Work" ("CHILDINFO"'))).toBe(false);
  });

  test("★RECURSIVEMATCH — 구독한 부모는 자손이 패턴에 맞아 나가도 CHILDINFO를 단다(RFC 5258 §3.5 표)", () => {
    const nested = [mailbox({ name: "Fruit" }), mailbox({ name: "Fruit/Apple" })];
    expect(list('l LIST (SUBSCRIBED RECURSIVEMATCH) "" "*"', nested)).toEqual([
      '* LIST (\\HasChildren \\Subscribed) "/" "Fruit" ("CHILDINFO" ("SUBSCRIBED"))',
      '* LIST (\\HasNoChildren \\Subscribed) "/" "Fruit/Apple"',
      "l OK LIST completed",
    ]);
  });

  test("RFC 5258 §5 예시 9의 \"*2\" 응답과 같다 — baz2는 빼고 foo2·eps2는 CHILDINFO", () => {
    // 예시 9의 계층·구독 그대로(qux2는 메일함 없이 qux2/bar2만 있다). 속성은 우리 서버가 항상 내는
    // \\HasChildren/\\HasNoChildren이 더 붙을 뿐이다.
    const sub = (name: string, subscribed: boolean): ImapMailbox => mailbox({ name, subscribed });
    const example9 = [
      sub("foo2", false), sub("foo2/bar1", true), sub("foo2/bar2", true),
      sub("baz2", false), sub("baz2/bar2", true), sub("baz2/bar22", true), sub("baz2/bar222", true),
      sub("eps2", true), sub("eps2/mamba", true), sub("qux2/bar2", true),
    ];
    expect(list('l LIST (RECURSIVEMATCH SUBSCRIBED) "" "*2"', example9)).toEqual([
      '* LIST (\\HasChildren) "/" "foo2" ("CHILDINFO" ("SUBSCRIBED"))',
      '* LIST (\\HasNoChildren \\Subscribed) "/" "foo2/bar2"',
      '* LIST (\\HasNoChildren \\Subscribed) "/" "baz2/bar2"',
      '* LIST (\\HasNoChildren \\Subscribed) "/" "baz2/bar22"',
      '* LIST (\\HasNoChildren \\Subscribed) "/" "baz2/bar222"',
      '* LIST (\\HasChildren \\Subscribed) "/" "eps2" ("CHILDINFO" ("SUBSCRIBED"))',
      '* LIST (\\HasNoChildren \\Subscribed) "/" "qux2/bar2"',
      "l OK LIST completed",
    ]);
    // 같은 계층에 "%"면 baz2가 나온다 — 구독한 자손이 전부 패턴 밖이기 때문이다. "*2"에서 빠지고
    // "%"에서 나오는 이 대비가 집합을 둘로 나눈 이유다. (qux2는 메일함이 없어 \\NonExistent 줄을
    // 만들지 않는다 — 스토어가 부모 없는 메일함을 만들지 않으므로 닿지 않는 경로다.)
    expect(list('l LIST (RECURSIVEMATCH SUBSCRIBED) "" "%"', example9)).toEqual([
      '* LIST (\\HasChildren) "/" "foo2" ("CHILDINFO" ("SUBSCRIBED"))',
      '* LIST (\\HasChildren) "/" "baz2" ("CHILDINFO" ("SUBSCRIBED"))',
      '* LIST (\\HasChildren \\Subscribed) "/" "eps2" ("CHILDINFO" ("SUBSCRIBED"))',
      "l OK LIST completed",
    ]);
  });

  test("RECURSIVEMATCH — 여러 단계 조상: 패턴 밖 자손이 있는 조상만 낸다(§3.3 2.B)", () => {
    // 조상을 단계마다 펼치는 계산은 2단계 이상에서만 시험된다 — a·a/b는 구독 안 함, a/b/c만 구독.
    const deep = [mailbox({ name: "a", subscribed: false }), mailbox({ name: "a/b", subscribed: false }), mailbox({ name: "a/b/c" })];
    expect(list('l LIST (SUBSCRIBED RECURSIVEMATCH) "" "*"', deep)).toEqual([
      '* LIST (\\HasNoChildren \\Subscribed) "/" "a/b/c"',
      "l OK LIST completed",
    ]);
    expect(list('l LIST (SUBSCRIBED RECURSIVEMATCH) "" "%"', deep)).toEqual([
      '* LIST (\\HasChildren) "/" "a" ("CHILDINFO" ("SUBSCRIBED"))',
      "l OK LIST completed",
    ]);
    expect(list('l LIST (SUBSCRIBED RECURSIVEMATCH) "" ("a" "a/b")', deep)).toEqual([
      '* LIST (\\HasChildren) "/" "a" ("CHILDINFO" ("SUBSCRIBED"))',
      '* LIST (\\HasChildren) "/" "a/b" ("CHILDINFO" ("SUBSCRIBED"))',
      "l OK LIST completed",
    ]);
  });

  /** 빈 목록·조합 — 문법상 허용되는 경계 형태(코드 검수가 짚은 빈칸). */
  test("빈 선택 목록·빈 RETURN·선택된 부모의 CHILDINFO·SPECIAL-USE+RECURSIVEMATCH·STATUS 조합", () => {
    expect(list('l LIST () "" "*"')).toEqual(list('l LIST "" "*"'));
    expect(list('l LIST "" "*" RETURN ()')).toEqual(list('l LIST "" "*"'));
    expect(list('l LIST (SPECIAL-USE RECURSIVEMATCH) "" "*"').at(-1)).toBe("l OK LIST completed");
    // 구독한 부모 + 구독한 자식 → 부모 줄 자체에 CHILDINFO가 붙는다(RFC 5258 §5 예시).
    const nested = [mailbox({ name: "Fruit" }), mailbox({ name: "Fruit/Apple" })];
    expect(list('l LIST (SUBSCRIBED RECURSIVEMATCH) "" "%"', nested)).toEqual([
      '* LIST (\\HasChildren \\Subscribed) "/" "Fruit" ("CHILDINFO" ("SUBSCRIBED"))',
      "l OK LIST completed",
    ]);
    expect(list('l LIST (SPECIAL-USE) "" "*" RETURN (STATUS (MESSAGES))')).toEqual([
      '* LIST (\\Sent \\HasNoChildren) "/" "Sent"',
      '* STATUS "Sent" (MESSAGES 4)',
      '* LIST (\\Trash \\HasNoChildren) "/" "Trash"',
      '* STATUS "Trash" (MESSAGES 4)',
      "l OK LIST completed",
    ]);
  });
});
