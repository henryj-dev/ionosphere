/**
 * SORT / THREAD (RFC 5256) + SAVEDATE (RFC 8514).
 *
 * ★정렬 키는 **스토어가 물질화해 둔 값**으로 온다. 원문을 파싱해 제목·발신자를 뽑으면 정렬
 * 한 번에 메일함 전체 블롭이 메모리에 올라온다 — SEARCH가 예전에 그렇게 해서 2.5GB였다.
 * 아래 테스트가 `needSortKeys`를 요청하는지까지 보는 이유다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapBackendRequest, type ImapFetchData, type ImapMailbox } from "../src/engine.ts";
import { formatThreadLine, parseSortSpec, type SortItem } from "../src/sort-thread.ts";
import type { ImapValue } from "../src/parser.ts";

const enc = new TextEncoder();
const BOX: ImapMailbox = { name: "INBOX", role: "inbox", uidvalidity: 100, uidnext: 10, highestmodseq: 50, totalCount: 3, unreadCount: 0, totalBytes: 300 };

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
function backendReq(actions: ImapAction[]): ImapBackendRequest | null {
  return actions.find((a): a is { kind: "backend"; req: ImapBackendRequest } => a.kind === "backend")?.req ?? null;
}

/** uid → (제목, Date 시각, 스레드, 발신자, 크기, 도착 시각). */
function msg(
  uid: number,
  o: { subject?: string; sentAt?: number; thread?: string; from?: string; size?: number; arrival?: number; saved?: number } = {},
): ImapFetchData {
  return {
    uid,
    flags: [],
    internalDateMs: o.arrival ?? 0,
    saveDateMs: o.saved ?? o.arrival ?? 0,
    size: o.size ?? 100,
    modseq: 1,
    sortKeys: {
      subjectBase: o.subject ?? "",
      sentAtMs: o.sentAt ?? 0,
      threadId: o.thread ?? "",
      from: o.from ?? "",
      to: "",
      cc: "",
    },
  };
}

function atoms(...v: string[]): ImapValue[] {
  return v.map((value) => ({ kind: "atom", value }) as ImapValue);
}

describe("정렬 기준 파싱", () => {
  test("기본 기준들", () => {
    expect(parseSortSpec(atoms("DATE"))).toEqual([{ key: "DATE", reverse: false }]);
    expect(parseSortSpec(atoms("ARRIVAL", "SUBJECT"))).toEqual([
      { key: "ARRIVAL", reverse: false },
      { key: "SUBJECT", reverse: false },
    ]);
  });

  /** ★`REVERSE`는 **바로 다음 하나**만 뒤집는다(§3 ABNF) — 나머지까지 뒤집으면 안 된다. */
  test("REVERSE는 다음 기준 하나에만 걸린다", () => {
    expect(parseSortSpec(atoms("REVERSE", "DATE", "SUBJECT"))).toEqual([
      { key: "DATE", reverse: true },
      { key: "SUBJECT", reverse: false },
    ]);
  });

  test("문법 오류는 null", () => {
    expect(parseSortSpec(atoms("NONSENSE"))).toBe(null);
    expect(parseSortSpec(atoms("REVERSE"))).toBe(null); // 매달린 REVERSE
    expect(parseSortSpec(atoms("REVERSE", "REVERSE", "DATE"))).toBe(null);
    expect(parseSortSpec([])).toBe(null);
  });
});

describe("SORT", () => {
  const run = (cmd: string, data: ImapFetchData[]): string[] => {
    const e = selected();
    e.feed(enc.encode(cmd));
    return replies(e.backendResult({ kind: "messages", messages: data }));
  };

  test("SUBJECT 오름차순", () => {
    const out = run('q1 SORT (SUBJECT) UTF-8 ALL\r\n', [
      msg(3, { subject: "charlie" }),
      msg(7, { subject: "alpha" }),
      msg(9, { subject: "bravo" }),
    ]);
    expect(out[0]).toBe("* SORT 2 3 1"); // seq 2(alpha) 3(bravo) 1(charlie)
  });

  test("REVERSE SUBJECT", () => {
    const out = run('q1 SORT (REVERSE SUBJECT) UTF-8 ALL\r\n', [
      msg(3, { subject: "charlie" }),
      msg(7, { subject: "alpha" }),
      msg(9, { subject: "bravo" }),
    ]);
    expect(out[0]).toBe("* SORT 1 3 2");
  });

  test("UID SORT는 uid를 낸다", () => {
    const out = run('q1 UID SORT (SUBJECT) UTF-8 ALL\r\n', [
      msg(3, { subject: "charlie" }),
      msg(7, { subject: "alpha" }),
      msg(9, { subject: "bravo" }),
    ]);
    expect(out[0]).toBe("* SORT 7 9 3");
  });

  test("SIZE / ARRIVAL", () => {
    const data = [msg(3, { size: 300, arrival: 30 }), msg(7, { size: 100, arrival: 10 }), msg(9, { size: 200, arrival: 20 })];
    expect(run('q1 SORT (SIZE) UTF-8 ALL\r\n', data)[0]).toBe("* SORT 2 3 1");
    expect(run('q1 SORT (ARRIVAL) UTF-8 ALL\r\n', data)[0]).toBe("* SORT 2 3 1");
  });

  /** ★`DATE`는 Date 헤더, `ARRIVAL`이 도착 시각이다(§3) — 둘을 섞으면 순서가 뒤집힌다. */
  test("DATE는 Date 헤더이지 도착 시각이 아니다", () => {
    const data = [msg(3, { sentAt: 10, arrival: 300 }), msg(7, { sentAt: 30, arrival: 100 }), msg(9, { sentAt: 20, arrival: 200 })];
    expect(run('q1 SORT (DATE) UTF-8 ALL\r\n', data)[0]).toBe("* SORT 1 3 2");
    expect(run('q1 SORT (ARRIVAL) UTF-8 ALL\r\n', data)[0]).toBe("* SORT 2 3 1");
  });

  /** Date가 없으면 도착 시각으로 떨어진다(§2.2). */
  test("Date가 없으면 도착 시각을 쓴다", () => {
    const data = [msg(3, { sentAt: 0, arrival: 300 }), msg(7, { sentAt: 0, arrival: 100 }), msg(9, { sentAt: 0, arrival: 200 })];
    expect(run('q1 SORT (DATE) UTF-8 ALL\r\n', data)[0]).toBe("* SORT 2 3 1");
  });

  /** 동점은 **번호 오름차순**으로 고정한다 — 없으면 화면이 이유 없이 흔들린다. */
  test("동점은 번호순으로 안정 정렬", () => {
    const data = [msg(3, { subject: "same" }), msg(7, { subject: "same" }), msg(9, { subject: "same" })];
    expect(run('q1 SORT (SUBJECT) UTF-8 ALL\r\n', data)[0]).toBe("* SORT 1 2 3");
  });

  test("여러 기준은 앞에서부터 적용된다", () => {
    const data = [msg(3, { subject: "b", size: 100 }), msg(7, { subject: "a", size: 300 }), msg(9, { subject: "a", size: 200 })];
    expect(run('q1 SORT (SUBJECT SIZE) UTF-8 ALL\r\n', data)[0]).toBe("* SORT 3 2 1");
  });

  test("매칭이 없으면 빈 SORT", () => {
    const out = run('q1 SORT (SUBJECT) UTF-8 SUBJECT "nope"\r\n', [msg(3), msg(7), msg(9)]);
    expect(out[0]).toBe("* SORT");
  });

  /** ★정렬 키를 요청해야 백엔드가 실어 보낸다 — 안 하면 전부 빈 키로 정렬된다. */
  test("백엔드에 needSortKeys를 요청한다", () => {
    const e = selected();
    const req = backendReq(e.feed(enc.encode('q1 SORT (SUBJECT) UTF-8 ALL\r\n')));
    expect(req).toMatchObject({ kind: "fetchMessages", needSortKeys: true, needRaw: false });
  });

  test("문법·charset 오류", () => {
    const e = selected();
    expect(replies(e.feed(enc.encode('q1 SORT (NONSENSE) UTF-8 ALL\r\n')))[0]).toContain("BAD");
    expect(replies(e.feed(enc.encode('q2 SORT UTF-8 ALL\r\n')))[0]).toContain("BAD"); // 리스트가 아니다
    expect(replies(e.feed(enc.encode('q3 SORT (SUBJECT) KOI8-R ALL\r\n')))[0]).toContain("BADCHARSET");
  });
});

describe("THREAD", () => {
  const run = (cmd: string, data: ImapFetchData[]): string[] => {
    const e = selected();
    e.feed(enc.encode(cmd));
    return replies(e.backendResult({ kind: "messages", messages: data }));
  };

  test("같은 thread_id끼리 묶는다", () => {
    const out = run("q1 THREAD REFERENCES UTF-8 ALL\r\n", [
      msg(3, { thread: "T1", sentAt: 10 }),
      msg(7, { thread: "T2", sentAt: 20 }),
      msg(9, { thread: "T1", sentAt: 30 }),
    ]);
    expect(out[0]).toBe("* THREAD (1 3)(2)");
  });

  /** thread_id가 없으면 혼자 한 묶음 — 묶을 근거가 없다. */
  test("thread_id가 없으면 각자 한 묶음", () => {
    const out = run("q1 THREAD REFERENCES UTF-8 ALL\r\n", [msg(3, { sentAt: 10 }), msg(7, { sentAt: 20 })]);
    expect(out[0]).toBe("* THREAD (1)(2)");
  });

  /** ORDEREDSUBJECT는 묶음을 **제목순**으로, REFERENCES는 **시각순**으로 낸다(§4). */
  test("두 알고리즘이 묶음 순서를 다르게 낸다", () => {
    const data = [
      msg(3, { thread: "T1", subject: "zulu", sentAt: 10 }),
      msg(7, { thread: "T2", subject: "alpha", sentAt: 20 }),
    ];
    expect(run("q1 THREAD ORDEREDSUBJECT UTF-8 ALL\r\n", data)[0]).toBe("* THREAD (2)(1)");
    expect(run("q1 THREAD REFERENCES UTF-8 ALL\r\n", data)[0]).toBe("* THREAD (1)(2)");
  });

  test("묶음 안은 시각순", () => {
    const out = run("q1 THREAD REFERENCES UTF-8 ALL\r\n", [
      msg(3, { thread: "T1", sentAt: 300 }),
      msg(7, { thread: "T1", sentAt: 100 }),
      msg(9, { thread: "T1", sentAt: 200 }),
    ]);
    expect(out[0]).toBe("* THREAD (2 3 1)");
  });

  test("UID THREAD는 uid를 낸다", () => {
    const out = run("q1 UID THREAD REFERENCES UTF-8 ALL\r\n", [msg(3, { thread: "T1" }), msg(7, { thread: "T1" })]);
    expect(out[0]).toBe("* THREAD (3 7)");
  });

  test("모르는 알고리즘은 BAD", () => {
    const e = selected();
    expect(replies(e.feed(enc.encode("q1 THREAD NONSENSE UTF-8 ALL\r\n")))[0]).toContain("BAD");
  });

  test("매칭이 없으면 빈 THREAD", () => {
    expect(run('q1 THREAD REFERENCES UTF-8 SUBJECT "nope"\r\n', [msg(3), msg(7)])[0]).toBe("* THREAD");
  });

  /** 순수 함수 단위 — 빈 입력에서 괄호를 만들지 않는다. */
  test("formatThreadLine — 빈 입력", () => {
    expect(formatThreadLine([] as SortItem[], "REFERENCES")).toBe("* THREAD");
  });
});

describe("SAVEDATE (RFC 8514)", () => {
  test("CAPABILITY가 SAVEDATE·SORT·THREAD를 광고한다", () => {
    const e = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
    const caps = replies(e.feed(enc.encode("c1 CAPABILITY\r\n")))[0] ?? "";
    for (const c of ["SAVEDATE", "SORT", "THREAD=ORDEREDSUBJECT", "THREAD=REFERENCES"]) {
      expect(caps.split(" ").includes(c)).toBe(true);
    }
  });

  /** ★SAVEDATE와 INTERNALDATE는 **다른 값**이다 — COPY한 사본이 그 차이를 만든다. */
  test("FETCH SAVEDATE는 INTERNALDATE와 다른 값을 낸다", () => {
    const e = selected();
    e.feed(enc.encode("f1 FETCH 1 (INTERNALDATE SAVEDATE)\r\n"));
    // FETCH 데이터 줄은 replyBinary로 나온다(리터럴을 실을 수 있어야 하므로).
    const dec = new TextDecoder();
    let text = "";
    for (const a of e.backendResult({
      kind: "messages",
      messages: [{ uid: 3, flags: [], internalDateMs: Date.UTC(2020, 0, 1), saveDateMs: Date.UTC(2024, 5, 15), size: 10, modseq: 1 }],
    })) {
      if (a.kind === "reply") text += a.text + "\n";
      else if (a.kind === "replyBinary") text += dec.decode(a.bytes);
    }
    expect(text).toContain("INTERNALDATE \"01-Jan-2020");
    expect(text).toContain("SAVEDATE \"15-Jun-2024");
  });

  /** 저장 시각을 모르면 NIL이 규격이다(§3). */
  test("saveDateMs가 없으면 NIL", () => {
    const e = selected();
    e.feed(enc.encode("f1 FETCH 1 (SAVEDATE)\r\n"));
    const dec = new TextDecoder();
    let text = "";
    for (const a of e.backendResult({ kind: "messages", messages: [{ uid: 3, flags: [], internalDateMs: 0, size: 10, modseq: 1 }] })) {
      if (a.kind === "replyBinary") text += dec.decode(a.bytes);
    }
    expect(text).toContain("SAVEDATE NIL");
  });

  test("SAVEDSINCE / SAVEDBEFORE 검색", () => {
    const mk = (uid: number, savedMs: number): ImapFetchData => ({ uid, flags: [], internalDateMs: 0, saveDateMs: savedMs, size: 10, modseq: 1 });
    const run = (crit: string): string => {
      const e = selected();
      e.feed(enc.encode(`q1 SEARCH ${crit}\r\n`));
      return replies(e.backendResult({
        kind: "messages",
        messages: [mk(3, Date.UTC(2020, 0, 1)), mk(7, Date.UTC(2024, 0, 1)), mk(9, Date.UTC(2026, 0, 1))],
      }))[0]!;
    };
    expect(run("SAVEDSINCE 1-Jan-2024")).toBe("* SEARCH 2 3");
    expect(run("SAVEDBEFORE 1-Jan-2024")).toBe("* SEARCH 1");
    expect(run("SAVEDON 1-Jan-2024")).toBe("* SEARCH 2");
  });
});
