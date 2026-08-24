/**
 * 글롭 캡처 (`globCaptures`) — Sieve `variables`(RFC 5229 §3)의 `${1}`이 여기서 나온다.
 *
 * ★불리언 판정과 **같은 답**을 내야 한다. 캡처 경로가 따로 있으면 "매칭은 됐는데 ${1}이
 * 비었다"거나 그 반대가 생기고, 사용자는 원인을 알 방법이 없다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { globCaptures, globMatch, imapListSyntax, SIEVE_MATCH_SYNTAX } from "../src/glob.ts";

const S = SIEVE_MATCH_SYNTAX;

describe("기본 캡처", () => {
  test("`*` 하나", () => {
    expect(globCaptures("*", "hello", S)).toEqual({ matched: true, captures: ["hello"] });
    expect(globCaptures("a*c", "abc", S)).toEqual({ matched: true, captures: ["b"] });
  });

  test("`?`는 한 글자", () => {
    expect(globCaptures("a?c", "abc", S)).toEqual({ matched: true, captures: ["b"] });
  });

  test("여러 와일드카드는 나온 순서대로", () => {
    expect(globCaptures("*-*", "a-b", S)).toEqual({ matched: true, captures: ["a", "b"] });
    expect(globCaptures("?*?", "abcd", S).captures).toEqual(["a", "bc", "d"]);
  });

  test("리터럴만 있으면 캡처가 없다", () => {
    expect(globCaptures("abc", "abc", S)).toEqual({ matched: true, captures: [] });
  });

  test("매칭 실패는 빈 캡처", () => {
    expect(globCaptures("a*c", "xyz", S)).toEqual({ matched: false, captures: [] });
  });

  test("빈 것도 캡처한다", () => {
    expect(globCaptures("a*b", "ab", S)).toEqual({ matched: true, captures: [""] });
  });
});

describe("탐욕성", () => {
  /**
   * ★앞쪽 와일드카드가 **최대로** 먹는다. RFC 5229는 규정하지 않는데, 정하지 않으면 같은
   * 스크립트가 구현마다 다른 `${1}`을 본다. 정규식의 `*`와 같은 쪽으로 고정한다.
   */
  test("앞쪽이 최대로 먹는다", () => {
    expect(globCaptures("*-*", "a-b-c", S).captures).toEqual(["a-b", "c"]);
    expect(globCaptures("*a*", "aaa", S).captures).toEqual(["aa", ""]);
  });
});

describe("불리언 판정과 일치한다", () => {
  const cases: [string, string][] = [
    ["*", ""],
    ["a*c", "abc"],
    ["a*c", "ac"],
    ["a*c", "abd"],
    ["*a%b", "xa/ab"],
    ["%", "a/b"],
    ["a%c", "abc"],
    ["a%c", "a/c"],
    ["\\*", "*"],
    ["\\*", "x"],
    ["?", ""],
    ["??", "ab"],
  ];

  /** ★두 경로가 갈라지면 "매칭은 됐는데 ${1}이 비었다"가 생긴다. */
  test("같은 패턴·값에서 matched가 같다", () => {
    for (const [pattern, value] of cases) {
      expect(globCaptures(pattern, value, S).matched).toBe(globMatch(pattern, value, S));
    }
  });
});

describe("`%`는 구분자를 넘지 않는다", () => {
  const IMAP = imapListSyntax("/");

  /** `a%`는 `a/b`를 **끝까지 먹을 수 없다** — `%`가 `/`를 넘지 못하므로 매칭 자체가 실패다. */
  test("`%`가 구분자에 막히면 매칭이 실패한다", () => {
    expect(globCaptures("a%", "a/b", IMAP).matched).toBe(false);
    expect(globMatch("a%", "a/b", IMAP)).toBe(false);
  });

  test("구분자 앞까지는 먹는다", () => {
    const r = globCaptures("a%", "abc", IMAP);
    expect(r.matched).toBe(true);
    expect(r.captures).toEqual(["bc"]);
  });

  test("`*`는 구분자를 넘는다", () => {
    expect(globCaptures("a*", "a/b", IMAP).captures).toEqual(["/b"]);
  });

  /** 2포인터가 틀리는 그 입력 — 캡처 경로도 같은 답이어야 한다. */
  test("`*a%b` vs `xa/ab`", () => {
    const r = globCaptures("*a%b", "xa/ab", IMAP);
    expect(r.matched).toBe(true);
    expect(globMatch("*a%b", "xa/ab", IMAP)).toBe(true);
  });
});

describe("대소문자·이스케이프", () => {
  test("대소문자를 무시해도 캡처는 원문 표기다", () => {
    expect(globCaptures("A*C", "aBc", S).captures).toEqual(["B"]);
  });

  test("이스케이프된 와일드카드는 리터럴이라 캡처가 없다", () => {
    expect(globCaptures("\\*", "*", S)).toEqual({ matched: true, captures: [] });
  });
});

describe("상한", () => {
  /**
   * ★표 크기 상한을 넘으면 캡처를 만들지 않는다 — `body :matches`처럼 큰 값에 걸면 표가
   * 곧 메모리 폭발이다. 그때도 **matched는 정확해야** 한다.
   */
  test("아주 큰 값에서도 matched는 정확하고 캡처는 비운다", () => {
    const big = "x".repeat(600_000) + "needle";
    const r = globCaptures("*needle", big, S);
    expect(r.matched).toBe(true);
    expect(r.captures).toEqual([]);
    expect(globMatch("*needle", big, S)).toBe(true);
  });

  test("큰 값에서 매칭 실패도 정확하다", () => {
    const big = "x".repeat(600_000);
    expect(globCaptures("*needle", big, S).matched).toBe(false);
  });
});

describe("선형 시간", () => {
  /** 백트래킹 폭발이 성립하지 않는지 — 이 파일과 glob.ts가 함께 막는 것. */
  test("병적인 패턴도 빠르다", () => {
    const started = Date.now();
    globCaptures("*".repeat(20) + "b", "a".repeat(3000), S);
    globCaptures("*a*a*a*a*a*b", "a".repeat(3000), S);
    expect(Date.now() - started < 2000).toBe(true);
  });
});
