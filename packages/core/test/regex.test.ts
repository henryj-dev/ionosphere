/**
 * 역추적 없는 정규식 엔진.
 *
 * ★이 파일의 존재 이유는 마지막 describe다: **병적인 패턴이 빨라야 한다.** 사용자가 쓴
 * `:regex` 필터가 배달되는 메일마다 도는데, JS `RegExp`이었다면 `(a+)+b` 하나로 이벤트
 * 루프가 멈추고 그건 **메일 서비스 전체가 멈추는** 것이다(모든 프로토콜이 한 프로세스다).
 *
 * 나머지 테스트는 "선형인데 답도 맞나"를 본다 — 빠르기만 하고 틀리면 소용이 없다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { compileRegex, execRegex, regexMatch, RegexSyntaxError } from "../src/regex.ts";

const m = (pattern: string, input: string): boolean => regexMatch(pattern, input).matched;
const caps = (pattern: string, input: string): string[] => regexMatch(pattern, input).captures;

describe("기본 문법", () => {
  test("리터럴은 부분 매칭이다", () => {
    expect(m("abc", "xxabcxx")).toBe(true);
    expect(m("abc", "abd")).toBe(false);
    expect(m("", "anything")).toBe(true);
  });

  test("`.`은 아무 글자", () => {
    expect(m("a.c", "abc")).toBe(true);
    expect(m("a.c", "ac")).toBe(false);
  });

  test("`*` `+` `?`", () => {
    expect(m("^ab*c$", "ac")).toBe(true);
    expect(m("^ab*c$", "abbbc")).toBe(true);
    expect(m("^ab+c$", "ac")).toBe(false);
    expect(m("^ab+c$", "abc")).toBe(true);
    expect(m("^ab?c$", "ac")).toBe(true);
    expect(m("^ab?c$", "abbc")).toBe(false);
  });

  test("`|` 교대", () => {
    expect(m("^(cat|dog)$", "cat")).toBe(true);
    expect(m("^(cat|dog)$", "dog")).toBe(true);
    expect(m("^(cat|dog)$", "cow")).toBe(false);
  });

  test("`^` `$` 앵커", () => {
    expect(m("^abc", "abcdef")).toBe(true);
    expect(m("^abc", "xabc")).toBe(false);
    expect(m("abc$", "xxabc")).toBe(true);
    expect(m("abc$", "abcx")).toBe(false);
  });

  test("`{n,m}` 반복", () => {
    expect(m("^a{3}$", "aaa")).toBe(true);
    expect(m("^a{3}$", "aa")).toBe(false);
    expect(m("^a{2,4}$", "aaa")).toBe(true);
    expect(m("^a{2,4}$", "aaaaa")).toBe(false);
    expect(m("^a{2,}$", "aaaaa")).toBe(true);
    expect(m("^a{2,}$", "a")).toBe(false);
  });

  /** 반복 문법이 아닌 `{`는 리터럴이다(POSIX의 관용). */
  test("반복이 아닌 `{`는 리터럴", () => {
    expect(m("^a{x}$", "a{x}")).toBe(true);
  });

  test("이스케이프", () => {
    expect(m("^a\\.c$", "a.c")).toBe(true);
    expect(m("^a\\.c$", "abc")).toBe(false);
    expect(m("^\\*$", "*")).toBe(true);
  });

  test("중첩 그룹과 교대", () => {
    expect(m("^((a|b)c)+$", "acbc")).toBe(true);
    expect(m("^((a|b)c)+$", "acx")).toBe(false);
  });
});

describe("문자 클래스", () => {
  test("범위·집합·부정", () => {
    expect(m("^[a-c]+$", "abcab")).toBe(true);
    expect(m("^[a-c]+$", "abd")).toBe(false);
    expect(m("^[^a-c]+$", "xyz")).toBe(true);
    expect(m("^[^a-c]+$", "xay")).toBe(false);
  });

  test("축약 클래스", () => {
    expect(m("^\\d+$", "12345")).toBe(true);
    expect(m("^\\d+$", "12a45")).toBe(false);
    expect(m("^\\w+$", "a_1")).toBe(true);
    expect(m("^\\s$", " ")).toBe(true);
    expect(m("^\\D$", "a")).toBe(true);
    expect(m("^\\D$", "1")).toBe(false);
  });

  test("클래스 안의 축약", () => {
    expect(m("^[\\d-]+$", "12-34")).toBe(true);
  });

  test("맨 앞의 `]`는 리터럴", () => {
    expect(m("^[]a]+$", "]a]")).toBe(true);
  });

  test("끝의 `-`는 리터럴", () => {
    expect(m("^[a-]+$", "a-a")).toBe(true);
  });
});

describe("캡처", () => {
  test("그룹이 순서대로 나온다", () => {
    expect(caps("^(a+)(b+)$", "aabbb")).toEqual(["aa", "bbb"]);
  });

  /** ★탐욕적이고 왼쪽 우선 — 정규식의 관례와 같게 고정한다. */
  test("탐욕적이다", () => {
    expect(caps("^(.*)-(.*)$", "a-b-c")).toEqual(["a-b", "c"]);
  });

  test("교대는 왼쪽이 이긴다", () => {
    expect(caps("^(a|ab)", "ab")).toEqual(["a"]);
  });

  test("참여하지 않은 그룹은 빈 문자열", () => {
    expect(caps("^(x)?(a)$", "a")).toEqual(["", "a"]);
  });

  test("대소문자 무시에서도 캡처는 원문 표기", () => {
    const re = compileRegex("^(a+)$", { caseInsensitive: true });
    expect(execRegex(re, "AaA")).toEqual({ matched: true, captures: ["AaA"] });
  });

  /** 부분 매칭은 **가장 왼쪽**에서 시작한다 — 아니면 `${1}`이 사용자가 보는 것과 달라진다. */
  test("가장 왼쪽 매칭이 이긴다", () => {
    expect(caps("(a+)", "bbaaabaa")).toEqual(["aaa"]);
  });
});

describe("거절하는 것", () => {
  /**
   * ★역참조와 룩어라운드는 이 방식으로 선형 시간이 성립하지 않는다.
   * 조용히 다르게 동작시키느니 **문법 오류**가 낫다 — 그래야 규칙이 안 먹는 이유를 안다.
   */
  test("역참조는 문법 오류", () => {
    expect(() => compileRegex("(a)\\1")).toThrow(RegexSyntaxError);
  });

  test("(?...)는 문법 오류", () => {
    expect(() => compileRegex("(?=a)b")).toThrow(RegexSyntaxError);
    expect(() => compileRegex("(?:a)")).toThrow(RegexSyntaxError);
  });

  test("문법이 깨진 패턴", () => {
    expect(() => compileRegex("(a")).toThrow(RegexSyntaxError);
    expect(() => compileRegex("a)")).toThrow(RegexSyntaxError);
    expect(() => compileRegex("[a")).toThrow(RegexSyntaxError);
    expect(() => compileRegex("a\\")).toThrow(RegexSyntaxError);
    expect(() => compileRegex("[z-a]")).toThrow(RegexSyntaxError);
  });

  /** 시간은 선형이어도 **메모리**는 아니다 — `{n,m}`을 펼치므로 상한이 필요하다. */
  test("과한 반복은 거절한다", () => {
    expect(() => compileRegex("a{99999}")).toThrow(RegexSyntaxError);
    expect(() => compileRegex("(a{1000}){1000}")).toThrow(RegexSyntaxError);
  });

  test("너무 긴 패턴은 거절한다", () => {
    expect(() => compileRegex("a".repeat(5000))).toThrow(RegexSyntaxError);
  });
});

describe("★ReDoS가 성립하지 않는다", () => {
  /**
   * 아래는 역추적 엔진에서 **지수 시간**이 되는 고전적 입력들이다. `RegExp`으로 돌리면
   * 이 테스트가 끝나지 않고, 운영에서는 그게 곧 메일 서비스 정지다.
   */
  const evil: [string, string][] = [
    ["^(a+)+$", "a".repeat(40) + "b"],
    ["^(a|a)*$", "a".repeat(40) + "b"],
    ["^(a*)*b$", "a".repeat(40)],
    ["^(x+x+)+y$", "x".repeat(40)],
    ["(a|b|ab)*c", "ab".repeat(30)],
  ];

  test("병적인 패턴이 즉시 끝난다", () => {
    const started = Date.now();
    for (const [pattern, input] of evil) {
      expect(regexMatch(pattern, input).matched).toBe(false);
    }
    const elapsed = Date.now() - started;
    // 역추적이면 초 단위가 아니라 **끝나지 않는다**. 넉넉히 잡아도 이 상한에 걸릴 수 없다.
    expect(elapsed < 2000).toBe(true);
  });

  test("긴 입력에서도 선형이다", () => {
    const started = Date.now();
    expect(regexMatch("^(a+)+$", "a".repeat(20_000)).matched).toBe(true);
    expect(Date.now() - started < 2000).toBe(true);
  });
});

describe("컴파일 재사용", () => {
  /** 호출부가 루프 안에서 다시 컴파일하지 않게 — 값이 여럿일 때의 낭비를 막는다. */
  test("같은 프로그램으로 여러 입력을 돌린다", () => {
    const re = compileRegex("^(\\w+)@(\\w+)$");
    expect(execRegex(re, "alice@example").captures).toEqual(["alice", "example"]);
    expect(execRegex(re, "bob@test").captures).toEqual(["bob", "test"]);
    expect(execRegex(re, "nope").matched).toBe(false);
  });
});
