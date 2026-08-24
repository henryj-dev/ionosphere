/**
 * 와일드카드 매칭 정본 — 문법 정확성 + **ReDoS 회귀**.
 *
 * 시간 검사가 이 파일의 존재 이유다. 예전 구현(정규식 `*` → `.*`)은 아래 입력에서
 * 19초~120초+ 걸렸고, 전 프로토콜이 단일 프로세스라 그동안 메일 서비스 전체가 멈췄다.
 */
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { compileGlob, globMatch, imapListSyntax, SIEVE_MATCH_SYNTAX } from "@ionosphere/core";

const IMAP = imapListSyntax("/");

describe("globMatch — IMAP LIST 문법", () => {
  test("리터럴", () => {
    expect(globMatch("INBOX", "INBOX", IMAP)).toBe(true);
    expect(globMatch("INBOX", "INBOXX", IMAP)).toBe(false);
    expect(globMatch("INBOX", "INBO", IMAP)).toBe(false);
  });

  test("`*`는 구분자를 넘는다", () => {
    expect(globMatch("*", "a/b/c", IMAP)).toBe(true);
    expect(globMatch("a/*", "a/b/c", IMAP)).toBe(true);
    expect(globMatch("*c", "a/b/c", IMAP)).toBe(true);
    expect(globMatch("a*c", "a/b/c", IMAP)).toBe(true);
  });

  test("`%`는 구분자를 넘지 못한다", () => {
    expect(globMatch("%", "a", IMAP)).toBe(true);
    expect(globMatch("%", "a/b", IMAP)).toBe(false);
    expect(globMatch("a/%", "a/b", IMAP)).toBe(true);
    expect(globMatch("a/%", "a/b/c", IMAP)).toBe(false);
    expect(globMatch("%/%", "a/b", IMAP)).toBe(true);
  });

  test("빈 문자열을 먹는다", () => {
    expect(globMatch("*", "", IMAP)).toBe(true);
    expect(globMatch("%", "", IMAP)).toBe(true);
    expect(globMatch("a*", "a", IMAP)).toBe(true);
    expect(globMatch("a%", "a", IMAP)).toBe(true);
  });

  test("연속 `*`는 하나와 같다(되돌아갈 지점을 늘리지 않는다)", () => {
    expect(globMatch("**a", "xxa", IMAP)).toBe(true);
    expect(globMatch("a***b", "ab", IMAP)).toBe(true);
  });

  /**
   * ★대소문자를 **구분한다**. 예전엔 정규식에 `i` 플래그가 붙어 `LIST "" "work"`가 `Work`도
   * 매치했다 — RFC 9051에서 대소문자 무관인 것은 `INBOX` 하나뿐이고 그건
   * `normalizeMailboxName()`이 처리한다.
   */
  test("IMAP은 대소문자를 구분한다", () => {
    expect(globMatch("work", "Work", IMAP)).toBe(false);
    expect(globMatch("Work", "Work", IMAP)).toBe(true);
    expect(globMatch("WORK", "work", IMAP)).toBe(false);
  });

  test("IMAP에는 이스케이프가 없다 — `\\`는 평범한 문자", () => {
    expect(globMatch("a\\b", "a\\b", IMAP)).toBe(true);
    expect(globMatch("a\\*", "a\\zz", IMAP)).toBe(true); // `\` 리터럴 + `*` 와일드카드
  });

  /**
   * ★DP를 쓰는 이유가 이 케이스다. 표준 글롭 2포인터(마지막 `*` 하나만 되돌아감)는
   * `%`가 구분자에 막혀 소진됐을 때 **그 앞의 `*`를 더 늘려야** 답이 나오는 것을 못 본다.
   * `*`=`xa/`, `a`=`a`, `%`=``, `b`=`b`로 맞는데 2포인터는 거짓을 낸다.
   */
  test("`*` 뒤의 `%`가 구분자에 막혀도 앞의 `*`를 늘려 답을 찾는다", () => {
    expect(globMatch("*a%b", "xa/ab", IMAP)).toBe(true);
    expect(globMatch("*a%b", "xa/a/b", IMAP)).toBe(false); // `%`가 넘을 수 없다
  });
});

describe("globMatch — Sieve :matches 문법", () => {
  test("`*`와 `?`", () => {
    expect(globMatch("*", "anything", SIEVE_MATCH_SYNTAX)).toBe(true);
    expect(globMatch("a?c", "abc", SIEVE_MATCH_SYNTAX)).toBe(true);
    expect(globMatch("a?c", "ac", SIEVE_MATCH_SYNTAX)).toBe(false);
    expect(globMatch("*urgent*", "re: urgent: hello", SIEVE_MATCH_SYNTAX)).toBe(true);
  });

  test("`\\*`·`\\?`는 리터럴", () => {
    expect(globMatch("a\\*b", "a*b", SIEVE_MATCH_SYNTAX)).toBe(true);
    expect(globMatch("a\\*b", "axxb", SIEVE_MATCH_SYNTAX)).toBe(false);
    expect(globMatch("a\\?b", "a?b", SIEVE_MATCH_SYNTAX)).toBe(true);
    expect(globMatch("a\\?b", "axb", SIEVE_MATCH_SYNTAX)).toBe(false);
  });

  test("i;ascii-casemap — 대소문자 무시", () => {
    expect(globMatch("*URGENT*", "re: urgent", SIEVE_MATCH_SYNTAX)).toBe(true);
  });

  test("Sieve `*`는 개행도 넘는다(예전 `s` 플래그와 동일)", () => {
    expect(globMatch("a*b", "a\nb", SIEVE_MATCH_SYNTAX)).toBe(true);
  });
});

describe("ReDoS 회귀 — 지수 백트래킹이 성립하지 않아야 한다", () => {
  /**
   * 예전 정규식 구현 실측: Sieve 19,653ms / IMAP 120초 초과.
   * 상한을 넉넉히 100ms로 잡는다 — 선형이면 1ms 미만이라, 이 값을 넘으면 알고리즘이
   * 다시 백트래킹으로 돌아간 것이다.
   */
  const BUDGET_MS = 100;

  test("Sieve :matches — `*x`×16 + Z vs x×32", () => {
    const pattern = "*x".repeat(16) + "Z";
    const value = "x".repeat(32);
    const t = Date.now();
    expect(globMatch(pattern, value, SIEVE_MATCH_SYNTAX)).toBe(false);
    expect(Date.now() - t < BUDGET_MS).toBe(true);
  });

  test("IMAP LIST — `*a`×22 + b vs a×44", () => {
    const pattern = "*a".repeat(22) + "b";
    const value = "a".repeat(44);
    const t = Date.now();
    expect(globMatch(pattern, value, IMAP)).toBe(false);
    expect(Date.now() - t < BUDGET_MS).toBe(true);
  });

  test("`%`가 섞여도 폭발하지 않는다", () => {
    const pattern = "%a".repeat(12) + "b";
    const value = "a".repeat(24);
    const t = Date.now();
    expect(globMatch(pattern, value, IMAP)).toBe(false);
    expect(Date.now() - t < BUDGET_MS).toBe(true);
  });

  test("긴 값 × 많은 별 — 선형이어야 한다", () => {
    const pattern = "*x".repeat(40) + "Z";
    const value = "x".repeat(5000);
    const t = Date.now();
    expect(globMatch(pattern, value, SIEVE_MATCH_SYNTAX)).toBe(false);
    expect(Date.now() - t < BUDGET_MS).toBe(true);
  });
});

describe("compileGlob", () => {
  test("컴파일된 매처는 같은 답을 낸다", () => {
    const m = compileGlob("a/%", IMAP);
    expect(m("a/b")).toBe(true);
    expect(m("a/b/c")).toBe(false);
    expect(m("a/")).toBe(true);
  });
});
