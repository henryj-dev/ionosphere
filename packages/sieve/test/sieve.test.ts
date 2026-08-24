/** Sieve 렉서·파서·평가기 테스트 (RFC 5228 + fileinto/imap4flags/envelope). */
import { describe, expect, test } from "@ionosphere/testkit";
import { parseSieve } from "../src/parser.ts";
import { runSieve, SieveError, type SieveEnv } from "../src/interpret.ts";
import { SieveSyntaxError } from "../src/lexer.ts";

function env(over: Partial<SieveEnv> = {}): SieveEnv {
  return {
    headers: new Map([
      ["from", ["Alice <alice@example.com>"]],
      ["to", ["bob@test.local"]],
      ["subject", ["Re: [list] hello world"]],
    ]),
    envelopeFrom: "bounce@example.com",
    envelopeTo: ["bob@test.local"],
    size: 5000,
    ...over,
  };
}

describe("파서", () => {
  test("require + if/elsif/else 블록 파싱", () => {
    const cmds = parseSieve(`require ["fileinto"];
      if header :contains "subject" "spam" { discard; }
      elsif size :over 1M { fileinto "Big"; }
      else { keep; }`);
    expect(cmds.map((c) => c.name)).toEqual(["require", "if", "elsif", "else"]);
    expect(cmds[1]!.test!.name).toBe("header");
    expect(cmds[1]!.block!.map((c) => c.name)).toEqual(["discard"]);
  });

  test("주석·multi-line·숫자단위", () => {
    const cmds = parseSieve(`# 주석\n/* 블록 */ if size :over 2K { stop; }`);
    expect(cmds[0]!.test!.args.some((a) => a.kind === "number" && a.value === 2048)).toBe(true);
  });

  test("문법 오류 → SieveSyntaxError", () => {
    expect(() => parseSieve('if header "subject"')).toThrow(); // 미완결
    expect(() => parseSieve('keep "unterminated')).toThrow(SieveSyntaxError);
  });
});

describe("암묵/명시 keep", () => {
  test("빈 스크립트 → 암묵 keep(INBOX)", () => {
    const r = runSieve("", env());
    expect(r.keep).toBe(true);
    expect(r.fileinto).toEqual([]);
    expect(r.discarded).toBe(false);
  });

  test("fileinto는 암묵 keep 취소", () => {
    const r = runSieve('require "fileinto"; fileinto "Work";', env());
    expect(r.fileinto).toEqual(["Work"]);
    expect(r.keep).toBe(false);
  });

  test("fileinto :copy는 암묵 keep 유지", () => {
    const r = runSieve('require ["fileinto","copy"]; fileinto :copy "Archive";', env());
    expect(r.fileinto).toEqual(["Archive"]);
    expect(r.keep).toBe(true);
  });

  test("discard 단독 → 폐기", () => {
    const r = runSieve("discard;", env());
    expect(r.keep).toBe(false);
    expect(r.discarded).toBe(true);
  });

  test("keep + fileinto 동시", () => {
    const r = runSieve('require "fileinto"; fileinto "X"; keep;', env());
    expect(r.keep).toBe(true);
    expect(r.fileinto).toEqual(["X"]);
  });
});

describe("테스트 평가", () => {
  test("header :contains (대소문자 무시)", () => {
    expect(runSieve('require "fileinto"; if header :contains "Subject" "HELLO" { fileinto "H"; }', env()).fileinto).toEqual(["H"]);
    expect(runSieve('require "fileinto"; if header :contains "subject" "nope" { fileinto "H"; }', env()).fileinto).toEqual([]);
  });

  test("header :is / :matches(글롭)", () => {
    expect(runSieve('if header :is "to" "bob@test.local" { discard; }', env()).discarded).toBe(true);
    expect(runSieve('require "fileinto"; if header :matches "subject" "Re: *world" { fileinto "M"; }', env()).fileinto).toEqual(["M"]);
  });

  test("address :domain / :localpart", () => {
    expect(runSieve('require "fileinto"; if address :domain :is "from" "example.com" { fileinto "D"; }', env()).fileinto).toEqual(["D"]);
    expect(runSieve('require "fileinto"; if address :localpart :is "from" "alice" { fileinto "L"; }', env()).fileinto).toEqual(["L"]);
  });

  test("envelope :domain (봉투 from)", () => {
    expect(runSieve('require "envelope"; if envelope :domain :is "from" "example.com" { discard; }', env()).discarded).toBe(true);
  });

  test("size :over / :under", () => {
    expect(runSieve('require "fileinto"; if size :over 1K { fileinto "Big"; }', env({ size: 5000 })).fileinto).toEqual(["Big"]);
    expect(runSieve('require "fileinto"; if size :under 1K { fileinto "Big"; }', env({ size: 5000 })).fileinto).toEqual([]);
  });

  test("exists / allof / anyof / not", () => {
    expect(runSieve('require "fileinto"; if allof(exists "from", exists "subject") { fileinto "A"; }', env()).fileinto).toEqual(["A"]);
    expect(runSieve('require "fileinto"; if anyof(exists "nope", size :over 1K) { fileinto "B"; }', env()).fileinto).toEqual(["B"]);
    expect(runSieve('require "fileinto"; if not exists "x-nope" { fileinto "C"; }', env()).fileinto).toEqual(["C"]);
  });
});

describe("제어 흐름·플래그·오류", () => {
  test("stop은 이후 실행 중단", () => {
    const r = runSieve('require "fileinto"; fileinto "First"; stop; fileinto "Second";', env());
    expect(r.fileinto).toEqual(["First"]);
  });

  test("if/elsif/else 배타 선택", () => {
    const script = 'require "fileinto"; if size :over 1M { fileinto "Big"; } elsif size :over 1K { fileinto "Med"; } else { fileinto "Small"; }';
    expect(runSieve(script, env({ size: 5000 })).fileinto).toEqual(["Med"]);
    expect(runSieve(script, env({ size: 100 })).fileinto).toEqual(["Small"]);
  });

  test("imap4flags — setflag/addflag/removeflag", () => {
    const r = runSieve('require ["imap4flags","fileinto"]; addflag "\\\\Seen"; addflag "$label1"; removeflag "$label1"; fileinto "F";', env());
    expect(r.flags).toEqual(["\\Seen"]);
  });

  test("redirect", () => {
    const r = runSieve('redirect "forward@other.test";', env());
    expect(r.redirect).toEqual(["forward@other.test"]);
    expect(r.keep).toBe(false);
  });

  test("미지원 확장 require → SieveError", () => {
    // ★예시를 `vacation`에서 바꿨다 — 2026-08-24에 지원 목록에 들어갔다.
    //   지원 확장이 늘 때마다 여기가 깨지는 것이 맞다(그게 이 테스트가 하는 일이다).
    expect(() => runSieve('require "variables"; keep;', env())).toThrow(SieveError);
    expect(() => runSieve('require "editheader"; keep;', env())).toThrow(SieveError);
  });
});
