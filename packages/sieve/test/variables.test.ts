/**
 * Sieve `variables` (RFC 5229).
 *
 * ★두 가지가 이 파일의 핵심이다:
 *  · **옵트인** — `require "variables"` 없이는 `${...}`가 평범한 글자다(§3). 전개해 버리면
 *    본문에 우연히 `${x}`가 들어간 기존 스크립트의 뜻이 조용히 바뀐다.
 *  · **재귀 전개 금지** — 값 안의 `${...}`를 다시 펴면 발신자가 제목에 `${x}`를 넣어 남의
 *    변수를 읽는 형태가 된다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { runSieve, SieveError, type SieveEnv } from "../src/interpret.ts";
import { applyModifiers, isValidVariableName, SieveVariables } from "../src/variables.ts";

function env(over: Partial<SieveEnv> = {}): SieveEnv {
  return {
    headers: new Map([
      ["subject", ["Re: [dev] patch 42"]],
      ["from", ["Alice <alice@example.com>"]],
    ]),
    envelopeFrom: "alice@example.com",
    envelopeTo: ["bob@test.local"],
    size: 100,
    ...over,
  };
}

const R = 'require ["variables","fileinto"];';

describe("SieveVariables 단위", () => {
  test("이름 규칙", () => {
    expect(isValidVariableName("x")).toBe(true);
    expect(isValidVariableName("_a1")).toBe(true);
    expect(isValidVariableName("ns.name")).toBe(true);
    expect(isValidVariableName("1x")).toBe(false);
    expect(isValidVariableName("a-b")).toBe(false);
    expect(isValidVariableName("")).toBe(false);
  });

  test("이름은 대소문자를 구분하지 않는다", () => {
    const v = new SieveVariables();
    v.set("Foo", "bar");
    expect(v.get("foo")).toBe("bar");
    expect(v.expand("${FOO}")).toBe("bar");
  });

  test("모르는 변수는 빈 문자열", () => {
    expect(new SieveVariables().expand("[${nope}]")).toBe("[]");
  });

  /** ★재귀 전개 금지 — 값 안의 `${...}`는 그대로 남는다(§3). */
  test("재귀 전개하지 않는다", () => {
    const v = new SieveVariables();
    v.set("a", "${b}");
    v.set("b", "secret");
    expect(v.expand("${a}")).toBe("${b}");
  });

  /** 이름 규칙에 안 맞으면 **그대로 둔다** — 지우면 본문의 우연한 문자열이 사라진다. */
  test("이름 규칙에 안 맞으면 원문을 남긴다", () => {
    const v = new SieveVariables();
    expect(v.expand("${1 + 2}")).toBe("${1 + 2}");
    expect(v.expand("${a-b}")).toBe("${a-b}");
    expect(v.expand("${unclosed")).toBe("${unclosed");
  });

  test("캡처는 ${0}이 전체, ${1}부터 조각", () => {
    const v = new SieveVariables();
    v.setMatches("a-b", ["a", "b"]);
    expect(v.expand("${0}|${1}|${2}|${3}")).toBe("a-b|a|b|");
  });
});

describe("수식어 (§4)", () => {
  test("대소문자 계열", () => {
    expect(applyModifiers("aBc", new Set(["upper"]))).toBe("ABC");
    expect(applyModifiers("aBc", new Set(["lower"]))).toBe("abc");
    expect(applyModifiers("abc", new Set(["upperfirst"]))).toBe("Abc");
    expect(applyModifiers("ABC", new Set(["lowerfirst"]))).toBe("aBC");
  });

  /**
   * ★`:quotewildcard`가 없으면 발신자가 제목에 `*`를 넣어 **남의 필터 규칙을 바꾼다** —
   * 변수 값이 `:matches` 패턴에 끼워지기 때문이다.
   */
  test(":quotewildcard가 와일드카드를 막는다", () => {
    expect(applyModifiers("a*b?c\\d", new Set(["quotewildcard"]))).toBe("a\\*b\\?c\\\\d");
  });

  /** ★`:length`가 **가장 나중**이다(§4의 precedence) — 다른 수식어를 거친 결과의 길이다. */
  test(":length는 마지막에 적용된다", () => {
    expect(applyModifiers("ab", new Set(["length"]))).toBe("2");
    expect(applyModifiers("a*b", new Set(["quotewildcard", "length"]))).toBe("4"); // a\*b = 4글자
  });

  test("빈 문자열에도 안전하다", () => {
    expect(applyModifiers("", new Set(["upperfirst"]))).toBe("");
    expect(applyModifiers("", new Set(["length"]))).toBe("0");
  });
});

describe("set / 전개", () => {
  test("set 후 전개된다", () => {
    const r = runSieve(`${R} set "box" "Work"; fileinto "\${box}";`, env());
    expect(r.fileinto).toEqual(["Work"]);
  });

  test("수식어를 스크립트에서 쓴다", () => {
    const r = runSieve(`${R} set :upper "box" "work"; fileinto "\${box}";`, env());
    expect(r.fileinto).toEqual(["WORK"]);
  });

  /** ★옵트인 — require 없이는 `${...}`가 평범한 글자다(§3). */
  test('require "variables" 없이는 전개하지 않는다', () => {
    const r = runSieve('require ["fileinto"]; fileinto "${box}";', env());
    expect(r.fileinto).toEqual(["${box}"]);
  });

  test('require 없이 set은 SieveError', () => {
    expect(() => runSieve('require ["fileinto"]; set "a" "b";', env())).toThrow(SieveError);
  });

  test("잘못된 변수 이름은 SieveError", () => {
    expect(() => runSieve(`${R} set "1bad" "x";`, env())).toThrow(SieveError);
    expect(() => runSieve(`${R} set :nonsense "a" "x";`, env())).toThrow(SieveError);
  });

  test("인자가 모자라면 SieveError", () => {
    expect(() => runSieve(`${R} set "only";`, env())).toThrow(SieveError);
  });
});

describe(":matches 캡처", () => {
  /** ★`${1}`은 **가장 최근** `:matches`가 정한다(§3). */
  test("헤더 매칭의 조각을 쓴다", () => {
    const r = runSieve(`${R} if header :matches "subject" "Re: [*] *" { fileinto "\${1}/\${2}"; }`, env());
    expect(r.fileinto).toEqual(["dev/patch 42"]);
  });

  test("주소 매칭에서도 캡처된다", () => {
    const r = runSieve(`${R} if address :matches "from" "*@*" { fileinto "\${2}"; }`, env());
    expect(r.fileinto).toEqual(["example.com"]);
  });

  test("가장 최근 매칭이 이긴다", () => {
    const script =
      `${R} if header :matches "subject" "Re: [*] *" { set "first" "\${1}"; }` +
      ` if address :matches "from" "*@*" { fileinto "\${first}-\${1}"; }`;
    expect(runSieve(script, env()).fileinto).toEqual(["dev-alice"]);
  });

  test("매칭이 실패하면 이전 캡처가 남는다", () => {
    const script =
      `${R} if header :matches "subject" "Re: [*] *" { set "x" "\${1}"; }` +
      ` if header :matches "subject" "nope-*" { set "y" "hit"; }` +
      ` fileinto "\${x}";`;
    expect(runSieve(script, env()).fileinto).toEqual(["dev"]);
  });

  /** 캡처 값을 다시 패턴으로 쓸 때 `:quotewildcard`가 필요한 이유를 보인다. */
  test("캡처를 :quotewildcard로 감싸 패턴 주입을 막는다", () => {
    const e = env({ headers: new Map([["subject", ["evil*star"]]]) });
    const script =
      `${R} if header :matches "subject" "*" { set :quotewildcard "s" "\${1}"; }` +
      ` if string :matches "\${s}" "evil*star" { fileinto "LITERAL"; }`;
    // 이스케이프된 값은 리터럴 `*`를 뜻하므로 `evil*star` 패턴에 정확히 걸린다
    expect(runSieve(script, e).fileinto).toEqual(["LITERAL"]);
  });
});

describe("string 테스트 (§5)", () => {
  test("변수 값을 비교한다", () => {
    expect(runSieve(`${R} set "a" "hello"; if string :is "\${a}" "hello" { fileinto "HIT"; }`, env()).fileinto).toEqual(["HIT"]);
    expect(runSieve(`${R} set "a" "hello"; if string :contains "\${a}" "ell" { fileinto "HIT"; }`, env()).fileinto).toEqual(["HIT"]);
    expect(runSieve(`${R} set "a" "hello"; if string :is "\${a}" "nope" { fileinto "HIT"; }`, env()).fileinto).toEqual([]);
  });

  test("relational과 함께", () => {
    const script =
      'require ["variables","relational","comparator-i;ascii-numeric","fileinto"];' +
      ' set "n" "42"; if string :value "gt" :comparator "i;ascii-numeric" "${n}" "10" { fileinto "HIT"; }';
    expect(runSieve(script, env()).fileinto).toEqual(["HIT"]);
  });

  test("키가 없으면 SieveError", () => {
    expect(() => runSieve(`${R} if string :is "x" { keep; }`, env())).toThrow(SieveError);
  });
});

describe("include와 함께", () => {
  /** ★변수는 include된 스크립트와 **공유한다**(RFC 6609 §3.2: 하나의 스크립트처럼 동작). */
  test("include된 스크립트가 같은 변수를 본다", () => {
    const e = env({ scripts: new Map([["child", 'require ["variables","fileinto"]; fileinto "${box}";']]) });
    const r = runSieve('require ["variables","include","fileinto"]; set "box" "Shared"; include "child";', e);
    expect(r.fileinto).toEqual(["Shared"]);
  });

  test("include된 스크립트가 설정한 변수를 바깥이 본다", () => {
    const e = env({ scripts: new Map([["child", 'require ["variables"]; set "box" "FromChild";']]) });
    const r = runSieve('require ["variables","include","fileinto"]; include "child"; fileinto "${box}";', e);
    expect(r.fileinto).toEqual(["FromChild"]);
  });
});
