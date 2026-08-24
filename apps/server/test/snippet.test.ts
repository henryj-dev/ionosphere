/**
 * `SearchSnippet/get`의 조각 만들기 — 출력이 **HTML**이라 이스케이프가 이 파일의 절반이다.
 *
 * ★원문은 남이 보낸 메일의 제목과 본문이고, 그게 그대로 클라이언트의 DOM에 들어간다.
 * 이스케이프를 빠뜨리면 메일 한 통으로 스크립트가 실행된다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { buildSnippet, escapeHtml, snippetTermsFromFilter } from "../src/snippet.ts";

describe("HTML 이스케이프", () => {
  test("특수문자를 전부 바꾼다", () => {
    expect(escapeHtml(`<a href="x">&'`)).toBe("&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
  });

  /** `&`를 가장 먼저 바꾸지 않으면 `&lt;`가 다시 `&amp;lt;`가 된다. */
  test("이중 이스케이프가 생기지 않는다", () => {
    expect(escapeHtml("<")).toBe("&lt;");
    expect(escapeHtml("&lt;")).toBe("&amp;lt;");
  });
});

describe("조각 만들기", () => {
  test("매치를 <mark>로 감싼다", () => {
    expect(buildSnippet("hello world", ["world"])).toBe("hello <mark>world</mark>");
  });

  test("대소문자를 구분하지 않고 원문 표기를 유지한다", () => {
    expect(buildSnippet("Hello World", ["world"])).toBe("Hello <mark>World</mark>");
  });

  /** ★조각은 **부분 문자열**로 찾는다 — 토큰 경계로 찾으면 `foobar` 안의 `foo`를 못 보여 준다. */
  test("단어 중간의 매치도 표시한다", () => {
    expect(buildSnippet("a foobar b", ["oob"])).toBe("a f<mark>oob</mark>ar b");
  });

  test("창 안의 매치를 전부 표시한다", () => {
    expect(buildSnippet("cat and cat", ["cat"])).toBe("<mark>cat</mark> and <mark>cat</mark>");
  });

  /**
   * ★핵심 — **이스케이프 먼저, 마크 나중**이다. 반대로 하면 우리가 넣은 `<mark>`까지
   * 이스케이프돼 화면에 `&lt;mark&gt;`가 보인다.
   */
  test("원문의 태그는 이스케이프되고 우리 mark는 살아 있다", () => {
    const out = buildSnippet('<script>alert(1)</script> secret', ["secret"]);
    expect(out).toBe("&lt;script&gt;alert(1)&lt;/script&gt; <mark>secret</mark>");
    expect(out!.includes("<script>")).toBe(false);
  });

  /** 매치 자체에 특수문자가 있어도 이스케이프된다 — mark 안이라고 예외가 아니다. */
  test("매치 안의 특수문자도 이스케이프된다", () => {
    expect(buildSnippet("x <b> y", ["<b>"])).toBe("x <mark>&lt;b&gt;</mark> y");
  });

  /** §5 — 매치가 없는 부분은 빈 문자열이 아니라 null이다(빈 제목으로 읽히면 안 된다). */
  test("매치가 없으면 null", () => {
    expect(buildSnippet("hello", ["nope"])).toBe(null);
    expect(buildSnippet(null, ["x"])).toBe(null);
    expect(buildSnippet("hello", [])).toBe(null);
  });

  test("긴 본문은 첫 매치 주위로 자르고 말줄임을 붙인다", () => {
    const long = "a".repeat(500) + "NEEDLE" + "b".repeat(500);
    const out = buildSnippet(long, ["needle"])!;
    expect(out.includes("<mark>NEEDLE</mark>")).toBe(true);
    expect(out.startsWith("…")).toBe(true);
    expect(out.endsWith("…")).toBe(true);
    expect(out.length).toBeLessThan(400); // 창 상한 + 마크업
  });

  test("짧은 본문에는 말줄임이 없다", () => {
    expect(buildSnippet("hi there", ["hi"])).toBe("<mark>hi</mark> there");
  });

  test("여러 항이면 가장 앞선 매치를 기준으로 삼는다", () => {
    expect(buildSnippet("alpha beta", ["beta", "alpha"])).toBe("<mark>alpha</mark> <mark>beta</mark>");
  });
});

describe("필터에서 검색어 뽑기", () => {
  test("text/subject/body만 본다", () => {
    expect(snippetTermsFromFilter({ text: "Foo", subject: "Bar", inMailbox: "m1" })).toEqual(["foo", "bar"]);
  });

  /** 구조 조건만 있으면 표시할 글자가 없다 — 조각은 전부 null이 된다. */
  test("구조 조건만이면 빈 목록", () => {
    expect(snippetTermsFromFilter({ inMailbox: "m1", hasKeyword: "$seen" })).toEqual([]);
  });

  /** ★빈 문자열은 버린다 — 모든 위치에 매치돼 본문 전체가 <mark>가 된다. */
  test("빈 문자열·공백은 버린다", () => {
    expect(snippetTermsFromFilter({ text: "", subject: "   " })).toEqual([]);
    expect(buildSnippet("hello", snippetTermsFromFilter({ text: "" }))).toBe(null);
  });

  test("중복은 한 번만", () => {
    expect(snippetTermsFromFilter({ text: "x", subject: "X" })).toEqual(["x"]);
  });

  test("필터가 없거나 객체가 아니면 빈 목록", () => {
    expect(snippetTermsFromFilter(undefined)).toEqual([]);
    expect(snippetTermsFromFilter(null)).toEqual([]);
    expect(snippetTermsFromFilter(["x"])).toEqual([]);
  });
});
