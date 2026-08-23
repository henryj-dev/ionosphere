import { describe, expect, test } from "@ionosphere/testkit";
import { tokenize, tokenizeQuery } from "../src/tokenize.ts";

describe("tokenize (SCHEMA.md §8: NFKC → casefold → CJK 바이그램 + 라틴 단어)", () => {
  test("CJK 런: 2자 슬라이딩 윈도 바이그램", () => {
    expect(new Set(tokenize("안녕하세요"))).toEqual(new Set(["안녕", "녕하", "하세", "세요"]));
  });

  test("CJK 런 길이 2: 바이그램 1개", () => {
    expect(tokenize("하나")).toEqual(["하나"]);
  });

  test("단일 CJK 글자: 1-gram으로 방출", () => {
    expect(tokenize("가")).toEqual(["가"]);
  });

  test("혼합 CJK+라틴: 런 단위로 분리", () => {
    const tokens = new Set(tokenize("hello 세계"));
    expect(tokens).toEqual(new Set(["hello", "세계"]));
  });

  test("라틴 단어는 소문자화", () => {
    expect(tokenize("Hello World")).toEqual(expect.arrayContaining(["hello", "world"]));
    expect(tokenize("Hello World")).toHaveLength(2);
  });

  test("NFKC 정규화: 전각 라틴 → 반각", () => {
    expect(tokenize("ＡＢＣ")).toEqual(["abc"]);
  });

  test("중복 제거", () => {
    expect(tokenize("test test test")).toEqual(["test"]);
  });

  test("라틴 단어 VARCHAR(16) 절단", () => {
    const long = "a".repeat(20);
    const tokens = tokenize(long);
    expect(tokens).toHaveLength(1);
    expect(tokens[0]).toHaveLength(16);
    expect(tokens[0]).toBe("a".repeat(16));
  });

  test("빈 문자열 → 빈 토큰 목록", () => {
    expect(tokenize("")).toEqual([]);
    expect(tokenize("   ")).toEqual([]);
  });

  test("tokenizeQuery는 tokenize와 동일 규칙", () => {
    expect(tokenizeQuery("회의 안내")).toEqual(tokenize("회의 안내"));
  });
});

describe("토크나이저 입력 상한 (CJK 바이그램 증폭 방어)", () => {
  // 상한 없을 때 25MB 한글 본문 = 토큰 8058394개 · RSS 1.3GB · search_index 1,169.7MB(둘 다 실측).
  // 전 프로토콜이 한 프로세스라 OOM이 곧 서비스 전체 중단이었다.
  const MAX_INDEX_TEXT_CHARS = 64 * 1024;

  /**
   * 난수 한글 음절 n개 — 중복 제거가 듣지 않는 최악 입력(공격자가 만들 수 있다).
   * 단순 증가(i % 11172)로는 바이그램이 11172개에서 순환해 상한이 걸렸는지 구분되지 않는다.
   * 음절 조합이 11172^2가지라 난수 나열이면 바이그램이 입력 길이만큼 나온다.
   */
  function randomHangul(n: number): string {
    let seed = 12345;
    const out: string[] = [];
    for (let i = 0; i < n; i++) {
      seed = (seed + 0x9e3779b9) | 0; // splitmix32 — 하위 비트 편향이 없어야 음절이 고르게 퍼진다
      let z = seed;
      z = Math.imul(z ^ (z >>> 16), 0x21f0aaad);
      z = Math.imul(z ^ (z >>> 15), 0x735a2d97);
      z = (z ^ (z >>> 15)) >>> 0;
      out.push(String.fromCodePoint(0xac00 + (z % 11172)));
    }
    return out.join("");
  }

  test("거대 CJK 본문은 상한에서 멈춘다 — 토큰 수가 입력에 비례해 폭발하지 않는다", () => {
    const huge = randomHangul(MAX_INDEX_TEXT_CHARS * 4);
    const tokens = tokenize(huge);
    // 바이그램은 n글자에서 n-1개 → 상한 이하여야 한다
    expect(tokens.length).toBeLessThanOrEqual(MAX_INDEX_TEXT_CHARS);
    // 상한이 실제로 걸렸는지(무상한이면 4배가 나온다)
    expect(tokens.length).toBeGreaterThan(MAX_INDEX_TEXT_CHARS / 2);
  });

  test("색인은 상한 초과에도 throw하지 않는다 — 메일 저장·배달을 막으면 안 된다", () => {
    expect(() => tokenize(randomHangul(MAX_INDEX_TEXT_CHARS * 4))).not.toThrow();
  });

  test("상한 이내 본문의 앞부분은 그대로 색인된다", () => {
    const body = `회의 안내 ${"가".repeat(10)}`;
    expect(new Set(tokenize(body))).toContain("회의");
  });

  test("정상 한국어 검색은 그대로 동작한다", () => {
    const tokens = tokenizeQuery("회의 안내");
    expect(new Set(tokens)).toEqual(new Set(["회의", "안내"]));
  });

  test("과도하게 긴 질의는 토큰화 전에 거부된다(조용히 자르면 더 넓게 매칭돼 위험)", () => {
    expect(() => tokenizeQuery(randomHangul(4097))).toThrow(/too long/);
  });

  test("상한 이내 질의는 통과한다", () => {
    expect(() => tokenizeQuery(randomHangul(4096))).not.toThrow();
  });
});
