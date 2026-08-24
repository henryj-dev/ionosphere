/**
 * IMAP SEARCH는 **부분 문자열**이다 (RFC 9051 §6.4.4) — 2026-08-24 결정을 지키는 테스트.
 *
 * ★이 파일이 있는 이유: `search_index`(단어/바이그램 토큰)를 선필터로 쓰고 싶어지는 유혹이
 * 반복해서 생긴다. 색인은 `oo`로 `foo`를 찾지 못하므로 선필터로 쓰면 **거짓 음성**이 생기고,
 * 그건 성능 최적화가 아니라 정확성 회귀다. 아래가 깨지면 그 회귀가 들어온 것이다.
 *
 * 상세한 근거는 `search-criteria.ts` 머리 주석에 있다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { evaluateSearch, parseSearchProgram } from "../src/search-criteria.ts";
import type { ImapValue } from "../src/parser.ts";

const enc = new TextEncoder();

const RAW = enc.encode(
  ["From: alice@x.test", "To: bob@y.test", "Subject: about foobar", "", "the word is foobar and 안녕하세요 반갑습니다", ""].join("\r\n"),
);

/** `"..."`로 감싼 것은 quoted 값, 나머지는 atom — 파서가 보는 것과 같은 모양으로 만든다. */
function values(...parts: string[]): ImapValue[] {
  return parts.map((p) =>
    p.startsWith('"') && p.endsWith('"')
      ? ({ kind: "quoted", value: p.slice(1, -1) } as ImapValue)
      : ({ kind: "atom", value: p } as ImapValue),
  );
}

/** `SEARCH <criteria>`가 이 메시지를 매치하는가. */
function matches(...parts: string[]): boolean {
  const program = parseSearchProgram(values(...parts));
  if (!program.ok) throw new Error(`parse failed: ${parts.join(" ")}`);
  return evaluateSearch(program.key, { seq: 1, uid: 1, flags: [], size: RAW.length, internalDateMs: 0, modseq: 1, raw: RAW }, 1, 1);
}

describe("BODY/TEXT는 부분 문자열이다", () => {
  /** ★핵심 — 토큰 경계에 걸리지 않는 조각도 매치해야 한다. 색인으로는 이게 안 된다. */
  test("단어 중간의 조각이 매치된다", () => {
    expect(matches("BODY", '"oo"')).toBe(true); // foobar 안의 "oo"
    expect(matches("BODY", '"ooba"')).toBe(true);
    expect(matches("BODY", '"bar"')).toBe(true); // 접미사
  });

  test("온전한 단어도 당연히 매치된다", () => {
    expect(matches("BODY", '"foobar"')).toBe(true);
  });

  test("없는 조각은 매치되지 않는다", () => {
    expect(matches("BODY", '"quux"')).toBe(false);
  });

  test("대소문자를 구분하지 않는다", () => {
    expect(matches("BODY", '"FOOBAR"')).toBe(true);
  });

  /** CJK도 같다 — 바이그램 경계와 무관하게 걸려야 한다(색인은 2글자 토큰으로 자른다). */
  test("CJK도 부분 문자열이다", () => {
    expect(matches("BODY", '"안녕하세요"')).toBe(true);
    expect(matches("BODY", '"녕하세"')).toBe(true); // 바이그램 경계를 가로지르는 3글자
  });

  /** BODY는 헤더를 보지 않고 TEXT는 본다 — 부분 문자열 성질은 둘 다 같다. */
  test("BODY는 헤더를 보지 않고 TEXT는 본다", () => {
    expect(matches("BODY", '"alice"')).toBe(false); // From 헤더에만 있다
    expect(matches("TEXT", '"alice"')).toBe(true);
    expect(matches("TEXT", '"lic"')).toBe(true); // TEXT도 부분 문자열
  });

  /** HEADER 검색도 부분 문자열이다(§6.4.4). */
  test("HEADER도 부분 문자열", () => {
    expect(matches("HEADER", "SUBJECT", '"oobar"')).toBe(true);
  });
});
