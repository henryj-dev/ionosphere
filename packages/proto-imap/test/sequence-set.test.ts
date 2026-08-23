/** sequence-set 파싱/매칭/정규화 테스트 (RFC 9051 §9). */
import { describe, expect, test } from "@ionosphere/testkit";
import { matchSequenceSet, normalizeRanges, parseSequenceSet } from "../src/sequence-set.ts";

describe("parseSequenceSet", () => {
  test("단일/범위/별표/혼합", () => {
    expect(parseSequenceSet("7")).toEqual([{ from: 7, to: 7 }]);
    expect(parseSequenceSet("2:4")).toEqual([{ from: 2, to: 4 }]);
    expect(parseSequenceSet("*")).toEqual([{ from: "*", to: "*" }]);
    expect(parseSequenceSet("4:*")).toEqual([{ from: 4, to: "*" }]);
    expect(parseSequenceSet("1,3:5,9,*")).toEqual([
      { from: 1, to: 1 },
      { from: 3, to: 5 },
      { from: 9, to: 9 },
      { from: "*", to: "*" },
    ]);
  });

  test("불량 입력 → null", () => {
    for (const bad of ["", "0", "1:", ":5", "a", "1,,2", "1:2:3", "-1", "1 :2"]) {
      expect(parseSequenceSet(bad)).toBeNull();
    }
  });
});

describe("matchSequenceSet", () => {
  test("* 해석 — max 주입", () => {
    const set = parseSequenceSet("*")!;
    expect(matchSequenceSet(set, 10, 10)).toBe(true);
    expect(matchSequenceSet(set, 9, 10)).toBe(false);
  });

  test("역순 범위 정규화 — 12:5 == 5:12", () => {
    const set = parseSequenceSet("12:5")!;
    expect(matchSequenceSet(set, 7, 100)).toBe(true);
    expect(matchSequenceSet(set, 4, 100)).toBe(false);
  });

  test("4:*에서 max<4 — RFC: 4:* == *:4 == max:4", () => {
    const set = parseSequenceSet("4:*")!;
    expect(matchSequenceSet(set, 2, 2)).toBe(true); // max=2 → 2:4 범위
    expect(matchSequenceSet(set, 1, 2)).toBe(false);
  });
});

describe("normalizeRanges", () => {
  test("정렬 + 병합(인접 포함)", () => {
    const set = parseSequenceSet("9,1:3,4:6,20")!;
    expect(normalizeRanges(set, 100)).toEqual([
      [1, 6],
      [9, 9],
      [20, 20],
    ]);
  });

  test("* 해석 후 병합", () => {
    const set = parseSequenceSet("1:5,8:*")!;
    expect(normalizeRanges(set, 10)).toEqual([
      [1, 5],
      [8, 10],
    ]);
  });

  test("빈 메일함(max=0)에서 * 구간 제외", () => {
    expect(normalizeRanges(parseSequenceSet("*")!, 0)).toEqual([]);
    expect(normalizeRanges(parseSequenceSet("1:*")!, 0)).toEqual([]);
  });
});
