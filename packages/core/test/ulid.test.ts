import { describe, expect, test } from "@ionosphere/testkit";
import { isUlid, ulid } from "@ionosphere/core";

describe("ulid", () => {
  test("26자 Crockford base32", () => {
    const id = ulid();
    expect(id).toHaveLength(26);
    expect(isUlid(id)).toBe(true);
    expect(id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
  });

  test("같은 ms 내 단조 증가", () => {
    const now = Date.now();
    const ids = Array.from({ length: 1000 }, () => ulid(now));
    const sorted = [...ids].sort();
    expect(ids).toEqual(sorted);
    expect(new Set(ids).size).toBe(1000);
  });

  test("시간 순서 정렬 (ms 경계)", () => {
    const a = ulid(1_000_000_000_000);
    const b = ulid(1_000_000_000_001);
    expect(a < b).toBe(true);
  });

  test("isUlid 거부 케이스", () => {
    expect(isUlid("")).toBe(false);
    expect(isUlid("I".repeat(26))).toBe(false); // I는 Crockford 제외 문자
    expect(isUlid(ulid() + "0")).toBe(false);
  });
});
