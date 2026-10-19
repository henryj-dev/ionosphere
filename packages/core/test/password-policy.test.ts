/**
 * 공통 비밀번호 규칙(2026-10-18 결정 1) — 8자 이상, 영소문자·영대문자·숫자·그 밖의 문자 4종 가운데 3종 이상.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { checkPasswordPolicy } from "../src/password-policy.ts";

describe("checkPasswordPolicy", () => {
  test("8자 미만은 거절", () => {
    expect(checkPasswordPolicy("Ab1!xyz")).toMatchObject({ ok: false, reason: "too_short" });
  });
  test("3종 미만은 거절", () => {
    expect(checkPasswordPolicy("abcdefgh")).toMatchObject({ ok: false, reason: "too_few_classes" });
    expect(checkPasswordPolicy("abcdEFGH")).toMatchObject({ ok: false, reason: "too_few_classes" });
  });
  test("3종이면 통과(어느 조합이든)", () => {
    expect(checkPasswordPolicy("abcdEF12").ok).toBe(true);
    expect(checkPasswordPolicy("abcd12!!").ok).toBe(true);
    expect(checkPasswordPolicy("ABCD12!!").ok).toBe(true);
  });
  test("공백·한글은 특수문자 종류로 센다", () => {
    expect(checkPasswordPolicy("abcd 1234").ok).toBe(true);
    expect(checkPasswordPolicy("비밀번호abcd12").ok).toBe(true);
  });
  test("최대 길이는 없다", () => {
    expect(checkPasswordPolicy("Aa1" + "x".repeat(10_000)).ok).toBe(true);
  });
  test("길이는 정규화 뒤 코드포인트 수다(지우는 문자는 세지 않는다)", () => {
    expect(checkPasswordPolicy("Ab1­­­­­!").ok).toBe(false);
  });
  test("제어 문자가 섞이면 거절", () => {
    expect(checkPasswordPolicy("Abcd1234\u0007")).toMatchObject({ ok: false, reason: "invalid_characters" });
  });
});
