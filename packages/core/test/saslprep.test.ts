/**
 * SASLprep(RFC 4013) — 비밀번호 정규화. 예시는 RFC 4013 §3의 표 그대로다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { saslprep } from "../src/saslprep.ts";

describe("saslprep (RFC 4013 \u00A73 예시)", () => {
  test("ASCII는 그대로다", () => {
    expect(saslprep("user", "stored")).toBe("user");
    expect(saslprep("USER", "stored")).toBe("USER");
  });
  test("보통 지우는 문자(SOFT HYPHEN)는 사라진다", () => {
    expect(saslprep("I\u00ADX", "stored")).toBe("IX");
  });
  test("호환 문자는 NFKC로 접힌다", () => {
    expect(saslprep("\u00AA", "stored")).toBe("a");
    expect(saslprep("\u2168", "stored")).toBe("IX");
  });
  test("ASCII가 아닌 공백은 U+0020이 된다", () => {
    expect(saslprep("a\u00A0b", "stored")).toBe("a b");
  });
  test("제어 문자는 금지다", () => {
    expect(saslprep("\u0007", "stored")).toBeNull();
    expect(saslprep("a\u0000b", "query")).toBeNull();
  });
  test("양방향 규칙 위반(RandAL 뒤에 다른 방향 끝)은 금지다", () => {
    expect(saslprep("\u06271", "stored")).toBeNull();
    expect(saslprep("\u06271\u0628", "stored")).toBe("\u06271\u0628");
  });
  test("한글은 NFKC 그대로 통과한다(조합형은 완성형으로)", () => {
    expect(saslprep("비밀번호", "stored")).toBe("비밀번호");
    expect(saslprep("\u1100\u1161", "stored")).toBe("가");
  });
  test("미할당 코드포인트는 저장용에서만 금지다", () => {
    expect(saslprep("a\u{E0080}", "query")).not.toBeNull();
    expect(saslprep("a\u{E0080}", "stored")).toBeNull();
  });
});
