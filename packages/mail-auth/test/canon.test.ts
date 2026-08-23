import { describe, expect, test } from "@ionosphere/testkit";
import { canonBody, canonHeaderField, parseHeaderFields, splitMessage } from "../src/canon.ts";

// RFC 6376 §3.4.5 예시 메시지 (헤더는 "A: X" / "B : Y\t<fold>\tZ  ", 본문은 " C \r\nD \t E\r\n\r\n\r\n").
const HEADER_BLOCK = "A: X\r\nB : Y\t\r\n\tZ  ";
const BODY = " C \r\nD \t E\r\n\r\n\r\n";
const RAW = `${HEADER_BLOCK}\r\n\r\n${BODY}`;

describe("splitMessage — RFC 6376 §3.4.5 예시", () => {
  test("헤더 블록/본문 분리", () => {
    const { headerBlock, body } = splitMessage(RAW);
    expect(headerBlock).toBe(HEADER_BLOCK);
    expect(body).toBe(BODY);
  });
});

describe("canonHeaderField — RFC 6376 §3.4.5 예시", () => {
  test("relaxed: a:X / b:Y Z", () => {
    const fields = parseHeaderFields(HEADER_BLOCK);
    expect(fields).toHaveLength(2);
    const [a, b] = fields;
    expect(canonHeaderField(a!, "relaxed")).toBe("a:X\r\n");
    expect(canonHeaderField(b!, "relaxed")).toBe("b:Y Z\r\n");
  });

  test("simple: 원문 그대로 + CRLF", () => {
    const fields = parseHeaderFields(HEADER_BLOCK);
    const [a, b] = fields;
    expect(canonHeaderField(a!, "simple")).toBe("A: X\r\n");
    expect(canonHeaderField(b!, "simple")).toBe("B : Y\t\r\n\tZ  \r\n");
  });
});

describe("canonBody — RFC 6376 §3.4.5 예시", () => {
  test("relaxed: 줄 끝 WSP 제거 + 내부 WSP 압축 + 끝 빈 줄 제거", () => {
    expect(canonBody(BODY, "relaxed")).toBe(" C\r\nD E\r\n");
  });

  test("simple: 끝 빈 줄만 제거, 내부 공백은 무변경", () => {
    expect(canonBody(BODY, "simple")).toBe(" C \r\nD \t E\r\n");
  });

  test("relaxed 완전 빈 본문 → 빈 문자열", () => {
    expect(canonBody("", "relaxed")).toBe("");
    expect(canonBody("\r\n\r\n", "relaxed")).toBe("");
  });

  test("simple 완전 빈 본문 → CRLF 한 줄", () => {
    expect(canonBody("", "simple")).toBe("\r\n");
    expect(canonBody("\r\n\r\n", "simple")).toBe("\r\n");
  });

  test("트레일링 CRLF 없는 본문에는 CRLF가 추가된다", () => {
    expect(canonBody("hello", "simple")).toBe("hello\r\n");
    expect(canonBody("hello", "relaxed")).toBe("hello\r\n");
  });
});
