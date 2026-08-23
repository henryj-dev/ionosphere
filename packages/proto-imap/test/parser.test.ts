/** IMAP 값/명령 파서 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import type { LinePart } from "../src/reader.ts";
import { ImapParseError, parseCommand, parseValues, valueText } from "../src/parser.ts";

const enc = new TextEncoder();

function text(t: string): LinePart {
  return { kind: "text", text: t };
}

describe("parseCommand — envelope", () => {
  test("tag + 명령명(대문자 정규화) + 인자", () => {
    const cmd = parseCommand([text("a1 login alice secret")]);
    expect(cmd.tag).toBe("a1");
    expect(cmd.name).toBe("LOGIN");
    expect(cmd.args).toEqual([
      { kind: "atom", value: "alice" },
      { kind: "atom", value: "secret" },
    ]);
  });

  test("quoted 인자 — 이스케이프 해제", () => {
    const cmd = parseCommand([text('a1 LOGIN "al ice" "p\\"w\\\\d"')]);
    expect(cmd.args).toEqual([
      { kind: "quoted", value: "al ice" },
      { kind: "quoted", value: 'p"w\\d' },
    ]);
  });

  test("리터럴 인자 — 바이트 보존", () => {
    const cmd = parseCommand([text("a1 LOGIN "), { kind: "literal", bytes: enc.encode("alice") }, text(" pw")]);
    expect(cmd.args[0]).toEqual({ kind: "literal", bytes: enc.encode("alice") });
    expect(valueText(cmd.args[0]!)).toBe("alice");
    expect(cmd.args[1]).toEqual({ kind: "atom", value: "pw" });
  });

  test("괄호 리스트 — 중첩 + 리터럴 혼합", () => {
    const cmd = parseCommand([
      text("a1 FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (From To)] ("),
      { kind: "literal", bytes: enc.encode("x") },
      text("))"),
    ]);
    expect(cmd.name).toBe("FETCH");
    expect(cmd.args[0]).toEqual({ kind: "atom", value: "1:*" });
    const list = cmd.args[1]!;
    if (list.kind !== "list") throw new Error("expected list");
    expect(list.items[0]).toEqual({ kind: "atom", value: "FLAGS" });
    // `[`/`]`는 atom 문자로 수용 — FETCH 섹션은 핸들러에서 상세 파싱
    expect(list.items[1]).toEqual({ kind: "atom", value: "BODY.PEEK[HEADER.FIELDS" });
    expect(list.items[3]).toEqual({ kind: "atom", value: "]" }); // 닫는 대괄호도 atom으로 수용
    const inner = list.items[4]!;
    if (inner.kind !== "list") throw new Error("expected inner list");
    expect(inner.items[0]).toEqual({ kind: "literal", bytes: enc.encode("x") });
  });

  test("STATUS 형태 — 메일함명 + 옵션 리스트", () => {
    const cmd = parseCommand([text('a1 STATUS "My Box" (UIDNEXT MESSAGES)')]);
    expect(cmd.args).toEqual([
      { kind: "quoted", value: "My Box" },
      { kind: "list", items: [{ kind: "atom", value: "UIDNEXT" }, { kind: "atom", value: "MESSAGES" }] },
    ]);
  });

  test("빈 리스트 ()", () => {
    const cmd = parseCommand([text("a1 X ()")]);
    expect(cmd.args).toEqual([{ kind: "list", items: [] }]);
  });

  test("tag 없음/이상 → ImapParseError", () => {
    expect(() => parseCommand([text("")])).toThrow(ImapParseError);
    expect(() => parseCommand([text('"quoted" NOOP')])).toThrow(ImapParseError);
    expect(() => parseCommand([text("a+1 NOOP")])).toThrow(ImapParseError); // tag에 '+' 금지
    expect(() => parseCommand([text("a1")])).toThrow(ImapParseError); // 명령명 없음
  });

  test("깨진 구문 → ImapParseError", () => {
    expect(() => parseValues([text('a1 X "unterminated')])).toThrow(ImapParseError);
    expect(() => parseValues([text("a1 X (unclosed")])).toThrow(ImapParseError);
    expect(() => parseValues([text('a1 X "bad\\escape"')])).toThrow(ImapParseError);
  });
});

describe("parseValues — 값 파서 세부", () => {
  test("NIL은 그냥 atom — 해석은 엔진 소관", () => {
    expect(parseValues([text("NIL")])).toEqual([{ kind: "atom", value: "NIL" }]);
  });

  test("플래그(\\ + atom) 프로덕션 — STORE/APPEND 플래그 리스트", () => {
    expect(parseValues([text("(\\Seen \\Deleted $Fwd)")])).toEqual([
      {
        kind: "list",
        items: [
          { kind: "atom", value: "\\Seen" },
          { kind: "atom", value: "\\Deleted" },
          { kind: "atom", value: "$Fwd" },
        ],
      },
    ]);
  });

  test("연속 공백 무시", () => {
    expect(parseValues([text("a   b")])).toEqual([
      { kind: "atom", value: "a" },
      { kind: "atom", value: "b" },
    ]);
  });
});
