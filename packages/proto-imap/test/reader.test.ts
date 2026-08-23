/** ImapLineReader — 리터럴 인식 논리 라인 조립 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { ImapLineReader, type ReaderEvent } from "../src/reader.ts";

const enc = new TextEncoder();

function feedAll(reader: ImapLineReader, ...chunks: string[]): ReaderEvent[] {
  const events: ReaderEvent[] = [];
  for (const c of chunks) events.push(...reader.feed(enc.encode(c)));
  return events;
}

function textOf(ev: ReaderEvent): string {
  if (ev.kind !== "line") throw new Error(`expected line, got ${ev.kind}`);
  return ev.parts.map((p) => (p.kind === "text" ? p.text : `<LIT:${p.bytes.length}>`)).join("");
}

describe("ImapLineReader — 기본 라인", () => {
  test("단일 라인 완성", () => {
    const events = feedAll(new ImapLineReader(), "a1 NOOP\r\n");
    expect(events).toHaveLength(1);
    expect(textOf(events[0]!)).toBe("a1 NOOP");
  });

  test("분할 도착(바이트 단위) — 한 라인으로 조립", () => {
    const reader = new ImapLineReader();
    const events: ReaderEvent[] = [];
    for (const ch of "a2 CAPABILITY\r\n") events.push(...reader.feed(enc.encode(ch)));
    expect(events).toHaveLength(1);
    expect(textOf(events[0]!)).toBe("a2 CAPABILITY");
  });

  test("한 청크에 여러 라인", () => {
    const events = feedAll(new ImapLineReader(), "a1 NOOP\r\na2 NOOP\r\n");
    expect(events.map(textOf)).toEqual(["a1 NOOP", "a2 NOOP"]);
  });

  test("LF만 있는 종결도 수용(관용)", () => {
    const events = feedAll(new ImapLineReader(), "a1 NOOP\n");
    expect(textOf(events[0]!)).toBe("a1 NOOP");
  });
});

describe("ImapLineReader — 리터럴", () => {
  test("sync 리터럴: continue 이벤트 후 데이터+잔여 라인", () => {
    const reader = new ImapLineReader();
    const first = feedAll(reader, "a1 LOGIN {5}\r\n");
    expect(first).toEqual([{ kind: "continue", size: 5 }]);
    const second = feedAll(reader, "alice {6}\r\n");
    expect(second).toEqual([{ kind: "continue", size: 6 }]);
    const third = feedAll(reader, "secret\r\n");
    expect(third).toHaveLength(1);
    const line = third[0]!;
    expect(line.kind).toBe("line");
    if (line.kind !== "line") return;
    expect(line.parts).toEqual([
      { kind: "text", text: "a1 LOGIN " },
      { kind: "literal", bytes: enc.encode("alice") },
      { kind: "text", text: " " },
      { kind: "literal", bytes: enc.encode("secret") },
      { kind: "text", text: "" },
    ]);
  });

  test("non-sync 리터럴({n+}): continue 없이 바로 데이터", () => {
    const events = feedAll(new ImapLineReader(), "a1 LOGIN {5+}\r\nalice pw\r\n");
    expect(events).toHaveLength(1);
    const line = events[0]!;
    if (line.kind !== "line") throw new Error("expected line");
    expect(line.parts[1]).toEqual({ kind: "literal", bytes: enc.encode("alice") });
    expect(line.parts[2]).toEqual({ kind: "text", text: " pw" });
  });

  test("리터럴 내용의 CRLF는 라인 경계로 취급하지 않음", () => {
    const reader = new ImapLineReader();
    feedAll(reader, "a1 APPEND INBOX {12+}\r\n");
    const events = feedAll(reader, "line1\r\nline2\r\n");
    expect(events).toHaveLength(1);
    const line = events[0]!;
    if (line.kind !== "line") throw new Error("expected line");
    expect(line.parts[1]).toEqual({ kind: "literal", bytes: enc.encode("line1\r\nline2") });
  });

  test("리터럴 자체가 분할 도착해도 조립", () => {
    const reader = new ImapLineReader();
    feedAll(reader, "a1 X {10+}\r\n", "01234");
    const events = feedAll(reader, "56789\r\n");
    expect(events).toHaveLength(1);
    const line = events[0]!;
    if (line.kind !== "line") throw new Error("expected line");
    expect(line.parts[1]).toEqual({ kind: "literal", bytes: enc.encode("0123456789") });
  });
});

describe("ImapLineReader — 한도 방어", () => {
  test("sync 리터럴 상한 초과 → 즉시 error, 데이터 수신 없이 다음 명령 정상", () => {
    const reader = new ImapLineReader({ maxLiteralBytes: 100 });
    const events = feedAll(reader, "a1 APPEND INBOX {5000}\r\n");
    expect(events).toEqual([{ kind: "error", message: "literal too large" }]);
    const next = feedAll(reader, "a2 NOOP\r\n");
    expect(textOf(next[0]!)).toBe("a2 NOOP");
  });

  test("non-sync 리터럴 상한 초과 → 데이터를 소비해 버린 뒤 error, 경계 유지", () => {
    const reader = new ImapLineReader({ maxNonSyncLiteralBytes: 4 });
    const events = feedAll(reader, "a1 X {10+}\r\n0123456789\r\na2 NOOP\r\n");
    expect(events[0]).toEqual({ kind: "error", message: "literal too large" });
    expect(textOf(events[1]!)).toBe("a2 NOOP");
  });

  test("라인 길이 상한 초과 → error 후 다음 라인 정상", () => {
    const reader = new ImapLineReader({ maxLineBytes: 16 });
    const events = feedAll(reader, `a1 X ${"y".repeat(100)}\r\na2 NOOP\r\n`);
    expect(events[0]).toEqual({ kind: "error", message: "line too long" });
    expect(textOf(events[1]!)).toBe("a2 NOOP");
  });

  test("CRLF 없이 폭주하는 라인도 상한에서 폐기 모드 진입 후 복구", () => {
    const reader = new ImapLineReader({ maxLineBytes: 16 });
    expect(feedAll(reader, "z".repeat(50))).toEqual([]);
    expect(feedAll(reader, "z".repeat(50))).toEqual([]);
    const events = feedAll(reader, "zzz\r\na2 NOOP\r\n");
    expect(events[0]).toEqual({ kind: "error", message: "line too long" });
    expect(textOf(events[1]!)).toBe("a2 NOOP");
  });
});
