/**
 * IMAP 명령 파서 — 논리 라인(LinePart[])을 값 트리로 (RFC 9051 §9 ABNF의 실용 부분집합).
 *
 * 범용 데이터 파서다: atom / quoted / literal / 괄호 리스트만 안다.
 * 명령별 인자 검증(astring이냐 sequence-set이냐 등)은 엔진의 명령 핸들러 소관 —
 * Dovecot도 같은 구조(범용 arg 파서 + 명령별 해석).
 *
 * ABNF 주의: `[`는 atom에 허용되고 `]`는 resp-specials지만 astring에는 허용된다(RFC 9051).
 * BODY[HEADER.FIELDS (...)]<0.100> 같은 FETCH 섹션 구문 때문에 여기서는 `[`/`]`를
 * atom 문자로 수용하고, 섹션 상세 파싱은 FETCH 핸들러에서 한다(실서버 관행).
 */
import type { LinePart } from "./reader.ts";

export type ImapValue =
  | { kind: "atom"; value: string }
  | { kind: "quoted"; value: string }
  | { kind: "literal"; bytes: Uint8Array }
  | { kind: "list"; items: ImapValue[] };

export interface ParsedCommand {
  tag: string;
  /** 대문자 정규화된 명령명. `UID COPY`처럼 UID 접두는 엔진에서 결합 처리. */
  name: string;
  args: ImapValue[];
}

export class ImapParseError extends Error {}

/**
 * atom에서 제외되는 문자 — atom-specials(RFC 9051) 중 실용 편차 3종:
 * `[`/`]` 수용(FETCH 섹션), `*`/`%` 수용(sequence-set `1:*`·LIST 와일드카드가 이 파서를
 * 통과해야 함 — ABNF상 별도 프로덕션이지만 범용 arg 파서에서는 atom으로 흡수하는 게 관행).
 */
const ATOM_SPECIALS = new Set([...'(){ "\\']);

function isAtomChar(ch: string): boolean {
  const code = ch.charCodeAt(0);
  if (code <= 0x1f || code === 0x7f) return false; // CTL
  return !ATOM_SPECIALS.has(ch);
}

/** LinePart[] 위를 걷는 커서 — 텍스트는 문자 단위, 리터럴은 값 하나로 소비. */
class Cursor {
  private readonly parts: readonly LinePart[];
  private partIdx = 0;
  private charIdx = 0;

  constructor(parts: readonly LinePart[]) {
    this.parts = parts;
  }

  /** 현재 위치가 텍스트 문자면 그 문자, 리터럴 경계면 "{", 끝이면 null. */
  peek(): string | null {
    const part = this.parts[this.partIdx];
    if (!part) return null;
    if (part.kind === "literal") return "{"; // 리터럴 값 시작 표지
    if (this.charIdx < part.text.length) return part.text[this.charIdx] ?? null;
    // 텍스트 조각 소진 — 다음 조각으로
    this.partIdx += 1;
    this.charIdx = 0;
    return this.peek();
  }

  nextChar(): string | null {
    const ch = this.peek();
    if (ch === null) return null;
    const part = this.parts[this.partIdx];
    if (!part || part.kind === "literal") throw new ImapParseError("internal: nextChar on literal boundary");
    this.charIdx += 1;
    return ch;
  }

  /** 리터럴 경계에서 리터럴 값을 통째로 소비. */
  takeLiteral(): Uint8Array {
    const part = this.parts[this.partIdx];
    if (!part || part.kind !== "literal") throw new ImapParseError("internal: takeLiteral off boundary");
    this.partIdx += 1;
    this.charIdx = 0;
    return part.bytes;
  }

  atLiteral(): boolean {
    const part = this.parts[this.partIdx];
    if (!part) return false;
    if (part.kind === "literal") return true;
    if (this.charIdx >= part.text.length) {
      this.partIdx += 1;
      this.charIdx = 0;
      return this.atLiteral();
    }
    return false;
  }

  skipSpaces(): void {
    while (this.peek() === " " && !this.atLiteral()) this.nextChar();
  }

  atEnd(): boolean {
    return this.peek() === null;
  }
}

function parseQuoted(cur: Cursor): ImapValue {
  cur.nextChar(); // 여는 따옴표
  let out = "";
  for (;;) {
    const ch = cur.nextChar();
    if (ch === null) throw new ImapParseError("unterminated quoted string");
    if (ch === '"') return { kind: "quoted", value: out };
    if (ch === "\\") {
      const esc = cur.nextChar();
      if (esc !== '"' && esc !== "\\") throw new ImapParseError("invalid quoted-string escape");
      out += esc;
      continue;
    }
    out += ch;
  }
}

function parseAtom(cur: Cursor): ImapValue {
  let out = "";
  for (;;) {
    if (cur.atLiteral()) break;
    const ch = cur.peek();
    if (ch === null || !isAtomChar(ch)) break;
    out += cur.nextChar();
  }
  if (out.length === 0) throw new ImapParseError("expected atom");
  return { kind: "atom", value: out };
}

function parseList(cur: Cursor): ImapValue {
  cur.nextChar(); // '('
  const items: ImapValue[] = [];
  for (;;) {
    cur.skipSpaces();
    if (cur.atLiteral()) {
      items.push({ kind: "literal", bytes: cur.takeLiteral() });
      continue;
    }
    const ch = cur.peek();
    if (ch === null) throw new ImapParseError("unterminated parenthesized list");
    if (ch === ")") {
      cur.nextChar();
      return { kind: "list", items };
    }
    items.push(parseValue(cur));
  }
}

function parseValue(cur: Cursor): ImapValue {
  if (cur.atLiteral()) return { kind: "literal", bytes: cur.takeLiteral() };
  const ch = cur.peek();
  if (ch === null) throw new ImapParseError("unexpected end of command");
  if (ch === '"') return parseQuoted(cur);
  if (ch === "(") return parseList(cur);
  if (ch === "\\") {
    // flag 프로덕션(RFC 9051): `\` + atom — STORE (\Seen)·APPEND 플래그 리스트용.
    cur.nextChar();
    const inner = parseAtom(cur);
    return { kind: "atom", value: `\\${inner.kind === "atom" ? inner.value : ""}` };
  }
  return parseAtom(cur);
}

/** 논리 라인 전체를 값 배열로 — 명령 인자 파싱의 공통 기반. */
export function parseValues(parts: readonly LinePart[]): ImapValue[] {
  const cur = new Cursor(parts);
  const values: ImapValue[] = [];
  for (;;) {
    cur.skipSpaces();
    if (cur.atEnd()) return values;
    values.push(parseValue(cur));
  }
}

/**
 * 명령 envelope 파싱: `tag SP name [SP args...]`.
 * tag/name은 atom이어야 하고, name은 대문자 정규화된다.
 */
export function parseCommand(parts: readonly LinePart[]): ParsedCommand {
  const values = parseValues(parts);
  const tagVal = values[0];
  if (!tagVal || tagVal.kind !== "atom") throw new ImapParseError("missing command tag");
  if (tagVal.value.includes("+")) throw new ImapParseError("invalid tag"); // tag는 '+' 금지(RFC 9051)
  const nameVal = values[1];
  if (!nameVal || nameVal.kind !== "atom") throw new ImapParseError("missing command name");
  return { tag: tagVal.value, name: nameVal.value.toUpperCase(), args: values.slice(2) };
}

/** astring 값(atom/quoted/literal)을 텍스트로 — 리터럴은 latin1 바이트 보존 디코드. */
export function valueText(v: ImapValue): string | null {
  switch (v.kind) {
    case "atom":
    case "quoted":
      return v.value;
    case "literal":
      // Bun의 TextDecoder 타입이 latin1 라벨을 안 받아 Buffer 경유(reader.ts와 동일)
      return Buffer.from(v.bytes.buffer, v.bytes.byteOffset, v.bytes.byteLength).toString("latin1");
    case "list":
      return null;
  }
}
