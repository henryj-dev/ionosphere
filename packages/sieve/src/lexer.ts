/**
 * Sieve 렉서 (RFC 5228 §8.1). 소스를 토큰 스트림으로. 순수 함수 — I/O 없음.
 * 주석: `#`(줄 끝까지), `/* ... *​/`(블록). 문자열: quoted("...") + multi-line(text: ... .).
 */

export type TokenType =
  | "identifier"
  | "tag" // :fileinto 같은 :xxx
  | "number" // 10, 1K, 2M, 3G
  | "string"
  | "(" | ")" | "{" | "}" | "[" | "]" | "," | ";";

export interface Token {
  type: TokenType;
  value: string; // string은 디코드된 값, number는 정수 문자열, tag/identifier는 이름
  pos: number;
}

export class SieveSyntaxError extends Error {
  readonly pos: number;
  constructor(message: string, pos: number) {
    super(`${message} (pos ${pos})`);
    this.name = "SieveSyntaxError";
    this.pos = pos;
  }
}

const IDENT_START = /[A-Za-z_]/;
const IDENT_CHAR = /[A-Za-z0-9_.]/;

export function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const n = src.length;

  const push = (type: TokenType, value: string, pos: number): void => {
    tokens.push({ type, value, pos });
  };

  while (i < n) {
    const c = src[i]!;
    // 공백
    if (c === " " || c === "\t" || c === "\r" || c === "\n") {
      i++;
      continue;
    }
    // 주석
    if (c === "#") {
      while (i < n && src[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      const start = i;
      i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) i++;
      if (i >= n) throw new SieveSyntaxError("unterminated block comment", start);
      i += 2;
      continue;
    }
    // 구두점
    if ("(){}[],;".includes(c)) {
      push(c as TokenType, c, i);
      i++;
      continue;
    }
    // 태그 :xxx
    if (c === ":") {
      const start = i;
      i++;
      let name = "";
      while (i < n && IDENT_CHAR.test(src[i]!)) name += src[i++]!;
      if (name.length === 0) throw new SieveSyntaxError("empty tag", start);
      push("tag", name, start);
      continue;
    }
    // 숫자 (+ K/M/G 단위)
    if (c >= "0" && c <= "9") {
      const start = i;
      let num = "";
      while (i < n && src[i]! >= "0" && src[i]! <= "9") num += src[i++]!;
      let mult = 1;
      const unit = src[i];
      if (unit === "K" || unit === "k") { mult = 1024; i++; }
      else if (unit === "M" || unit === "m") { mult = 1024 * 1024; i++; }
      else if (unit === "G" || unit === "g") { mult = 1024 * 1024 * 1024; i++; }
      push("number", String(Number(num) * mult), start);
      continue;
    }
    // quoted string
    if (c === '"') {
      const start = i;
      i++;
      let s = "";
      while (i < n && src[i] !== '"') {
        if (src[i] === "\\") {
          const esc = src[i + 1];
          // RFC 5228: \" 와 \\ 만 특수. 그 외 \x 는 x.
          s += esc ?? "";
          i += 2;
        } else {
          s += src[i++]!;
        }
      }
      if (i >= n) throw new SieveSyntaxError("unterminated string", start);
      i++; // 닫는 "
      push("string", s, start);
      continue;
    }
    // multi-line: text: ... CRLF . CRLF
    if (c === "t" && src.startsWith("text:", i)) {
      const start = i;
      i += 5;
      // 같은 줄의 나머지(주석/공백) 건너뛰고 줄바꿈까지
      while (i < n && src[i] !== "\n") i++;
      if (i < n) i++; // \n
      let s = "";
      for (;;) {
        // 줄 시작
        const lineStart = i;
        let line = "";
        while (i < n && src[i] !== "\n") line += src[i++]!;
        if (i < n) i++; // \n
        const trimmed = line.replace(/\r$/, "");
        if (trimmed === ".") break;
        // dot-stuffing 해제: 줄 선두 ".." → "."
        s += (trimmed.startsWith("..") ? trimmed.slice(1) : trimmed) + "\r\n";
        if (i >= n && trimmed !== ".") throw new SieveSyntaxError("unterminated multi-line string", lineStart);
      }
      push("string", s, start);
      continue;
    }
    // 식별자
    if (IDENT_START.test(c)) {
      const start = i;
      let name = "";
      while (i < n && IDENT_CHAR.test(src[i]!)) name += src[i++]!;
      push("identifier", name, start);
      continue;
    }
    throw new SieveSyntaxError(`unexpected character ${JSON.stringify(c)}`, i);
  }
  return tokens;
}
