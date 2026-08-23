/** Sieve AST (RFC 5228 §8.2). 명령/테스트는 동일한 형태(이름 + 인자) — 파서가 문맥으로 구분. */

/** 인자: 태그(:contains), 문자열/문자열리스트, 숫자. */
export type SieveArg =
  | { kind: "tag"; name: string }
  | { kind: "strings"; values: string[] }
  | { kind: "number"; value: number };

export interface SieveTest {
  name: string;
  args: SieveArg[];
  /** allof/anyof/not의 하위 테스트. */
  tests: SieveTest[];
}

export interface SieveCommand {
  name: string;
  args: SieveArg[];
  /** if/elsif의 조건. */
  test: SieveTest | null;
  /** 블록(if/elsif/else 본문). null이면 `;`로 끝난 단순 명령. */
  block: SieveCommand[] | null;
}
