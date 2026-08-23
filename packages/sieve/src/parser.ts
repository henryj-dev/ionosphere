/**
 * Sieve 파서 (RFC 5228 §8.2) — 토큰 → 명령 목록. 재귀 하강.
 * 문법: command = identifier arguments (test / test-list)? (block / ";")
 *       arguments = *(string-list / number / tag)
 *       test = identifier arguments (test / test-list)?
 */
import type { SieveArg, SieveCommand, SieveTest } from "./ast.ts";
import { SieveSyntaxError, tokenize, type Token } from "./lexer.ts";

/** 조건(test)을 받는 명령 — 뒤에 test가 온다. */
const CONTROL_WITH_TEST = new Set(["if", "elsif"]);
/** 블록을 갖는 제어 명령. */
const CONTROL_WITH_BLOCK = new Set(["if", "elsif", "else"]);
/** 하위 test를 받는 테스트(test-list). */
const TEST_WITH_SUBTESTS = new Set(["allof", "anyof"]);
const TEST_WITH_SUBTEST = new Set(["not"]);

/**
 * 블록 중첩 깊이 상한.
 *
 * 파서가 재귀라 `if { if { ... } }`를 깊게 쌓으면 **스택이 터진다**. 스크립트는 사용자가
 * 올리는 값이고(ManageSieve PUTSCRIPT, 최대 1MB), 스택 오버플로는 RangeError라 호출부가
 * 잡긴 하지만 — 배달 경로에서 그걸 매번 밟게 두는 것보다 파싱 단계에서 문법 오류로
 * 거절하는 편이 낫다(저장 시점에 사용자가 바로 안다).
 */
const MAX_BLOCK_DEPTH = 64;

class Parser {
  private i = 0;
  private depth = 0;
  private readonly toks: Token[];
  constructor(toks: Token[]) {
    this.toks = toks;
  }

  private peek(): Token | undefined {
    return this.toks[this.i];
  }
  private next(): Token {
    const t = this.toks[this.i];
    if (!t) throw new SieveSyntaxError("unexpected end of script", this.toks[this.i - 1]?.pos ?? 0);
    this.i++;
    return t;
  }
  private expect(type: Token["type"]): Token {
    const t = this.next();
    if (t.type !== type) throw new SieveSyntaxError(`expected '${type}', got '${t.type}'`, t.pos);
    return t;
  }

  parseCommands(): SieveCommand[] {
    const cmds: SieveCommand[] = [];
    while (this.peek() && this.peek()!.type !== "}") {
      cmds.push(this.parseCommand());
    }
    return cmds;
  }

  private parseCommand(): SieveCommand {
    const id = this.expect("identifier");
    const args = this.parseArgs();
    let test: SieveTest | null = null;
    if (CONTROL_WITH_TEST.has(id.value)) {
      test = this.parseTest();
    }
    let block: SieveCommand[] | null = null;
    const t = this.peek();
    if (t?.type === "{") {
      if (!CONTROL_WITH_BLOCK.has(id.value)) throw new SieveSyntaxError(`'${id.value}' cannot have a block`, t.pos);
      this.next();
      if (++this.depth > MAX_BLOCK_DEPTH) {
        throw new SieveSyntaxError(`block nesting too deep (max ${MAX_BLOCK_DEPTH})`, this.peek()?.pos ?? 0);
      }
      block = this.parseCommands();
      this.depth--;
      this.expect("}");
    } else {
      this.expect(";");
    }
    return { name: id.value, args, test, block };
  }

  private parseArgs(): SieveArg[] {
    const args: SieveArg[] = [];
    for (;;) {
      const t = this.peek();
      if (!t) break;
      if (t.type === "tag") {
        this.next();
        args.push({ kind: "tag", name: t.value });
      } else if (t.type === "number") {
        this.next();
        args.push({ kind: "number", value: Number(t.value) });
      } else if (t.type === "string") {
        this.next();
        args.push({ kind: "strings", values: [t.value] });
      } else if (t.type === "[") {
        args.push({ kind: "strings", values: this.parseStringList() });
      } else {
        break; // identifier(=test/다음 명령), ;, {, ( 등 → 인자 끝
      }
    }
    return args;
  }

  private parseStringList(): string[] {
    this.expect("[");
    const out: string[] = [];
    if (this.peek()?.type !== "]") {
      out.push(this.expect("string").value);
      while (this.peek()?.type === ",") {
        this.next();
        out.push(this.expect("string").value);
      }
    }
    this.expect("]");
    return out;
  }

  private parseTest(): SieveTest {
    const id = this.expect("identifier");
    const name = id.value;
    if (TEST_WITH_SUBTESTS.has(name)) {
      const tests = this.parseTestList();
      return { name, args: [], tests };
    }
    if (TEST_WITH_SUBTEST.has(name)) {
      const inner = this.parseTest();
      return { name, args: [], tests: [inner] };
    }
    const args = this.parseArgs();
    return { name, args, tests: [] };
  }

  private parseTestList(): SieveTest[] {
    this.expect("(");
    const out: SieveTest[] = [];
    if (this.peek()?.type !== ")") {
      out.push(this.parseTest());
      while (this.peek()?.type === ",") {
        this.next();
        out.push(this.parseTest());
      }
    }
    this.expect(")");
    return out;
  }
}

/** 스크립트 문자열을 명령 AST로. SieveSyntaxError를 throw. */
export function parseSieve(src: string): SieveCommand[] {
  return new Parser(tokenize(src)).parseCommands();
}
