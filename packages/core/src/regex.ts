/**
 * **역추적 없는** 정규식 엔진 (POSIX ERE 부분집합) — Sieve `:regex` 전용.
 *
 * ## 왜 `RegExp`을 쓰지 않는가
 *
 * `:regex`의 패턴은 **사용자가 쓴 필터 규칙**이고, 그게 배달되는 메일마다 돌아간다.
 * JS의 `RegExp`은 역추적 엔진이라 `(a+)+b` 같은 패턴 하나로 입력 길이에 지수 시간이 된다
 * (ReDoS). 이 서버는 SMTP·IMAP·POP3·JMAP이 **한 프로세스**에서 도므로, 그 지수가 이벤트
 * 루프를 붙잡으면 필터를 쓴 한 사용자가 **전체 메일 서비스를 멈춘다**. 자기 발로 밟는
 * 지뢰이기도 하고, 스팸 발신자가 그 사용자에게 긴 메일을 보내 유발할 수도 있다.
 *
 * `glob.ts`가 같은 이유로 DP 매처를 손으로 쓴 것과 같은 판단이다. 여기서는 캡처가 필요해
 * DP 대신 **Pike VM**(스레드 집합 시뮬레이션)을 쓴다 — 같은 pc의 스레드를 합치므로 스레드
 * 수가 프로그램 길이를 넘지 않고, 전체가 O(패턴 × 입력)이다. 역추적이라는 개념이 없어
 * 폭발이 성립하지 않는다.
 *
 * ## 지원 범위
 *
 * 리터럴 · `.` · `*` `+` `?` · `{n,m}` · `|` · `()` · `[...]`(범위·부정) · `^` `$` · `\` 이스케이프.
 *
 * ★**역참조(`\1`)와 룩어라운드는 지원하지 않는다.** 둘 다 이 방식으로는 선형 시간이
 * 성립하지 않는 기능이라, 조용히 다르게 동작시키느니 **문법 오류로 거절한다** —
 * 그래야 사용자가 규칙이 안 먹는 이유를 안다.
 */

/** 패턴 길이 상한 — 파싱 자체의 비용을 묶는다. */
const MAX_PATTERN_CHARS = 4096;
/**
 * 컴파일된 프로그램 명령 수 상한.
 *
 * ★`{n,m}`은 **펼쳐서** 구현하므로 `a{1000}{1000}` 같은 패턴이 프로그램을 폭발시킬 수 있다.
 * 시간은 선형이어도 **메모리**가 아니다 — 그래서 여기서 끊는다.
 */
const MAX_PROGRAM_SIZE = 20_000;
/** `{n,m}`의 반복 상한 — 위 프로그램 상한에 닿기 전에 더 읽기 쉬운 오류를 낸다. */
const MAX_REPEAT = 1000;

export class RegexSyntaxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegexSyntaxError";
  }
}

// ── AST ───────────────────────────────────────────────────────────────────────

type Node =
  | { kind: "empty" }
  | { kind: "char"; ch: string }
  | { kind: "any" }
  | { kind: "class"; negate: boolean; ranges: [number, number][] }
  | { kind: "bol" }
  | { kind: "eol" }
  | { kind: "cat"; parts: Node[] }
  | { kind: "alt"; parts: Node[] }
  | { kind: "repeat"; node: Node; min: number; max: number | null }
  | { kind: "group"; node: Node; index: number };

interface ParserState {
  src: string;
  pos: number;
  groups: number;
}

/** `\d` 류 축약 — POSIX ERE에는 없지만 실사용이 압도적이라 받는다. */
const SHORTHAND: Record<string, { negate: boolean; ranges: [number, number][] }> = {
  d: { negate: false, ranges: [[48, 57]] },
  D: { negate: true, ranges: [[48, 57]] },
  w: {
    negate: false,
    ranges: [
      [48, 57],
      [65, 90],
      [95, 95],
      [97, 122],
    ],
  },
  W: {
    negate: true,
    ranges: [
      [48, 57],
      [65, 90],
      [95, 95],
      [97, 122],
    ],
  },
  s: {
    negate: false,
    ranges: [
      [9, 13],
      [32, 32],
    ],
  },
  S: {
    negate: true,
    ranges: [
      [9, 13],
      [32, 32],
    ],
  },
};

/** `\n` 류 제어문자 이스케이프. 소스에 리터럴 제어문자를 두지 않는다(저장소 규약). */
const CONTROL_ESCAPES: Record<string, string> = {
  n: "\n",
  r: "\r",
  t: "\t",
  f: "\f",
  v: "\v",
  0: "\u0000",
};

function parseAlternation(st: ParserState): Node {
  const parts: Node[] = [parseConcat(st)];
  while (st.src[st.pos] === "|") {
    st.pos += 1;
    parts.push(parseConcat(st));
  }
  return parts.length === 1 ? parts[0]! : { kind: "alt", parts };
}

function parseConcat(st: ParserState): Node {
  const parts: Node[] = [];
  while (st.pos < st.src.length && st.src[st.pos] !== "|" && st.src[st.pos] !== ")") {
    parts.push(parseRepeat(st));
  }
  if (parts.length === 0) return { kind: "empty" };
  return parts.length === 1 ? parts[0]! : { kind: "cat", parts };
}

function parseRepeat(st: ParserState): Node {
  let node = parseAtom(st);
  for (;;) {
    const ch = st.src[st.pos];
    if (ch === "*") {
      st.pos += 1;
      node = { kind: "repeat", node, min: 0, max: null };
    } else if (ch === "+") {
      st.pos += 1;
      node = { kind: "repeat", node, min: 1, max: null };
    } else if (ch === "?") {
      st.pos += 1;
      node = { kind: "repeat", node, min: 0, max: 1 };
    } else if (ch === "{") {
      const saved = st.pos;
      const bounds = parseBounds(st);
      // `{`가 반복 문법이 아니면 리터럴이다(POSIX의 관용) — 위치를 되돌린다.
      if (bounds === null) {
        st.pos = saved;
        return node;
      }
      node = { kind: "repeat", node, min: bounds.min, max: bounds.max };
    } else {
      return node;
    }
  }
}

function parseBounds(st: ParserState): { min: number; max: number | null } | null {
  const close = st.src.indexOf("}", st.pos);
  if (close === -1) return null;
  const body = st.src.slice(st.pos + 1, close);
  const m = /^(\d+)(?:(,)(\d*))?$/.exec(body);
  if (!m) return null;
  const min = Number(m[1]);
  const max = m[2] === undefined ? min : m[3] === "" ? null : Number(m[3]);
  if (min > MAX_REPEAT || (max !== null && max > MAX_REPEAT)) {
    throw new RegexSyntaxError(`repetition count too large (max ${MAX_REPEAT})`);
  }
  if (max !== null && max < min) throw new RegexSyntaxError("repetition bounds out of order");
  st.pos = close + 1;
  return { min, max };
}

function parseAtom(st: ParserState): Node {
  const ch = st.src[st.pos];
  if (ch === undefined) return { kind: "empty" };
  if (ch === "(") {
    st.pos += 1;
    /**
     * ★`(?...)`는 룩어라운드·비캡처 그룹 등인데, 룩어라운드는 이 엔진으로 선형 시간이
     * 성립하지 않는다. 일부만 받으면 "어떤 건 되고 어떤 건 안 되는" 상태가 되므로
     * `(?`로 시작하는 것은 전부 거절한다.
     */
    if (st.src[st.pos] === "?") throw new RegexSyntaxError("(?...) groups are not supported");
    st.groups += 1;
    const index = st.groups;
    const inner = parseAlternation(st);
    if (st.src[st.pos] !== ")") throw new RegexSyntaxError("unclosed group");
    st.pos += 1;
    return { kind: "group", node: inner, index };
  }
  if (ch === "[") return parseClass(st);
  if (ch === ".") {
    st.pos += 1;
    return { kind: "any" };
  }
  if (ch === "^") {
    st.pos += 1;
    return { kind: "bol" };
  }
  if (ch === "$") {
    st.pos += 1;
    return { kind: "eol" };
  }
  if (ch === "\\") {
    st.pos += 1;
    const esc = st.src[st.pos];
    if (esc === undefined) throw new RegexSyntaxError("trailing backslash");
    st.pos += 1;
    /**
     * ★역참조(`\1`)는 **거절한다.** 스레드 집합 시뮬레이션으로는 표현할 수 없고
     * (같은 pc의 스레드를 합칠 수 없게 된다), 역추적으로 구현하면 이 파일의 존재 이유가
     * 사라진다. 조용히 다르게 동작시키느니 문법 오류가 낫다.
     */
    if (/^[1-9]$/.test(esc)) throw new RegexSyntaxError("backreferences are not supported");
    const short = SHORTHAND[esc];
    if (short) return { kind: "class", negate: short.negate, ranges: short.ranges.map((r) => [r[0], r[1]]) };
    const ctrl = CONTROL_ESCAPES[esc];
    return { kind: "char", ch: ctrl ?? esc };
  }
  if (ch === ")") throw new RegexSyntaxError("unmatched )");
  st.pos += 1;
  return { kind: "char", ch };
}

function parseClass(st: ParserState): Node {
  st.pos += 1; // `[`
  let negate = false;
  if (st.src[st.pos] === "^") {
    negate = true;
    st.pos += 1;
  }
  const ranges: [number, number][] = [];
  // `]`가 맨 앞이면 리터럴이다(POSIX).
  if (st.src[st.pos] === "]") {
    ranges.push([93, 93]);
    st.pos += 1;
  }
  for (;;) {
    const ch = st.src[st.pos];
    if (ch === undefined) throw new RegexSyntaxError("unclosed character class");
    if (ch === "]") {
      st.pos += 1;
      break;
    }
    let lo: number;
    if (ch === "\\") {
      st.pos += 1;
      const esc = st.src[st.pos];
      if (esc === undefined) throw new RegexSyntaxError("trailing backslash in class");
      st.pos += 1;
      const short = SHORTHAND[esc];
      if (short) {
        // 클래스 안의 축약은 **부정이 아닌 것만** 합칠 수 있다 — `[\D]`는 범위 합집합으로
        // 표현할 수 없으므로 거절한다(조용히 틀리는 것보다 낫다).
        if (short.negate) throw new RegexSyntaxError(`\\${esc} inside a character class is not supported`);
        for (const r of short.ranges) ranges.push([r[0], r[1]]);
        continue;
      }
      lo = (CONTROL_ESCAPES[esc] ?? esc).charCodeAt(0);
    } else {
      lo = ch.charCodeAt(0);
      st.pos += 1;
    }
    if (st.src[st.pos] === "-" && st.src[st.pos + 1] !== undefined && st.src[st.pos + 1] !== "]") {
      st.pos += 1;
      const hiCh = st.src[st.pos]!;
      let hi: number;
      if (hiCh === "\\") {
        st.pos += 1;
        const esc = st.src[st.pos];
        if (esc === undefined) throw new RegexSyntaxError("trailing backslash in class");
        st.pos += 1;
        hi = (CONTROL_ESCAPES[esc] ?? esc).charCodeAt(0);
      } else {
        hi = hiCh.charCodeAt(0);
        st.pos += 1;
      }
      if (hi < lo) throw new RegexSyntaxError("character class range out of order");
      ranges.push([lo, hi]);
    } else {
      ranges.push([lo, lo]);
    }
  }
  return { kind: "class", negate, ranges };
}

// ── 컴파일 ────────────────────────────────────────────────────────────────────

type Inst =
  | { op: "char"; ch: number }
  | { op: "any" }
  | { op: "class"; negate: boolean; ranges: [number, number][] }
  | { op: "bol" }
  | { op: "eol" }
  | { op: "split"; a: number; b: number }
  | { op: "jmp"; to: number }
  | { op: "save"; slot: number }
  | { op: "match" };

/** 컴파일된 패턴 — 재사용 가능하다(호출부가 루프 안에서 다시 컴파일하지 않게). */
export interface CompiledRegex {
  prog: Inst[];
  groups: number;
  caseInsensitive: boolean;
}

function emit(prog: Inst[], inst: Inst): number {
  if (prog.length >= MAX_PROGRAM_SIZE) throw new RegexSyntaxError(`pattern too complex (max ${MAX_PROGRAM_SIZE} instructions)`);
  prog.push(inst);
  return prog.length - 1;
}

function compileNode(node: Node, prog: Inst[], ci: boolean): void {
  switch (node.kind) {
    case "empty":
      return;
    case "char":
      emit(prog, { op: "char", ch: (ci ? node.ch.toLowerCase() : node.ch).charCodeAt(0) });
      return;
    case "any":
      emit(prog, { op: "any" });
      return;
    case "class":
      emit(prog, { op: "class", negate: node.negate, ranges: node.ranges });
      return;
    case "bol":
      emit(prog, { op: "bol" });
      return;
    case "eol":
      emit(prog, { op: "eol" });
      return;
    case "cat":
      for (const p of node.parts) compileNode(p, prog, ci);
      return;
    case "alt": {
      /**
       * 왼쪽부터 우선하는 분기 사슬. Pike VM이 스레드를 **추가 순서**로 우선하므로
       * 이 순서가 곧 "왼쪽 우선"이 된다 — 캡처가 정규식의 관례와 같아진다.
       */
      const jumps: number[] = [];
      for (let i = 0; i < node.parts.length; i++) {
        const last = i === node.parts.length - 1;
        if (last) {
          compileNode(node.parts[i]!, prog, ci);
          break;
        }
        const sp = emit(prog, { op: "split", a: 0, b: 0 });
        (prog[sp] as { a: number }).a = prog.length;
        compileNode(node.parts[i]!, prog, ci);
        jumps.push(emit(prog, { op: "jmp", to: 0 }));
        (prog[sp] as { b: number }).b = prog.length;
      }
      for (const j of jumps) (prog[j] as { to: number }).to = prog.length;
      return;
    }
    case "group": {
      emit(prog, { op: "save", slot: node.index * 2 });
      compileNode(node.node, prog, ci);
      emit(prog, { op: "save", slot: node.index * 2 + 1 });
      return;
    }
    case "repeat": {
      const { min, max } = node;
      // 최소 횟수만큼 먼저 펼친다.
      for (let i = 0; i < min; i++) compileNode(node.node, prog, ci);
      if (max === null) {
        if (min > 0) {
          /**
           * `x{n,}` — 마지막 하나를 `x*`로 이어 붙인다. `x+`를 `xx*`로 쓰는 것과 같다.
           * ★**탐욕적**이다(split의 a가 본체) — 정규식의 관례와 같게 둔다.
           */
          const start = prog.length;
          const sp = emit(prog, { op: "split", a: 0, b: 0 });
          (prog[sp] as { a: number }).a = prog.length;
          compileNode(node.node, prog, ci);
          emit(prog, { op: "jmp", to: start });
          (prog[sp] as { b: number }).b = prog.length;
        } else {
          const start = prog.length;
          const sp = emit(prog, { op: "split", a: 0, b: 0 });
          (prog[sp] as { a: number }).a = prog.length;
          compileNode(node.node, prog, ci);
          emit(prog, { op: "jmp", to: start });
          (prog[sp] as { b: number }).b = prog.length;
        }
        return;
      }
      // `x{n,m}` — 남은 (m-n)개를 선택적으로 펼친다.
      const optional = max - min;
      const splits: number[] = [];
      for (let i = 0; i < optional; i++) {
        const sp = emit(prog, { op: "split", a: 0, b: 0 });
        (prog[sp] as { a: number }).a = prog.length;
        splits.push(sp);
        compileNode(node.node, prog, ci);
      }
      for (const sp of splits) (prog[sp] as { b: number }).b = prog.length;
      return;
    }
  }
}

/**
 * 패턴을 컴파일한다. 문법 오류는 `RegexSyntaxError`.
 *
 * ★호출부가 **루프 안에서 다시 컴파일하지 않게** 결과를 재사용하라 — 값이 여럿일 때
 * (헤더가 여러 줄, 주소가 여럿) 매번 컴파일하면 그 자체가 낭비다(`compileGlob`과 같은 이유).
 */
export function compileRegex(pattern: string, opts: { caseInsensitive?: boolean } = {}): CompiledRegex {
  if (pattern.length > MAX_PATTERN_CHARS) throw new RegexSyntaxError(`pattern too long (max ${MAX_PATTERN_CHARS})`);
  const st: ParserState = { src: pattern, pos: 0, groups: 0 };
  const ast = parseAlternation(st);
  if (st.pos !== pattern.length) throw new RegexSyntaxError(`unexpected ${pattern[st.pos]} at ${st.pos}`);
  const ci = opts.caseInsensitive === true;
  const prog: Inst[] = [];
  emit(prog, { op: "save", slot: 0 });
  compileNode(ast, prog, ci);
  emit(prog, { op: "save", slot: 1 });
  emit(prog, { op: "match" });
  return { prog, groups: st.groups, caseInsensitive: ci };
}

// ── 실행 (Pike VM) ────────────────────────────────────────────────────────────

function inClass(inst: Extract<Inst, { op: "class" }>, code: number): boolean {
  let hit = false;
  for (const [lo, hi] of inst.ranges) {
    if (code >= lo && code <= hi) {
      hit = true;
      break;
    }
  }
  return inst.negate ? !hit : hit;
}

export interface RegexMatch {
  matched: boolean;
  /** `${1}`..`${n}` — 그룹이 참여하지 않았으면 빈 문자열. */
  captures: string[];
}

/**
 * 부분 매칭(어디서든 시작). 문자열 전체를 요구하려면 패턴에 `^`/`$`를 쓴다.
 *
 * ★같은 pc의 스레드는 **합친다** — 그래서 살아 있는 스레드가 프로그램 길이를 넘지 않고,
 * 전체가 O(프로그램 × 입력)이다. 역추적 엔진이 지수가 되는 자리가 정확히 여기서 사라진다.
 *
 * ★스레드는 **추가 순서로 우선**한다(먼저 들어온 것이 이긴다). 컴파일이 왼쪽·탐욕을
 * 먼저 넣으므로 캡처가 정규식의 관례와 같아진다.
 */
export function execRegex(re: CompiledRegex, input: string): RegexMatch {
  const hay = re.caseInsensitive ? input.toLowerCase() : input;
  const n = re.prog.length;
  const slotCount = (re.groups + 1) * 2;

  let clist: { pc: number; slots: number[] }[] = [];
  let nlist: { pc: number; slots: number[] }[] = [];
  let onClist = new Int32Array(n).fill(-1);
  let onNlist = new Int32Array(n).fill(-1);
  let best: number[] | null = null;

  const addThread = (
    list: { pc: number; slots: number[] }[],
    seen: Int32Array,
    gen: number,
    pc: number,
    slots: number[],
    pos: number,
  ): void => {
    // 같은 pc를 두 번 넣지 않는다 — 이 한 줄이 지수를 선형으로 만든다.
    if (seen[pc] === gen) return;
    seen[pc] = gen;
    const inst = re.prog[pc]!;
    switch (inst.op) {
      case "jmp":
        addThread(list, seen, gen, inst.to, slots, pos);
        return;
      case "split":
        addThread(list, seen, gen, inst.a, slots, pos);
        addThread(list, seen, gen, inst.b, slots, pos);
        return;
      case "save": {
        const copy = slots.slice();
        copy[inst.slot] = pos;
        addThread(list, seen, gen, pc + 1, copy, pos);
        return;
      }
      case "bol":
        if (pos === 0) addThread(list, seen, gen, pc + 1, slots, pos);
        return;
      case "eol":
        if (pos === hay.length) addThread(list, seen, gen, pc + 1, slots, pos);
        return;
      default:
        list.push({ pc, slots });
    }
  };

  for (let pos = 0; pos <= hay.length; pos++) {
    /**
     * ★매칭을 아직 못 찾았을 때만 새 시작점을 넣는다. 찾은 뒤에도 넣으면 **가장 왼쪽**이
     * 아닌 매칭이 이길 수 있고, 그러면 `${0}`이 사용자가 보는 것과 달라진다.
     */
    if (best === null) addThread(clist, onClist, pos, 0, new Array<number>(slotCount).fill(-1), pos);
    if (clist.length === 0 && best !== null) break;

    const ch = pos < hay.length ? hay.charCodeAt(pos) : -1;
    nlist = [];
    onNlist = onNlist.fill(-1);
    for (const th of clist) {
      const inst = re.prog[th.pc]!;
      if (inst.op === "match") {
        /**
         * ★첫 스레드가 이긴다(추가 순서 우선). 뒤엣것을 받으면 왼쪽·탐욕 우선이 깨진다.
         * 남은 스레드는 더 볼 이유가 없으므로 여기서 끊는다.
         */
        best = th.slots;
        break;
      }
      if (ch === -1) continue;
      let ok = false;
      if (inst.op === "char") ok = inst.ch === ch;
      else if (inst.op === "any") ok = true;
      else if (inst.op === "class") ok = inClass(inst, ch);
      if (ok) addThread(nlist, onNlist, pos + 1, th.pc + 1, th.slots, pos + 1);
    }
    const swapList = clist;
    clist = nlist;
    nlist = swapList;
    const swapSeen = onClist;
    onClist = onNlist;
    onNlist = swapSeen;
  }

  if (best === null) return { matched: false, captures: [] };
  const captures: string[] = [];
  for (let g = 1; g <= re.groups; g++) {
    const s = best[g * 2] ?? -1;
    const e = best[g * 2 + 1] ?? -1;
    captures.push(s >= 0 && e >= s ? input.slice(s, e) : "");
  }
  return { matched: true, captures };
}

/** 한 번 쓰는 자리용 — 패턴을 컴파일해 바로 실행한다. */
export function regexMatch(pattern: string, input: string, opts: { caseInsensitive?: boolean } = {}): RegexMatch {
  return execRegex(compileRegex(pattern, opts), input);
}
