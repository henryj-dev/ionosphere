/**
 * `expect` — node:assert 위에 얹은 최소 매처 집합.
 *
 * ★왜 자체 구현인가: 러너를 node:test로 옮기면서 183개 테스트 파일(약 3,900개 단언)의 본문을
 * `assert`로 손수 바꾸면 **의미가 조용히 변한다.** 특히 `toEqual`은 jest/bun 계열에서
 * `undefined` 프로퍼티를 무시하는데 `assert.deepStrictEqual`은 무시하지 않는다 —
 * 이 저장소는 `exactOptionalPropertyTypes` 때문에 선택 필드를 조건부 스프레드로 **생략**하고,
 * 기대값 쪽에는 `host: undefined`를 명시한 곳이 있다. 그대로 바꾸면 수백 곳이 깨지거나,
 * 반대로 느슨해져서 **결함 상태에서도 통과**하게 된다(DKIM ed25519 사고와 같은 계열).
 *
 * 그래서 매처 집합을 **닫힌 집합**으로 고정하고, 이 파일 자체를 테스트로 지킨다
 * (`test/expect.test.ts` — 통과·실패 양방향).
 *
 * 의존성 0: node:assert만 쓴다.
 */
import { AssertionError } from "node:assert";

/** 비대칭 매처 태그 — deepEqual/toMatchObject의 비교 지점에서 먼저 처리한다. */
const ASYMMETRIC = Symbol("asymmetric");

interface Asymmetric {
  [ASYMMETRIC]: true;
  name: string;
  test(actual: unknown): boolean;
}

function isAsymmetric(v: unknown): v is Asymmetric {
  return typeof v === "object" && v !== null && ASYMMETRIC in v;
}

/** 값 요약 — 실패 메시지에 쓴다. 길면 자른다(로그가 본문에 잡아먹히지 않게). */
function show(v: unknown, max = 200): string {
  if (isAsymmetric(v)) return v.name;
  if (typeof v === "string") return JSON.stringify(v.length > max ? `${v.slice(0, max)}…` : v);
  if (v instanceof Uint8Array) return `Uint8Array(${v.length})`;
  if (v instanceof Error) return `${v.name}: ${v.message}`;
  try {
    const s = JSON.stringify(v, (_k, val: unknown) => (typeof val === "bigint" ? String(val) : val));
    return s === undefined ? String(v) : s.length > max ? `${s.slice(0, max)}…` : s;
  } catch {
    return String(v);
  }
}

/**
 * 깊은 동등 비교.
 *
 * ★`ignoreUndefined`가 기본이다(jest/bun의 `toEqual` 의미). `{a:1}`과 `{a:1, b:undefined}`는
 * 같다고 본다 — 조건부 스프레드로 키를 생략하는 이 저장소의 관례와 맞물린다.
 * Set/Map/TypedArray/Date/RegExp는 구조가 아니라 **내용**으로 비교한다.
 */
function deepEqual(a: unknown, b: unknown, seen = new Map<object, object>()): boolean {
  if (isAsymmetric(b)) return b.test(a);
  if (isAsymmetric(a)) return a.test(b);
  if (Object.is(a, b)) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;

  // 순환 참조 가드 — 같은 쌍을 다시 만나면 참으로 본다(무한 재귀 방지).
  const prev = seen.get(a);
  if (prev === b) return true;
  seen.set(a, b);

  if (a instanceof Date || b instanceof Date) {
    return a instanceof Date && b instanceof Date && a.getTime() === b.getTime();
  }
  if (a instanceof RegExp || b instanceof RegExp) {
    return a instanceof RegExp && b instanceof RegExp && a.source === b.source && a.flags === b.flags;
  }
  if (a instanceof Set || b instanceof Set) {
    if (!(a instanceof Set) || !(b instanceof Set) || a.size !== b.size) return false;
    // 원소가 객체일 수 있으므로 has()가 아니라 짝짓기로 본다.
    const rest = [...b];
    for (const x of a) {
      const i = rest.findIndex((y) => deepEqual(x, y, seen));
      if (i < 0) return false;
      rest.splice(i, 1);
    }
    return true;
  }
  if (a instanceof Map || b instanceof Map) {
    if (!(a instanceof Map) || !(b instanceof Map) || a.size !== b.size) return false;
    for (const [k, v] of a) {
      if (!b.has(k) || !deepEqual(v, b.get(k), seen)) return false;
    }
    return true;
  }
  if (ArrayBuffer.isView(a) || ArrayBuffer.isView(b)) {
    if (!ArrayBuffer.isView(a) || !ArrayBuffer.isView(b)) return false;
    const x = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
    const y = new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    if (x.length !== y.length) return false;
    for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
    return true;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((x, i) => deepEqual(x, b[i], seen));
  }

  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  // ★undefined 값을 가진 키는 없는 것으로 친다(jest/bun toEqual 의미).
  const keys = (o: Record<string, unknown>): string[] => Object.keys(o).filter((k) => o[k] !== undefined);
  const ak = keys(ao);
  const bk = keys(bo);
  if (ak.length !== bk.length) return false;
  return ak.every((k) => bk.includes(k) && deepEqual(ao[k], bo[k], seen));
}

/** 부분 매칭 — 기대 객체의 키만 본다(toMatchObject). Error 인스턴스도 일반 속성 접근으로 읽는다. */
function matchObject(actual: unknown, expected: unknown): boolean {
  if (isAsymmetric(expected)) return expected.test(actual);
  if (typeof expected !== "object" || expected === null) return deepEqual(actual, expected);
  if (typeof actual !== "object" || actual === null) return false;
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual) || actual.length !== expected.length) return false;
    return expected.every((e, i) => matchObject(actual[i], e));
  }
  const ao = actual as Record<string, unknown>;
  return Object.entries(expected as Record<string, unknown>).every(([k, v]) => matchObject(ao[k], v));
}

function throwFail(message: string): never {
  throw new AssertionError({ message, stackStartFn: throwFail });
}

/** 던져진 값이 기대와 맞는가 — toThrow의 4형태(없음/생성자/정규식/문자열). */
function throwMatches(err: unknown, expected: unknown): boolean {
  if (expected === undefined) return true;
  if (typeof expected === "function") return err instanceof (expected as new (...a: never[]) => object);
  const msg = err instanceof Error ? err.message : String(err);
  if (expected instanceof RegExp) return expected.test(msg);
  return msg.includes(String(expected));
}

export interface Matchers {
  toBe(expected: unknown): void;
  toEqual(expected: unknown): void;
  toContain(expected: unknown): void;
  toContainEqual(expected: unknown): void;
  toHaveLength(expected: number): void;
  toMatch(expected: RegExp | string): void;
  toMatchObject(expected: unknown): void;
  toStartWith(expected: string): void;
  toEndWith(expected: string): void;
  toThrow(expected?: unknown): void;
  toBeNull(): void;
  toBeUndefined(): void;
  toBeDefined(): void;
  toBeTruthy(): void;
  toBeFalsy(): void;
  toBeInstanceOf(expected: unknown): void;
  toBeGreaterThan(n: number | bigint): void;
  toBeGreaterThanOrEqual(n: number | bigint): void;
  toBeLessThan(n: number | bigint): void;
  toBeLessThanOrEqual(n: number | bigint): void;
  toBeCloseTo(n: number, digits?: number): void;
  toHaveProperty(path: string, value?: unknown): void;
  readonly not: Matchers;
}

export interface AsyncMatchers {
  toThrow(expected?: unknown): Promise<void>;
  toBeInstanceOf(expected: unknown): Promise<void>;
  toBeTruthy(): Promise<void>;
  toBeUndefined(): Promise<void>;
  toMatchObject(expected: unknown): Promise<void>;
  toBe(expected: unknown): Promise<void>;
  toEqual(expected: unknown): Promise<void>;
  toContain(expected: unknown): Promise<void>;
  readonly not: AsyncMatchers;
}

/**
 * 매처 본체. `negated`를 들고 다니며 각 매처는 `pass`만 계산한다 —
 * `.not` 체이닝이 매처마다 반전 로직을 복제하지 않게 하려는 것.
 */
function makeMatchers(actual: unknown, negated: boolean, label?: string): Matchers {
  const check = (pass: boolean, msg: string, negMsg: string): void => {
    if (pass === negated) throwFail(`${label ? `${label}: ` : ""}${negated ? negMsg : msg}`);
  };
  const len = (v: unknown): number | undefined => {
    if (typeof v === "string" || Array.isArray(v)) return v.length;
    if (v instanceof Set || v instanceof Map) return v.size;
    if (ArrayBuffer.isView(v)) return v.byteLength;
    if (typeof v === "object" && v !== null && "length" in v) return Number((v as { length: unknown }).length);
    return undefined;
  };

  const m: Matchers = {
    toBe(expected) {
      check(Object.is(actual, expected), `${show(actual)} !== ${show(expected)}`, `${show(actual)}이(가) ${show(expected)}와 같으면 안 된다`);
    },
    toEqual(expected) {
      check(deepEqual(actual, expected), `깊은 비교 불일치\n  실제: ${show(actual, 400)}\n  기대: ${show(expected, 400)}`, `${show(actual)}이(가) 기대값과 같으면 안 된다`);
    },
    toContain(expected) {
      let pass: boolean;
      if (typeof actual === "string") pass = actual.includes(String(expected));
      else if (Array.isArray(actual)) pass = actual.some((x) => Object.is(x, expected));
      else if (actual instanceof Set) pass = actual.has(expected);
      else pass = false;
      check(pass, `${show(actual, 300)}에 ${show(expected)}가 없다`, `${show(actual, 300)}에 ${show(expected)}가 있으면 안 된다`);
    },
    toContainEqual(expected) {
      const pass = Array.isArray(actual) ? actual.some((x) => deepEqual(x, expected)) : false;
      check(pass, `배열에 ${show(expected)}와 같은 원소가 없다`, `배열에 ${show(expected)}와 같은 원소가 있으면 안 된다`);
    },
    toHaveLength(expected) {
      const n = len(actual);
      check(n === expected, `length ${String(n)} !== ${expected}`, `length가 ${expected}이면 안 된다`);
    },
    toMatch(expected) {
      const s = String(actual);
      const pass = expected instanceof RegExp ? expected.test(s) : s.includes(expected);
      check(pass, `${show(s, 300)}이(가) ${String(expected)}와 맞지 않는다`, `${show(s, 300)}이(가) ${String(expected)}와 맞으면 안 된다`);
    },
    toMatchObject(expected) {
      check(matchObject(actual, expected), `부분 매칭 실패\n  실제: ${show(actual, 400)}\n  기대: ${show(expected, 400)}`, "부분 매칭이 성립하면 안 된다");
    },
    toStartWith(expected) {
      const s = String(actual);
      check(s.startsWith(expected), `${show(s, 200)}이(가) ${show(expected)}로 시작하지 않는다`, `${show(s, 200)}이(가) ${show(expected)}로 시작하면 안 된다`);
    },
    toEndWith(expected) {
      const s = String(actual);
      check(s.endsWith(expected), `${show(s, 200)}이(가) ${show(expected)}로 끝나지 않는다`, `${show(s, 200)}이(가) ${show(expected)}로 끝나면 안 된다`);
    },
    toThrow(expected) {
      if (typeof actual !== "function") throwFail(`toThrow는 함수에만 쓸 수 있다: ${show(actual)}`);
      let threw = false;
      let err: unknown;
      try {
        (actual as () => unknown)();
      } catch (e) {
        threw = true;
        err = e;
      }
      // ★부정(.not.toThrow)일 때 "던지지 않았다"가 통과다. 기대 일치 여부는 던진 경우에만 본다.
      const pass = threw && throwMatches(err, expected);
      check(pass, threw ? `던진 값이 기대와 다르다: ${show(err)}` : "던지지 않았다", `던지면 안 된다: ${show(err)}`);
    },
    toBeNull() {
      check(actual === null, `${show(actual)} !== null`, "null이면 안 된다");
    },
    toBeUndefined() {
      check(actual === undefined, `${show(actual)} !== undefined`, "undefined이면 안 된다");
    },
    toBeDefined() {
      check(actual !== undefined, "undefined이다", "정의되어 있으면 안 된다");
    },
    toBeTruthy() {
      check(Boolean(actual), `${show(actual)}은(는) truthy가 아니다`, `${show(actual)}이(가) truthy이면 안 된다`);
    },
    toBeFalsy() {
      check(!actual, `${show(actual)}은(는) falsy가 아니다`, `${show(actual)}이(가) falsy이면 안 된다`);
    },
    toBeInstanceOf(expected) {
      const pass = typeof expected === "function" && actual instanceof (expected as new (...a: never[]) => object);
      const name = typeof expected === "function" ? expected.name : String(expected);
      check(pass, `${show(actual)}은(는) ${name}의 인스턴스가 아니다`, `${show(actual)}이(가) ${name}의 인스턴스이면 안 된다`);
    },
    toBeGreaterThan(n) {
      check((actual as number) > (n as number), `${show(actual)} <= ${String(n)}`, `${show(actual)}이(가) ${String(n)}보다 크면 안 된다`);
    },
    toBeGreaterThanOrEqual(n) {
      check((actual as number) >= (n as number), `${show(actual)} < ${String(n)}`, `${show(actual)}이(가) ${String(n)} 이상이면 안 된다`);
    },
    toBeLessThan(n) {
      check((actual as number) < (n as number), `${show(actual)} >= ${String(n)}`, `${show(actual)}이(가) ${String(n)}보다 작으면 안 된다`);
    },
    toBeLessThanOrEqual(n) {
      check((actual as number) <= (n as number), `${show(actual)} > ${String(n)}`, `${show(actual)}이(가) ${String(n)} 이하이면 안 된다`);
    },
    toBeCloseTo(n, digits = 2) {
      const diff = Math.abs((actual as number) - n);
      check(diff < Math.pow(10, -digits) / 2, `${show(actual)}이(가) ${n}에 가깝지 않다(차이 ${diff})`, `${show(actual)}이(가) ${n}에 가까우면 안 된다`);
    },
    toHaveProperty(path, value) {
      let cur: unknown = actual;
      let found = true;
      for (const key of path.split(".")) {
        if (typeof cur !== "object" || cur === null || !(key in cur)) {
          found = false;
          break;
        }
        cur = (cur as Record<string, unknown>)[key];
      }
      const pass = found && (arguments.length < 2 || deepEqual(cur, value));
      check(pass, `속성 ${path}이(가) 없거나 값이 다르다`, `속성 ${path}이(가) 있으면 안 된다`);
    },
    get not(): Matchers {
      return makeMatchers(actual, !negated, label);
    },
  };
  return m;
}

/** Promise 결과에 매처를 거는 래퍼(.resolves / .rejects). */
function makeAsync(promise: Promise<unknown>, wantReject: boolean, negated: boolean): AsyncMatchers {
  const settle = async (): Promise<unknown> => {
    /**
     * ★판정을 try 블록 **밖**에서 한다. 안에서 throwFail을 부르면 바로 아래 catch가
     * **자기가 던진 AssertionError를 잡아** 그것을 "거부 값"으로 반환한다 — 그러면
     * `rejects`가 이행한 Promise에도 통과해 **매처가 무력화**된다(자기 테스트가 잡았다).
     */
    let value: unknown;
    let rejected: boolean;
    try {
      value = await promise;
      rejected = false;
    } catch (e) {
      value = e;
      rejected = true;
    }
    if (wantReject && !rejected) throwFail(`거부될 줄 알았는데 ${show(value)}로 이행했다`);
    if (!wantReject && rejected) throw value;
    return value;
  };
  const run = async (fn: (m: Matchers) => void): Promise<void> => {
    const v = await settle();
    fn(makeMatchers(v, negated));
  };
  const a: AsyncMatchers = {
    /**
     * ★`rejects.toThrow()`는 "거부됐다" 자체가 이미 settle()에서 확인된다. 인자가 있으면
     * **거부 값**을 기대와 대조한다(생성자/정규식/문자열) — 동기 toThrow와 같은 규칙.
     */
    async toThrow(expected) {
      const v = await settle();
      const pass = throwMatches(v, expected);
      if (pass === negated) {
        throwFail(negated ? `던진 값이 기대와 맞으면 안 된다: ${show(v)}` : `던진 값이 기대와 다르다: ${show(v)}`);
      }
    },
    toBeInstanceOf: (expected) => run((m) => m.toBeInstanceOf(expected)),
    toBeTruthy: () => run((m) => m.toBeTruthy()),
    toBeUndefined: () => run((m) => m.toBeUndefined()),
    toMatchObject: (expected) => run((m) => m.toMatchObject(expected)),
    toBe: (expected) => run((m) => m.toBe(expected)),
    toEqual: (expected) => run((m) => m.toEqual(expected)),
    toContain: (expected) => run((m) => m.toContain(expected)),
    get not(): AsyncMatchers {
      return makeAsync(promise, wantReject, !negated);
    },
  };
  return a;
}

export interface Expectation extends Matchers {
  readonly resolves: AsyncMatchers;
  readonly rejects: AsyncMatchers;
}

export interface ExpectFn {
  /**
   * `label`은 bun의 2번째 인자(실패 메시지 라벨)다. 같은 단언을 여러 대상에 반복할 때
   * "어느 것이 틀렸는지"를 남기려고 쓴다(`expect(server, "imap").toBeDefined()`).
   */
  (actual: unknown, label?: string): Expectation;
  /** 타입만 보는 비대칭 매처 — deepEqual/toMatchObject 안에서 처리된다. */
  any(ctor: unknown): Asymmetric;
  stringContaining(sub: string): Asymmetric;
  arrayContaining(items: readonly unknown[]): Asymmetric;
}

function expectImpl(actual: unknown, label?: string): Expectation {
  const base = makeMatchers(actual, false, label);
  return Object.create(base, {
    resolves: { get: () => makeAsync(Promise.resolve(actual as Promise<unknown>), false, false) },
    rejects: { get: () => makeAsync(Promise.resolve(actual as Promise<unknown>), true, false) },
  }) as Expectation;
}

export const expect: ExpectFn = Object.assign(expectImpl, {
  any(ctor: unknown): Asymmetric {
    const name = typeof ctor === "function" ? ctor.name : String(ctor);
    return {
      [ASYMMETRIC]: true,
      name: `expect.any(${name})`,
      test(actual: unknown): boolean {
        if (ctor === String) return typeof actual === "string";
        if (ctor === Number) return typeof actual === "number";
        if (ctor === Boolean) return typeof actual === "boolean";
        return typeof ctor === "function" && actual instanceof (ctor as new (...a: never[]) => object);
      },
    };
  },
  stringContaining(sub: string): Asymmetric {
    return {
      [ASYMMETRIC]: true,
      name: `expect.stringContaining(${JSON.stringify(sub)})`,
      test: (actual: unknown): boolean => typeof actual === "string" && actual.includes(sub),
    };
  },
  arrayContaining(items: readonly unknown[]): Asymmetric {
    return {
      [ASYMMETRIC]: true,
      name: `expect.arrayContaining(${show(items)})`,
      test: (actual: unknown): boolean => Array.isArray(actual) && items.every((i) => actual.some((x) => deepEqual(x, i))),
    };
  },
});
