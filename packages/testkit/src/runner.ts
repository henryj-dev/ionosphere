/**
 * `describe`/`test`/훅 — node:test 어댑터.
 *
 * ★이 파일의 가장 중요한 일은 **3번째 인자 타임아웃을 흡수**하는 것이다.
 * bun은 `test(name, fn, 20000)`을 받는데 **node는 그 인자를 조용히 무시한다** — 경고도
 * 에러도 없다. 그대로 두면 90초짜리 e2e가 전역 타임아웃으로 강등돼 **CI에서만 간헐 실패**하는,
 * 이 저장소가 여러 번 겪은 유형의 사고가 된다. 그래서 여기서 `{ timeout }` 옵션으로 옮긴다.
 *
 * `test.skip`·`describe.skip`은 **함수로도 값으로도** 쓰인다
 * (`const d = PG_URL ? describe : describe.skip`, `(pgUrl ? test : test.skip)(...)`).
 * 그래서 프로퍼티가 아니라 호출 가능한 함수여야 한다.
 */
import { after, before, beforeEach as nodeBeforeEach, afterEach as nodeAfterEach, describe as nodeDescribe, test as nodeTest } from "node:test";

type Fn = () => void | Promise<void>;
type SuiteFn = () => void;

interface TestOpts {
  skip?: boolean;
  timeout?: number;
}

/** bun 시그니처(name, fn, timeout?)를 node의 (name, opts, fn)으로 옮긴다. */
function toOpts(timeout: number | undefined, skip: boolean): TestOpts {
  return {
    ...(skip ? { skip: true } : {}),
    ...(timeout !== undefined ? { timeout } : {}),
  };
}

export interface TestFn {
  (name: string, fn: Fn, timeout?: number): void;
  skip(name: string, fn?: Fn, timeout?: number): void;
  skipIf(cond: boolean): (name: string, fn: Fn, timeout?: number) => void;
  todo(name: string, fn?: Fn): void;
}

export interface DescribeFn {
  (name: string, fn: SuiteFn): void;
  skip(name: string, fn?: SuiteFn): void;
  skipIf(cond: boolean): (name: string, fn: SuiteFn) => void;
  /**
   * `describe.each(rows)(name, fn)` — 행마다 스위트를 만든다.
   * 이름의 `%s`/`%d`/`%i`는 행 값으로 치환한다(bun/jest 관례, 이 저장소는 `%s`만 쓴다).
   */
  each<T>(rows: readonly T[]): (name: string, fn: (row: T) => void) => void;
}

function makeTest(): TestFn {
  const t = ((name: string, fn: Fn, timeout?: number): void => {
    nodeTest(name, toOpts(timeout, false), fn);
  }) as TestFn;
  // 테스트 스킵도 같은 이유로 **본문을 넘기지 않는다**(위 describe.skip 주석 참고).
  t.skip = (name: string, _fn?: Fn, timeout?: number): void => {
    nodeTest(name, toOpts(timeout, true), (): void => {});
  };
  t.skipIf = (cond: boolean) => (name: string, fn: Fn, timeout?: number) => {
    nodeTest(name, toOpts(timeout, cond), cond ? (): void => {} : fn);
  };
  t.todo = (name: string, fn?: Fn): void => {
    nodeTest(name, { todo: true }, fn ?? ((): void => {}));
  };
  return t;
}

function fmt(name: string, row: unknown): string {
  const s = typeof row === "string" ? row : Array.isArray(row) ? row.map(String).join(", ") : String(row);
  return name.replace(/%[sdi]/g, s);
}

function makeDescribe(): DescribeFn {
  const d = ((name: string, fn: SuiteFn): void => {
    nodeDescribe(name, fn);
  }) as DescribeFn;
  /**
   * ★스킵은 **콜백을 아예 등록하지 않는** 방식으로 한다. `describe(name, {skip:true}, fn)`은
   * node에서는 정상이지만 **bun은 그 옵션을 무시하고 fn을 실행한다**(실측: node 1 skipped /
   * bun 1 skip + 1 fail). 이전이 끝나면 bun을 안 쓰지만 **이전 중에는 양쪽이 다 살아 있어야**
   * 안전망이 유지되므로, 러너에 의존하지 않는 방식을 쓴다.
   *
   * 빈 스위트로 등록해 "건너뛰었다"는 사실 자체는 보고에 남긴다.
   */
  d.skip = (name: string, _fn?: SuiteFn): void => {
    nodeDescribe(name, { skip: true }, (): void => {});
  };
  d.skipIf = (cond: boolean) => (name: string, fn: SuiteFn) => {
    if (cond) {
      nodeDescribe(name, { skip: true }, (): void => {});
      return;
    }
    nodeDescribe(name, fn);
  };
  d.each = <T,>(rows: readonly T[]) => (name: string, fn: (row: T) => void): void => {
    for (const row of rows) nodeDescribe(fmt(name, row), () => fn(row));
  };
  return d;
}

export const test: TestFn = makeTest();
export const it: TestFn = test;
export const describe: DescribeFn = makeDescribe();

/**
 * 훅 — bun 이름을 node 이름으로 잇는다. 3번째가 아니라 **2번째** 인자가 타임아웃이다
 * (`beforeAll(fn, 25000)`), 이것도 node의 `{ timeout }`으로 옮겨야 한다.
 */
export function beforeAll(fn: Fn, timeout?: number): void {
  before(fn, timeout !== undefined ? { timeout } : {});
}
export function afterAll(fn: Fn, timeout?: number): void {
  after(fn, timeout !== undefined ? { timeout } : {});
}
export function beforeEach(fn: Fn, timeout?: number): void {
  nodeBeforeEach(fn, timeout !== undefined ? { timeout } : {});
}
export function afterEach(fn: Fn, timeout?: number): void {
  nodeAfterEach(fn, timeout !== undefined ? { timeout } : {});
}
