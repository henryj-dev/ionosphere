/**
 * `@ionosphere/testkit` — node:test 위에 bun:test와 같은 API 표면을 올린 테스트 지원 패키지.
 *
 * 테스트 파일은 `import { describe, expect, test } from "@ionosphere/testkit"` 한 줄만 쓴다.
 * 러너는 node:test이고 bun 의존은 0이다.
 *
 * ⚠ 런타임 코드가 이 패키지를 import하면 안 된다 — 각 패키지의 **devDependencies**로만 선언한다.
 */
export { describe, test, it, beforeAll, afterAll, beforeEach, afterEach, type TestFn, type DescribeFn } from "./runner.ts";
export { expect, type Matchers, type AsyncMatchers, type Expectation, type ExpectFn } from "./expect.ts";
