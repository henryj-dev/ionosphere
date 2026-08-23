/**
 * expect shim 자기 검증 — **통과와 실패 양방향**을 본다.
 *
 * ★왜 양방향인가: 매처가 "항상 통과"해도 테스트 스위트는 초록불이다. 이 저장소는
 * DKIM ed25519 사고에서 **결함 상태인데 기존 28건이 전부 pass**하는 것을 겪었다.
 * 3,900개 단언의 의미가 이 파일 하나에 달려 있으므로, 각 매처가 **틀렸을 때 실제로 던지는지**를
 * 확인해야 한다.
 *
 * ⚠ node:test를 직접 import한다 — 검증 대상(testkit)을 검증 도구로 쓸 수 없기 때문이다.
 */
import { describe, test } from "node:test";
import assert from "node:assert";
import { expect } from "../src/expect.ts";

/** fn이 AssertionError를 던지는지 — "실패해야 할 때 실패하는가"를 보는 도구. */
function throws(fn: () => void): boolean {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
}

describe("expect — 기본 매처", () => {
  test("toBe는 Object.is 의미다", () => {
    expect(1).toBe(1);
    expect("a").toBe("a");
    assert.ok(throws(() => expect(1).toBe(2)));
    // NaN은 === 로는 다르지만 Object.is로는 같다
    expect(NaN).toBe(NaN);
    assert.ok(throws(() => expect(0).toBe(-0)));
  });

  test("★toEqual은 undefined 프로퍼티를 무시한다 (조건부 스프레드 관례)", () => {
    // 이 저장소는 exactOptionalPropertyTypes 때문에 선택 필드를 **생략**하는데
    // 기대값에는 `host: undefined`를 쓴 곳이 있다. deepStrictEqual이면 여기서 깨진다.
    expect({ a: 1 }).toEqual({ a: 1, b: undefined });
    expect({ a: 1, b: undefined }).toEqual({ a: 1 });
    // 그렇다고 아무거나 통과하면 안 된다
    assert.ok(throws(() => expect({ a: 1 }).toEqual({ a: 2 })));
    assert.ok(throws(() => expect({ a: 1 }).toEqual({ a: 1, b: 2 })));
  });

  test("toEqual — Set·Map·TypedArray는 내용으로 비교한다", () => {
    expect(new Set([1, 2])).toEqual(new Set([2, 1]));
    expect(new Map([["k", 1]])).toEqual(new Map([["k", 1]]));
    expect(new Uint8Array([1, 2, 3])).toEqual(new Uint8Array([1, 2, 3]));
    assert.ok(throws(() => expect(new Set([1])).toEqual(new Set([1, 2]))));
    assert.ok(throws(() => expect(new Uint8Array([1])).toEqual(new Uint8Array([2]))));
  });

  test("toEqual — 순환 참조에서 죽지 않는다", () => {
    const a: Record<string, unknown> = { x: 1 };
    a.self = a;
    const b: Record<string, unknown> = { x: 1 };
    b.self = b;
    expect(a).toEqual(b);
  });

  test("toContain — 문자열·배열·Set", () => {
    expect("hello world").toContain("world");
    expect([1, 2, 3]).toContain(2);
    expect(new Set(["a"])).toContain("a");
    assert.ok(throws(() => expect("hello").toContain("bye")));
    assert.ok(throws(() => expect([1]).toContain(2)));
  });

  test("toHaveLength — 문자열·배열·Set", () => {
    expect("abc").toHaveLength(3);
    expect([1, 2]).toHaveLength(2);
    expect(new Set([1])).toHaveLength(1);
    assert.ok(throws(() => expect("abc").toHaveLength(4)));
  });

  test("toThrow — 없음·생성자·정규식·문자열 4형태", () => {
    class MyErr extends Error {}
    expect(() => {
      throw new Error("boom");
    }).toThrow();
    expect(() => {
      throw new MyErr("x");
    }).toThrow(MyErr);
    expect(() => {
      throw new Error("포트 값이 잘못됨");
    }).toThrow(/포트/);
    expect(() => {
      throw new Error("tls_mode 오류");
    }).toThrow("tls_mode");
    // 던지지 않으면 실패
    assert.ok(throws(() => expect(() => undefined).toThrow()));
    // 다른 생성자면 실패
    assert.ok(
      throws(() =>
        expect(() => {
          throw new Error("x");
        }).toThrow(MyErr),
      ),
    );
  });

  test("toMatchObject — 부분 매칭, Error도 속성으로 읽는다", () => {
    expect({ a: 1, b: 2 }).toMatchObject({ a: 1 });
    const e = Object.assign(new Error("x"), { type: "accountNotFound" });
    expect(e).toMatchObject({ type: "accountNotFound" });
    assert.ok(throws(() => expect({ a: 1 }).toMatchObject({ a: 2 })));
    assert.ok(throws(() => expect({ a: 1 }).toMatchObject({ b: 1 })));
  });

  test("비교 매처", () => {
    expect(5).toBeGreaterThan(3);
    expect(5).toBeGreaterThanOrEqual(5);
    expect(3).toBeLessThan(5);
    expect(3).toBeLessThanOrEqual(3);
    expect(0.1 + 0.2).toBeCloseTo(0.3);
    assert.ok(throws(() => expect(3).toBeGreaterThan(5)));
    assert.ok(throws(() => expect(0.1).toBeCloseTo(0.3)));
  });

  test("null/undefined/truthy 계열", () => {
    expect(null).toBeNull();
    expect(undefined).toBeUndefined();
    expect(1).toBeDefined();
    expect("x").toBeTruthy();
    expect("").toBeFalsy();
    assert.ok(throws(() => expect(0).toBeNull()));
    assert.ok(throws(() => expect(undefined).toBeDefined()));
  });

  test("toStartWith·toEndWith·toMatch", () => {
    expect("hello").toStartWith("he");
    expect("hello").toEndWith("lo");
    expect("hello").toMatch(/ell/);
    expect("hello").toMatch("ell");
    assert.ok(throws(() => expect("hello").toStartWith("lo")));
  });

  test("toHaveProperty — 점 경로", () => {
    expect({ a: { b: 1 } }).toHaveProperty("a.b");
    expect({ a: { b: 1 } }).toHaveProperty("a.b", 1);
    assert.ok(throws(() => expect({ a: 1 }).toHaveProperty("b")));
    assert.ok(throws(() => expect({ a: { b: 1 } }).toHaveProperty("a.b", 2)));
  });
});

describe("expect — .not 체이닝", () => {
  test("부정이 양방향으로 동작한다", () => {
    expect(1).not.toBe(2);
    expect("abc").not.toContain("z");
    expect(null).not.toBeUndefined();
    expect(() => undefined).not.toThrow();
    // 부정이 틀렸을 때는 던져야 한다 — 이게 없으면 .not이 무조건 통과가 된다
    assert.ok(throws(() => expect(1).not.toBe(1)));
    assert.ok(throws(() => expect("abc").not.toContain("a")));
    assert.ok(
      throws(() =>
        expect(() => {
          throw new Error("x");
        }).not.toThrow(),
      ),
    );
  });
});

describe("expect — resolves/rejects", () => {
  test("rejects.toThrow — 거부되면 통과, 이행하면 실패", async () => {
    await expect(Promise.reject(new Error("boom"))).rejects.toThrow();
    await expect(Promise.reject(new Error("포트 오류"))).rejects.toThrow(/포트/);
    let failed = false;
    try {
      await expect(Promise.resolve(1)).rejects.toThrow();
    } catch {
      failed = true;
    }
    assert.ok(failed, "이행한 Promise에 rejects를 걸면 실패해야 한다");
  });

  test("rejects.toBeInstanceOf", async () => {
    class E extends Error {}
    await expect(Promise.reject(new E("x"))).rejects.toBeInstanceOf(E);
    let failed = false;
    try {
      await expect(Promise.reject(new Error("x"))).rejects.toBeInstanceOf(E);
    } catch {
      failed = true;
    }
    assert.ok(failed);
  });

  test("resolves 계열", async () => {
    await expect(Promise.resolve({ a: 1 })).resolves.toMatchObject({ a: 1 });
    await expect(Promise.resolve(undefined)).resolves.toBeUndefined();
    await expect(Promise.resolve(1)).resolves.toBe(1);
  });

  test("rejects.not 체이닝", async () => {
    class E extends Error {}
    await expect(Promise.reject(new Error("x"))).rejects.not.toBeInstanceOf(E);
  });
});

describe("expect — 비대칭 매처", () => {
  test("any/stringContaining/arrayContaining", () => {
    expect({ id: "x" }).toMatchObject({ id: expect.any(String) });
    expect({ msg: "hello world" }).toMatchObject({ msg: expect.stringContaining("world") });
    expect([1, 2, 3]).toEqual(expect.arrayContaining([1, 3]));
    expect([{ a: 1 }]).toContainEqual({ a: 1 });
    // 틀렸을 때 실패하는지
    assert.ok(throws(() => expect({ id: 1 }).toMatchObject({ id: expect.any(String) })));
    assert.ok(throws(() => expect([1]).toEqual(expect.arrayContaining([2]))));
  });
});
