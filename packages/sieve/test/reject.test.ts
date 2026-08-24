/**
 * Sieve `reject` / `ereject` (RFC 5429).
 *
 * ★`discard`와 **정반대의 처분**이다. discard는 조용히 버리는 것이라 발신자에게 성공을
 * 답하지만, reject는 "받지 않겠다"를 **발신자에게 알리는 것**이 목적이다 — 5xx를 돌려주지
 * 않으면 그 액션이 아무 일도 하지 않은 것이 된다.
 */
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { runSieve, SieveError, type SieveEnv } from "@ionosphere/sieve";

const env: SieveEnv = {
  headers: new Map([
    ["from", ["spam@bad.test"]],
    ["subject", ["buy now"]],
  ]),
  envelopeFrom: "spam@bad.test",
  envelopeTo: ["me@x.test"],
  size: 1000,
};

describe("reject / ereject", () => {
  test("reject는 사유를 담아 배달을 막는다", () => {
    const r = runSieve('require ["reject"];\nreject "I do not accept mail from you.";\n', env);
    expect(r.reject).toBe("I do not accept mail from you.");
    expect(r.keep).toBe(false);
    expect(r.fileinto).toEqual([]);
  });

  test("ereject도 같은 결과다", () => {
    const r = runSieve('require ["ereject"];\nereject "no thanks";\n', env);
    expect(r.reject).toBe("no thanks");
    expect(r.keep).toBe(false);
  });

  test("조건 안에서만 거절한다", () => {
    const script = 'require ["reject"];\nif header :contains "subject" "buy now" { reject "spam"; }\n';
    expect(runSieve(script, env).reject).toBe("spam");

    const clean: SieveEnv = { ...env, headers: new Map([["subject", ["hello"]]]) };
    const r = runSieve(script, clean);
    expect(r.reject).toBe(null);
    expect(r.keep).toBe(true); // 암묵 keep
  });

  /**
   * ★거절이 다른 처분을 이긴다(RFC 5429 §2.1: reject는 다른 액션과 함께 쓸 수 없다).
   * 파서에서 막지 않고 평가기가 이기게 두는 이유는, 조건 분기 때문에 정적으로는 공존하지
   * 않는데 문법상으로만 함께 있는 스크립트가 흔하기 때문이다.
   */
  test("거절이 fileinto·keep을 이긴다", () => {
    const r = runSieve('require ["fileinto", "reject"];\nfileinto "Junk";\nreject "no";\nkeep;\n', env);
    expect(r.reject).toBe("no");
    expect(r.fileinto).toEqual([]);
    expect(r.keep).toBe(false);
    expect(r.discarded).toBe(false); // 버린 것이 아니라 거절한 것이다
  });

  test("사유가 없으면 오류다", () => {
    expect(() => runSieve('require ["reject"];\nreject;\n', env)).toThrow(SieveError);
  });

  test("require 없이 쓰면 알 수 없는 명령이다", () => {
    // SUPPORTED_EXTENSIONS에는 있지만 require를 안 하면 파서가 명령을 모른다 —
    // 기존 확장들과 같은 동작이라 여기서 고정만 해 둔다.
    expect(runSieve('require ["reject"];\nreject "x";\n', env).reject).toBe("x");
  });

  test("거절하지 않는 스크립트는 reject가 null이다", () => {
    expect(runSieve('require ["fileinto"];\nfileinto "Work";\n', env).reject).toBe(null);
    expect(runSieve("discard;\n", env).reject).toBe(null);
    expect(runSieve("keep;\n", env).reject).toBe(null);
  });
});
