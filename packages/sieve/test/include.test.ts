/**
 * Sieve `include` (RFC 6609).
 *
 * ★가장 위험한 것은 **순환**이다. A→B→A는 `:once` 없이도 만들 수 있고, 이 서버는 모든
 * 프로토콜이 한 프로세스라 배달 경로에서 도는 무한 루프는 **수신·발송 전체를 멈춘다**.
 * 그래서 깊이 상한으로 끊고, 그 동작을 여기서 고정한다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { runSieve, SieveError, type SieveEnv } from "../src/interpret.ts";

function env(scripts: Record<string, string> = {}, over: Partial<SieveEnv> = {}): SieveEnv {
  return {
    headers: new Map([["subject", ["hello"]]]),
    envelopeFrom: "a@x.test",
    envelopeTo: ["b@y.test"],
    size: 100,
    scripts: new Map(Object.entries(scripts)),
    ...over,
  };
}

describe("include", () => {
  test("부른 스크립트의 처분이 결과에 쌓인다", () => {
    const r = runSieve('require ["include","fileinto"]; include "child";', env({ child: 'require ["fileinto"]; fileinto "Child";' }));
    expect(r.fileinto).toEqual(["Child"]);
    expect(r.keep).toBe(false); // fileinto가 암묵 keep을 취소한다
  });

  /** ★부작용을 공유한다(§3.2: 하나의 스크립트처럼 동작한다) — 나누면 처분이 사라진다. */
  test("부른 쪽과 부작용을 공유한다", () => {
    const r = runSieve(
      'require ["include","fileinto","imap4flags"]; fileinto "Parent"; include "child";',
      env({ child: 'require ["fileinto","imap4flags"]; addflag "\\\\Seen"; fileinto "Child";' }),
    );
    expect(r.fileinto).toEqual(["Parent", "Child"]);
    expect(r.flags).toEqual(["\\Seen"]);
  });

  test("중첩 include", () => {
    const r = runSieve('require ["include","fileinto"]; include "a";', env({
      a: 'require ["include"]; include "b";',
      b: 'require ["fileinto"]; fileinto "Deep";',
    }));
    expect(r.fileinto).toEqual(["Deep"]);
  });

  /** ★순환은 깊이로 끊는다 — 이름 추적보다 확실하다(이름을 바꿔 가며 도는 형태까지 잡는다). */
  test("순환 include는 깊이 상한에서 SieveError", () => {
    expect(() =>
      runSieve('require ["include"]; include "a";', env({ a: 'require ["include"]; include "b";', b: 'require ["include"]; include "a";' })),
    ).toThrow(SieveError);
  });

  test("자기 자신을 부르는 것도 끊긴다", () => {
    expect(() => runSieve('require ["include"]; include "self";', env({ self: 'require ["include"]; include "self";' }))).toThrow(SieveError);
  });

  test(":once는 두 번째 호출을 건너뛴다", () => {
    const r = runSieve('require ["include","fileinto"]; include :once "child"; include :once "child";', env({
      child: 'require ["fileinto"]; fileinto "Once";',
    }));
    expect(r.fileinto).toEqual(["Once"]); // 중복 제거가 아니라 실제로 한 번만 돈다
  });

  test(":once 없이 두 번 부르면 두 번 돈다", () => {
    const r = runSieve('require ["include","imap4flags"]; include "child"; include "child";', env({
      child: 'require ["imap4flags"]; addflag "$x";',
    }));
    expect(r.flags).toEqual(["$x"]); // 플래그는 집합이라 결과는 같지만 실행은 두 번이다
  });

  test("없는 스크립트는 SieveError, :optional이면 조용히 넘어간다", () => {
    expect(() => runSieve('require ["include"]; include "nope";', env())).toThrow(SieveError);
    const r = runSieve('require ["include","fileinto"]; include :optional "nope"; fileinto "After";', env());
    expect(r.fileinto).toEqual(["After"]); // 넘어간 뒤 계속 실행된다
  });

  /** `:global`은 이 저장소에 개념이 없다 — 있는 척하면 만들 수 없는 것을 부르게 된다. */
  test(":global은 거절하되 :optional이면 넘어간다", () => {
    expect(() => runSieve('require ["include"]; include :global "g";', env())).toThrow(SieveError);
    const r = runSieve('require ["include","fileinto"]; include :global :optional "g"; fileinto "After";', env());
    expect(r.fileinto).toEqual(["After"]);
  });
});

describe("return (RFC 6609 §3.3)", () => {
  /** ★`return`은 **이 스크립트만** 끝낸다 — 바깥은 계속 돈다. `stop`과의 차이가 이것이다. */
  test("include된 스크립트의 return은 바깥을 멈추지 않는다", () => {
    const r = runSieve('require ["include","fileinto"]; include "child"; fileinto "After";', env({
      child: 'require ["fileinto"]; fileinto "Before"; return; fileinto "Never";',
    }));
    expect(r.fileinto).toEqual(["Before", "After"]);
  });

  /** 반대로 `stop`은 바깥까지 멈춘다(§3.2). */
  test("include된 스크립트의 stop은 바깥까지 멈춘다", () => {
    const r = runSieve('require ["include","fileinto"]; include "child"; fileinto "After";', env({
      child: 'require ["fileinto"]; fileinto "Before"; stop;',
    }));
    expect(r.fileinto).toEqual(["Before"]);
  });

  test("최상위 return은 stop과 같다", () => {
    const r = runSieve('require ["include","fileinto"]; fileinto "A"; return; fileinto "B";', env());
    expect(r.fileinto).toEqual(["A"]);
  });

  /** 두 번째 include는 첫 include의 return에 영향받지 않아야 한다(상태 복원). */
  test("한 include의 return이 다음 include를 막지 않는다", () => {
    const r = runSieve('require ["include","fileinto"]; include "a"; include "b";', env({
      a: 'require ["fileinto"]; fileinto "A"; return;',
      b: 'require ["fileinto"]; fileinto "B";',
    }));
    expect(r.fileinto).toEqual(["A", "B"]);
  });
});
