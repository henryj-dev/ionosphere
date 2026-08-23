/**
 * DNS 응답 출처 검증.
 *
 * 과거 결함: `socket.on("message", (msg) => ...)`가 `rinfo`를 버려 **아무 IP에서 온 첫
 * 데이터그램이든** 응답으로 채택했다. 트랜잭션 ID도 `Math.random`이라 예측 가능했다
 * (V8 xorshift128+는 출력 몇 개로 내부 상태가 복원된다). 둘이 겹치면 off-path 공격자가
 * 위조 응답을 심을 수 있고, 그 결과는 캐시에 들어가 SPF/DKIM/DMARC/MTA-STS 판정 근거가 된다.
 * 자체 재귀 리졸버(IONOSPHERE_RECURSIVE_DNS=1)에서 캐시 포이즈닝은 곧 인증 우회다.
 *
 * 여기서는 판정 로직을 검증한다. 소켓 배선은 한 줄이지만(출처가 다르면 무시하고 계속 대기),
 * 실제 스푸핑 재현은 서로 다른 로컬 IP에서 53번 포트 바인딩이 필요해 단위테스트로는 세우기 어렵다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { isExpectedSource } from "../src/transport.ts";

describe("isExpectedSource", () => {
  test("물어본 서버에서 온 응답은 받는다", () => {
    expect(isExpectedSource("198.41.0.4", "198.41.0.4")).toBe(true);
    expect(isExpectedSource("2001:db8::1", "2001:db8::1")).toBe(true);
  });

  test("다른 IP에서 온 응답은 버린다 — 위조 방어의 본체", () => {
    expect(isExpectedSource("198.41.0.4", "6.6.6.6")).toBe(false);
    expect(isExpectedSource("198.41.0.4", "198.41.0.5")).toBe(false);
    expect(isExpectedSource("2001:db8::1", "2001:db8::2")).toBe(false);
  });

  test("IPv4-mapped IPv6 표기 차이는 흡수한다(같은 주소를 다르게 적은 것뿐)", () => {
    expect(isExpectedSource("1.2.3.4", "::ffff:1.2.3.4")).toBe(true);
    expect(isExpectedSource("::ffff:1.2.3.4", "1.2.3.4")).toBe(true);
  });

  test("IPv6 대소문자는 구분하지 않는다", () => {
    expect(isExpectedSource("2001:DB8::1", "2001:db8::1")).toBe(true);
  });

  test("호스트명으로 지정한 업스트림은 검사를 생략한다(문자열 비교가 성립하지 않음)", () => {
    // OS가 해석한 주소로 응답이 오므로 비교할 수 없다 — 그 구성을 깨뜨리지 않으려는 절충.
    expect(isExpectedSource("dns.example.test", "9.9.9.9")).toBe(true);
  });
});
