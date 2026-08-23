/**
 * 리스너 사양 파서 — env 오타가 조용히 넘어가면 안 되는 자리다.
 *
 * 잘못 읽으면 두 방향으로 사고가 난다: **열었다고 생각한 포트가 안 열려 있거나**,
 * **껐다고 생각한 포트가 열려 있거나**. 둘 다 로그 없이 지나가므로 파싱은 엄격하고
 * 실패는 시끄러워야 한다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import {
  LISTENER_ENV_SUFFIX,
  LISTENER_NAMES,
  ListenerSpecError,
  listenersFromEnv,
  parseListenerSpec,
  resolveListener,
} from "../src/listeners.ts";

describe("parseListenerSpec", () => {
  test("포트만", () => {
    expect(parseListenerSpec("8080")).toEqual({ enabled: true, port: 8080 });
    expect(parseListenerSpec("  8080  ")).toEqual({ enabled: true, port: 8080 });
  });

  test("주소 + 포트", () => {
    expect(parseListenerSpec("0.0.0.0:8080")).toEqual({ enabled: true, host: "0.0.0.0", port: 8080 });
    expect(parseListenerSpec("127.0.0.1:9090")).toEqual({ enabled: true, host: "127.0.0.1", port: 9090 });
  });

  /** 주소만 줄 때 콜론을 요구하는 이유: `0.0.0.0`과 `8080`을 형태만으로 구분할 수 없다. */
  test("주소만(끝 콜론) — 포트는 기본값을 쓴다", () => {
    expect(parseListenerSpec("0.0.0.0:")).toEqual({ enabled: true, host: "0.0.0.0" });
    expect(parseListenerSpec("127.0.0.1:")).toEqual({ enabled: true, host: "127.0.0.1" });
  });

  test("IPv6은 대괄호로", () => {
    expect(parseListenerSpec("[::]:8080")).toEqual({ enabled: true, host: "::", port: 8080 });
    expect(parseListenerSpec("[::1]:")).toEqual({ enabled: true, host: "::1" });
  });

  /** 대괄호 없는 IPv6은 포트와 구분할 수 없다 — 추측하지 않고 거절한다. */
  test("대괄호 없는 IPv6은 거절하고 고치는 법을 알려 준다", () => {
    expect(() => parseListenerSpec("::1:8080")).toThrow(/대괄호/);
  });

  test("끄기", () => {
    for (const off of ["off", "OFF", "false", "no", "0", "disabled"]) {
      expect(parseListenerSpec(off)).toEqual({ enabled: false });
    }
  });

  test("잘못된 포트는 던진다", () => {
    expect(() => parseListenerSpec("0.0.0.0:70000")).toThrow(ListenerSpecError);
    expect(() => parseListenerSpec("0.0.0.0:abc")).toThrow(ListenerSpecError);
    expect(() => parseListenerSpec("0.0.0.0:-1")).toThrow(ListenerSpecError);
    expect(() => parseListenerSpec("")).toThrow(ListenerSpecError);
  });

  /** 포트 0은 "빈 포트 자동 할당"이라 유효하다 — 테스트가 이 값을 쓴다. */
  test("포트 0은 유효(자동 할당)", () => {
    expect(parseListenerSpec("127.0.0.1:0")).toEqual({ enabled: true, host: "127.0.0.1", port: 0 });
  });
});

/**
 * 바인딩 주소 검증 — `0`은 OFF 값인데 `0:8080`은 node가 정수 IP로 재해석해 **0.0.0.0**,
 * 즉 전면 개방이 된다. 한 글자 차이로 의미가 정반대가 되는 자리라 추측하지 않고 거절한다.
 */
describe("parseListenerSpec: 바인딩 주소 검증", () => {
  test("정수 IP 표기는 거절한다 — 이게 M-12의 실제 변종이다", () => {
    expect(() => parseListenerSpec("0:8080")).toThrow(ListenerSpecError);
    expect(() => parseListenerSpec("0:8080")).toThrow(/정수 IP 표기/);
    expect(() => parseListenerSpec("2130706433:8080")).toThrow(ListenerSpecError); // 10진 127.0.0.1
    expect(() => parseListenerSpec("0x7f000001:8080")).toThrow(ListenerSpecError); // 16진
    expect(() => parseListenerSpec("192.168.1:8080")).toThrow(ListenerSpecError); // 생략형(→192.168.0.1)
    expect(() => parseListenerSpec("0177.0.0.1:8080")).toThrow(ListenerSpecError); // 8진
  });

  /** 회귀: 감사 §6 항목 8이 확인한 기존 올바른 동작 — 주소를 비우면 기본 host가 보존된다. */
  test('":8080"은 host를 지정하지 않는다(기본 host 보존)', () => {
    expect(parseListenerSpec(":8080")).toEqual({ enabled: true, port: 8080 });
    expect(resolveListener(parseListenerSpec(":8080"), 9999, "127.0.0.1")).toEqual({
      enabled: true,
      port: 8080,
      host: "127.0.0.1",
    });
  });

  test("`0` 단독은 여전히 OFF다", () => {
    expect(parseListenerSpec("0")).toEqual({ enabled: false });
  });

  test("정상 IP·호스트명은 통과한다", () => {
    expect(parseListenerSpec("127.0.0.1:8080")).toEqual({ enabled: true, host: "127.0.0.1", port: 8080 });
    expect(parseListenerSpec("0.0.0.0:8080")).toEqual({ enabled: true, host: "0.0.0.0", port: 8080 });
    expect(parseListenerSpec("[::1]:8080")).toEqual({ enabled: true, host: "::1", port: 8080 });
    expect(parseListenerSpec("localhost:8080")).toEqual({ enabled: true, host: "localhost", port: 8080 });
    expect(parseListenerSpec("mx.ionosphere.test:25")).toEqual({ enabled: true, host: "mx.ionosphere.test", port: 25 });
    // 링크로컬 바인딩에는 zone id가 실제로 필요하다.
    expect(parseListenerSpec("[fe80::1%eth0]:8080")).toEqual({ enabled: true, host: "fe80::1%eth0", port: 8080 });
  });

  test("IP도 호스트명도 아니면 거절한다", () => {
    expect(() => parseListenerSpec("-bad-:8080")).toThrow(ListenerSpecError);
    expect(() => parseListenerSpec("a_b:8080")).toThrow(ListenerSpecError);
    expect(() => parseListenerSpec("999.999.999.999:8080")).toThrow(ListenerSpecError);
  });

  test("어느 env가 잘못됐는지 알려 준다", () => {
    expect(() => listenersFromEnv({ IONOSPHERE_LISTEN_ADMIN: "0:8080" })).toThrow(/IONOSPHERE_LISTEN_ADMIN/);
  });
});

describe("listenersFromEnv", () => {
  test("IONOSPHERE_LISTEN_* 만 읽는다", () => {
    const got = listenersFromEnv({
      IONOSPHERE_LISTEN_ADMIN: "0.0.0.0:8080",
      IONOSPHERE_LISTEN_METRICS: "off",
      IONOSPHERE_ADMIN_PORT: "9999", // 기존 변수는 여기서 읽지 않는다
      UNRELATED: "x",
    });
    expect(got).toEqual({ admin: { enabled: true, host: "0.0.0.0", port: 8080 }, metrics: { enabled: false } });
  });

  test("지정이 없으면 빈 오버라이드 — 기본 동작이 바뀌지 않는다", () => {
    expect(listenersFromEnv({})).toEqual({});
  });

  test("오타는 어느 변수인지 알려 주며 던진다", () => {
    expect(() => listenersFromEnv({ IONOSPHERE_LISTEN_HTTPS_FRONT: "0.0.0.0:99999" })).toThrow(/IONOSPHERE_LISTEN_HTTPS_FRONT/);
  });

  /** 이름과 env 접미사가 어긋나면 "설정했는데 안 먹는" 상태가 된다. */
  test("모든 리스너 이름에 env 접미사가 있다", () => {
    expect(LISTENER_NAMES.length).toBe(Object.keys(LISTENER_ENV_SUFFIX).length);
    for (const n of LISTENER_NAMES) expect(LISTENER_ENV_SUFFIX[n]).toBeTruthy();
    // 접미사는 서로 겹치면 안 된다(겹치면 한쪽이 먹히지 않는다)
    expect(new Set(Object.values(LISTENER_ENV_SUFFIX)).size).toBe(LISTENER_NAMES.length);
  });
});

describe("resolveListener", () => {
  test("오버라이드가 없으면 기존 포트·기본 주소를 쓴다", () => {
    expect(resolveListener(undefined, 8080, undefined)).toEqual({ enabled: true, port: 8080, host: undefined });
    expect(resolveListener(undefined, 9090, "127.0.0.1")).toEqual({ enabled: true, port: 9090, host: "127.0.0.1" });
  });

  test("포트가 어디에도 없으면 기동하지 않는다", () => {
    expect(resolveListener(undefined, undefined, undefined)).toBeUndefined();
    // enabled만 켜고 포트를 안 주면 열 수 없다 — 조용히 0번 포트로 열지 않는다
    expect(resolveListener({ enabled: true }, undefined, undefined)).toBeUndefined();
  });

  test("off는 기존 포트가 있어도 기동을 막는다", () => {
    expect(resolveListener({ enabled: false }, 8080, undefined)).toBeUndefined();
  });

  test("주소 오버라이드가 기본 주소를 이긴다 — 루프백을 여는 유일한 방법", () => {
    expect(resolveListener({ enabled: true, host: "0.0.0.0" }, 9090, "127.0.0.1")).toEqual({
      enabled: true,
      port: 9090,
      host: "0.0.0.0",
    });
  });

  test("포트 오버라이드가 기존 포트를 이긴다", () => {
    expect(resolveListener({ enabled: true, port: 18080 }, 8080, undefined)?.port).toBe(18080);
  });
});
