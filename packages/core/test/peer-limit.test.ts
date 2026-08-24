/**
 * IP 프리픽스별 동시 연결 상한.
 *
 * `MAX_LISTENER_CONNECTIONS`(1024)는 **전역**이라 한 주소가 혼자 소진할 수 있었다. 그러면
 * `limits.ts`가 그 값에 적어 둔 취지 — "초과분을 즉시 끊으면 이미 붙은 세션은 살아남는다" —
 * 가 성립하지 않는다: 새 연결이 전부 거절되므로 **정상 사용자도 접속하지 못한다.**
 */
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { PeerConnectionLimiter } from "@ionosphere/core";

describe("PeerConnectionLimiter", () => {
  test("상한까지 받고 그 뒤로 거절한다", () => {
    const l = new PeerConnectionLimiter(3);
    expect(l.tryAcquire("1.2.3.4")).toBe(true);
    expect(l.tryAcquire("1.2.3.4")).toBe(true);
    expect(l.tryAcquire("1.2.3.4")).toBe(true);
    expect(l.tryAcquire("1.2.3.4")).toBe(false);
  });

  test("놓으면 다시 받는다", () => {
    const l = new PeerConnectionLimiter(1);
    expect(l.tryAcquire("1.2.3.4")).toBe(true);
    expect(l.tryAcquire("1.2.3.4")).toBe(false);
    l.release("1.2.3.4");
    expect(l.tryAcquire("1.2.3.4")).toBe(true);
  });

  /** ★한 주소가 상한에 닿아도 **다른 주소는 영향이 없어야** 한다 — 이 장치의 존재 이유다. */
  test("한 주소가 막혀도 다른 주소는 통과한다", () => {
    const l = new PeerConnectionLimiter(2);
    l.tryAcquire("1.2.3.4");
    l.tryAcquire("1.2.3.4");
    expect(l.tryAcquire("1.2.3.4")).toBe(false);
    expect(l.tryAcquire("5.6.7.8")).toBe(true);
  });

  /**
   * ★IPv6는 /64로 묶는다. VPS 하나면 라우팅된 /64를 받는 것이 관행이라, 주소 전체를 키로
   * 쓰면 공격자가 **위조 없이** 매 연결마다 소스를 바꿔 상한을 우회한다.
   */
  test("IPv6는 /64 프리픽스로 함께 센다", () => {
    const l = new PeerConnectionLimiter(2);
    expect(l.tryAcquire("2001:db8:1:2::1")).toBe(true);
    expect(l.tryAcquire("2001:db8:1:2::2")).toBe(true); // 같은 /64
    expect(l.tryAcquire("2001:db8:1:2::3")).toBe(false);
    expect(l.tryAcquire("2001:db8:1:3::1")).toBe(true); // 다른 /64
  });

  test("IPv4-매핑 IPv6는 IPv4와 같은 버킷이다", () => {
    const l = new PeerConnectionLimiter(1);
    expect(l.tryAcquire("::ffff:1.2.3.4")).toBe(true);
    expect(l.tryAcquire("1.2.3.4")).toBe(false);
  });

  /** 스쳐 간 주소마다 키가 남으면 맵이 계속 자란다 — 0이 되면 지워야 한다. */
  test("전부 놓으면 추적 엔트리가 남지 않는다", () => {
    const l = new PeerConnectionLimiter(4);
    for (let i = 0; i < 100; i++) {
      const ip = `10.0.0.${i}`;
      l.tryAcquire(ip);
      l.release(ip);
    }
    expect(l.size).toBe(0);
  });

  test("거절된 연결은 카운터를 올리지 않는다", () => {
    const l = new PeerConnectionLimiter(1);
    l.tryAcquire("1.2.3.4");
    expect(l.tryAcquire("1.2.3.4")).toBe(false);
    expect(l.countFor("1.2.3.4")).toBe(1);
  });

  /** 판정 불가 주소는 한 버킷으로 모은다(fail closed) — 흩어놓으면 상한이 무의미해진다. */
  test("알 수 없는 주소는 한 버킷으로 모인다", () => {
    const l = new PeerConnectionLimiter(2);
    expect(l.tryAcquire(undefined)).toBe(true);
    expect(l.tryAcquire("garbage")).toBe(true);
    expect(l.tryAcquire("")).toBe(false);
  });
});
