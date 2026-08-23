/**
 * CIDR 매처(parseCidrList) — 신뢰 릴레이 판정의 근거라 **보안 판정**이다.
 *
 * 여기서 보는 것은 두 가지다: ① 기본이 "아무도 신뢰 안 함"인가 ② SPF의 `ip4:`/`ip6:` 매칭과
 * 같은 파서를 쓰는가(특히 `::ffff:` 매핑 — node 소켓이 IPv4 접속에 흔히 내주는 형태다.
 * 여기서 접어 주지 않으면 같은 호스트가 검사마다 다른 신원이 된다).
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { parseCidrList } from "../src/spf.ts";

describe("CIDR 매처", () => {
  test("빈 목록은 아무것도 신뢰하지 않는다", () => {
    const m = parseCidrList([]);
    expect(m.size).toBe(0);
    expect(m.matches("10.0.82.134")).toBe(false);
    expect(m.matches("127.0.0.1")).toBe(false);
  });

  test("프리픽스 없는 항목은 단일 주소(/32)", () => {
    const m = parseCidrList(["10.0.82.134"]);
    expect(m.matches("10.0.82.134")).toBe(true);
    expect(m.matches("10.0.82.135")).toBe(false);
  });

  test("IPv4 프리픽스 경계", () => {
    const m = parseCidrList(["10.0.64.0/18"]); // 10.0.64.0 ~ 10.0.127.255
    expect(m.matches("10.0.77.135")).toBe(true);
    expect(m.matches("10.0.101.12")).toBe(true);
    expect(m.matches("10.0.63.255")).toBe(false);
    expect(m.matches("10.0.128.0")).toBe(false);
  });

  test("IPv4-매핑 IPv6(::ffff:)를 같은 주소로 본다", () => {
    const m = parseCidrList(["10.0.82.134/32"]);
    // node 소켓의 remoteAddress가 이 형태로 오는 배포가 있다 — 접지 못하면 신뢰가 조용히 풀린다.
    expect(m.matches("::ffff:10.0.82.134")).toBe(true);
    expect(m.matches("::ffff:10.0.82.135")).toBe(false);
  });

  test("IPv6 대역", () => {
    const m = parseCidrList(["2001:db8:1c02:4d9::/64"]);
    expect(m.matches("2001:db8:1c02:4d9:5400:6ff:fe79:f9a6")).toBe(true);
    expect(m.matches("2001:db8:1c02:4da::1")).toBe(false);
  });

  test("계열이 다르면 매칭되지 않는다", () => {
    const m = parseCidrList(["10.0.0.0/8"]);
    expect(m.matches("::1")).toBe(false);
    expect(parseCidrList(["::1/128"]).matches("10.0.0.1")).toBe(false);
  });

  test("파싱 못 한 접속 주소는 신뢰하지 않는다(fail closed)", () => {
    const m = parseCidrList(["0.0.0.0/0"]); // 전부 허용해도
    expect(m.matches("not-an-ip")).toBe(false);
    expect(m.matches("")).toBe(false);
  });

  test("잘못된 항목은 조용히 버리지 않고 throw한다", () => {
    // 오타 하나로 목록이 비면 서버는 정상 기동하고 운영자는 예외가 걸린 줄 안다 — 기동 실패가 낫다.
    expect(() => parseCidrList(["10.0.82.999"])).toThrow();
    expect(() => parseCidrList(["10.0.82.0/33"])).toThrow();
    expect(() => parseCidrList(["::1/129"])).toThrow();
    expect(() => parseCidrList(["10.0.82.0/x"])).toThrow();
  });

  test("빈 문자열 항목은 건너뛴다(쉼표 구분 env의 후행 쉼표)", () => {
    const m = parseCidrList(["10.0.82.134", "  ", ""]);
    expect(m.size).toBe(1);
    expect(m.matches("10.0.82.134")).toBe(true);
  });
});
