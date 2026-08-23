/**
 * `isPrivateLocalAddress` — 443 vhost 노출 정책의 판정 근거.
 *
 * 여기서 고정하는 계약은 두 가지다:
 *  ① 이 배포에서 실제로 쓰는 형태를 내부로 본다(10/8 VPC·메시, 루프백, IPv4-매핑 IPv6).
 *  ② **판정할 수 없으면 내부가 아니다.** 이 방향이 뒤집히면 주소를 못 읽는 상황에서
 *     관리 표면이 통째로 열린다 — 반대 방향의 최악은 "콘솔이 안 열린다"로 되돌릴 수 있다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { isPrivateLocalAddress } from "../src/internal-address.ts";

describe("isPrivateLocalAddress", () => {
  test("이 배포가 실제로 쓰는 내부 주소", () => {
    for (const a of [
      "10.0.101.12", // VPC (node-01)
      "10.0.82.134", // VPC (node-03)
      "10.1.0.6", // 관리자 메시
      "127.0.0.1",
      "::1",
      "192.168.0.5",
      "172.16.0.1",
      "172.31.255.254",
      "169.254.169.254", // 링크로컬
      "fd00::1", // ULA
      "fe80::1", // IPv6 링크로컬
    ]) {
      expect(isPrivateLocalAddress(a)).toBe(true);
    }
  });

  test("★듀얼스택 바인딩이 주는 IPv4-매핑 형태 — 여기가 틀리면 판정이 통째로 뒤집힌다", () => {
    // `*:443`처럼 듀얼스택으로 열면 커널이 로컬 주소를 이 형태로 준다(실측).
    expect(isPrivateLocalAddress("::ffff:10.0.101.12")).toBe(true);
    expect(isPrivateLocalAddress("::ffff:127.0.0.1")).toBe(true);
    // 공인 주소가 매핑 형태로 와도 공개로 봐야 한다.
    expect(isPrivateLocalAddress("::ffff:203.0.113.57")).toBe(false);
  });

  test("공인 주소는 내부가 아니다", () => {
    for (const a of [
      "203.0.113.57", // node-01 공인
      "203.0.113.133", // node-02 공인
      "203.0.113.113", // node-03 공인
      "8.8.8.8",
      "172.32.0.1", // 172.16/12 **바로 바깥**
      "172.15.255.255",
      "192.169.0.1", // 192.168/16 바로 바깥
      "11.0.0.1", // 10/8 바로 바깥
      "2001:db8:1c01:2d0::1", // 공인 IPv6
    ]) {
      expect(isPrivateLocalAddress(a)).toBe(false);
    }
  });

  test("★판정 불가는 전부 '내부 아님' — fail closed", () => {
    for (const a of [undefined, "", "   ", "nonsense", "10.1.2", "10.1.2.3.4", "999.1.1.1", "10.-1.0.1"]) {
      expect(isPrivateLocalAddress(a)).toBe(false);
    }
  });
});
