import { describe, expect, test } from "@ionosphere/testkit";
import { open, seal } from "@ionosphere/core";

describe("secretbox", () => {
  test("암호화 왕복 + 포맷 + sealed=true", () => {
    const s = seal("비밀키 PEM 내용", "master-pass");
    expect(s.sealed).toBe(true);
    expect(s.value.startsWith("enc$v1$")).toBe(true);
    expect(open(s.value, "master-pass")).toBe("비밀키 PEM 내용");
  });

  test("잘못된 마스터키 → throw (조용한 실패 금지)", () => {
    const s = seal("secret", "right");
    expect(() => open(s.value, "wrong")).toThrow();
    expect(() => open(s.value, undefined)).toThrow();
  });

  test("마스터키 미설정 → sealed=false + plain$ 폴백(호출자가 인지 가능)", () => {
    const s = seal("data", undefined);
    // 반환 타입이 평문 여부를 드러낸다 — string만 돌려주던 시절엔 호출자가 모르고 지나쳤다.
    expect(s.sealed).toBe(false);
    expect(s.value).toBe("plain$data");
    expect(open(s.value, undefined)).toBe("data");
    expect(open(s.value, "any")).toBe("data"); // plain은 키 무관 읽기 가능
  });

  test("손상 데이터 → throw", () => {
    expect(() => open("enc$v1$broken", "k")).toThrow();
    expect(() => open("garbage", "k")).toThrow();
  });
});
