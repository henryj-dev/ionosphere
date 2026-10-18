/** TOTP — RFC 6238 부록 B 벡터, base32 왕복, 시계 오차 창, 재사용 거절. */
import { describe, expect, test } from "@ionosphere/testkit";
import { base32Decode, base32Encode, generateTotpSecret, hotp, totpStep, totpUri, verifyTotp } from "@ionosphere/core";

// RFC 6238 부록 B — SHA-1 비밀 "12345678901234567890"(ASCII 20바이트), 8자리.
const RFC_SECRET = new TextEncoder().encode("12345678901234567890");
const RFC_VECTORS: [number, string][] = [
  [59, "94287082"],
  [1111111109, "07081804"],
  [1111111111, "14050471"],
  [1234567890, "89005924"],
  [2000000000, "69279037"],
  [20000000000, "65353130"],
];

describe("TOTP", () => {
  test("RFC 6238 부록 B 벡터(SHA-1, 8자리)", () => {
    for (const [t, code] of RFC_VECTORS) expect(hotp(RFC_SECRET, Math.floor(t / 30), 8)).toBe(code);
  });

  test("base32 — RFC 4648 왕복, 소문자·공백·패딩 허용, 모르는 문자는 null", () => {
    const b32 = base32Encode(RFC_SECRET);
    expect(b32).toBe("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    expect(Buffer.from(base32Decode(b32)!).equals(Buffer.from(RFC_SECRET))).toBe(true);
    expect(Buffer.from(base32Decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq==")!).equals(Buffer.from(RFC_SECRET))).toBe(true);
    expect(base32Decode("GEZD1")).toBeNull();
  });

  test("±1 스텝은 받고 ±2 스텝은 거절한다, 맞은 스텝 번호를 돌려준다", () => {
    const secret = base32Encode(RFC_SECRET);
    const now = 1_111_111_111_000;
    const step = totpStep(now);
    const code = (s: number) => hotp(RFC_SECRET, s);
    expect(verifyTotp(secret, code(step), now, null)).toBe(step);
    expect(verifyTotp(secret, code(step - 1), now, null)).toBe(step - 1);
    expect(verifyTotp(secret, code(step + 1), now, null)).toBe(step + 1);
    expect(verifyTotp(secret, code(step - 2), now, null)).toBeNull();
    expect(verifyTotp(secret, code(step + 2), now, null)).toBeNull();
  });

  test("★마지막으로 쓴 스텝 이하는 맞아도 거절한다(재사용 방지)", () => {
    const secret = base32Encode(RFC_SECRET);
    const now = 1_111_111_111_000;
    const step = totpStep(now);
    expect(verifyTotp(secret, hotp(RFC_SECRET, step), now, step)).toBeNull();
    expect(verifyTotp(secret, hotp(RFC_SECRET, step - 1), now, step - 1)).toBeNull();
    expect(verifyTotp(secret, hotp(RFC_SECRET, step + 1), now, step)).toBe(step + 1);
  });

  test("형식이 틀린 코드·비밀은 null", () => {
    const secret = generateTotpSecret();
    expect(verifyTotp(secret, "12345", Date.now(), null)).toBeNull();
    expect(verifyTotp(secret, "12345a", Date.now(), null)).toBeNull();
    expect(verifyTotp("!!!", "123456", Date.now(), null)).toBeNull();
  });

  test("새 비밀은 160비트(base32 32자), otpauth URI에 파라미터가 실린다", () => {
    const secret = generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    const uri = totpUri(secret, "ionosphere", "admin@ionosphere.test");
    expect(uri).toStartWith("otpauth://totp/ionosphere:admin%40ionosphere.test?");
    expect(uri).toContain(`secret=${secret}`);
    expect(uri).toContain("period=30");
  });
});
