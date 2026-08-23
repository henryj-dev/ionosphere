/** SASL OAuth 파서 — XOAUTH2 / OAUTHBEARER. */
import { describe, expect, test } from "@ionosphere/testkit";
import { isOAuthMechanism, parseSaslOAuth } from "@ionosphere/core";

const A = "\u0001";

describe("XOAUTH2", () => {
  test("user + Bearer 토큰 추출", () => {
    const payload = `user=you@x.test${A}auth=Bearer tok-abc${A}${A}`;
    expect(parseSaslOAuth("XOAUTH2", payload)).toEqual({ user: "you@x.test", token: "tok-abc" });
  });

  test("소문자 메커니즘도 허용", () => {
    const payload = `user=u@x${A}auth=Bearer T${A}${A}`;
    expect(parseSaslOAuth("xoauth2", payload)).toEqual({ user: "u@x", token: "T" });
  });

  test("토큰/유저 없으면 null", () => {
    expect(parseSaslOAuth("XOAUTH2", `user=u@x${A}${A}`)).toBeNull(); // Bearer 없음
    expect(parseSaslOAuth("XOAUTH2", `auth=Bearer T${A}${A}`)).toBeNull(); // user 없음
  });
});

describe("OAUTHBEARER", () => {
  test("GS2 a= 유저 + Bearer 토큰", () => {
    const payload = `n,a=you@x.test,${A}host=mx.x${A}port=993${A}auth=Bearer tok-xyz${A}${A}`;
    expect(parseSaslOAuth("OAUTHBEARER", payload)).toEqual({ user: "you@x.test", token: "tok-xyz" });
  });

  test("GS2 saslname 이스케이프(=2C/=3D) 디코딩", () => {
    const payload = `n,a=a=2Cb,${A}auth=Bearer T${A}${A}`;
    expect(parseSaslOAuth("OAUTHBEARER", payload)).toEqual({ user: "a,b", token: "T" });
  });

  test("authzid 없으면(n,,) user 없음 → null", () => {
    expect(parseSaslOAuth("OAUTHBEARER", `n,,${A}auth=Bearer T${A}${A}`)).toBeNull();
  });
});

describe("기타", () => {
  test("미지원 메커니즘 → null", () => {
    expect(parseSaslOAuth("PLAIN", "whatever")).toBeNull();
  });
  test("isOAuthMechanism", () => {
    expect(isOAuthMechanism("XOAUTH2")).toBe(true);
    expect(isOAuthMechanism("oauthbearer")).toBe(true);
    expect(isOAuthMechanism("PLAIN")).toBe(false);
  });
});
