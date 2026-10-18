/** JWT 검증 — 허용 알고리즘 고정, 키 종류 일치, 클레임 필수 항목(OIDC Core §3.1.3.7). */
import { describe, expect, test } from "@ionosphere/testkit";
import { createHmac, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { JwtError, verifyJwt, type Jwk } from "@ionosphere/core";

const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const rsaJwk = { ...(rsa.publicKey.export({ format: "jwk" }) as Jwk), kid: "r1", alg: "RS256", use: "sig" } as Jwk;
const ecJwk = { ...(ec.publicKey.export({ format: "jwk" }) as Jwk), kid: "e1" } as Jwk;

function b64(o: unknown): string {
  return Buffer.from(JSON.stringify(o)).toString("base64url");
}
function jwt(header: Record<string, unknown>, claims: Record<string, unknown>, key: KeyObject | null): string {
  const input = `${b64(header)}.${b64(claims)}`;
  if (key === null) return `${input}.AAAA`; // 서명 칸을 채운다 — 비어 있으면 alg 검사 전에 malformed로 끝나 검사가 안 보인다
  const alg = header.alg;
  const sig = alg === "ES256" ? sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" }) : sign("RSA-SHA256", Buffer.from(input), key);
  return `${input}.${sig.toString("base64url")}`;
}

const NOW = 1_800_000_000_000;
const base = { iss: "https://idp.example.com", aud: "client-1", sub: "user-42", exp: NOW / 1000 + 300, iat: NOW / 1000 - 5, nonce: "n1" };
const req = { issuer: "https://idp.example.com", audience: "client-1", nowMs: NOW, nonce: "n1" };

function reason(fn: () => unknown): string {
  try {
    fn();
    return "ok";
  } catch (e) {
    return e instanceof JwtError ? e.reason : String(e);
  }
}

describe("verifyJwt", () => {
  test("RS256·ES256 정상 토큰은 sub를 돌려준다", () => {
    expect(verifyJwt(jwt({ alg: "RS256", kid: "r1" }, base, rsa.privateKey), [rsaJwk], req).sub).toBe("user-42");
    expect(verifyJwt(jwt({ alg: "ES256", kid: "e1" }, base, ec.privateKey), [ecJwk], req).sub).toBe("user-42");
  });

  test("★none·HS256(alg 혼동)은 거부한다", () => {
    expect(reason(() => verifyJwt(jwt({ alg: "none" }, base, null), [rsaJwk], req))).toBe("alg_not_allowed");
    // 공개키(n)를 HMAC 비밀로 쓴 위조 — 헤더 alg를 믿으면 통과하는 고전적 공격.
    const input = `${b64({ alg: "HS256", kid: "r1" })}.${b64(base)}`;
    const forged = `${input}.${createHmac("sha256", String(rsaJwk.n)).update(input).digest("base64url")}`;
    expect(reason(() => verifyJwt(forged, [rsaJwk], req))).toBe("alg_not_allowed");
  });

  test("키 종류가 alg와 다르면 고르지 않는다(RSA 키로 ES256 검증 안 함)", () => {
    expect(reason(() => verifyJwt(jwt({ alg: "ES256", kid: "r1" }, base, ec.privateKey), [rsaJwk], req))).toBe("unknown_key");
  });

  test("서명이 다른 키면 bad_signature", () => {
    const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
    expect(reason(() => verifyJwt(jwt({ alg: "RS256", kid: "r1" }, base, other.privateKey), [rsaJwk], req))).toBe("bad_signature");
  });

  test("클레임: iss·aud·azp·exp·iat·nonce·sub", () => {
    const t = (claims: Record<string, unknown>) => reason(() => verifyJwt(jwt({ alg: "RS256", kid: "r1" }, claims, rsa.privateKey), [rsaJwk], req));
    expect(t({ ...base, iss: "https://evil.example.com" })).toBe("bad_issuer");
    expect(t({ ...base, aud: "other" })).toBe("bad_audience");
    expect(t({ ...base, aud: ["client-1", "other"] })).toBe("bad_azp");
    expect(t({ ...base, aud: ["client-1", "other"], azp: "client-1" })).toBe("ok");
    expect(t({ ...base, exp: NOW / 1000 - 120 })).toBe("expired");
    expect(t({ ...base, exp: undefined })).toBe("no_exp");
    expect(t({ ...base, iat: NOW / 1000 + 600 })).toBe("bad_iat");
    expect(t({ ...base, nonce: "n2" })).toBe("bad_nonce");
    expect(t({ ...base, sub: "" })).toBe("no_sub");
  });

  test("형식이 깨진 토큰은 malformed", () => {
    expect(reason(() => verifyJwt("a.b", [rsaJwk], req))).toBe("malformed");
    expect(reason(() => verifyJwt("e30.bm90LWpzb24.c2ln", [rsaJwk], req))).toBe("malformed");
  });
});
