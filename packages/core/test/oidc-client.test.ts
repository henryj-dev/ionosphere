/** OIDC RP 클라이언트 — discovery 검증, PKCE·nonce, 키 교체 재시도, MFA 증거 계약(공급자별). */
import { describe, expect, test } from "@ionosphere/testkit";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { mfaSatisfiedAt, OidcClient, OidcError, type Jwk, type OidcFetch } from "@ionosphere/core";

const ISSUER = "https://idp.example.com";

function makeIdp(): { fetch: OidcFetch; issue: (claims: Record<string, unknown>) => void; rotate: () => void; calls: string[] } {
  let key = generateKeyPairSync("rsa", { modulusLength: 2048 });
  let kid = "k1";
  let pending: Record<string, unknown> = {};
  const calls: string[] = [];
  const jwk = () => ({ ...(key.publicKey.export({ format: "jwk" }) as Jwk), kid, alg: "RS256" });
  const signJwt = (claims: Record<string, unknown>, k: KeyObject) => {
    const input = `${Buffer.from(JSON.stringify({ alg: "RS256", kid })).toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}`;
    return `${input}.${sign("RSA-SHA256", Buffer.from(input), k).toString("base64url")}`;
  };
  const fetch: OidcFetch = async (url, init) => {
    calls.push(url);
    if (url === `${ISSUER}/.well-known/openid-configuration`) {
      return { status: 200, json: { issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token`, jwks_uri: `${ISSUER}/jwks` } };
    }
    if (url === `${ISSUER}/jwks`) return { status: 200, json: { keys: [jwk()] } };
    if (url === `${ISSUER}/token`) {
      const body = new URLSearchParams(init?.body ?? "");
      if (body.get("code") !== "good-code" || !init?.headers?.authorization?.startsWith("Basic ")) return { status: 400, json: { error: "invalid_grant" } };
      return { status: 200, json: { id_token: signJwt(pending, key.privateKey), access_token: "ignored" } };
    }
    return { status: 404, json: null };
  };
  return {
    fetch,
    issue: (c) => (pending = c),
    rotate: () => {
      key = generateKeyPairSync("rsa", { modulusLength: 2048 });
      kid = "k2";
    },
    calls,
  };
}

const provider = { id: "corp", issuer: ISSUER, clientId: "client-1", clientSecret: "s3cret" };

describe("OidcClient", () => {
  test("인가 URL에 PKCE S256·state·nonce가 실린다", async () => {
    const idp = makeIdp();
    const c = new OidcClient(provider, idp.fetch);
    const u = new URL(await c.authorizationUrl({ redirectUri: "https://admin.ionosphere.test/cb", state: "st", nonce: "nn", codeChallenge: "cc" }));
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("state")).toBe("st");
    expect(u.searchParams.get("nonce")).toBe("nn");
    expect(u.searchParams.get("scope")).toContain("openid");
  });

  test("★discovery issuer가 설정과 다르면 거부한다", async () => {
    const bad: OidcFetch = async () => ({ status: 200, json: { issuer: "https://evil.example.com", authorization_endpoint: "https://x/a", token_endpoint: "https://x/t", jwks_uri: "https://x/j" } });
    await expect(new OidcClient(provider, bad).discover()).rejects.toThrow(/discovery_issuer_mismatch/);
  });

  test("평문 issuer는 루프백이 아니면 거부한다", () => {
    expect(() => new OidcClient({ ...provider, issuer: "http://idp.example.com" })).toThrow(/https/);
    expect(() => new OidcClient({ ...provider, issuer: "http://127.0.0.1:9" })).not.toThrow();
  });

  test("code 교환 → ID 토큰 검증, nonce가 다르면 거부", async () => {
    const idp = makeIdp();
    const c = new OidcClient(provider, idp.fetch);
    const now = Date.now();
    idp.issue({ iss: ISSUER, aud: "client-1", sub: "u1", exp: now / 1000 + 300, iat: now / 1000, nonce: "n1" });
    expect((await c.exchangeAndVerify({ code: "good-code", redirectUri: "r", codeVerifier: "v", nonce: "n1" })).sub).toBe("u1");
    await expect(c.exchangeAndVerify({ code: "good-code", redirectUri: "r", codeVerifier: "v", nonce: "other" })).rejects.toThrow(/id_token_bad_nonce/);
    await expect(c.exchangeAndVerify({ code: "bad", redirectUri: "r", codeVerifier: "v", nonce: "n1" })).rejects.toThrow(/token_exchange_failed/);
  });

  test("키가 교체되면(낯선 kid) JWKS를 한 번 다시 받아 검증한다", async () => {
    const idp = makeIdp();
    const c = new OidcClient(provider, idp.fetch);
    const now = Date.now();
    const claims = { iss: ISSUER, aud: "client-1", sub: "u1", exp: now / 1000 + 300, iat: now / 1000, nonce: "n1" };
    idp.issue(claims);
    await c.exchangeAndVerify({ code: "good-code", redirectUri: "r", codeVerifier: "v", nonce: "n1" });
    idp.rotate();
    expect((await c.exchangeAndVerify({ code: "good-code", redirectUri: "r", codeVerifier: "v", nonce: "n1" })).sub).toBe("u1");
    expect(idp.calls.filter((u) => u.endsWith("/jwks")).length).toBe(2);
  });

  test("오류 객체는 OidcError이고 사유를 싣는다", async () => {
    const c = new OidcClient(provider, async () => ({ status: 500, json: null }));
    try {
      await c.discover();
    } catch (e) {
      expect(e instanceof OidcError && e.reason === "discovery_failed").toBe(true);
    }
  });
});

describe("MFA 증거 계약", () => {
  const now = 1_800_000_000_000;
  const contract = { acceptAcr: ["urn:corp:mfa:totp"], requireAmrAll: ["pwd", "otp"], maxAgeSec: 300 };

  test("계약이 없으면 무엇도 MFA로 인정하지 않는다(로컬 TOTP 필요)", () => {
    expect(mfaSatisfiedAt({ acr: "urn:corp:mfa:totp", amr: ["pwd", "otp"], auth_time: now / 1000 }, undefined, now)).toBeNull();
  });

  test("acr 또는 amr 전부가 맞고 auth_time이 최근이면 auth_time을 돌려준다", () => {
    expect(mfaSatisfiedAt({ acr: "urn:corp:mfa:totp", auth_time: now / 1000 - 10 }, contract, now)).toBe(now - 10_000);
    expect(mfaSatisfiedAt({ amr: ["pwd", "otp"], auth_time: now / 1000 - 10 }, contract, now)).toBe(now - 10_000);
  });

  test("★amr 일부만·auth_time 없음·오래됨은 인정하지 않는다", () => {
    expect(mfaSatisfiedAt({ amr: ["otp"], auth_time: now / 1000 }, contract, now)).toBeNull();
    expect(mfaSatisfiedAt({ amr: ["mfa"], auth_time: now / 1000 }, contract, now)).toBeNull();
    expect(mfaSatisfiedAt({ acr: "urn:corp:mfa:totp" }, contract, now)).toBeNull();
    expect(mfaSatisfiedAt({ acr: "urn:corp:mfa:totp", auth_time: now / 1000 - 301 }, contract, now)).toBeNull();
  });

  test("lodestar 같은 응답(amr 없음, acr에 신뢰 기기 포함)은 계약을 충족하지 못한다", () => {
    // 일반 MFA acr만으로는 TOTP를 보장하지 못하므로 계약에 넣지 않는 것이 맞다 — 넣지 않으면 null이다.
    expect(mfaSatisfiedAt({ acr: "mfa", auth_time: now / 1000 }, contract, now)).toBeNull();
  });

  test("빈 계약(둘 다 비어 있음)으로 MFA를 면제하지 않는다", () => {
    expect(mfaSatisfiedAt({ acr: "x", amr: [], auth_time: now / 1000 }, { maxAgeSec: 300 }, now)).toBeNull();
  });
});

describe("보안 재검토 반영(2026-10-18)", () => {
  test("★issuer가 루프백이 아니면 discovery 엔드포인트의 평문·사설 주소를 거부한다(SSRF)", async () => {
    const mk = (token: string): OidcFetch => async () => ({ status: 200, json: { issuer: ISSUER, authorization_endpoint: `${ISSUER}/a`, token_endpoint: token, jwks_uri: `${ISSUER}/j` } });
    await expect(new OidcClient(provider, mk("http://127.0.0.1:8080/token")).discover()).rejects.toThrow(/https/);
    await expect(new OidcClient(provider, mk("https://10.0.0.5/token")).discover()).rejects.toThrow(/private/);
    await expect(new OidcClient(provider, mk("https://127.0.0.1/token")).discover()).rejects.toThrow(/private/);
    expect((await new OidcClient(provider, mk("https://login.example.com/token")).discover()).token_endpoint).toBe("https://login.example.com/token");
  });

  test("미래의 auth_time은 지금으로 자른다(step-up 창이 늘지 않게)", () => {
    const now = 1_800_000_000_000;
    expect(mfaSatisfiedAt({ acr: "a", auth_time: now / 1000 + 30 }, { acceptAcr: ["a"], maxAgeSec: 300 }, now)).toBe(now);
  });
});
