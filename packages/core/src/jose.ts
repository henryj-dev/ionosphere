/**
 * JWT(JWS compact) 서명 검증 — OIDC ID 토큰(E3)과 메일 클라이언트용 access token(E4)이 함께 쓴다. I/O 없음.
 *
 * ★받는 알고리즘을 **고정한다**: RS256·ES256. `none`은 서명이 없는 토큰이고, HS256은 공개키를 HMAC 비밀로 쓰게 만드는
 * 고전적 혼동 공격(alg confusion)의 입구다. 헤더의 `alg`를 믿고 검증 방법을 고르지 않고, **키(JWK)가 허용한 알고리즘과
 * 헤더가 같을 때만** 검증한다.
 *
 * 클레임 검사(iss·aud·exp·nonce 등)는 용도마다 달라 `verifyJwtClaims`가 요구 목록을 받는다. 서명만 맞고 클레임을
 * 안 본 토큰을 "검증됨"으로 쓰지 않게, 두 단계를 합친 `verifyJwt`만 밖에 쓴다.
 */
import { createPublicKey, verify as cryptoVerify, type JsonWebKey, type KeyObject } from "node:crypto";

export const ACCEPTED_JWS_ALGS = ["RS256", "ES256"] as const;
export type AcceptedJwsAlg = (typeof ACCEPTED_JWS_ALGS)[number];

export interface Jwk {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
}

export interface JwtHeader {
  alg: string;
  kid?: string;
  typ?: string;
}

export type JwtClaims = Record<string, unknown>;

export class JwtError extends Error {
  /** 기계가 읽는 사유 — 감사·로그에 남긴다(토큰 원문은 남기지 않는다). */
  readonly reason: string;
  constructor(reason: string, message?: string) {
    super(message ?? reason);
    this.reason = reason;
  }
}

function b64urlJson(part: string, what: string): Record<string, unknown> {
  try {
    const v = JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as unknown;
    if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error("not object");
    return v as Record<string, unknown>;
  } catch {
    throw new JwtError("malformed", `${what} is not a JSON object`);
  }
}

/** 형식만 본다(검증 아님). 세 부분, 헤더·페이로드가 JSON 객체. */
export function decodeJwt(token: string): { header: JwtHeader; claims: JwtClaims; signingInput: string; signature: Buffer } {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((p) => p === "")) throw new JwtError("malformed", "not a compact JWS");
  const header = b64urlJson(parts[0]!, "header");
  const claims = b64urlJson(parts[1]!, "payload");
  if (typeof header.alg !== "string") throw new JwtError("malformed", "header.alg missing");
  return {
    header: { alg: header.alg, ...(typeof header.kid === "string" ? { kid: header.kid } : {}), ...(typeof header.typ === "string" ? { typ: header.typ } : {}) },
    claims,
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: Buffer.from(parts[2]!, "base64url"),
  };
}

/** JWK의 종류와 헤더 alg가 맞는가 — RSA 키로 ES256을, EC 키로 RS256을 검증하지 않는다. */
function keyAllows(jwk: Jwk, alg: AcceptedJwsAlg): boolean {
  if (jwk.alg !== undefined && jwk.alg !== alg) return false;
  if (jwk.use !== undefined && jwk.use !== "sig") return false;
  if (alg === "RS256") return jwk.kty === "RSA";
  return jwk.kty === "EC" && jwk.crv === "P-256";
}

function publicKeyOf(jwk: Jwk): KeyObject {
  try {
    return createPublicKey({ key: jwk as JsonWebKey, format: "jwk" });
  } catch {
    throw new JwtError("bad_key", "JWK could not be imported");
  }
}

/** 서명만 본다. 헤더 kid로 키를 고르되, kid가 없으면 맞는 종류의 키를 하나씩 시도한다. */
export function verifyJwtSignature(token: string, keys: readonly Jwk[]): { header: JwtHeader; claims: JwtClaims } {
  const { header, claims, signingInput, signature } = decodeJwt(token);
  const alg = header.alg as AcceptedJwsAlg;
  if (!(ACCEPTED_JWS_ALGS as readonly string[]).includes(header.alg)) throw new JwtError("alg_not_allowed", `alg ${header.alg} is not accepted`);
  const candidates = keys.filter((k) => (header.kid === undefined || k.kid === header.kid) && keyAllows(k, alg));
  if (candidates.length === 0) throw new JwtError("unknown_key", "no matching key");
  for (const jwk of candidates) {
    const key = publicKeyOf(jwk);
    // ES256 서명은 JWS에서 r||s(IEEE P1363) 형식이다 — DER로 해석하면 맞는 서명도 거절된다.
    const ok = alg === "RS256"
      ? cryptoVerify("RSA-SHA256", Buffer.from(signingInput), key, signature)
      : cryptoVerify("sha256", Buffer.from(signingInput), { key, dsaEncoding: "ieee-p1363" }, signature);
    if (ok) return { header, claims };
  }
  throw new JwtError("bad_signature", "signature does not verify");
}

export interface ClaimRequirements {
  issuer: string;
  /** 이 값이 aud에 있어야 한다. */
  audience: string;
  nowMs: number;
  /** 시계 오차 허용(초). 기본 60. */
  skewSec?: number;
  /** 있으면 nonce가 같아야 한다(ID 토큰). */
  nonce?: string;
  /** aud가 여럿이면 azp가 우리여야 한다(OIDC Core §3.1.3.7). 기본 true. */
  requireAzpWhenMultiAud?: boolean;
  /** exp가 반드시 있어야 하는가. 기본 true. */
  requireExp?: boolean;
}

/**
 * 클레임 검사 — OIDC Core §3.1.3.7의 필수 항목. 실패 사유는 `JwtError.reason`으로 드러낸다.
 * `sub`는 항상 비어 있지 않은 문자열이어야 한다(연결의 키다).
 */
export function verifyJwtClaims(claims: JwtClaims, req: ClaimRequirements): { sub: string } {
  const skew = (req.skewSec ?? 60) * 1000;
  if (claims.iss !== req.issuer) throw new JwtError("bad_issuer");
  const aud = claims.aud;
  const auds = typeof aud === "string" ? [aud] : Array.isArray(aud) ? aud.filter((a): a is string => typeof a === "string") : [];
  if (!auds.includes(req.audience)) throw new JwtError("bad_audience");
  if ((req.requireAzpWhenMultiAud ?? true) && auds.length > 1 && claims.azp !== req.audience) throw new JwtError("bad_azp");
  if (claims.azp !== undefined && claims.azp !== req.audience) throw new JwtError("bad_azp");
  const exp = claims.exp;
  if (typeof exp !== "number") {
    if (req.requireExp ?? true) throw new JwtError("no_exp");
  } else if (exp * 1000 + skew <= req.nowMs) {
    throw new JwtError("expired");
  }
  const iat = claims.iat;
  if (iat !== undefined && (typeof iat !== "number" || iat * 1000 - skew > req.nowMs)) throw new JwtError("bad_iat");
  const nbf = claims.nbf;
  if (nbf !== undefined && (typeof nbf !== "number" || nbf * 1000 - skew > req.nowMs)) throw new JwtError("not_yet_valid");
  if (req.nonce !== undefined && claims.nonce !== req.nonce) throw new JwtError("bad_nonce");
  if (typeof claims.sub !== "string" || claims.sub === "") throw new JwtError("no_sub");
  return { sub: claims.sub };
}

/** 서명 + 클레임. 밖에서는 이것만 쓴다(서명만 본 토큰이 "검증됨"으로 흘러가지 않게). */
export function verifyJwt(token: string, keys: readonly Jwk[], req: ClaimRequirements): { header: JwtHeader; claims: JwtClaims; sub: string } {
  const { header, claims } = verifyJwtSignature(token, keys);
  const { sub } = verifyJwtClaims(claims, req);
  return { header, claims, sub };
}
