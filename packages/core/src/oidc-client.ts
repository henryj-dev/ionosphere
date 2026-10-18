/**
 * OIDC Relying Party 클라이언트 — discovery·JWKS·code 교환·ID 토큰 검증·MFA 증거 판정 (회원 정책 E3).
 *
 * 흐름은 Authorization Code + PKCE(S256)다. 비밀은 서버에만 있다(client_secret_basic).
 *
 * ★MFA 증거 계약(2026-10-18 사용자 결정: "IdP MFA 증거 계약부터"):
 *  - IdP의 seed나 OTP를 받지 않는다. ID 토큰의 `acr`·`amr`·`auth_time`으로 IdP가 한 인증을 **검증해서** 인정한다.
 *  - 공급자마다 무엇을 "TOTP를 포함한 MFA"로 볼지 **설정으로 계약**한다(`MfaEvidenceContract`). amr=otp만으로 TOTP를,
 *    mfa만으로 특정 방법을 보장하지 못하므로(RFC 8176) 해석을 코드에 박지 않는다.
 *  - 요청한 `acr_values`·`prompt=login`·`max_age`만으로 충족으로 보지 않는다 — **응답의 클레임**만 본다.
 *  - `auth_time`이 계약의 최근성 안이어야 한다. refresh로 받은 토큰의 iat를 새 MFA 시각으로 보지 않는다(refresh를 쓰지 않는다).
 *  - 계약이 없거나 응답이 충족하지 못하면 **MFA 생략·자동 폴백 없이** 로컬 TOTP를 요구한다(호출자 몫 — `mfaSatisfiedAt`이 null).
 *    lodestar는 현재 ID 토큰에 amr이 없고 acr에 신뢰 기기가 섞여 계약을 충족할 수 없다(orc 경유 보고, 2026-10-18).
 */
import { createHash, randomBytes } from "node:crypto";
import { decodeJwt, JwtError, verifyJwt, type Jwk, type JwtClaims } from "./jose.ts";

/** 공급자별 MFA 증거 계약. 생략하면 IdP MFA를 인정하지 않는다(로컬 TOTP 필수). */
export interface MfaEvidenceContract {
  /** 이 중 하나의 acr이면 계약 충족 후보. */
  acceptAcr?: readonly string[];
  /** 이 값들이 **모두** amr에 있으면 계약 충족 후보. */
  requireAmrAll?: readonly string[];
  /** auth_time이 이만큼(초) 안이어야 한다. 요청에도 max_age로 싣지만, 판정은 응답의 auth_time으로 한다. */
  maxAgeSec: number;
}

export interface OidcProviderConfig {
  /** 내부 식별자(설정·감사·연결 키). */
  id: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  scopes?: readonly string[];
  mfaContract?: MfaEvidenceContract;
}

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

/** HTTP 호출 — 테스트가 갈아 끼운다. 기본은 전역 fetch(node 내장). */
export type OidcFetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => Promise<{ status: number; json: unknown }>;

const defaultFetch: OidcFetch = async (url, init) => {
  const res = await fetch(url, {
    method: init?.method ?? "GET",
    ...(init?.headers ? { headers: init.headers } : {}),
    ...(init?.body !== undefined ? { body: init.body } : {}),
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  const text = await res.text();
  let json: unknown = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json };
};

function isLoopbackHost(h: string): boolean {
  return h === "127.0.0.1" || h === "::1" || h === "[::1]" || h === "localhost" || /^127\./.test(h);
}

/** 사설·링크로컬·루프백 IP 리터럴인가(이름은 판정하지 않는다 — DNS 재바인딩까지 막지는 못한다). */
function isPrivateLiteral(h: string): boolean {
  const host = h.replace(/^\[|\]$/g, "");
  if (isLoopbackHost(host)) return true;
  const m = host.match(/^(\d+)\.(\d+)\.\d+\.\d+$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    return a === 10 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  return /^(fc|fd|fe80)/i.test(host);
}

/**
 * IdP 엔드포인트는 https여야 한다. 평문 http는 **issuer 자신이 루프백일 때만**(테스트·로컬 IdP) 허용한다.
 *
 * ★discovery가 내려준 엔드포인트는 IdP가 정하는 값이다. 루프백 예외를 그쪽에도 열어 두면, 침해되거나 잘못 설정된 IdP가
 * `token_endpoint=http://127.0.0.1:<관리 포트>`를 내려 우리 서버가 client_secret과 code를 실어 내부 서비스로 POST하게
 * 만들 수 있다(SSRF, 2026-10-18 검토). 그래서 issuer가 루프백이 아니면 엔드포인트의 사설·루프백 IP 리터럴도 거부한다.
 */
function requireSecureUrl(raw: string, what: string, issuerIsLoopback: boolean): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new OidcError("bad_config", `${what} is not a URL`);
  }
  if (u.protocol === "http:" && issuerIsLoopback && isLoopbackHost(u.hostname)) return u;
  if (u.protocol !== "https:") throw new OidcError("bad_config", `${what} must be https`);
  if (!issuerIsLoopback && isPrivateLiteral(u.hostname)) throw new OidcError("bad_config", `${what} must not point to a private address`);
  return u;
}

export class OidcError extends Error {
  readonly reason: string;
  constructor(reason: string, message?: string) {
    super(message ?? reason);
    this.reason = reason;
  }
}

/** PKCE·state·nonce. 셋 다 추측할 수 없어야 한다(32바이트 난수). */
export function newPkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}
export function newOpaque(): string {
  return randomBytes(32).toString("base64url");
}

/** JWKS 캐시 수명 — 키 교체를 이만큼 늦게 본다. 낯선 kid가 오면 수명과 무관하게 한 번 다시 받는다. */
const JWKS_TTL_MS = 10 * 60 * 1000;
/** discovery 캐시 수명 — IdP가 엔드포인트를 바꾸면 이만큼 뒤에 반영된다(영구 캐시는 재시작을 요구한다). */
const DISCOVERY_TTL_MS = 60 * 60 * 1000;
/**
 * 낯선 kid로 JWKS를 강제로 다시 받는 최소 간격. 무인증 IMAP·SMTP에서 임의 kid를 단 JWT 모양 문자열을 보내면 시도마다
 * IdP로 요청이 나가 DoS 증폭기가 된다(2026-10-18 검토). 간격 안의 낯선 kid는 받지 않고 바로 거절한다.
 */
const JWKS_FORCED_REFRESH_MIN_MS = 60 * 1000;
/** access token 수명 상한(exp − iat). 철회 수단이 exp뿐이라 너무 긴 토큰은 받지 않는다. ⚠ 임시값. */
export const PROVISIONAL_MAX_ACCESS_TOKEN_LIFETIME_SEC = 60 * 60;

export class OidcClient {
  readonly provider: OidcProviderConfig;
  private readonly fetchJson: OidcFetch;
  private discovery: { doc: OidcDiscovery; fetchedAt: number } | null = null;
  private readonly issuerIsLoopback: boolean;
  private jwks: { keys: Jwk[]; fetchedAt: number } | null = null;
  /** 진행 중인 JWKS 요청 — 동시에 온 요청이 같은 것을 기다린다(single-flight). */
  private jwksInFlight: Promise<Jwk[]> | null = null;
  private lastForcedRefreshAt = 0;

  constructor(provider: OidcProviderConfig, fetchJson: OidcFetch = defaultFetch) {
    this.issuerIsLoopback = isLoopbackHost(new URL(provider.issuer).hostname);
    requireSecureUrl(provider.issuer, "issuer", this.issuerIsLoopback);
    if (provider.mfaContract && !(provider.mfaContract.maxAgeSec > 0)) throw new OidcError("bad_config", "mfaContract.maxAgeSec must be positive");
    this.provider = provider;
    this.fetchJson = fetchJson;
  }

  /** discovery — 문서의 issuer가 설정 issuer와 **정확히** 같아야 한다(OIDC Discovery §4.3). 엔드포인트는 https. */
  async discover(): Promise<OidcDiscovery> {
    if (this.discovery && Date.now() - this.discovery.fetchedAt < DISCOVERY_TTL_MS) return this.discovery.doc;
    const url = this.provider.issuer.replace(/\/$/, "") + "/.well-known/openid-configuration";
    const { status, json } = await this.fetchJson(url);
    const d = json as Partial<OidcDiscovery> | null;
    if (status !== 200 || !d) throw new OidcError("discovery_failed");
    if (d.issuer !== this.provider.issuer) throw new OidcError("discovery_issuer_mismatch");
    for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri"] as const) {
      if (typeof d[k] !== "string") throw new OidcError("discovery_failed", `${k} missing`);
      requireSecureUrl(d[k]!, k, this.issuerIsLoopback);
    }
    this.discovery = { doc: d as OidcDiscovery, fetchedAt: Date.now() };
    return this.discovery.doc;
  }

  private async keys(force: boolean): Promise<Jwk[]> {
    if (!force && this.jwks && Date.now() - this.jwks.fetchedAt < JWKS_TTL_MS) return this.jwks.keys;
    if (force) {
      // 최근에 이미 강제로 받았다면 다시 받지 않는다 — 가진 키로 판정하게 해 "unknown_key"로 끝난다.
      if (Date.now() - this.lastForcedRefreshAt < JWKS_FORCED_REFRESH_MIN_MS && this.jwks) return this.jwks.keys;
      this.lastForcedRefreshAt = Date.now();
    }
    this.jwksInFlight ??= this.fetchKeys().finally(() => {
      this.jwksInFlight = null;
    });
    return await this.jwksInFlight;
  }

  private async fetchKeys(): Promise<Jwk[]> {
    const d = await this.discover();
    const { status, json } = await this.fetchJson(d.jwks_uri);
    const keys = (json as { keys?: unknown } | null)?.keys;
    if (status !== 200 || !Array.isArray(keys)) throw new OidcError("jwks_failed");
    this.jwks = { keys: keys.filter((k): k is Jwk => k !== null && typeof k === "object" && typeof (k as Jwk).kty === "string"), fetchedAt: Date.now() };
    return this.jwks.keys;
  }

  /**
   * 메일 클라이언트용 **access token** 검증(회원 정책 E4) — JWT(RFC 9068 형식)를 이 IdP의 키로 검증한다.
   *
   * ★ID 토큰과 섞지 않는다: audience는 **메일 전용 값**이어야 하고(설정이 웹 로그인 clientId와 같으면 기동 시 거부),
   * 메일 scope가 있어야 한다. ID 토큰은 aud가 clientId라 여기서 통과할 수 없다.
   * introspection은 하지 않는다 — 철회는 토큰의 exp까지 반영되지 않는다(지원 제한, 호출자 문서 참조).
   */
  async verifyAccessToken(
    token: string,
    req: { audience: string; requiredScope: string; nowMs?: number; requireAtJwtTyp?: boolean; maxLifetimeSec?: number },
  ): Promise<{ sub: string; claims: JwtClaims }> {
    const nowMs = req.nowMs ?? Date.now();
    const claimReq = { issuer: this.provider.issuer, audience: req.audience, nowMs, requireExp: true, checkAzp: false };
    // ★RFC 9068 typ — ID 토큰을 access token으로 받지 않는 두 번째 근거(첫째는 aud). 지키지 않는 IdP는 설정으로 끈다.
    if (req.requireAtJwtTyp ?? true) {
      let typ: string | undefined;
      try {
        typ = decodeJwt(token).header.typ?.toLowerCase();
      } catch {
        throw new OidcError("access_token_malformed");
      }
      if (typ !== "at+jwt" && typ !== "application/at+jwt") throw new OidcError("access_token_bad_typ");
    }
    const maxLifetime = (req.maxLifetimeSec ?? PROVISIONAL_MAX_ACCESS_TOKEN_LIFETIME_SEC) * 1000;
    const check = (claims: JwtClaims): void => {
      if (!scopesOf(claims).includes(req.requiredScope)) throw new OidcError("access_token_missing_scope");
      const exp = Number(claims.exp) * 1000;
      // 메일 경로에서는 exp에 시계 오차를 주지 않는다 — 막 만료된 토큰이 AUTH를 통과한 직후 바로 끊기는 혼란을 없앤다.
      if (exp <= nowMs) throw new OidcError("access_token_expired");
      const iat = typeof claims.iat === "number" ? claims.iat * 1000 : nowMs;
      if (exp - iat > maxLifetime) throw new OidcError("access_token_lifetime_too_long");
    };
    try {
      const r = verifyJwt(token, await this.keys(false), claimReq);
      check(r.claims);
      return { sub: r.sub, claims: r.claims };
    } catch (err) {
      if (err instanceof JwtError && err.reason === "unknown_key") {
        try {
          const r = verifyJwt(token, await this.keys(true), claimReq);
          check(r.claims);
          return { sub: r.sub, claims: r.claims };
        } catch (err2) {
          if (err2 instanceof OidcError) throw err2;
          throw new OidcError(err2 instanceof JwtError ? `access_token_${err2.reason}` : "access_token_invalid");
        }
      }
      if (err instanceof OidcError) throw err;
      throw new OidcError(err instanceof JwtError ? `access_token_${err.reason}` : "access_token_invalid");
    }
  }

  /** 인가 요청 URL. MFA 계약이 있으면 max_age를 싣는다(요청일 뿐 — 판정은 응답으로 한다). */
  async authorizationUrl(input: { redirectUri: string; state: string; nonce: string; codeChallenge: string }): Promise<string> {
    const d = await this.discover();
    const u = new URL(d.authorization_endpoint);
    u.searchParams.set("response_type", "code");
    u.searchParams.set("client_id", this.provider.clientId);
    u.searchParams.set("redirect_uri", input.redirectUri);
    u.searchParams.set("scope", (this.provider.scopes ?? ["openid"]).includes("openid") ? (this.provider.scopes ?? ["openid"]).join(" ") : ["openid", ...(this.provider.scopes ?? [])].join(" "));
    u.searchParams.set("state", input.state);
    u.searchParams.set("nonce", input.nonce);
    u.searchParams.set("code_challenge", input.codeChallenge);
    u.searchParams.set("code_challenge_method", "S256");
    if (this.provider.mfaContract) u.searchParams.set("max_age", String(this.provider.mfaContract.maxAgeSec));
    return u.toString();
  }

  /**
   * code → ID 토큰 검증 결과. access token은 쓰지 않는다(웹 로그인에는 신원만 필요하다 — E4의 메일용 토큰과 용도가 다르다).
   * 실패는 `OidcError`(사유 포함). 토큰 원문은 오류에 싣지 않는다.
   */
  async exchangeAndVerify(input: { code: string; redirectUri: string; codeVerifier: string; nonce: string; nowMs?: number }): Promise<{ sub: string; claims: JwtClaims }> {
    const d = await this.discover();
    const body = new URLSearchParams({ grant_type: "authorization_code", code: input.code, redirect_uri: input.redirectUri, code_verifier: input.codeVerifier });
    const basic = Buffer.from(`${encodeURIComponent(this.provider.clientId)}:${encodeURIComponent(this.provider.clientSecret)}`).toString("base64");
    const { status, json } = await this.fetchJson(d.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${basic}`, accept: "application/json" },
      body: body.toString(),
    });
    const idToken = (json as { id_token?: unknown } | null)?.id_token;
    if (status !== 200 || typeof idToken !== "string") throw new OidcError("token_exchange_failed");
    const req = { issuer: this.provider.issuer, audience: this.provider.clientId, nowMs: input.nowMs ?? Date.now(), nonce: input.nonce };
    try {
      const r = verifyJwt(idToken, await this.keys(false), req);
      return { sub: r.sub, claims: r.claims };
    } catch (err) {
      // 낯선 kid — IdP가 키를 교체했을 수 있다. 한 번만 다시 받는다(무한 재시도는 DoS 증폭기다).
      if (err instanceof JwtError && err.reason === "unknown_key") {
        try {
          const r = verifyJwt(idToken, await this.keys(true), req);
          return { sub: r.sub, claims: r.claims };
        } catch (err2) {
          throw new OidcError(err2 instanceof JwtError ? `id_token_${err2.reason}` : "id_token_invalid");
        }
      }
      throw new OidcError(err instanceof JwtError ? `id_token_${err.reason}` : "id_token_invalid");
    }
  }
}

/**
 * access token의 scope 클레임 — RFC 9068은 `scope`(공백 구분 문자열), 일부 IdP는 `scp`(배열·문자열)를 쓴다. 둘 다 읽는다.
 */
function scopesOf(claims: JwtClaims): string[] {
  const out: string[] = [];
  for (const v of [claims.scope, claims.scp]) {
    if (typeof v === "string") out.push(...v.split(/\s+/).filter(Boolean));
    else if (Array.isArray(v)) out.push(...v.filter((x): x is string => typeof x === "string"));
  }
  return out;
}

/**
 * MFA 증거 판정 — 계약을 충족하면 **IdP가 인증한 시각(auth_time, ms)**, 아니면 null(로컬 TOTP 필요).
 *
 * 계약 충족 = (acr이 acceptAcr 중 하나 OR amr에 requireAmrAll이 모두) AND auth_time이 maxAgeSec 안.
 * 둘 다 설정되지 않은 계약은 아무것도 충족하지 않는다(빈 계약으로 MFA를 면제하지 않는다).
 */
export function mfaSatisfiedAt(claims: JwtClaims, contract: MfaEvidenceContract | undefined, nowMs: number): number | null {
  if (!contract) return null;
  const acrOk = contract.acceptAcr !== undefined && contract.acceptAcr.length > 0 && typeof claims.acr === "string" && contract.acceptAcr.includes(claims.acr);
  const amr = Array.isArray(claims.amr) ? claims.amr.filter((v): v is string => typeof v === "string") : [];
  const amrOk = contract.requireAmrAll !== undefined && contract.requireAmrAll.length > 0 && contract.requireAmrAll.every((m) => amr.includes(m));
  if (!acrOk && !amrOk) return null;
  const authTime = claims.auth_time;
  if (typeof authTime !== "number") return null;
  const authMs = authTime * 1000;
  if (authMs > nowMs + 60_000 || nowMs - authMs > contract.maxAgeSec * 1000) return null;
  // 시계 오차로 미래인 auth_time을 그대로 쓰면 step-up 창이 그만큼 늘어난다 — 지금으로 자른다.
  return Math.min(authMs, nowMs);
}
