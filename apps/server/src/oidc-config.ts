/**
 * 외부 OIDC 공급자 설정(E3) — `IONOSPHERE_OIDC_PROVIDERS` JSON 배열 하나가 정본이다(directory-config.ts와 같은 형식).
 *
 * 원소: `{ id, realm: "admin"|"account", issuer, clientId, clientSecret, tenantId?, scopes?, mfaContract? }`
 *  - realm=account면 tenantId가 필수다(연결 조회 범위).
 *  - mfaContract: `{ acceptAcr?: string[], requireAmrAll?: string[], maxAgeSec: number }` — 생략하면 IdP MFA를 인정하지 않는다
 *    (로컬 TOTP 필수). acceptAcr·requireAmrAll 둘 다 비면 거부한다(빈 계약으로 MFA를 면제하지 않는다).
 *
 * 오류 메시지에 clientSecret을 싣지 않는다.
 */
import { OidcClient, type MfaEvidenceContract, type OidcProviderConfig } from "@ionosphere/core";
import { AUTH_SURFACES, type AuthSurface } from "@ionosphere/store";

/**
 * 메일 클라이언트용 access token 설정(E4) — account 영역 공급자에만. 있으면 IMAP·SMTP·POP3·JMAP·ManageSieve의
 * XOAUTH2/OAUTHBEARER(와 Basic/PLAIN의 비밀번호 칸)로 들어온 JWT를 이 IdP의 키로 검증한다.
 */
export interface MailAccessTokenConfig {
  /** 메일 전용 audience. 웹 로그인 clientId와 **달라야** 한다(같으면 ID 토큰이 access token으로 통한다). */
  audience: string;
  /** 반드시 있어야 하는 scope. */
  requiredScope: string;
  /** 허용 표면. 생략하면 전부. */
  surfaces?: readonly AuthSurface[];
  /** 헤더 typ=at+jwt(RFC 9068)를 요구한다. 기본 true — 지키지 않는 IdP만 false로 끈다(ID 토큰 차단의 근거가 aud 하나로 줄어든다). */
  requireAtJwtTyp?: boolean;
  /** access token 수명 상한(초). 기본은 임시 1시간. */
  maxLifetimeSec?: number;
}

export interface ParsedOidcProvider {
  realm: "admin" | "account";
  tenantId?: string;
  config: OidcProviderConfig;
  mailAccessToken?: MailAccessTokenConfig;
}

function str(v: unknown, field: string, i: number): string {
  if (typeof v !== "string" || v.trim() === "") throw new Error(`IONOSPHERE_OIDC_PROVIDERS[${i}].${field}가 비어 있음`);
  return v.trim();
}
function strList(v: unknown, field: string, i: number): string[] | undefined {
  if (v === undefined) return undefined;
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string" || x === "")) throw new Error(`IONOSPHERE_OIDC_PROVIDERS[${i}].${field}는 문자열 배열이어야 함`);
  return v as string[];
}

export function oidcProvidersFromJson(raw: string | undefined): ParsedOidcProvider[] {
  if (raw === undefined || raw.trim() === "") return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("IONOSPHERE_OIDC_PROVIDERS가 유효한 JSON이 아님");
  }
  if (!Array.isArray(parsed)) throw new Error("IONOSPHERE_OIDC_PROVIDERS는 배열이어야 함");
  const seen = new Set<string>();
  return parsed.map((item, i) => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) throw new Error(`IONOSPHERE_OIDC_PROVIDERS[${i}]가 객체가 아님`);
    const o = item as Record<string, unknown>;
    const id = str(o.id, "id", i).toLowerCase();
    if (!/^[a-z0-9._-]{1,32}$/.test(id)) throw new Error(`IONOSPHERE_OIDC_PROVIDERS[${i}].id 형식 오류`);
    if (seen.has(id)) throw new Error(`IONOSPHERE_OIDC_PROVIDERS id 중복: ${id}`);
    seen.add(id);
    const realm = o.realm;
    if (realm !== "admin" && realm !== "account") throw new Error(`IONOSPHERE_OIDC_PROVIDERS[${i}].realm은 admin 또는 account`);
    const tenantId = o.tenantId === undefined ? undefined : str(o.tenantId, "tenantId", i);
    if (realm === "account" && tenantId === undefined) throw new Error(`IONOSPHERE_OIDC_PROVIDERS[${i}].tenantId는 realm=account에서 필수`);
    let mfaContract: MfaEvidenceContract | undefined;
    if (o.mfaContract !== undefined) {
      const m = o.mfaContract as Record<string, unknown>;
      const acceptAcr = strList(m.acceptAcr, "mfaContract.acceptAcr", i);
      const requireAmrAll = strList(m.requireAmrAll, "mfaContract.requireAmrAll", i);
      if ((acceptAcr?.length ?? 0) === 0 && (requireAmrAll?.length ?? 0) === 0) {
        throw new Error(`IONOSPHERE_OIDC_PROVIDERS[${i}].mfaContract에 acceptAcr 또는 requireAmrAll이 필요함(빈 계약으로 MFA를 면제하지 않는다)`);
      }
      if (typeof m.maxAgeSec !== "number" || !Number.isInteger(m.maxAgeSec) || m.maxAgeSec <= 0) throw new Error(`IONOSPHERE_OIDC_PROVIDERS[${i}].mfaContract.maxAgeSec는 양의 정수`);
      mfaContract = { ...(acceptAcr ? { acceptAcr } : {}), ...(requireAmrAll ? { requireAmrAll } : {}), maxAgeSec: m.maxAgeSec };
    }
    const scopes = strList(o.scopes, "scopes", i);
    const config: OidcProviderConfig = {
      id,
      issuer: str(o.issuer, "issuer", i),
      clientId: str(o.clientId, "clientId", i),
      clientSecret: str(o.clientSecret, "clientSecret", i),
      ...(scopes ? { scopes } : {}),
      ...(mfaContract ? { mfaContract } : {}),
    };
    let mailAccessToken: MailAccessTokenConfig | undefined;
    if (o.mailAccessToken !== undefined) {
      if (realm !== "account") throw new Error(`IONOSPHERE_OIDC_PROVIDERS[${i}].mailAccessToken은 realm=account에서만`);
      const m = o.mailAccessToken as Record<string, unknown>;
      const audience = str(m.audience, "mailAccessToken.audience", i);
      // ★ID 토큰 혼용 차단 — 웹 로그인의 aud(clientId)와 같으면 ID 토큰이 메일 access token으로 받아들여진다.
      if (audience === config.clientId) throw new Error(`IONOSPHERE_OIDC_PROVIDERS[${i}].mailAccessToken.audience는 clientId와 달라야 함(ID 토큰과 access token을 섞지 않는다)`);
      const requiredScope = str(m.requiredScope, "mailAccessToken.requiredScope", i);
      const surfaces = strList(m.surfaces, "mailAccessToken.surfaces", i);
      if (surfaces) {
        const known: readonly string[] = AUTH_SURFACES;
        const bad = surfaces.filter((x) => !known.includes(x));
        if (bad.length > 0 || surfaces.length === 0) throw new Error(`IONOSPHERE_OIDC_PROVIDERS[${i}].mailAccessToken.surfaces에 알 수 없는 표면 또는 빈 배열`);
      }
      if (m.requireAtJwtTyp !== undefined && typeof m.requireAtJwtTyp !== "boolean") throw new Error(`IONOSPHERE_OIDC_PROVIDERS[${i}].mailAccessToken.requireAtJwtTyp는 boolean`);
      if (m.maxLifetimeSec !== undefined && (typeof m.maxLifetimeSec !== "number" || !Number.isInteger(m.maxLifetimeSec) || m.maxLifetimeSec <= 0)) {
        throw new Error(`IONOSPHERE_OIDC_PROVIDERS[${i}].mailAccessToken.maxLifetimeSec는 양의 정수`);
      }
      mailAccessToken = {
        audience,
        requiredScope,
        ...(surfaces ? { surfaces: surfaces as AuthSurface[] } : {}),
        ...(typeof m.requireAtJwtTyp === "boolean" ? { requireAtJwtTyp: m.requireAtJwtTyp } : {}),
        ...(typeof m.maxLifetimeSec === "number" ? { maxLifetimeSec: m.maxLifetimeSec } : {}),
      };
    }
    // 생성자가 issuer https·계약 형식을 다시 확인한다 — 기동 전에 실패시키려고 여기서 한 번 만든다.
    new OidcClient(config);
    return { realm, ...(tenantId ? { tenantId } : {}), config, ...(mailAccessToken ? { mailAccessToken } : {}) };
  });
}
