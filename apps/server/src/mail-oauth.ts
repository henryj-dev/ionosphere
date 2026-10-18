/**
 * 메일 클라이언트의 외부 OAuth access token 검증(2026-10-18 회원 정책 E4).
 *
 * XOAUTH2/OAUTHBEARER(와 비밀번호 칸)로 들어온 값이 JWT 모양이면, 설정된 account 영역 공급자의 키로 검증해
 * **연결된 메일 계정**으로 들인다. 로컬 자격증명(비밀번호·앱 비밀번호·자체 발급 토큰)이 먼저다(app.ts authenticatePassword).
 *
 * ★지키는 것:
 *  - 메일 전용 audience + 필수 scope. ID 토큰은 aud가 clientId라 통과하지 못한다(설정이 둘을 같게 두면 기동이 실패한다).
 *  - 계정은 **sub로만** 찾는다(공급자 테넌트의 directory_identities `oidc:<id>` — 셀프서비스와 같은 연결). 토큰의 email
 *    클레임으로 찾지 않는다. SASL이 말한 사용자(user=)가 그 계정 주소와 같아야 한다 — 다르면 거절한다.
 *  - IdP 장애·키 조회 실패는 **거절**이다(fail closed). 로컬 자격증명은 영향이 없다.
 *  - 실패는 전부 같은 null이다(인증 실패와 구분하지 않는다). 사유는 로그에만, 토큰 원문은 어디에도 남기지 않는다.
 *
 * ⚠ 지원 제한(lodestar 보고 반영):
 *  - introspection을 하지 않는다 — IdP에서 토큰을 철회해도 **exp까지** 통한다(lodestar access TTL 5분).
 *  - 인증은 연결을 열 때 한 번이다. 토큰이 만료돼도 열린 IMAP 연결은 계속된다. 계정 정지는 다음 명령에서 반영된다(G2).
 */
import { decodeJwt, noopLogger, OidcClient, type Logger, type OidcFetch } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import { accountByOidcIdentity, type AuthSurface } from "@ionosphere/store";
import type { ParsedOidcProvider } from "./oidc-config.ts";

interface MailTokenProvider {
  id: string;
  tenantId: string;
  client: OidcClient;
  audience: string;
  requiredScope: string;
  surfaces?: readonly AuthSurface[];
  requireAtJwtTyp?: boolean;
  maxLifetimeSec?: number;
}

/** JWT 모양인가(세 부분, base64url). 아니면 이 경로를 아예 타지 않는다 — 비밀번호마다 IdP를 부르지 않게. */
export function looksLikeJwt(s: string): boolean {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(s) && s.length < 16_384;
}

export class MailOAuthVerifier {
  private readonly byIssuer = new Map<string, MailTokenProvider[]>();
  private readonly db: DbDriver;
  private readonly log: Logger;

  constructor(db: DbDriver, providers: readonly ParsedOidcProvider[], opts: { logger?: Logger; fetch?: OidcFetch } = {}) {
    this.db = db;
    this.log = (opts.logger ?? noopLogger).child({ component: "mail-oauth" });
    for (const p of providers) {
      if (p.realm !== "account" || !p.mailAccessToken || !p.tenantId) continue;
      const entry: MailTokenProvider = {
        id: p.config.id,
        tenantId: p.tenantId,
        client: new OidcClient(p.config, ...(opts.fetch ? [opts.fetch] : [])),
        audience: p.mailAccessToken.audience,
        requiredScope: p.mailAccessToken.requiredScope,
        ...(p.mailAccessToken.surfaces ? { surfaces: p.mailAccessToken.surfaces } : {}),
        ...(p.mailAccessToken.requireAtJwtTyp !== undefined ? { requireAtJwtTyp: p.mailAccessToken.requireAtJwtTyp } : {}),
        ...(p.mailAccessToken.maxLifetimeSec !== undefined ? { maxLifetimeSec: p.mailAccessToken.maxLifetimeSec } : {}),
      };
      const list = this.byIssuer.get(p.config.issuer) ?? [];
      list.push(entry);
      this.byIssuer.set(p.config.issuer, list);
    }
  }

  get enabled(): boolean {
    return this.byIssuer.size > 0;
  }

  /** 검증되면 계정 id와 감사용 자격증명 종류. 아니면 null. */
  async authenticate(user: string, token: string, surface: AuthSurface): Promise<{ accountId: string; credKind: string } | null> {
    if (!this.enabled || !looksLikeJwt(token)) return null;
    let issuer: unknown;
    try {
      // 서명 전 클레임은 **공급자를 고르는 데만** 쓴다. 판정은 아래 verifyAccessToken이 그 공급자의 키로 한다.
      issuer = decodeJwt(token).claims.iss;
    } catch {
      return null;
    }
    const candidates = typeof issuer === "string" ? (this.byIssuer.get(issuer) ?? []) : [];
    for (const p of candidates) {
      if (p.surfaces && !p.surfaces.includes(surface)) continue;
      let sub: string;
      try {
        sub = (
          await p.client.verifyAccessToken(token, {
            audience: p.audience,
            requiredScope: p.requiredScope,
            ...(p.requireAtJwtTyp !== undefined ? { requireAtJwtTyp: p.requireAtJwtTyp } : {}),
            ...(p.maxLifetimeSec !== undefined ? { maxLifetimeSec: p.maxLifetimeSec } : {}),
          })
        ).sub;
      } catch (err) {
        this.log.info("mail access token 거절", { provider: p.id, reason: err instanceof Error ? (err as { reason?: string }).reason ?? "error" : "error" });
        continue;
      }
      const accountId = await accountByOidcIdentity(this.db, p.tenantId, p.id, sub);
      if (!accountId) {
        this.log.info("mail access token — 연결되지 않은 sub", { provider: p.id });
        continue;
      }
      const { rows } = await this.db.query({ sql: "SELECT email FROM accounts WHERE id = ?", params: [accountId] });
      // SASL이 말한 사용자와 토큰의 주인이 같아야 한다 — 남의 토큰으로 내 주소를 말하거나 그 반대를 막는다.
      if (String(rows[0]?.email ?? "").toLowerCase() !== user.trim().toLowerCase()) {
        this.log.info("mail access token — SASL 사용자와 토큰 주인이 다름", { provider: p.id });
        continue;
      }
      return { accountId, credKind: `oauth:${p.id}` };
    }
    return null;
  }
}
