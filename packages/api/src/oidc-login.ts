/**
 * OIDC 웹 로그인의 HTTP 흐름 — 시작(인가 요청)과 콜백(검증) (회원 정책 E3). 관리 콘솔과 셀프서비스가 같은 것을 쓴다.
 *
 * ★지키는 것:
 *  - state·nonce·PKCE verifier는 서버(DB)에 1회용으로 두고, state는 **브라우저 쿠키에도** 묶는다. 콜백의 state가
 *    그 쿠키와 같아야 한다 — 남의 인가 응답을 내 브라우저에 밀어 넣어 공격자 계정으로 로그인시키는 로그인 CSRF를 막는다.
 *  - 그 쿠키는 SameSite=Lax다. 콜백은 IdP에서 오는 **최상위 이동**이라 Strict 쿠키는 실리지 않는다.
 *    세션 쿠키는 그대로 Strict다(이 쿠키는 state 확인 한 번에만 쓰이고 바로 지워진다).
 *  - redirect_uri는 **설정된 오리진**에서 만든다. 요청 Host로 만들면 공격자가 고른 이름으로 code가 간다.
 *  - 실패 사유는 감사에만 남기고 화면에는 "실패"만 보인다.
 */
import type { IncomingMessage } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { mfaSatisfiedAt, newOpaque, newPkce, OidcError, type OidcClient } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import { saveOidcLoginState, takeOidcLoginState, type OidcRealm } from "@ionosphere/store";
import { readCookie } from "./admin-session.ts";

export interface OidcRealmProvider {
  client: OidcClient;
  /** 메일 계정 영역이면 그 공급자가 속한 테넌트(연결 조회 범위). */
  tenantId?: string;
}

export interface OidcCallbackResult {
  providerId: string;
  sub: string;
  /** IdP MFA 증거가 공급자 계약을 충족하면 그 인증 시각(ms), 아니면 null(로컬 TOTP 필요). */
  idpMfaAt: number | null;
  tenantId?: string;
}

export class OidcLoginFlow {
  private readonly db: DbDriver;
  readonly realm: OidcRealm;
  private readonly providers: ReadonlyMap<string, OidcRealmProvider>;
  private readonly callbackUrl: string;
  private readonly stateCookie: string;

  constructor(opts: { db: DbDriver; realm: OidcRealm; providers: ReadonlyMap<string, OidcRealmProvider>; callbackUrl: string }) {
    this.db = opts.db;
    this.realm = opts.realm;
    this.providers = opts.providers;
    this.callbackUrl = opts.callbackUrl;
    this.stateCookie = `__Host-ionosphere_oidc_${opts.realm}`;
  }

  providerIds(): string[] {
    return [...this.providers.keys()];
  }

  /** 인가 요청 — IdP로 보낼 Location과 state 쿠키. 모르는 공급자면 null. */
  async start(providerId: string): Promise<{ location: string; setCookie: string } | null | "busy"> {
    const p = this.providers.get(providerId);
    if (!p) return null;
    const state = newOpaque();
    const nonce = newOpaque();
    const pkce = newPkce();
    if (!(await saveOidcLoginState(this.db, { state, provider: providerId, realm: this.realm, nonce, codeVerifier: pkce.verifier }))) return "busy";
    const location = await p.client.authorizationUrl({ redirectUri: this.callbackUrl, state, nonce, codeChallenge: pkce.challenge });
    return { location, setCookie: `${this.stateCookie}=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600` };
  }

  /** state 쿠키를 지우는 Set-Cookie — 콜백은 성공·실패와 무관하게 지운다. */
  clearStateCookie(): string {
    return `${this.stateCookie}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
  }

  /**
   * 콜백 검증 — 성공이면 (공급자, sub, IdP MFA 시각), 실패면 `OidcError`(사유). 연결 조회(sub → 주체)는 호출자 몫이다.
   */
  async callback(req: IncomingMessage, url: URL): Promise<OidcCallbackResult> {
    if (url.searchParams.get("error")) throw new OidcError("idp_error");
    const state = url.searchParams.get("state") ?? "";
    const code = url.searchParams.get("code") ?? "";
    const cookieState = readCookie(req, this.stateCookie) ?? "";
    if (state === "" || code === "" || cookieState === "") throw new OidcError("missing_state_or_code");
    const a = Buffer.from(state);
    const b = Buffer.from(cookieState);
    if (a.length !== b.length || !timingSafeEqual(a, b)) throw new OidcError("state_cookie_mismatch");
    const saved = await takeOidcLoginState(this.db, state, this.realm);
    if (!saved) throw new OidcError("state_unknown_or_used");
    const p = this.providers.get(saved.provider);
    if (!p) throw new OidcError("provider_gone");
    const now = Date.now();
    const { sub, claims } = await p.client.exchangeAndVerify({ code, redirectUri: this.callbackUrl, codeVerifier: saved.codeVerifier, nonce: saved.nonce, nowMs: now });
    return {
      providerId: saved.provider,
      sub,
      idpMfaAt: mfaSatisfiedAt(claims, p.client.provider.mfaContract, now),
      ...(p.tenantId !== undefined ? { tenantId: p.tenantId } : {}),
    };
  }
}
