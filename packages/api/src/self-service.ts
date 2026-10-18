/**
 * 메일 계정 셀프서비스 HTTP 어댑터 (2026-10-18 회원 정책 E2).
 *
 * 메일 사용자가 웹에서 직접: 기본 비밀번호 변경, 앱 비밀번호 발급·목록·철회, 자기 TOTP 등록·복구.
 *
 * ★지키는 계약(공통 기준 1~4, 결정 D3):
 *  - 로그인은 **기본 비밀번호(kind=0)만**. 앱 비밀번호·토큰·디렉터리 bind로는 들어오지 못한다(store `account-web.ts`).
 *  - 쿠키 세션은 서버에 둔다. 보호 요청마다 계정 상태를 다시 본다 — 정지·삭제·로그아웃은 다음 요청부터 반영된다.
 *  - 상태를 바꾸는 요청은 Origin 일치 + CSRF 토큰(세션 토큰의 HMAC, 관리자와 다른 라벨).
 *  - **민감 작업(비밀번호 변경·앱 비밀번호 발급·철회)은 최근 MFA가 필요하다.** TOTP 미등록이면 할 수 없다 —
 *    면제는 없다(공통 기준 4). 미등록 사용자는 목록만 본다. 첫 등록에는 관리자가 발급한 일회용 등록 코드가 필요하다.
 *  - 셀프서비스 웹 세션을 끊어도 메일 클라이언트(앱 비밀번호·IMAP 연결)는 끊지 않는다(장기 메일 연결은 별도 계약).
 *
 * 실제 일은 관리 명령 계층이 한다(`@ionosphere/admin-cmd`) — 셀프서비스는 **자기 계정으로 고정해** 같은 명령을 부른다.
 * 같은 동작이 두 갈래로 갈라지지 않게(이 저장소의 반복 사고).
 *
 * 시도 제한의 계정 키는 메일 프로토콜과 **같다**(접두 없음). 같은 기본 비밀번호를 맞히는 시도라서, 웹과 IMAP이
 * 한도를 따로 가지면 대입 한도가 두 배가 된다. 관리자 로그인이 `admin|` 접두를 쓰는 것과 반대인 이유다(그쪽은 다른 비밀).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  AUDIT_OUTCOME,
  AUDIT_SURFACE,
  AuthFailureThrottle,
  hardenHttpListener,
  noopAuditSink,
  noopLogger,
  totpUri,
  trackListener,
  type AuditSink,
  type ListenerShutdown,
  type Logger,
} from "@ionosphere/core";
import { CREDENTIAL_KIND, type DbDriver } from "@ionosphere/db";
import {
  ACCOUNT_REALM,
  beginTotpEnrollment,
  burnTotpCost,
  confirmTotpEnrollment,
  createWebSession,
  csrfTokenForRealm,
  listCredentials,
  markWebSessionMfa,
  mfaEnrolled,
  PROVISIONAL_WEB_SESSION_POLICY,
  redeemRecoveryCode,
  remainingRecoveryCodes,
  resolveAccountSession,
  revokeWebSession,
  Store,
  verifyAccountPrimaryPassword,
  verifySecondFactorTotp,
  accountByOidcIdentity,
  type ResolvedAccountSession,
  type WebSessionPolicy,
} from "@ionosphere/store";
import { CommandError, createRegistry, runCommand, type CommandContext, type CommandRegistry } from "@ionosphere/admin-cmd";
import { ACCOUNT_SESSION_COOKIE, clearedSessionCookie, csrfMatches, originAllowed, PROVISIONAL_STEP_UP_MS, readCookie, sessionCookie } from "./admin-session.ts";
import { asRecord, clientIp, HttpError, readBody, sendJson } from "./http-util.ts";
import { SELF_SERVICE_UI_HTML } from "./self-service-ui.ts";
import type { OidcLoginFlow } from "./oidc-login.ts";
import { OidcError } from "@ionosphere/core";
import { ADMIN_UI_SECURITY_HEADERS } from "./admin-ui.ts";

export interface SelfServiceDeps {
  db: DbDriver;
  store: Store;
  /** TOTP 비밀 봉인 키. 없으면 TOTP를 다루지 않는다(등록·검증이 500으로 닫힌다). */
  masterKey?: string;
  logger?: Logger;
  /** 메일 프로토콜과 **같은 인스턴스**(파일 머리말 — 같은 비밀번호의 대입 한도를 하나로). */
  authThrottle?: AuthFailureThrottle;
  audit?: AuditSink;
  sessionPolicy?: WebSessionPolicy;
  stepUpMs?: number;
  /** 셀프서비스 화면의 정확한 오리진. 없으면 Origin host를 요청 Host와 비교한다. */
  origin?: string;
  totpIssuer?: string;
  /** 외부 OIDC 로그인(E3). 공급자는 메일 계정 영역(테넌트 고정)이다. */
  oidc?: OidcLoginFlow;
}

/** 셀프서비스가 부를 수 있는 명령과, 그 명령이 민감 작업인가. 이 표 밖의 명령은 부를 수 없다. */
const SELF_COMMANDS = {
  "app-password-list": { sensitive: false },
  "app-password-create": { sensitive: true },
  "credential-revoke": { sensitive: true },
  "account-password-set": { sensitive: true },
} as const;
type SelfCommand = keyof typeof SELF_COMMANDS;

/** 셀프서비스 새 비밀번호 최소 길이. ⚠ 임시(공통 비밀번호 규칙 미확정, 2026-10-18). */
const PROVISIONAL_MIN_PASSWORD_LENGTH = 10;

/**
 * 동시에 처리하는 로그인 수 상한. 로그인 한 번이 scrypt를 두 번 태우는데(비밀번호 + 응답 시간 맞추기) 이 표면은 공개다.
 * IP 축 스로틀은 흩어진 봇넷 앞에서 약하므로, 넘치면 바로 503으로 돌려 CPU가 메일 처리 몫까지 먹지 않게 한다.
 * 계정이 없을 때 비용을 건너뛰는 방법은 쓰지 않는다 — 기존 계정의 틀린 비밀번호와 응답 시간이 달라져 계정 존재가 샌다.
 */
const MAX_CONCURRENT_LOGINS = 8;

export class SelfServiceServer {
  private readonly deps: SelfServiceDeps;
  private readonly log: Logger;
  private readonly throttle: AuthFailureThrottle;
  private readonly audit: AuditSink;
  private readonly registry: CommandRegistry;
  private readonly origin: string | undefined;
  private server: Server | null = null;
  private shutdown: ListenerShutdown | null = null;
  private loginsInFlight = 0;

  constructor(deps: SelfServiceDeps) {
    this.deps = deps;
    this.log = (deps.logger ?? noopLogger).child({ component: "self-service" });
    this.throttle = deps.authThrottle ?? new AuthFailureThrottle({ ...(deps.logger ? { logger: deps.logger } : {}) });
    this.audit = deps.audit ?? noopAuditSink;
    this.registry = createRegistry();
    if (deps.origin !== undefined) {
      try {
        this.origin = new URL(deps.origin).origin;
      } catch {
        throw new Error("self-service origin이 URL이 아니다");
      }
    }
  }

  listen(port: number, host?: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = createServer((req, res) => void this.handle(req, res));
      const shutdown = trackListener(server);
      hardenHttpListener(server);
      server.once("error", reject);
      server.listen(port, host, () => {
        this.server = server;
        this.shutdown = shutdown;
        const addr = server.address();
        resolve(typeof addr === "object" && addr !== null ? addr.port : port);
      });
    });
  }

  async close(): Promise<void> {
    const shutdown = this.shutdown;
    this.server = null;
    this.shutdown = null;
    if (shutdown) await shutdown.close();
  }

  private async session(req: IncomingMessage): Promise<{ token: string; s: ResolvedAccountSession | null }> {
    const token = readCookie(req, ACCOUNT_SESSION_COOKIE) ?? "";
    return { token, s: await resolveAccountSession(this.deps.db, token, this.deps.sessionPolicy ?? PROVISIONAL_WEB_SESSION_POLICY) };
  }

  private requireSameOriginWrite(req: IncomingMessage, csrfHash: string): void {
    if (!originAllowed(req, this.origin) || !csrfMatches(req, csrfHash)) throw new HttpError(403, "csrf check failed", "csrf");
  }

  /** 민감 작업 관문 — 등록된 TOTP로 최근에 통과했어야 한다. 미등록은 `mfa_required`(면제 없음, 결정 D3). */
  private requireFreshMfa(s: ResolvedAccountSession): void {
    if (!s.account.mfaEnrolled) throw new HttpError(403, "mfa enrollment required for this action", "mfa_required");
    const window = this.deps.stepUpMs ?? PROVISIONAL_STEP_UP_MS;
    if (s.mfaAt === null || Date.now() - s.mfaAt > window) throw new HttpError(403, "mfa step-up required", "step_up");
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const ip = clientIp(req);
    const audit: { accountId?: string; tenantId?: string; user?: string; detail: Record<string, string | number> } = { detail: {} };
    const url = new URL(req.url ?? "/", "http://localhost");
    const method = req.method ?? "GET";
    const path = url.pathname;
    if (!path.startsWith("/healthz")) {
      res.on("finish", () => {
        const status = res.statusCode;
        this.audit.record({
          ts: Date.now(),
          surface: AUDIT_SURFACE.selfService,
          action: `${method} ${path}`,
          outcome: status === 429 ? AUDIT_OUTCOME.throttled : status === 403 ? AUDIT_OUTCOME.denied : status >= 400 ? AUDIT_OUTCOME.fail : AUDIT_OUTCOME.ok,
          ip,
          ...(audit.user !== undefined ? { user: audit.user } : {}),
          ...(audit.accountId !== undefined ? { accountId: audit.accountId } : {}),
          ...(audit.tenantId !== undefined ? { tenantId: audit.tenantId } : {}),
          detail: { status, ...audit.detail },
        });
      });
    }
    try {
      if (method === "GET" && path === "/healthz") return sendJson(res, 200, { ok: true });
      if (method === "GET" && (path === "/" || path === "/account")) {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", ...ADMIN_UI_SECURITY_HEADERS });
        res.end(SELF_SERVICE_UI_HTML);
        return;
      }
      if (method === "POST" && path === "/account/session/login") {
        if (this.loginsInFlight >= MAX_CONCURRENT_LOGINS) return sendJson(res, 503, { error: "busy, retry shortly" }, { "Retry-After": "1" });
        this.loginsInFlight++;
        try {
          return await this.login(req, res, ip, audit);
        } finally {
          this.loginsInFlight--;
        }
      }

      if (path.startsWith("/account/session/oidc/")) return await this.oidc(req, res, method, path, ip, audit);

      const { token, s } = await this.session(req);
      if (method === "POST" && path === "/account/session/logout") {
        if (s) {
          if (!originAllowed(req, this.origin)) throw new HttpError(403, "csrf check failed", "csrf");
          await revokeWebSession(this.deps.db, ACCOUNT_REALM, s.sessionId);
        }
        return sendJson(res, 200, { ok: true }, { "Set-Cookie": clearedSessionCookie(ACCOUNT_SESSION_COOKIE) });
      }
      if (!s) return sendJson(res, 401, { error: "no session", code: "no_session" }, { "Set-Cookie": clearedSessionCookie(ACCOUNT_SESSION_COOKIE) });
      audit.accountId = s.account.accountId;
      audit.tenantId = s.account.tenantId;
      if (method !== "GET") this.requireSameOriginWrite(req, s.csrfHash);

      if (method === "GET" && path === "/account/session") {
        return sendJson(
          res,
          200,
          {
            email: s.account.email,
            mfaEnrolled: s.account.mfaEnrolled,
            mfaAt: s.mfaAt,
            stepUpMs: this.deps.stepUpMs ?? PROVISIONAL_STEP_UP_MS,
            csrfToken: csrfTokenForRealm(ACCOUNT_REALM, token),
            recoveryCodesRemaining: await remainingRecoveryCodes(this.deps.db, ACCOUNT_REALM, s.account.accountId),
          },
          { "Cache-Control": "no-store" },
        );
      }
      if (path.startsWith("/account/session/mfa/")) return await this.mfa(req, res, ip, path, s);

      if (method === "GET" && path === "/account/app-passwords") {
        return sendJson(res, 200, await this.run(s, "app-password-list", {}));
      }
      if (method === "POST" && path === "/account/app-passwords") {
        const body = asRecord(await readBody(req));
        const args: Record<string, string> = {};
        if (typeof body.label === "string") args.label = body.label;
        if (typeof body.scopes === "string") args.scopes = body.scopes;
        return sendJson(res, 200, await this.run(s, "app-password-create", args), { "Cache-Control": "no-store" });
      }
      const revoke = path.match(/^\/account\/credentials\/([^/]+)\/revoke$/);
      if (method === "POST" && revoke) {
        const credentialId = decodeURIComponent(revoke[1]!);
        /**
         * ★소유 확인이 여기 있어야 한다. `credential-revoke` 명령은 **테넌트**만 확인한다(관리자용) — 그대로 부르면
         * 같은 테넌트의 남의 앱 비밀번호를 끊을 수 있다. 자기 계정의 자격증명 목록에 있는 id만 받는다.
         */
        // 앱 비밀번호만 — 기본 비밀번호(kind=0)를 지우면 웹·IMAP이 모두 막혀 관리자만 되살릴 수 있다(2026-10-18 검토).
        const own = await listCredentials(this.deps.db, s.account.accountId, CREDENTIAL_KIND.appPassword);
        if (!own.some((c) => c.id === credentialId)) throw new HttpError(404, "credential not found");
        return sendJson(res, 200, await this.run(s, "credential-revoke", { credentialId }));
      }
      if (method === "POST" && path === "/account/password") {
        const body = asRecord(await readBody(req));
        const current = typeof body.currentPassword === "string" ? body.currentPassword : "";
        const next = typeof body.newPassword === "string" ? body.newPassword : "";
        // 민감 작업 관문을 먼저 — 현재 비밀번호 확인이 step-up을 건너뛰는 길이 되면 안 된다.
        this.requireFreshMfa(s);
        // 현재 비밀번호도 확인한다 — 잠깐 비운 자리에 남은 세션 하나로 비밀번호를 바꾸지 못하게.
        if (!(await verifyAccountPrimaryPassword(this.deps.db, s.account.email, current))) {
          await this.throttle.recordFailure({ ip, account: s.account.email });
          throw new HttpError(401, "current password is wrong", "invalid_password");
        }
        // 사용자가 직접 정하는 값이라 최소 길이를 둔다. ⚠ 수치는 임시다(공통 비밀번호 규칙 미확정).
        if (next.length < PROVISIONAL_MIN_PASSWORD_LENGTH) {
          throw new HttpError(400, `new password must be at least ${PROVISIONAL_MIN_PASSWORD_LENGTH} characters`, "weak_password");
        }
        const result = await this.run(s, "account-password-set", { password: next });
        // 명령이 이 계정의 셀프서비스 세션을 전부 끊었다 — 쿠키도 지운다(다시 로그인).
        return sendJson(res, 200, result, { "Set-Cookie": clearedSessionCookie(ACCOUNT_SESSION_COOKIE) });
      }
      return sendJson(res, 404, { error: "not found" });
    } catch (err) {
      if (err instanceof HttpError) return sendJson(res, err.status, { error: err.message, ...(err.code ? { code: err.code } : {}) });
      if (err instanceof CommandError) {
        const status = err.kind === "invalid" ? 400 : err.kind === "notFound" ? 404 : err.kind === "conflict" ? 409 : err.kind === "denied" ? 403 : 501;
        return sendJson(res, status, { error: err.message });
      }
      this.log.error("self-service request failed", { error: String(err) });
      return sendJson(res, 500, { error: "internal error" });
    }
  }

  /**
   * 자기 계정으로 고정해 명령을 부른다. 계정 인자는 **언제나** 세션의 계정이다 — 요청이 다른 계정을 지목할 자리가 없다.
   * 민감 명령은 여기서 step-up을 요구한다(표 `SELF_COMMANDS`가 근거).
   */
  private async run(s: ResolvedAccountSession, name: SelfCommand, args: Record<string, string>): Promise<Record<string, unknown>> {
    if (SELF_COMMANDS[name].sensitive) this.requireFreshMfa(s);
    const ctx: CommandContext = {
      db: this.deps.db,
      store: this.deps.store,
      tenantId: s.account.tenantId,
      isRoot: false,
      masterKey: this.deps.masterKey,
      resolveTxt: async () => [],
      resolveMx: async () => [],
    };
    const result = await runCommand(this.registry, ctx, name, { ...args, account: s.account.accountId });
    return {
      ...(result.rows ? { rows: result.rows } : {}),
      ...(result.data ? { data: result.data } : {}),
      ...(result.message ? { message: result.message } : {}),
      ...(result.secret ? { __secret: result.secret } : {}),
    };
  }

  /** 로그인 — 비밀번호·TOTP·복구 코드 실패를 구분하지 않는다(오라클 금지). 관리자 로그인과 같은 순서·비용. */
  private async login(req: IncomingMessage, res: ServerResponse, ip: string, audit: { accountId?: string; tenantId?: string; user?: string; detail: Record<string, string | number> }): Promise<void> {
    if (!originAllowed(req, this.origin)) throw new HttpError(403, "csrf check failed", "csrf");
    const body = asRecord(await readBody(req));
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const totp = typeof body.totp === "string" ? body.totp : "";
    const recoveryCode = typeof body.recoveryCode === "string" ? body.recoveryCode : "";
    audit.user = email;
    const subject = { ip, account: email };
    const now = Date.now();
    const retryAfter = await this.throttle.retryAfterSeconds(subject, now);
    if (retryAfter > 0) return sendJson(res, 429, { error: "too many failed auth attempts" }, { "Retry-After": String(retryAfter) });

    const account = email && password ? await verifyAccountPrimaryPassword(this.deps.db, email, password) : null;
    const checksTotp = account !== null && account.mfaEnrolled && totp !== "";
    const checksRecovery = account !== null && account.mfaEnrolled && !checksTotp && recoveryCode !== "";
    let recovered: { enrollCode: string } | null = null;
    if (checksRecovery) recovered = await redeemRecoveryCode(this.deps.db, ACCOUNT_REALM, account.accountId, recoveryCode, now);
    /**
     * ★미등록 계정은 비밀번호만으로 들어온다 — 단, 그 세션은 **민감 작업을 하지 못한다**(D3). 등록된 계정은
     * TOTP(또는 복구 코드)까지 맞아야 들어온다. 등록된 계정이 TOTP 없이 비밀번호로만 들어와 목록이라도 보게 하면
     * 비밀번호 확인 오라클이 된다.
     */
    const ok =
      account !== null &&
      (!account.mfaEnrolled || recovered !== null || (checksTotp && (await verifySecondFactorTotp(this.deps.db, ACCOUNT_REALM, account.accountId, totp, this.deps.masterKey, now))));
    if (!checksTotp) await burnTotpCost(this.deps.masterKey);
    if (!account || !ok) {
      await this.throttle.recordFailure(subject, now);
      return sendJson(res, 401, { error: "invalid credentials" });
    }
    // 계정 축만 지운다 — IP 축까지 지우면 자기 계정 하나로 같은 IP의 IMAP 대입 기록을 초기화할 수 있다(2026-10-18 검토).
    await this.throttle.clear({ account: email });
    const previous = await resolveAccountSession(this.deps.db, readCookie(req, ACCOUNT_SESSION_COOKIE) ?? "", this.deps.sessionPolicy ?? PROVISIONAL_WEB_SESSION_POLICY, now);
    if (previous) await revokeWebSession(this.deps.db, ACCOUNT_REALM, previous.sessionId, now);
    const enrolledNow = account.mfaEnrolled && recovered === null;
    const session = await createWebSession(this.deps.db, ACCOUNT_REALM, account.accountId, enrolledNow ? now : null, now);
    audit.accountId = account.accountId;
    audit.tenantId = account.tenantId;
    if (recovered) audit.detail.recoveryCode = 1;
    return sendJson(
      res,
      200,
      { csrfToken: session.csrfToken, email: account.email, mfaEnrolled: enrolledNow, ...(recovered ? { enrollCode: recovered.enrollCode } : {}) },
      { "Set-Cookie": sessionCookie(session.token, ACCOUNT_SESSION_COOKIE), "Cache-Control": "no-store" },
    );
  }

  /**
   * 외부 OIDC 로그인(E3) — 연결된 메일 계정만(자동 연결·JIT 없음). IdP MFA 계약을 충족하고 로컬 TOTP가 등록된 계정이면
   * IdP 인증 시각을 MFA 시각으로 쓴다. 아니면 MFA 시각 없이 열린다 — 목록만 보고, 민감 작업 때 로컬 TOTP를 묻는다.
   */
  private async oidc(
    req: IncomingMessage,
    res: ServerResponse,
    method: string,
    path: string,
    ip: string,
    audit: { accountId?: string; tenantId?: string; user?: string; detail: Record<string, string | number> },
  ): Promise<void> {
    const flow = this.deps.oidc;
    if (method === "GET" && path === "/account/session/oidc/providers") return sendJson(res, 200, { providers: flow?.providerIds() ?? [] });
    if (!flow) return sendJson(res, 404, { error: "oidc not configured" });
    if (method === "GET" && path === "/account/session/oidc/start") {
      const providerId = new URL(req.url ?? "/", "http://localhost").searchParams.get("provider") ?? "";
      // 무인증 시작 요청도 IP 축 스로틀을 본다 — 반복으로 인가 상태 행을 쌓지 못하게(2026-10-18 검토).
      if ((await this.throttle.retryAfterSeconds(ip, Date.now())) > 0) return sendJson(res, 429, { error: "too many attempts" });
      const started = await flow.start(providerId);
      if (started === "busy") return sendJson(res, 503, { error: "busy, retry shortly" }, { "Retry-After": "5" });
      if (!started) {
        await this.throttle.recordFailure(ip, Date.now());
        return sendJson(res, 404, { error: "unknown provider" });
      }
      audit.detail.oidcProvider = providerId;
      res.writeHead(302, { Location: started.location, "Set-Cookie": started.setCookie, "Cache-Control": "no-store" });
      res.end();
      return;
    }
    if (method === "GET" && path === "/account/session/oidc/callback") {
      const now = Date.now();
      const fail = (reason: string): void => {
        audit.detail.oidcFailure = reason;
        // 응답을 기다리게 하지 않는다 — recordFailure는 저장소 실패를 안에서 삼키므로 거부되지 않는다.
        void this.throttle.recordFailure(ip, now);
        res.writeHead(302, { Location: "/account?sso=failed", "Set-Cookie": flow.clearStateCookie(), "Cache-Control": "no-store" });
        res.end();
      };
      if ((await this.throttle.retryAfterSeconds(ip, now)) > 0) return fail("throttled");
      let result;
      try {
        result = await flow.callback(req, new URL(req.url ?? "/", "http://localhost"));
      } catch (err) {
        return fail(err instanceof OidcError ? err.reason : "error");
      }
      audit.detail.oidcProvider = result.providerId;
      if (result.tenantId === undefined) return fail("provider_without_tenant");
      const accountId = await accountByOidcIdentity(this.deps.db, result.tenantId, result.providerId, result.sub);
      if (!accountId) {
        audit.detail.oidcUnlinkedSub = result.sub.slice(0, 255);
        return fail("not_linked");
      }
      const enrolled = await mfaEnrolled(this.deps.db, ACCOUNT_REALM, accountId);
      const previous = await resolveAccountSession(this.deps.db, readCookie(req, ACCOUNT_SESSION_COOKIE) ?? "", this.deps.sessionPolicy ?? PROVISIONAL_WEB_SESSION_POLICY, now);
      if (previous) await revokeWebSession(this.deps.db, ACCOUNT_REALM, previous.sessionId, now);
      const mfaAt = enrolled && result.idpMfaAt !== null ? result.idpMfaAt : null;
      if (mfaAt !== null) audit.detail.idpMfa = 1;
      const session = await createWebSession(this.deps.db, ACCOUNT_REALM, accountId, mfaAt, now);
      audit.accountId = accountId;
      audit.tenantId = result.tenantId;
      res.writeHead(302, { Location: "/account", "Set-Cookie": [sessionCookie(session.token, ACCOUNT_SESSION_COOKIE), flow.clearStateCookie()], "Cache-Control": "no-store" });
      res.end();
      return;
    }
    return sendJson(res, 404, { error: "not found" });
  }

  /** MFA 등록(일회용 등록 코드 필요)·확정(복구 코드 발급)·step-up. */
  private async mfa(req: IncomingMessage, res: ServerResponse, ip: string, path: string, s: ResolvedAccountSession): Promise<void> {
    if (req.method !== "POST") throw new HttpError(404, "not found");
    const body = asRecord(await readBody(req));
    const subject = { ip, account: s.account.email };
    const now = Date.now();
    if ((await this.throttle.retryAfterSeconds(subject, now)) > 0) throw new HttpError(429, "too many failed auth attempts");
    const id = s.account.accountId;
    if (path === "/account/session/mfa/enroll") {
      if (await mfaEnrolled(this.deps.db, ACCOUNT_REALM, id)) throw new HttpError(409, "mfa already enrolled");
      const enrollCode = typeof body.enrollCode === "string" ? body.enrollCode : "";
      const secret = await beginTotpEnrollment(this.deps.db, ACCOUNT_REALM, id, enrollCode, this.deps.masterKey, now);
      if (!secret) {
        await this.throttle.recordFailure(subject, now);
        throw new HttpError(401, "invalid or expired enrollment code", "invalid_enroll_code");
      }
      return sendJson(res, 200, { secret, uri: totpUri(secret, this.deps.totpIssuer ?? "ionosphere", s.account.email) }, { "Cache-Control": "no-store" });
    }
    const code = typeof body.code === "string" ? body.code : "";
    if (path === "/account/session/mfa/confirm" || path === "/account/session/mfa/verify") {
      const recoveryCodes = path === "/account/session/mfa/confirm" ? await confirmTotpEnrollment(this.deps.db, ACCOUNT_REALM, id, code, this.deps.masterKey, now) : null;
      const ok = recoveryCodes !== null || (path === "/account/session/mfa/verify" && (await verifySecondFactorTotp(this.deps.db, ACCOUNT_REALM, id, code, this.deps.masterKey, now)));
      if (!ok) {
        await this.throttle.recordFailure(subject, now);
        throw new HttpError(401, "invalid code", "invalid_code");
      }
      await this.throttle.clear(subject);
      await markWebSessionMfa(this.deps.db, ACCOUNT_REALM, s.sessionId, now);
      return sendJson(res, 200, { ok: true, mfaAt: now, ...(recoveryCodes ? { recoveryCodes } : {}) }, { "Cache-Control": "no-store" });
    }
    throw new HttpError(404, "not found");
  }
}
