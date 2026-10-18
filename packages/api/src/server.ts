/**
 * 관리 REST API (PLAN.md §3 SaaS 레이어 + §8 SaaS 신뢰·규정준수 모델).
 *
 * node:http 위 얇은 어댑터 — bun/node 듀얼 런타임 대응(Bun.serve 금지, PLAN §4 설계원칙).
 * 프레임워크 없이 손수 라우팅(경로 2~5개대라 과설계 불필요).
 *
 * 구현 통제: §8 통제 ① 도메인 소유권 검증만 (② 미검증 도메인 발송 거부는 mta/ enqueue 게이트,
 * ③ 레이트리밋은 mta/+store/ 몫 — 이 패키지 스코프 아님).
 *
 * 인증: `Authorization: Bearer <key>` → sha256hex(key)를 api_keys.key_hash(revoked_at IS NULL)와
 * 대조. 부트스트랩 탈출구로 `deps.rootToken`(정적 토큰) 지원 — 최초 테넌트/키 생성 전용.
 * ⚠ rootToken은 환경변수 등으로 운영자가 직접 주입하고, 첫 테넌트+api_keys 생성 후에는
 * 회전/폐기를 권장한다(이 패키지는 회전 메커니즘을 제공하지 않음 — 배포 설정의 몫).
 */
import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  AUDIT_OUTCOME,
  AUDIT_SURFACE,
  AuthFailureThrottle,
  clientIpOf,
  hardenHttpListener,
  trackListener,
  type AuditSink,
  type ListenerShutdown,
  MAX_ALIAS_TARGETS,
  MAX_RELAY_TARGETS,
  noopAuditSink,
  noopLogger,
  sha256hex,
  ulid,
  type Logger,
} from "@ionosphere/core";
import { ADMIN_ROLE, ADMIN_STATUS, type AdminRole, type DbDriver } from "@ionosphere/db";
import {
  beginAdminTotpEnrollment,
  burnTotpCost,
  confirmAdminTotpEnrollment,
  csrfTokenFor,
  adminByIdentity,
  createAdminSession,
  getAdminUser,
  markAdminSessionMfa,
  PROVISIONAL_ADMIN_SESSION_POLICY,
  resolveAdminSession,
  revokeAdminSession,
  Store,
  StoreError,
  redeemAdminRecoveryCode,
  remainingAdminRecoveryCodes,
  verifyAdminPassword,
  verifyAdminTotp,
  type AdminSessionPolicy,
} from "@ionosphere/store";
import { totpUri } from "@ionosphere/core";
import {
  ADMIN_SESSION_COOKIE,
  clearedSessionCookie,
  csrfMatches,
  originAllowed,
  PROVISIONAL_STEP_UP_MS,
  readCookie,
  sessionCookie,
} from "./admin-session.ts";
import type { CertStatus } from "@ionosphere/tls";
import {
  COMMAND_ENCODINGS,
  CommandError,
  createRegistry,
  DomainNameError,
  runCommand,
  type CommandContext,
  type CommandFailure,
  type CommandRegistry,
  type CommandSpec,
  type AdminObserver,
  type SharedMailboxAdminPort,
  type TlsAdminPort,
} from "@ionosphere/admin-cmd";
import { matchRoute } from "./routes.ts";
import { asRecord, clientIp, HttpError, readBody, sendJson } from "./http-util.ts";
import type { OidcLoginFlow } from "./oidc-login.ts";
import { OidcError } from "@ionosphere/core";
import { ADMIN_UI_HTML, ADMIN_UI_SECURITY_HEADERS } from "./admin-ui.ts";

export interface AdminApiDeps {
  db: DbDriver;
  store: Store;
  /** DNS TXT 리졸버 — 주입 인터페이스 (조립층이 node:dns 또는 가짜 구현을 주입). */
  resolveTxt: (name: string) => Promise<string[]>;
  /** DNS MX 리졸버 — 주입 인터페이스. */
  resolveMx: (name: string) => Promise<{ exchange: string; preference: number }[]>;
  logger?: Logger;
  /**
   * 부트스트랩 탈출구: 이 정적 토큰으로 인증하면 api_keys 없이도 최초 테넌트/키를 만들 수 있다.
   * 어떤 tenant에도 속하지 않는 cross-tenant 주체로 취급된다. 미지정 시 root 라우트는 항상 403.
   */
  rootToken?: string;
  /** DKIM 개인키 봉인용(secretbox) — 미지정 시 평문 저장(plain$ 프리픽스, dev 전용). */
  masterKey?: string;
  /** TLS 인증서 관리(Phase 5) — 조립층이 certSource+리스너로 주입. 미지정 시 /v1/tls는 501. */
  tls?: TlsAdmin;
  /**
   * 인증 실패 스로틀 — **다른 리스너와 같은 인스턴스를 받아야 한다**(조립층이 주입).
   * 리스너마다 새로 만들면 587·465·993·995·JMAP·admin이 각각 10회를 갖게 되어
   * "IP당 분당 10회"라는 정책 표현과 실제(약 60회)가 달라진다.
   */
  authThrottle?: AuthFailureThrottle;
  /**
   * 접근 감사 싱크 — 다른 리스너와 **같은 인스턴스**를 받는다(조립층이 주입).
   *
   * ★이 표면은 **로그가 아예 없었다.** 관리 API는 계정 생성·도메인 삭제·앱 비밀번호 발급·
   * TLS 키 업로드를 하는 자리라 감사 대상 중 권한이 가장 크다. 그런데 누가 어떤 키로 무엇을
   * 했는지 남는 곳이 한 군데도 없었다(스코프 검사가 오래 없었던 것과 같은 뿌리다).
   *
   * 생략 시 기록하지 않는다(`noopAuditSink`) — 기존 동작 그대로.
   */
  audit?: AuditSink;
  /** 디렉터리 동기화·header 재생성·프로세스 cache flush의 실제 런타임 구현. */
  sharedMailbox?: SharedMailboxAdminPort;
  /** 명령 계층 관측 포트. 입력값을 받지 않아 자격증명과 필터가 로그에 섞이지 않는다. */
  observer?: AdminObserver;
  /** 사람 세션 수명 — 생략하면 임시 기본값(`PROVISIONAL_ADMIN_SESSION_POLICY`). */
  adminSessionPolicy?: AdminSessionPolicy;
  /** 민감 작업 전 최근 MFA 창(ms) — 생략하면 임시 기본값(`PROVISIONAL_STEP_UP_MS`). */
  stepUpMs?: number;
  /**
   * 관리 콘솔의 정확한 오리진(예: `https://admin.ionosphere.test`). 있으면 쿠키 요청의 Origin을
   * 이것과 정확히 비교하고, 없으면 Origin의 host를 요청 Host와 비교한다(`originAllowed`).
   */
  adminOrigin?: string;
  /** TOTP 등록 URI의 issuer — 인증 앱에 보이는 이름. 생략하면 "ionosphere". */
  totpIssuer?: string;
  /** 외부 OIDC 로그인(E3). 설정된 공급자가 없으면 생략 — 로그인 화면에 SSO 버튼이 없다. */
  oidc?: OidcLoginFlow;
  /** 연결 명령이 받을 수 있는 공급자 목록(설정의 사본 — 명령이 설정을 직접 읽지 않게). */
  oidcAccountProviders?: readonly { id: string; tenantId: string }[];
  oidcAdminProviders?: readonly string[];
}

/** 서버 전역 TLS 관리 인터페이스(root 전용). upload는 sealed 모드에서만 제공. */
export interface TlsAdmin {
  status(): Promise<CertStatus>;
  /** 재취득(재생성/재페치/갱신) + 리스너 무중단 교체 → 새 상태. */
  refresh(): Promise<CertStatus>;
  /** cert/key 업로드(개인키 masterKey 봉인 저장) + 교체 → 새 상태. */
  upload?(certPem: string, keyPem: string): Promise<CertStatus>;
}

/**
 * 인증 주체 세 갈래.
 *
 * - `root`: 정적 rootToken(부트스트랩 탈출구, 결정 D4 — 첫 관리자 뒤에는 쓰지 않는다).
 * - `apiKey`: 서비스 토큰(REST 자동화). 사람 세션이 아니라 MFA·step-up 대상이 아니다.
 * - `human`: 관리 콘솔 사람 세션(쿠키). 테넌트가 없으면 운영자(전 테넌트)다.
 *
 * `isRoot`는 "테넌트에 매이지 않고 rootOnly 명령을 부를 수 있는가"다. 사람 중에서는 운영자 owner만 참이다.
 */
type AuthContext =
  | { kind: "root"; isRoot: true }
  | { kind: "apiKey"; isRoot: false; tenantId: string; apiKeyId: string; scopes: string }
  | {
      kind: "human";
      isRoot: boolean;
      /** null = 운영자. */
      tenantId: string | null;
      adminUserId: string;
      username: string;
      role: AdminRole;
      sessionId: string;
      mfaAt: number | null;
      scopes: string;
      csrfHash: string;
    };

/**
 * 스로틀 계정 키에 접두를 붙인다. 스로틀 인스턴스는 메일 프로토콜과 공유하므로, 관리자 사용자명이 메일 주소와
 * 같으면 SMTP AUTH 실패가 콘솔 로그인을 잠그고 콘솔 로그인 성공이 메일 쪽 실패 기록을 지운다(2026-10-18 보안 검토).
 */
function adminThrottleAccount(username: string): string {
  return `admin|${username.trim().toLowerCase()}`;
}

/** 활성 운영자 owner가 있는가 — 있으면 부트스트랩이 끝난 것이다(rootToken을 더 쓸 이유가 없다). */
export async function hasActiveOperatorOwner(db: DbDriver): Promise<boolean> {
  const { rows } = await db.query({
    sql: "SELECT COUNT(*) AS n FROM admin_users WHERE role = ? AND status = ? AND tenant_id IS NULL",
    params: [ADMIN_ROLE.owner, ADMIN_STATUS.active],
  });
  return Number(rows[0]?.n ?? 0) > 0;
}

/** 사람 역할 → api_keys와 같은 스코프 축(columns.ts `ADMIN_ROLE` 주석). 권한 판단을 하나로 둔다. */
function scopesOfRole(role: AdminRole): string {
  return role === ADMIN_ROLE.readonly ? SCOPE_READ : SCOPE_WRITE;
}

/**
 * API 키 스코프.
 *
 * 과거 결함: `scopes`가 저장·전달만 되고 **어디서도 검사되지 않았다.** `scopes: "read-only"`로
 * 발급한 키가 계정 생성·도메인 삭제까지 전권을 가졌다.
 *
 * 강제 지점을 라우트마다 두지 않고 **메서드 기반 단일 관문**으로 만든 이유: 라우트가 늘 때마다
 * 손으로 붙이면 언젠가 하나가 빠지는데, 빠진 자리는 "권한 검사 없음"이라 조용히 통과한다.
 * GET=read / 그 외=write로 고정하면 새 라우트가 자동으로 덮인다.
 */
const SCOPE_ADMIN = "admin";
const SCOPE_READ = "read";
const SCOPE_WRITE = "write";
const KNOWN_SCOPES = new Set([SCOPE_ADMIN, SCOPE_READ, SCOPE_WRITE]);

function scopeSet(raw: string): Set<string> {
  return new Set(
    raw
      .split(/[,\s]+/)
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

/**
 * 스코프 검사. root 토큰은 전권(테넌트에 속하지 않는 부트스트랩 주체).
 * `write`는 `read`를 포함한다 — 변경할 수 있는데 조회를 못 하면 쓸 수 없는 키가 된다.
 */
function requireScope(auth: AuthContext, needed: typeof SCOPE_READ | typeof SCOPE_WRITE): void {
  if (auth.isRoot) return;
  const have = scopeSet(auth.scopes);
  if (have.has(SCOPE_ADMIN)) return;
  if (have.has(SCOPE_WRITE)) return; // write ⊇ read
  if (needed === SCOPE_READ && have.has(SCOPE_READ)) return;
  throw new HttpError(403, `insufficient scope: ${needed} required`);
}





/**
 * 정적 시크릿 비교. `===`는 첫 불일치 바이트에서 즉시 빠져나와 "몇 글자까지 맞았는지"가 시간으로
 * 새고, 공개 포트(443)에 노출된 관리 API에서는 그 누출로 토큰을 한 글자씩 복원할 수 있다.
 * timingSafeEqual은 길이가 다르면 throw하므로 양쪽을 sha256(항상 32바이트)으로 만든 뒤 비교한다
 * — 길이 정보 자체도 흘리지 않기 위해서다.
 */
function secretEquals(a: string, b: string): boolean {
  return timingSafeEqual(Buffer.from(sha256hex(a), "hex"), Buffer.from(sha256hex(b), "hex"));
}


/**
 * 팬아웃·릴레이 대상 상한의 정본은 `@ionosphere/core`(limits.ts)다 — 생성 경로(여기)와 배달
 * 경로(apps/server backend.ts)가 **같은 값을 봐야** 하기 때문이다. 하위호환으로 재수출한다.
 */
export { MAX_ALIAS_TARGETS, MAX_RELAY_TARGETS } from "@ionosphere/core";

/**
 * `forward_to` 문자열 → 대상 목록. 배달 경로(apps/server backend.ts resolveRoute)와 **같은
 * 분해 규칙**이어야 개수 검사가 실제 릴레이 수와 일치한다(콤마/공백 구분).
 */
export function splitForwardTargets(forwardTo: string): string[] {
  return forwardTo
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** targetAccountIds(배열) + targetAccountId(단수 호환)를 하나의 중복 없는 목록으로. */
function readTargetAccountIds(body: Record<string, unknown>): string[] {
  const raw = body.targetAccountIds;
  const many = Array.isArray(raw) ? raw.filter((v): v is string => typeof v === "string") : [];
  const one = typeof body.targetAccountId === "string" ? [body.targetAccountId] : [];
  return [...new Set([...many, ...one].map((s) => s.trim()).filter((s) => s.length > 0))];
}

function requireString(body: Record<string, unknown>, key: string): string {
  const v = body[key];
  if (typeof v !== "string" || v.trim() === "") throw new HttpError(400, `${key} required`);
  return v;
}

/** 대상 tenantId 결정: root는 body.tenantId 또는 ?tenantId= 필요, 테넌트 키는 항상 자기 테넌트. */
function resolveTenantId(auth: AuthContext, url: URL, body: Record<string, unknown>): string {
  if (!auth.isRoot && auth.tenantId !== null) return auth.tenantId;
  const provided = typeof body.tenantId === "string" ? body.tenantId : url.searchParams.get("tenantId");
  if (!provided) throw new HttpError(400, "tenantId required for root token");
  return provided;
}

async function safeResolveTxt(fn: AdminApiDeps["resolveTxt"], name: string): Promise<string[]> {
  try {
    return await fn(name);
  } catch {
    return [];
  }
}

async function safeResolveMx(
  fn: AdminApiDeps["resolveMx"],
  name: string,
): Promise<{ exchange: string; preference: number }[]> {
  try {
    return await fn(name);
  } catch {
    return [];
  }
}

/** api key 평문 발급 — "amk_" 접두 + 32byte 난수 hex. 저장은 sha256hex 해시만(§4 api_keys.key_hash). */
function generateApiKey(): string {
  return `amk_${randomBytes(32).toString("hex")}`;
}

export class AdminApiServer {
  private readonly deps: AdminApiDeps;
  private readonly log: Logger;
  private server: Server | null = null;
  /** 정상 종료 손잡이 — close 시 남은 연결을 끊는다. */
  private shutdown: ListenerShutdown | null = null;
  private readonly throttle: AuthFailureThrottle;
  /** 접근 감사 싱크 — 미주입 시 no-op(호출부가 `?.`를 쓰지 않게). */
  private readonly audit: AuditSink;
  /**
   * 관리 명령 레지스트리 — **이 서버의 기능 목록이자 GUI가 그리는 근거**다.
   * 라우트 표(routes.ts)는 경로를 명령 이름으로 옮길 뿐, 무엇을 할 수 있는지는 여기가 정한다.
   */
  private readonly registry: CommandRegistry;

  constructor(deps: AdminApiDeps) {
    this.deps = deps;
    this.registry = createRegistry();
    this.log = (deps.logger ?? noopLogger).child({ component: "api" });
    // 주입이 없으면 단독 기동(테스트·단일 사용)이라 자기 것을 쓴다. 조립층은 항상 넘긴다.
    this.throttle = deps.authThrottle ?? new AuthFailureThrottle({ ...(deps.logger ? { logger: deps.logger } : {}) });
    this.audit = deps.audit ?? noopAuditSink;
    /**
     * 오리진은 정규화해서 쥔다. 설정값을 문자열 그대로 비교하면 끝의 `/`나 대문자 하나로 모든 로그인이 403이 된다.
     * 해석이 안 되는 값은 기동을 멈춘다 — 조용히 무시하면 Host 비교로 떨어져 설정한 의도가 사라진다.
     */
    if (deps.adminOrigin !== undefined) {
      let parsed: URL;
      try {
        parsed = new URL(deps.adminOrigin);
      } catch {
        throw new Error("adminOrigin(IONOSPHERE_ADMIN_ORIGIN)이 URL이 아니다");
      }
      this.adminOrigin = parsed.origin;
    }
  }

  /** 정규화한 관리 콘솔 오리진 — 없으면 Host 비교(`originAllowed`). */
  private readonly adminOrigin: string | undefined;

  listen(port: number, host?: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = createServer((req, res) => {
        void this.handleRequest(req, res);
      });
      // 연결 수 상한 + slowloris 타임아웃. 정본은 @ionosphere/core가 소유한다(limits.ts) — HTTP 표면
      // 4곳이 각자 세 줄을 반복하다 **관리 API에만 셋 다 빠져 있던** 것이 감사 L-3이다.
      // 관리 포트는 rootToken 하나가 전 테넌트 권한이라 무인증 연결 고갈에 특히 민감하다.
      // ★trackListener로 닫는다. `server.close(cb)`는 **기존 연결이 전부 끝나야** 콜백이 오는데,
      // keep-alive 연결 하나만 남아도 영영 오지 않는다(2026-07-30 사고와 같은 계열 —
      // listener-shutdown.ts 주석). HTTP 서버 3종이 이 처리에서 빠져 있었고,
      // node:test로 옮기면서 **프로세스가 안 죽는** 형태로 드러났다.
      const shutdown = trackListener(server); // listen 전에 붙여야 그 사이 연결을 놓치지 않는다
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
    // ★shutdown.close()를 쓴다 — 남은 keep-alive 연결을 끊고 나서 닫는다.
    // 예전엔 server.close()만 불렀는데, 그건 기존 연결이 끝나야 콜백이 와서
    // **종료가 영영 끝나지 않는다**(listener-shutdown.ts 주석의 2026-07-30 사고).
    const shutdown = this.shutdown;
    this.server = null;
    this.shutdown = null;
    if (shutdown) await shutdown.close();
  }

  // ── 인증 ────────────────────────────────────────────────────────────
  private async authenticate(req: IncomingMessage): Promise<AuthContext | null> {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) return null;
    const token = header.slice("Bearer ".length).trim();
    if (!token) return null;

    if (this.deps.rootToken && secretEquals(token, this.deps.rootToken)) return { kind: "root", isRoot: true };

    // api-key는 sha256hex(token)으로 조회한다 — 비교 대상이 이미 해시라 접두사 타이밍이 새더라도
    // 원본 키를 복원할 수 없다(해시 역상을 만들어야 한다). rootToken과 달리 별도 상수시간 비교 불필요.
    const hash = sha256hex(token);
    const { rows } = await this.deps.db.query({
      sql: "SELECT id, tenant_id, scopes FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL",
      params: [hash],
    });
    const row = rows[0];
    if (!row) return null;
    return { kind: "apiKey", isRoot: false, tenantId: String(row.tenant_id), apiKeyId: String(row.id), scopes: String(row.scopes) };
  }

  /**
   * 쿠키 토큰 → 사람 주체. **매 요청 DB를 본다**(store `resolveAdminSession` 주석) — 로그아웃·정지·역할 하향이
   * 다음 보호 요청부터 반영되는 것이 이 조회에 달려 있다. 조회가 throw하면 최상위 catch가 500으로 닫는다.
   */
  private async authenticateSession(token: string): Promise<Extract<AuthContext, { kind: "human" }> | null> {
    const s = await resolveAdminSession(this.deps.db, token, this.deps.adminSessionPolicy ?? PROVISIONAL_ADMIN_SESSION_POLICY);
    if (!s) return null;
    return {
      kind: "human",
      // 운영자(테넌트 없음) owner만 rootOnly 명령을 부를 수 있다 — 테넌트 관리자는 자기 테넌트 밖을 보지 않는다.
      isRoot: s.user.tenantId === null && s.user.role === ADMIN_ROLE.owner,
      tenantId: s.user.tenantId,
      adminUserId: s.user.id,
      username: s.user.username,
      role: s.user.role,
      sessionId: s.sessionId,
      // 등록되지 않은 관리자는 MFA 시각이 있을 수 없다(초기화 직후 남은 값도 무효로 본다).
      mfaAt: s.user.mfaEnrolled ? s.mfaAt : null,
      scopes: scopesOfRole(s.user.role),
      csrfHash: s.csrfHash,
    };
  }

  /**
   * 쿠키로 인증한 **상태 변경 요청**의 출처 관문. SameSite=Strict 위에 Origin 일치 + CSRF 토큰을 겹친다.
   * GET은 상태를 바꾸지 않는 것이 계약이라(`requireScope`가 GET=read로 고정) 여기를 지나지 않는다.
   */
  private requireSameOriginWrite(req: IncomingMessage, csrfHash: string): void {
    if (!originAllowed(req, this.adminOrigin) || !csrfMatches(req, csrfHash)) {
      throw new HttpError(403, "csrf check failed", "csrf");
    }
  }

  /**
   * 민감 작업 관문 — 사람 세션이 `destructive`·`sensitive` 명령을 부르려면 최근 MFA가 있어야 한다(공통 기준 4).
   * API 키는 서비스 토큰이라 대상이 아니다(결정 D4 — 사람 로그인을 대신하는 데 쓰지 않는다).
   */
  private requireFreshMfa(auth: AuthContext, spec: CommandSpec): void {
    if (auth.kind !== "human" || (spec.destructive !== true && spec.sensitive !== true)) return;
    const window = this.deps.stepUpMs ?? PROVISIONAL_STEP_UP_MS;
    if (auth.mfaAt === null || Date.now() - auth.mfaAt > window) {
      throw new HttpError(403, "mfa step-up required", "step_up");
    }
  }

  // ── 사람 세션 엔드포인트 ──────────────────────────────────────────────
  /**
   * `/admin/session/*` — 로그인·로그아웃·MFA 등록/확정·step-up. 처리했으면 true.
   *
   * ★로그인 응답은 "비밀번호 틀림"과 "TOTP 틀림/없음"을 **구분하지 않는다**. 구분하면 TOTP 칸이
   * 비밀번호 확인 오라클이 된다. 그래서 콘솔은 TOTP 칸을 항상 보여 주고, 미등록이면 비워 둬도 된다.
   */
  private async handleSession(
    req: IncomingMessage,
    res: ServerResponse,
    method: string,
    pathname: string,
    ip: string,
    auditSubject: { tenantId?: string; detail: Record<string, string | number> },
  ): Promise<boolean> {
    if (!pathname.startsWith("/admin/session")) return false;
    const now = Date.now();

    if (pathname.startsWith("/admin/session/oidc/")) {
      await this.handleOidc(req, res, method, pathname, ip, auditSubject);
      return true;
    }

    if (method === "POST" && pathname === "/admin/session/login") {
      // 로그인 CSRF(남의 세션으로 로그인시키기)도 막는다 — 쿠키가 없을 때라 Origin만 본다.
      if (!originAllowed(req, this.adminOrigin)) throw new HttpError(403, "csrf check failed", "csrf");
      const body = asRecord(await readBody(req));
      const username = typeof body.username === "string" ? body.username : "";
      const password = typeof body.password === "string" ? body.password : "";
      const totp = typeof body.totp === "string" ? body.totp : "";
      const recoveryCode = typeof body.recoveryCode === "string" ? body.recoveryCode : "";
      const subject = { ip, account: adminThrottleAccount(username) };
      const retryAfter = this.throttle.retryAfterSeconds(subject, now);
      if (retryAfter > 0) {
        sendJson(res, 429, { error: "too many failed auth attempts" }, { "Retry-After": String(retryAfter) });
        return true;
      }
      const user = username && password ? await verifyAdminPassword(this.deps.db, username, password) : null;
      const checksTotp = user !== null && user.mfaEnrolled && totp !== "";
      /**
       * 복구 코드 갈래 — TOTP 칸이 비고 복구 코드가 있을 때만. 성공하면 TOTP가 지워지고 새 등록 코드가 나온다
       * (store `redeemAdminRecoveryCode`). 이 세션은 등록을 마치기 전까지 보호 요청을 쓰지 못한다.
       */
      const checksRecovery = user !== null && user.mfaEnrolled && !checksTotp && recoveryCode !== "";
      let recovered: { enrollCode: string } | null = null;
      if (checksRecovery) recovered = await redeemAdminRecoveryCode(this.deps.db, user.id, recoveryCode, now);
      const mfaOk =
        user !== null &&
        (!user.mfaEnrolled || recovered !== null || (checksTotp && (await verifyAdminTotp(this.deps.db, user.id, totp, this.deps.masterKey, now))));
      // ★봉인 해제(scrypt)를 돌리지 않은 갈래도 같은 비용을 태운다 — 응답 시간이 "비밀번호는 맞았다"를 흘리지 않게.
      if (!checksTotp) await burnTotpCost(this.deps.masterKey);
      if (!user || !mfaOk) {
        this.throttle.recordFailure(subject, now);
        auditSubject.detail.user = username;
        sendJson(res, 401, { error: "invalid credentials" });
        return true;
      }
      this.throttle.clear(subject);
      // 같은 브라우저의 이전 세션은 닫는다 — 쿠키는 덮이지만 서버 행은 idle 만료까지 살아 있게 된다.
      // 쿠키가 없으면 빈 토큰 — 세션 해석이 null을 돌려준다(조건 분기 없이 같은 경로를 탄다).
      const previousAuth = await this.authenticateSession(readCookie(req, ADMIN_SESSION_COOKIE) ?? "");
      if (previousAuth) await revokeAdminSession(this.deps.db, previousAuth.sessionId, now);
      const enrolledNow = user.mfaEnrolled && recovered === null;
      const session = await createAdminSession(this.deps.db, user.id, enrolledNow ? now : null, now);
      auditSubject.detail.adminUserId = user.id;
      if (recovered) auditSubject.detail.recoveryCode = 1;
      if (user.tenantId !== null) auditSubject.tenantId = user.tenantId;
      sendJson(
        res,
        200,
        {
          csrfToken: session.csrfToken,
          username: user.username,
          role: user.role,
          tenantId: user.tenantId,
          mfaEnrolled: enrolledNow,
          // 복구 코드로 들어왔으면 새 장치 등록에 쓸 일회용 코드 — 이 응답에서만 보인다.
          ...(recovered ? { enrollCode: recovered.enrollCode } : {}),
        },
        { "Set-Cookie": sessionCookie(session.token), "Cache-Control": "no-store" },
      );
      return true;
    }

    const token = readCookie(req, ADMIN_SESSION_COOKIE) ?? "";
    const auth = await this.authenticateSession(token);

    if (method === "POST" && pathname === "/admin/session/logout") {
      if (auth) {
        /**
         * Origin만 본다(CSRF 토큰은 요구하지 않는다). 강제 로그아웃은 공격자가 얻는 것이 없고, 토큰이 없는 탭에서
         * 로그아웃이 403으로 조용히 실패하면 사용자는 끊긴 줄 아는데 세션이 살아 있게 된다 — 그쪽이 더 위험하다.
         */
        if (!originAllowed(req, this.adminOrigin)) throw new HttpError(403, "csrf check failed", "csrf");
        await revokeAdminSession(this.deps.db, auth.sessionId, now);
        auditSubject.detail.adminUserId = auth.adminUserId;
      }
      // 세션이 이미 없어도 쿠키는 지운다 — 로그아웃은 항상 성공해야 사용자가 갇히지 않는다.
      sendJson(res, 200, { ok: true }, { "Set-Cookie": clearedSessionCookie() });
      return true;
    }

    if (!auth) {
      sendJson(res, 401, { error: "no session", code: "no_session" });
      return true;
    }
    auditSubject.detail.adminUserId = auth.adminUserId;
    if (auth.tenantId !== null) auditSubject.tenantId = auth.tenantId;

    if (method === "GET" && pathname === "/admin/session") {
      sendJson(
        res,
        200,
        {
          username: auth.username,
          role: auth.role,
          tenantId: auth.tenantId,
          mfaEnrolled: auth.mfaAt !== null || (await this.mfaEnrolled(auth.adminUserId)),
          mfaAt: auth.mfaAt,
          stepUpMs: this.deps.stepUpMs ?? PROVISIONAL_STEP_UP_MS,
          recoveryCodesRemaining: await remainingAdminRecoveryCodes(this.deps.db, auth.adminUserId),
          // 세션 토큰에서 유도한 값이라 언제든 다시 줄 수 있다 — 새 탭도 쓰기를 할 수 있게(store `csrfTokenFor`).
          csrfToken: csrfTokenFor(token),
        },
        { "Cache-Control": "no-store" },
      );
      return true;
    }

    if (method !== "POST") throw new HttpError(404, "not found");
    this.requireSameOriginWrite(req, auth.csrfHash);
    const body = asRecord(await readBody(req));
    const code = typeof body.code === "string" ? body.code : "";
    const subject = { ip, account: adminThrottleAccount(auth.username) };

    if (pathname === "/admin/session/mfa/enroll") {
      if (await this.mfaEnrolled(auth.adminUserId)) throw new HttpError(409, "mfa already enrolled");
      if (this.throttle.retryAfterSeconds(subject, now) > 0) throw new HttpError(429, "too many failed auth attempts");
      // 일회용 등록 코드가 있어야 한다 — 비밀번호만으로 MFA를 차지하지 못하게(store `issueAdminEnrollCode` 주석).
      const enrollCode = typeof body.enrollCode === "string" ? body.enrollCode : "";
      const secret = await beginAdminTotpEnrollment(this.deps.db, auth.adminUserId, enrollCode, this.deps.masterKey, now);
      if (!secret) {
        this.throttle.recordFailure(subject, now);
        throw new HttpError(401, "invalid or expired enrollment code", "invalid_enroll_code");
      }
      sendJson(res, 200, { secret, uri: totpUri(secret, this.deps.totpIssuer ?? "ionosphere", auth.username) }, { "Cache-Control": "no-store" });
      return true;
    }
    if (pathname === "/admin/session/mfa/confirm" || pathname === "/admin/session/mfa/verify") {
      if (this.throttle.retryAfterSeconds(subject, now) > 0) throw new HttpError(429, "too many failed auth attempts");
      const recoveryCodes = pathname === "/admin/session/mfa/confirm"
        ? await confirmAdminTotpEnrollment(this.deps.db, auth.adminUserId, code, this.deps.masterKey, now)
        : null;
      const ok = recoveryCodes !== null || (pathname === "/admin/session/mfa/verify" && (await verifyAdminTotp(this.deps.db, auth.adminUserId, code, this.deps.masterKey, now)));
      if (!ok) {
        this.throttle.recordFailure(subject, now);
        throw new HttpError(401, "invalid code", "invalid_code");
      }
      this.throttle.clear(subject);
      await markAdminSessionMfa(this.deps.db, auth.sessionId, now);
      // 등록 확정이면 복구 코드를 **이 응답에서만** 준다(저장은 해시뿐이다).
      sendJson(res, 200, { ok: true, mfaAt: now, ...(recoveryCodes ? { recoveryCodes } : {}) }, { "Cache-Control": "no-store" });
      return true;
    }
    throw new HttpError(404, "not found");
  }

  /**
   * rootToken은 **부트스트랩 전용**이다(회원 정책 결정 D4). 활성 운영자 owner가 이미 있는데 rootToken으로 들어오면
   * MFA 없는 전권 경로를 일상적으로 쓰고 있다는 뜻이라, 감사 줄에 표시하고 경고를 남긴다.
   * ⚠ 지금은 **거부하지 않는다** — 운영 절차(배포 스크립트 등)가 rootToken에 기대고 있을 수 있어, 경고로 먼저 드러낸 뒤
   * 이후 릴리즈에서 거부로 바꾼다(D4). 경고는 분당 한 번으로 묶는다(요청마다 찍으면 로그를 덮는다).
   */
  private lastRootWarnAt = 0;
  private async flagRootAfterBootstrap(auditSubject: { detail: Record<string, string | number> }): Promise<void> {
    if (!(await hasActiveOperatorOwner(this.deps.db))) return;
    auditSubject.detail.rootAfterBootstrap = 1;
    const now = Date.now();
    if (now - this.lastRootWarnAt >= 60_000) {
      this.lastRootWarnAt = now;
      this.log.warn("rootToken 사용 — 활성 운영자 owner가 있으므로 부트스트랩 전용 토큰을 쓰지 말 것(IONOSPHERE_ADMIN_TOKEN 제거 권장)", {});
    }
  }

  /**
   * 외부 OIDC 로그인(E3). 연결된 관리자만 들어온다(자동 연결·JIT 없음).
   *
   * MFA(2026-10-18 사용자 결정 "IdP MFA 증거 계약부터"): 공급자 계약을 충족한 응답이고 **로컬 TOTP도 등록된** 관리자면
   * IdP 인증 시각을 이 세션의 MFA 시각으로 쓴다. 아니면 MFA 시각 없이 열리고 콘솔이 로컬 TOTP를 묻는다(생략·폴백 없음).
   * ⚠ 민감 작업의 step-up은 언제나 로컬 TOTP다 — IdP 재인증으로 step-up하는 흐름은 없다(지원 제한). 그래서 로컬 TOTP
   * 미등록 관리자는 IdP 계약을 충족해도 콘솔을 쓸 수 없다(등록 코드로 먼저 등록).
   */
  private async handleOidc(
    req: IncomingMessage,
    res: ServerResponse,
    method: string,
    pathname: string,
    ip: string,
    auditSubject: { tenantId?: string; detail: Record<string, string | number> },
  ): Promise<void> {
    const flow = this.deps.oidc;
    if (method === "GET" && pathname === "/admin/session/oidc/providers") return sendJson(res, 200, { providers: flow?.providerIds() ?? [] });
    if (!flow) return sendJson(res, 404, { error: "oidc not configured" });
    if (method === "GET" && pathname === "/admin/session/oidc/start") {
      const providerId = new URL(req.url ?? "/", "http://localhost").searchParams.get("provider") ?? "";
      // 무인증 시작 요청도 IP 축 스로틀을 본다 — 반복으로 인가 상태 행을 쌓지 못하게(2026-10-18 검토).
      if (this.throttle.retryAfterSeconds(ip, Date.now()) > 0) return sendJson(res, 429, { error: "too many attempts" });
      const started = await flow.start(providerId);
      if (started === "busy") return sendJson(res, 503, { error: "busy, retry shortly" }, { "Retry-After": "5" });
      if (!started) {
        this.throttle.recordFailure(ip, Date.now());
        return sendJson(res, 404, { error: "unknown provider" });
      }
      auditSubject.detail.oidcProvider = providerId;
      res.writeHead(302, { Location: started.location, "Set-Cookie": started.setCookie, "Cache-Control": "no-store" });
      res.end();
      return;
    }
    if (method === "GET" && pathname === "/admin/session/oidc/callback") {
      const now = Date.now();
      const fail = (reason: string): void => {
        auditSubject.detail.oidcFailure = reason;
        this.throttle.recordFailure(ip, now);
        res.writeHead(302, { Location: "/admin?sso=failed", "Set-Cookie": flow.clearStateCookie(), "Cache-Control": "no-store" });
        res.end();
      };
      if (this.throttle.retryAfterSeconds(ip, now) > 0) return fail("throttled");
      let result;
      try {
        result = await flow.callback(req, new URL(req.url ?? "/", "http://localhost"));
      } catch (err) {
        return fail(err instanceof OidcError ? err.reason : "error");
      }
      auditSubject.detail.oidcProvider = result.providerId;
      const adminUserId = await adminByIdentity(this.deps.db, result.providerId, result.sub);
      if (!adminUserId) {
        // 연결하려는 운영자가 sub를 찾을 수 있게 감사에 남긴다(식별자일 뿐 비밀이 아니다).
        auditSubject.detail.oidcUnlinkedSub = result.sub.slice(0, 255);
        return fail("not_linked");
      }
      const user = await getAdminUser(this.deps.db, adminUserId);
      if (!user) return fail("not_active");
      this.throttle.clear(ip);
      const previousAuth = await this.authenticateSession(readCookie(req, ADMIN_SESSION_COOKIE) ?? "");
      if (previousAuth) await revokeAdminSession(this.deps.db, previousAuth.sessionId, now);
      const mfaAt = user.mfaEnrolled && result.idpMfaAt !== null ? result.idpMfaAt : null;
      if (mfaAt !== null) auditSubject.detail.idpMfa = 1;
      const session = await createAdminSession(this.deps.db, user.id, mfaAt, now);
      auditSubject.detail.adminUserId = user.id;
      if (user.tenantId !== null) auditSubject.tenantId = user.tenantId;
      res.writeHead(302, { Location: "/admin", "Set-Cookie": [sessionCookie(session.token), flow.clearStateCookie()], "Cache-Control": "no-store" });
      res.end();
      return;
    }
    return sendJson(res, 404, { error: "not found" });
  }

  private async mfaEnrolled(adminUserId: string): Promise<boolean> {
    const { rows } = await this.deps.db.query({ sql: "SELECT totp_secret FROM admin_users WHERE id = ?", params: [adminUserId] });
    return rows[0]?.totp_secret != null;
  }

  // ── 라우팅 ──────────────────────────────────────────────────────────
  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    /**
     * ★감사 기록을 **응답 완료 시점 한 곳에서** 한다(라우트마다가 아니라).
     *
     * 이유는 스코프 관문을 단일 지점으로 만든 것과 같다(위 `SCOPE_ADMIN` 주석): 라우트가 25개
     * 넘고 계속 늘어나는데 손으로 붙이면 언젠가 하나가 빠지고, **빠진 자리는 "감사 로그에 없으니
     * 일어나지 않았다"는 잘못된 결론으로 이어진다.** `finish`에 걸면 404·500·throw 경로까지
     * 자동으로 덮이고, `res.statusCode`가 곧 결과라 성패 판정을 따로 계산하지 않는다.
     *
     * 주체 정보(`apiKeyId`·`tenantId`·`isRoot`)는 인증을 통과한 뒤에 정해지므로, 아래 가변 객체를
     * 인증 지점에서 채운다. 401에서는 비어 있는 채로 남아 그 자체가 "인증 전 거부"를 뜻한다.
     */
    const auditIp = clientIp(req);
    const auditSubject: { tenantId?: string; detail: Record<string, string | number> } = { detail: {} };
    /**
     * `/healthz`만 제외한다. systemd·모니터가 초 단위로 때리는 무주체 생존 확인이라
     * 남겨도 "누가 무엇을 했나"에 답하지 못하면서 다른 줄을 파묻는다(볼륨이 이 설계의 실질 위험).
     * 관리 콘솔 HTML(`/`, `/admin`)은 **남긴다** — 사람이 접근한 흔적이라 값이 있다.
     */
    const auditSkip = (req.url ?? "/").startsWith("/healthz");
    if (!auditSkip) res.on("finish", () => {
      const status = res.statusCode;
      this.audit.record({
        ts: Date.now(),
        surface: AUDIT_SURFACE.api,
        action: `${req.method ?? "?"} ${new URL(req.url ?? "/", "http://localhost").pathname}`,
        /**
         * 403만 `denied`(인증은 됐는데 권한 부족)다. **401은 `fail`** — 자격증명이 틀린 것이라
         * 다른 표면의 인증 실패와 같은 값이어야 한다. 예전엔 401도 `denied`로 세어, 관리 API
         * 대입 공격이 "인증 실패" 집계에서 빠지고 "권한 거부" 쪽에 숨었다(2026-09-30 정정,
         * 알림을 만드는 쪽이 fail·denied를 합쳐야만 공격을 볼 수 있었다).
         * 나머지 4xx·5xx는 `fail`, 429는 `throttled`.
         */
        outcome:
          status === 429
            ? AUDIT_OUTCOME.throttled
            : status === 403
              ? AUDIT_OUTCOME.denied
              : status >= 400
                ? AUDIT_OUTCOME.fail
                : AUDIT_OUTCOME.ok,
        ip: auditIp,
        ...(auditSubject.tenantId !== undefined ? { tenantId: auditSubject.tenantId } : {}),
        detail: { status, ...auditSubject.detail },
      });
    });
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const method = req.method ?? "GET";
      const pathname = url.pathname;

      if (method === "GET" && pathname === "/healthz") {
        return sendJson(res, 200, { ok: true });
      }
      // 경량 관리 콘솔(정적 HTML, 무인증 — 토큰은 페이지에서 런타임 입력해 API 호출에 사용)
      if (method === "GET" && (pathname === "/" || pathname === "/admin")) {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", ...ADMIN_UI_SECURITY_HEADERS });
        res.end(ADMIN_UI_HTML);
        return;
      }

      // 인증이 필요한 구간부터 스로틀 적용 — /healthz와 콘솔 HTML은 인증을 태우지 않으므로
      // 차단된 IP도 콘솔 자체는 열 수 있다(스로틀 때문에 운영자가 화면조차 못 보는 상황 방지).
      const ip = clientIp(req);
      const now = Date.now();
      const retryAfter = this.throttle.retryAfterSeconds(ip, now);
      if (retryAfter > 0) {
        return sendJson(res, 429, { error: "too many failed auth attempts" }, { "Retry-After": String(retryAfter) });
      }

      if (await this.handleSession(req, res, method, pathname, ip, auditSubject)) return;

      /**
       * ★Bearer가 있으면 그것만 본다(쿠키는 무시). 자동화가 브라우저 쿠키를 들고 오는 경우에도
       * 주체가 하나로 정해져야 감사 줄이 "누가"에 답한다.
       */
      /**
       * 두 자격증명을 **먼저 모두 해석하고**, 그다음 어느 것을 쓸지 고른다. 해석을 사용자 값(헤더 유무)에 따라
       * 건너뛰는 분기가 없어야 "조건이 인증을 건너뛰게 한다"는 의심(CodeQL js/user-controlled-bypass)이 성립하지 않는다.
       * 없는 쪽은 null로 해석된다(헤더 없음 → null, 빈 토큰 → null).
       */
      const cookieToken = readCookie(req, ADMIN_SESSION_COOKIE) ?? "";
      const bearerAuth = await this.authenticate(req);
      const cookieAuth = await this.authenticateSession(cookieToken);
      const bearerPresented = typeof req.headers.authorization === "string";
      const auth: AuthContext | null = bearerPresented ? bearerAuth : cookieAuth;
      if (!auth) {
        // 만료된 쿠키는 공격이 아니라 일상이다 — 스로틀에 세지 않는다(256비트 토큰은 대입할 수 없다).
        if (!bearerPresented && cookieToken !== "") {
          return sendJson(res, 401, { error: "session expired", code: "no_session" }, { "Set-Cookie": clearedSessionCookie() });
        }
        this.throttle.recordFailure(ip, now);
        return sendJson(res, 401, { error: "unauthorized" });
      }
      if (auth.kind !== "human") this.throttle.clear(ip);
      if (auth.kind === "human") {
        auditSubject.detail.adminUserId = auth.adminUserId;
        if (method !== "GET") this.requireSameOriginWrite(req, auth.csrfHash);
        // MFA 1차 필수 — 미등록 세션은 등록 엔드포인트(/admin/session/mfa/*)만 쓸 수 있다.
        if (auth.mfaAt === null) throw new HttpError(403, "mfa enrollment required", "mfa_required");
      }
      /**
       * 주체를 감사 줄에 채운다. **`apiKeyId`가 핵심 값이다** — 관리 API는 사람이 아니라 키가
       * 주체이고, 키는 여러 개 발급되므로 "어느 키로 계정을 지웠나"에 답할 수 있어야 폐기 결정을
       * 내릴 수 있다. root 토큰은 테넌트가 없으므로 `isRoot`로만 드러난다(cross-tenant 주체).
       */
      auditSubject.detail.isRoot = auth.isRoot ? 1 : 0;
      if (auth.kind === "root") await this.flagRootAfterBootstrap(auditSubject);
      if (auth.kind === "apiKey") {
        auditSubject.tenantId = auth.tenantId;
        auditSubject.detail.apiKeyId = auth.apiKeyId;
      } else if (auth.kind === "human" && auth.tenantId !== null) {
        auditSubject.tenantId = auth.tenantId;
      }

      /**
       * 스코프 관문 — 라우트마다가 아니라 여기 한 곳. 새 라우트가 자동으로 덮인다(위 주석).
       *
       * ★예외는 범용 명령 입구(`POST /v1/commands/:name`) 하나다. 콘솔은 조회도 POST로 부르므로 메서드로 정하면
       * readonly 관리자·read 키가 조회조차 못 한다(2026-10-18 보안 검토). 그 경로는 아래에서 **명령 서술의
       * readOnly**로 정한다 — 메서드보다 정확한 근거이고, 모르는 명령은 404라 판정을 건너뛸 틈이 없다.
       */
      const genericCommand = method === "POST" && /^\/v1\/commands\/[^/]+$/.test(pathname);
      if (!genericCommand) requireScope(auth, method === "GET" ? SCOPE_READ : SCOPE_WRITE);

      /**
       * 명령 서술 — GUI가 화면을 그리는 근거다. **상태(무엇이 있는지)가 아니라 능력(무엇을 할 수
       * 있는지)만** 준다. 이걸 API가 주기 때문에 GUI가 탭·컬럼·상태 라벨을 하드코딩하지 않는다.
       */
      if (method === "GET" && pathname === "/v1/commands") {
        return sendJson(res, 200, { commands: this.registry.describe(), encodings: COMMAND_ENCODINGS });
      }

      /**
       * ★**범용 명령 입구** — 관리 콘솔이 쓰는 유일한 변경 경로다.
       *
       * REST 라우트 표(routes.ts)는 기존 계약을 지키기 위한 것이고 외부 사용처를 위한 것이다.
       * 반면 콘솔은 `/v1/commands`로 받은 서술만 알고 화면을 그리므로, **이름으로 부를 수 있는
       * 입구**가 있어야 명령이 늘 때 화면이 자동으로 따라온다. 여기가 없으면 콘솔에 기능을
       * 붙일 때마다 라우트를 손으로 더해야 하고, 그 순간 "화면에는 있는데 API에는 없는" 갈래가
       * 생긴다 — 이 리팩터링이 없애려던 바로 그 비대칭이다.
       *
       * 인증·스코프·root 판정은 위에서 이미 통과했다. 여기서 더하는 것은 없다.
       */
      const cmdMatch = pathname.match(/^\/v1\/commands\/([^/]+)$/);
      if (method === "POST" && cmdMatch) {
        const name = decodeURIComponent(cmdMatch[1]!);
        const command = this.registry.get(name);
        if (!command) throw new HttpError(404, `unknown command: ${name}`);
        requireScope(auth, command.spec.readOnly ? SCOPE_READ : SCOPE_WRITE);
        if (command.spec.rootOnly && !auth.isRoot) throw new HttpError(403, "root token required");
        this.requireFreshMfa(auth, command.spec);
        const body = asRecord(await readBody(req));
        const ctx = this.commandContext(auth, url, body, command.spec.rootOnly === true);
        auditSubject.detail.command = name;
        try {
          const result = await runCommand(this.registry, ctx, name, collectArgs(command.spec, url, body));
          /**
           * 콘솔은 표(`rows`)·단일 결과(`data`)·평문 시크릿을 구분해서 그린다. 시크릿을 `data`에
           * 섞으면 화면이 그것을 일반 값처럼 표에 찍고, **서버 로그·감사에서 걸러낼 수도 없다**.
           * `__secret`으로 따로 실어 보내는 이유가 그것이다.
           */
          return sendJson(res, 200, {
            ...(result.rows ? { rows: result.rows } : {}),
            ...(result.data ? { data: result.data } : {}),
            ...(result.message ? { message: result.message } : {}),
            ...(result.secret ? { __secret: result.secret } : {}),
          });
        } catch (err) {
          if (err instanceof CommandError) throw new HttpError(statusOf(err.kind), err.message);
          throw err;
        }
      }

      // ── 명령 위임 ────────────────────────────────────────────────────
      // 이 아래로 라우트별 핸들러가 없다. 표(routes.ts)가 경로를 명령으로 옮기고,
      // 실제 일은 전부 @ionosphere/admin-cmd가 한다 — CLI도 같은 명령을 부른다.
      const matched = matchRoute(method, pathname);
      if (matched) {
        const { route, pathArgs } = matched;
        const body = method === "GET" ? {} : asRecord(await readBody(req));
        const cmd = this.registry.get(route.command);
        if (!cmd) throw new HttpError(500, `route references unknown command: ${route.command}`);
        // root 전용 명령은 여기서 막는다 — 판단 근거(서술)는 명령이 들고 있고 집행은 어댑터가 한다.
        if (cmd.spec.rootOnly && !auth.isRoot) throw new HttpError(403, "root token required");
        this.requireFreshMfa(auth, cmd.spec);

        const ctx = this.commandContext(auth, url, body, cmd.spec.rootOnly === true);
        auditSubject.detail.command = route.command;
        try {
          const result = await runCommand(this.registry, ctx, route.command, {
            ...collectArgs(cmd.spec, url, body),
            ...pathArgs, // 경로 인자가 이긴다 — /v1/accounts/:id 의 id를 바디가 덮어쓰면 안 된다
          });
          const shaped = route.shape ? route.shape(result) : (result.rows ?? result.data ?? {});
          /**
           * `selfRevoked` — **여기서만 알 수 있는 사실**이다. 방금 자기를 인증한 키를 폐기했다면
           * 다음 요청부터 401이 되므로, 콘솔이 "이제 401이 됩니다"를 띄울 수 있게 알려 준다.
           * 자기 폐기 자체는 막지 않는다 — 유출 대응이 가장 급한 폐기다.
           */
          if (route.command === "api-key-revoke" && shaped !== null && typeof shaped === "object") {
            const keyId = (result.data ?? {}).keyId;
            (shaped as Record<string, unknown>).selfRevoked = auth.kind === "apiKey" && auth.apiKeyId === keyId;
            delete (shaped as Record<string, unknown>).keyId; // 응답 계약에 없는 내부 값
          }
          return sendJson(res, 200, shaped);
        } catch (err) {
          if (err instanceof CommandError) throw new HttpError(statusOf(err.kind), err.message);
          throw err;
        }
      }

      return sendJson(res, 404, { error: "not found" });
    } catch (err) {
      if (err instanceof HttpError) return sendJson(res, err.status, { error: err.message, ...(err.code ? { code: err.code } : {}) });
      // 도메인 이름 판정은 @ionosphere/api domains.ts 소유라 HttpError를 쓸 수 없다(server.ts 전용).
      // 자기 status를 들고 오므로 여기서 그대로 옮긴다 — 400/409가 400으로 뭉개지지 않게.
      if (err instanceof DomainNameError) return sendJson(res, err.status, { error: err.message });
      if (err instanceof StoreError) return sendJson(res, 400, { error: err.message });
      this.log.error("request failed", { error: String(err) });
      return sendJson(res, 500, { error: "internal error" });
    }
  }

  /**
   * 명령 문맥 조립 — 인증 결과를 명령 계층의 언어로 옮긴다.
   *
   * ★테넌트 해석이 **여기 한 곳**이다. 예전엔 라우트마다 `resolveTenantId(auth, url, body)`를
   * 손으로 불렀고, 그 호출을 빠뜨린 라우트는 남의 테넌트 자원을 만질 수 있었다. 지금은
   * 위임 경로가 하나라 빠뜨릴 자리가 없다.
   */
  private commandContext(auth: AuthContext, url: URL, body: Record<string, unknown>, rootOnly: boolean): CommandContext {
    /**
     * root는 대상 테넌트를 **명시**해야 한다(body.tenantId 또는 ?tenantId=). 추측하지 않는다 —
     * 잘못 추측하면 남의 테넌트에 계정을 만드는 것이 조용히 성공한다.
     * 단 `rootOnly` 명령(테넌트 목록·TLS)은 테넌트에 매이지 않으므로 없어도 된다.
     */
    let tenantId: string | undefined;
    const crossTenant = auth.kind === "root" || (auth.kind === "human" && auth.tenantId === null);
    if (crossTenant) {
      const provided = typeof body.tenantId === "string" ? body.tenantId : url.searchParams.get("tenantId");
      if (provided) tenantId = provided;
      else if (!rootOnly) throw new HttpError(400, "tenantId required for root token");
    } else {
      tenantId = auth.tenantId ?? undefined;
    }
    return {
      db: this.deps.db,
      store: this.deps.store,
      tenantId,
      isRoot: auth.isRoot,
      masterKey: this.deps.masterKey,
      resolveTxt: this.deps.resolveTxt,
      resolveMx: this.deps.resolveMx,
      ...(this.deps.sharedMailbox ? { sharedMailbox: this.deps.sharedMailbox } : {}),
      ...(this.deps.observer ? { observer: this.deps.observer } : {}),
      ...(this.deps.oidcAccountProviders ? { oidcAccountProviders: this.deps.oidcAccountProviders } : {}),
      ...(this.deps.oidcAdminProviders ? { oidcAdminProviders: this.deps.oidcAdminProviders } : {}),
      ...(this.deps.tls ? { tls: toTlsPort(this.deps.tls) } : {}),
    };
  }
}

/**
 * `TlsAdmin`(구체 타입) → `TlsAdminPort`(명령 계층이 아는 모양).
 *
 * ★단순 캐스트로 되지 않는 것이 오히려 옳다. `CertStatus`는 필드가 고정된 구조체고
 * 명령 계층은 "이름 붙은 값들"만 알면 된다 — 그 간극을 여기서 **한 번** 메운다.
 * 반대로 명령 계층이 `CertStatus`를 알게 하면 관리 명령이 TLS 구현 타입에 묶인다.
 */
function toTlsPort(tls: TlsAdmin): TlsAdminPort {
  const asRecord = (s: CertStatus): Record<string, unknown> => ({ ...s });
  return {
    status: async () => asRecord(await tls.status()),
    refresh: async () => asRecord(await tls.refresh()),
    // upload는 sealed 모드에서만 존재한다 — 없으면 키를 만들지 않아야 명령이 `unavailable`로 답한다.
    ...(tls.upload ? { upload: async (c: string, k: string) => asRecord(await tls.upload!(c, k)) } : {}),
  };
}

/**
 * 명령 실패 분류 → HTTP 상태코드. **매핑이 여기 있는 이유**는 명령 계층이 HTTP를 모르기 때문이다
 * (admin-cmd/types.ts `CommandFailure` 주석). 분류가 없으면 어댑터가 메시지 문자열로 상태코드를
 * 추측하게 되고, 예전에 StoreError를 전부 400으로 뭉갠 것이 정확히 그 모양이었다.
 */
function statusOf(kind: CommandFailure): number {
  switch (kind) {
    case "invalid":
      return 400;
    case "denied":
      return 403;
    case "notFound":
      return 404;
    case "conflict":
      return 409;
    case "unavailable":
      return 501;
  }
}

/**
 * 명령 인자를 요청에서 모은다 — GET은 쿼리스트링, 그 외는 JSON 바디.
 *
 * 서술(`ArgSpec`)에 있는 이름만 읽는다. 그래서 요청에 낯선 키가 섞여도 명령에 도달하지 않고,
 * 새 인자를 추가하면 세 표면이 **동시에** 그것을 받게 된다.
 */
function collectArgs(spec: CommandSpec, url: URL, body: Record<string, unknown>): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const a of spec.args) {
    const fromBody = body[a.name];
    if (typeof fromBody === "string") out[a.name] = fromBody;
    else if (typeof fromBody === "number" || typeof fromBody === "boolean") out[a.name] = String(fromBody);
    else if (Array.isArray(fromBody)) out[a.name] = fromBody.filter((v) => typeof v === "string").join(",");
    else {
      const q = url.searchParams.get(a.name);
      if (q !== null) out[a.name] = q;
    }
  }
  /**
   * 알리아스 생성의 하위호환 입구. 기존 클라이언트는 `targetAccountIds`(배열)/`targetAccountId`
   * (단수)/`forwardTo`로 보내는데, 명령은 그것을 `target` 하나로 받는다. 여기서 합치지 않으면
   * 기존 호출이 전부 "대상이 필요합니다"로 실패한다.
   */
  if (spec.name === "alias-add" && out.target === undefined) {
    const many = Array.isArray(body.targetAccountIds) ? body.targetAccountIds.filter((v): v is string => typeof v === "string") : [];
    const one = typeof body.targetAccountId === "string" ? [body.targetAccountId] : [];
    const fwd = typeof body.forwardTo === "string" ? [body.forwardTo] : [];
    const merged = [...new Set([...many, ...one, ...fwd].map((s) => s.trim()).filter(Boolean))];
    if (merged.length > 0) out.target = merged.join(",");
  }
  return out;
}
