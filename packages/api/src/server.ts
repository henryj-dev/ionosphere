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
import type { DbDriver } from "@ionosphere/db";
import { Store, StoreError } from "@ionosphere/store";
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
}

/** 서버 전역 TLS 관리 인터페이스(root 전용). upload는 sealed 모드에서만 제공. */
export interface TlsAdmin {
  status(): Promise<CertStatus>;
  /** 재취득(재생성/재페치/갱신) + 리스너 무중단 교체 → 새 상태. */
  refresh(): Promise<CertStatus>;
  /** cert/key 업로드(개인키 masterKey 봉인 저장) + 교체 → 새 상태. */
  upload?(certPem: string, keyPem: string): Promise<CertStatus>;
}

type AuthContext = { isRoot: true } | { isRoot: false; tenantId: string; apiKeyId: string; scopes: string };

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

/** 라우트 핸들러가 의도적으로 던지는 HTTP 상태 있는 에러 — 최상위 catch가 그대로 응답한다. */
class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", ...headers });
  res.end(payload);
}


/**
 * 인증 실패 스로틀 — 왜 필요한가: 관리 콘솔은 443의 `admin.` vhost로 네트워크에 열려 있다.
 * 앞단 방어가 두 겹(노출 정책 = 내부 인터페이스 착지만 허용, Host 화이트리스트)이지만,
 * 둘 다 설정이고 설정은 사람이 하는 일이다. 한 번 틀리면 정적 rootToken 하나가 유일한
 * 장벽으로 남는다.
 * 그 상황에서 대입 공격이 실용적이지 않으려면 실패 횟수 자체를 제한해야 한다(다층 방어).
 *
 * 구현은 @ionosphere/core가 소유한다 — 원래 여기 안에만 있어서 나머지 프로토콜에는 시도 제한이
 * 아예 없었다. 갈래마다 다시 만들면 한쪽이 빠지므로 정본을 하나로 둔다.
 */
function clientIp(req: IncomingMessage): string {
  return clientIpOf(req.headers["x-forwarded-for"], req.socket.remoteAddress);
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
 * 관리 API 요청 바디 상한.
 *
 * 가장 큰 정상 페이로드는 `/v1/tls/upload`의 인증서 체인 + 개인키(수 KB 수준)라 1MB면
 * 넉넉하다. 상한이 없으면 인증된 키 하나로 메모리를 고갈시킬 수 있었다 —
 * JMAP은 요청·업로드 모두 상한이 있는데(`jmap-server.ts`) 관리 API만 빠져 있었다.
 */
const MAX_ADMIN_BODY_BYTES = 1024 * 1024;

/** 요청 바디를 JSON으로 읽는다 — 빈 바디는 undefined, 파싱 실패는 400(HttpError)로 정규화. */
async function readBody(req: IncomingMessage): Promise<unknown> {
  /**
   * ★초과해도 **스트림은 끝까지 흘려보낸다.** 담기만 멈추면 메모리는 묶이고, 소켓은 건강하게
   * 유지된다. 다른 두 방법은 둘 다 실측에서 클라이언트를 매달리게 했다:
   *  · `req.destroy()`로 끊기 → 응답이 클라이언트에 도달하지 못한다
   *  · content-length를 보고 **읽기 전에** 413 응답 → 클라이언트는 아직 본문을 쓰는 중이라
   *    TCP 버퍼가 차고, 서버가 읽지 않으니 클라이언트는 응답을 읽을 차례가 오지 않는다(교착)
   * 대역폭은 클라이언트가 보낸 만큼 쓰지만, 인증된 표면이고 막아야 할 것은 메모리다.
   */
  const chunks: Buffer[] = [];
  let total = 0;
  let tooLarge = false;
  for await (const c of req) {
    const chunk = c as Buffer;
    total += chunk.length;
    if (total > MAX_ADMIN_BODY_BYTES) {
      if (!tooLarge) {
        tooLarge = true;
        chunks.length = 0; // 이미 담은 것도 버린다 — 어차피 거절이다
      }
      continue;
    }
    chunks.push(chunk);
  }
  if (tooLarge) throw new HttpError(413, `request body too large (max ${MAX_ADMIN_BODY_BYTES} bytes)`);
  if (chunks.length === 0) return undefined;
  const raw = Buffer.concat(chunks).toString("utf8");
  if (raw.trim() === "") return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    throw new HttpError(400, "invalid JSON body");
  }
}

function asRecord(body: unknown): Record<string, unknown> {
  return body !== null && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
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
  if (!auth.isRoot) return auth.tenantId;
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
  }

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

    if (this.deps.rootToken && secretEquals(token, this.deps.rootToken)) return { isRoot: true };

    // api-key는 sha256hex(token)으로 조회한다 — 비교 대상이 이미 해시라 접두사 타이밍이 새더라도
    // 원본 키를 복원할 수 없다(해시 역상을 만들어야 한다). rootToken과 달리 별도 상수시간 비교 불필요.
    const hash = sha256hex(token);
    const { rows } = await this.deps.db.query({
      sql: "SELECT id, tenant_id, scopes FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL",
      params: [hash],
    });
    const row = rows[0];
    if (!row) return null;
    return { isRoot: false, tenantId: String(row.tenant_id), apiKeyId: String(row.id), scopes: String(row.scopes) };
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
        // 401/403은 `denied`(권한), 4xx는 `fail`(요청 오류), 429는 `throttled`. 5xx도 `fail`.
        outcome:
          status === 429
            ? AUDIT_OUTCOME.throttled
            : status === 401 || status === 403
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

      const auth = await this.authenticate(req);
      if (!auth) {
        this.throttle.recordFailure(ip, now);
        return sendJson(res, 401, { error: "unauthorized" });
      }
      this.throttle.clear(ip);
      /**
       * 주체를 감사 줄에 채운다. **`apiKeyId`가 핵심 값이다** — 관리 API는 사람이 아니라 키가
       * 주체이고, 키는 여러 개 발급되므로 "어느 키로 계정을 지웠나"에 답할 수 있어야 폐기 결정을
       * 내릴 수 있다. root 토큰은 테넌트가 없으므로 `isRoot`로만 드러난다(cross-tenant 주체).
       */
      auditSubject.detail.isRoot = auth.isRoot ? 1 : 0;
      if (!auth.isRoot) {
        auditSubject.tenantId = auth.tenantId;
        auditSubject.detail.apiKeyId = auth.apiKeyId;
      }

      // 스코프 관문 — 라우트마다가 아니라 여기 한 곳. 새 라우트가 자동으로 덮인다(위 주석).
      requireScope(auth, method === "GET" ? SCOPE_READ : SCOPE_WRITE);

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
        if (command.spec.rootOnly && !auth.isRoot) throw new HttpError(403, "root token required");
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
            (shaped as Record<string, unknown>).selfRevoked = !auth.isRoot && auth.apiKeyId === keyId;
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
      if (err instanceof HttpError) return sendJson(res, err.status, { error: err.message });
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
    if (auth.isRoot) {
      const provided = typeof body.tenantId === "string" ? body.tenantId : url.searchParams.get("tenantId");
      if (provided) tenantId = provided;
      else if (!rootOnly) throw new HttpError(400, "tenantId required for root token");
    } else {
      tenantId = auth.tenantId;
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
