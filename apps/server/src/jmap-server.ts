/**
 * JMAP HTTP 어댑터 (RFC 8620 §2/§3). GET /jmap/session, POST /jmap/api.
 * 인증: Basic(계정 자격증명 → store.authenticate). JMAP은 소켓 상태머신이 아니라
 * 요청/응답이라 proto-jmap 엔진(순수)에 이 얇은 HTTP 계층만 씌운다.
 *
 * TLS는 리버스 프록시/별도 종단 전제(관리 API와 동일 패턴) — 여기선 평문 http.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  AUDIT_OUTCOME,
  AUDIT_SURFACE,
  AuthFailureThrottle,
  clientIpOf,
  hardenHttpListener,
  MAX_JMAP_UPLOAD_BYTES,
  noopAuditSink,
  noopLogger,
  sha256hex,
  trackListener,
  type AuditEvent,
  type AuditOutcome,
  type AuditSink,
  type ListenerShutdown,
  type Logger,
} from "@ionosphere/core";
import { authenticate, lookupBlob, putBlob, Store, type BlobStore, type JmapStates } from "@ionosphere/store";
import { BLOB_STATUS, REF_KIND, type DbDriver } from "@ionosphere/db";
import type { OutboundPolicy } from "@ionosphere/mta";
import {
  buildSession,
  coreModule,
  JmapEngine,
  RequestError,
  CORE_CAPABILITY,
  MAIL_CAPABILITY,
  QUOTA_CAPABILITY,
  SUBMISSION_CAPABILITY,
  VACATION_CAPABILITY,
  type CapabilityModule,
  type JmapRequest,
} from "@ionosphere/proto-jmap";
import { buildMailModule, buildQuotaModule, buildSubmissionModule, buildVacationModule } from "./jmap-backend.ts";
import { buildPushMethods, type PushModuleOptions } from "./push.ts";
import { principalContext } from "./principal-context.ts";

export interface JmapServerOptions {
  db: DbDriver;
  store: Store;
  blobs: BlobStore;
  hostname: string;
  /** 세션/URL 생성용 외부 베이스 URL(예: https://mx.ionosphere.test). 미지정 시 요청 Host 사용. */
  externalBaseUrl?: string;
  /** 외부 URL을 쓰지 않는 개발/테스트 모드의 Host 허용목록. 기본은 서버 이름과 loopback만 허용한다. */
  allowedHosts?: readonly string[];
  logger?: Logger;
  /**
   * 발송 레이트리밋 — SMTP submission(587/465)과 **같은 값을 넘겨야 한다**.
   * 미지정 시 DEFAULT_RATE_LIMIT 폴백이라 운영자 한도가 JMAP에서만 무시된다.
   */
  /** 발송 정책(레이트리밋·내부 전용) — SMTP submission과 같은 값을 받아야 한다. */
  outbound?: OutboundPolicy;
  /** 추가 capability 모듈(테스트/확장). 기본은 core + mail. */
  extraModules?: CapabilityModule[];
  /** EventSource(push) 상태 폴링 주기(ms). 기본 2000. 테스트는 짧게. */
  eventSourcePollMs?: number;
  /**
   * `PushSubscription`(RFC 8620 §7.2). 주면 메서드가 열리고 상태 변화가 등록된 URL로 나간다.
   *
   * ★opt-in인 이유: **사용자가 준 URL로 서버가 나가는** 기능이라 SSRF 표면이 새로 생긴다.
   * 가드가 걸린 fetch를 조립층이 만들어 넘기게 해서, 그 방어를 우회한 배선이 생길 수 없게 한다.
   */
  push?: PushModuleOptions;
  /**
   * 인증 실패 스로틀 — **다른 리스너와 같은 인스턴스를 받아야 한다**(조립층이 주입).
   * 리스너마다 새로 만들면 "IP당 분당 10회" 정책이 리스너 수만큼 곱해진다.
   */
  authThrottle?: AuthFailureThrottle;
  /**
   * 접근 감사 싱크 — 다른 리스너와 **같은 인스턴스**를 받는다(조립층이 주입).
   *
   * ★기록 지점이 `authenticate()`가 아니라 `handle()`인 이유: 30초 인증 캐시(`authCache`)가
   * `authenticate()`의 검증 경로를 건너뛴다. 거기 걸면 캐시가 살아 있는 동안의 요청이 감사
   * 로그에서 **전부 사라진다** — 30초에 한 줄만 남고 그 사이 수백 요청이 무기록이 된다.
   */
  audit?: AuditSink;
}

/** JMAP 타입명 ↔ JmapStates 키 (StateChange changed 맵). */
const STATE_TYPES: readonly [jmapType: string, key: "email" | "mailbox" | "thread" | "submission"][] = [
  ["Email", "email"],
  ["Mailbox", "mailbox"],
  ["Thread", "thread"],
  ["EmailSubmission", "submission"],
];

const MAX_BODY_BYTES = 10_000_000; // RFC 8620 maxSizeRequestObject 기본과 일치

/**
 * 인증 결과 캐시 수명.
 *
 * JMAP은 상태 없는 HTTP라 **요청마다** 자격증명을 다시 검증한다. 비밀번호 해시는 의도적으로
 * 비싸므로(scrypt) 정상 클라이언트의 연속 호출만으로도 CPU가 계속 탄다. 짧게 캐시해 그 비용을
 * 없앤다. 대가는 자격증명 폐기가 이 시간만큼 늦게 반영되는 것 — 그래서 짧게 잡는다.
 */
const AUTH_CACHE_TTL_MS = 30_000;

/** 동시에 열어 둘 수 있는 EventSource 스트림 수 — 각각이 주기 DB 폴링을 만든다. */
const MAX_SSE_CONNECTIONS = 256;

/** 인증 결과 캐시 상한 — 넘치면 만료분을 쓸고, 그래도 넘치면 삽입 순서로 버린다. */
const MAX_AUTH_CACHE = 10_000;

/**
 * 인증 결과.
 *
 * 실패를 `null` 하나로 표현하던 시절엔 **자격증명 미제시**와 **자격증명 오류**를 호출부가
 * 구분할 수 없어 둘 다 스로틀 실패로 셌다. 실패 사유를 타입에 드러내 그 구분을 강제한다
 * (`presented`가 false인 실패는 절대 세지 않는다).
 */
type JmapAuthResult =
  | { ok: true; accountId: string; email: string; credKind?: string | undefined; cached: boolean }
  | { ok: false; presented: boolean; user?: string };

export class JmapServer {
  private readonly opts: JmapServerOptions;
  private readonly log: Logger;
  private readonly engine: JmapEngine;
  private readonly capabilities: string[];
  private server: Server | null = null;
  /** 정상 종료 손잡이 — close 시 남은 연결을 끊는다(SSE 외 keep-alive 포함). */
  private shutdown: ListenerShutdown | null = null;
  /** 열린 EventSource 연결 — close() 시 정리(안 하면 server.close()가 대기). */
  private readonly sseConnections = new Set<{ res: ServerResponse; timer: ReturnType<typeof setInterval> }>();
  private readonly authThrottle: AuthFailureThrottle;
  /** 접근 감사 싱크 — 미주입 시 no-op(호출부가 `?.`를 쓰지 않게). */
  private readonly audit: AuditSink;
  /** Authorization 헤더 해시 → 인증 결과. 평문 자격증명은 담지 않는다. */
  private readonly authCache = new Map<string, { accountId: string; email: string; expiresAt: number }>();

  constructor(opts: JmapServerOptions) {
    this.opts = opts;
    this.log = (opts.logger ?? noopLogger).child({ component: "jmap" });
    // 주입이 없으면 단독 기동(테스트·단일 사용)이라 자기 것을 쓴다. 조립층은 항상 넘긴다.
    this.authThrottle = opts.authThrottle ?? new AuthFailureThrottle({ ...(opts.logger ? { logger: opts.logger } : {}) });
    this.audit = opts.audit ?? noopAuditSink;
    const modules: CapabilityModule[] = [
      coreModule,
      buildMailModule(opts.db, opts.store, opts.blobs),
      buildSubmissionModule(opts.db, opts.store, opts.blobs, opts.outbound),
      buildQuotaModule(opts.store),
      buildVacationModule(opts.db, opts.store),
      /**
       * `PushSubscription`(RFC 8620 §7.2)은 **Core capability**에 속한다 — 계정이 아니라
       * 사용자에 묶이므로 mail/submission 어디에도 들어가지 않는다. 별도 모듈로 얹어
       * `coreModule`을 건드리지 않는다(그쪽은 프로토콜 패키지의 순수 코드다).
       */
      ...(opts.push ? [{ capability: CORE_CAPABILITY, methods: buildPushMethods(opts.push) }] : []),
      ...(opts.extraModules ?? []),
    ];
    this.capabilities = [CORE_CAPABILITY, MAIL_CAPABILITY, SUBMISSION_CAPABILITY, QUOTA_CAPABILITY, VACATION_CAPABILITY];
    if (!opts.externalBaseUrl) {
      // Session 응답의 apiUrl/downloadUrl을 요청 Host로 만들게 된다 — 클라이언트가 보낸 값이라
      // 위조하면 다음 요청을 남의 호스트로 유도할 수 있다. 운영에서는 반드시 고정해야 한다.
      this.log.warn("externalBaseUrl 미설정 — Session URL을 요청 Host로 만든다(IONOSPHERE_JMAP_BASE_URL 권장)", {});
    }
    this.engine = new JmapEngine({
      modules,
      capabilities: this.capabilities,
      // sessionState는 계정별이 아니라 서버 전역 요약 — v1은 고정 문자열(클라이언트는 각 타입 state로 동기화)
      sessionState: () => "0",
    });
  }

  listen(port: number, host?: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = createServer((req, res) => void this.handle(req, res));
      // ★SSE만 정리하면 부족하다. 평범한 keep-alive 연결 하나만 남아도 server.close()의 콜백이
      // 오지 않아 **종료가 5초 예산을 넘긴다**(CI에서 실측 — 관리 API 0.46초, JMAP 5.4초 실패).
      const shutdown = trackListener(server); // listen 전에 붙여야 그 사이 연결을 놓치지 않는다
      server.once("error", reject);
      /**
       * 연결 수 상한 + 요청 타임아웃.
       *
       * ★소켓 유휴 타임아웃(`server.setTimeout`)을 쓰지 않는 이유: EventSource(§7.3)는
       * 상태 변화가 없으면 **아무것도 쓰지 않는 장수명 응답**이라(ping은 클라이언트가 요청해야
       * 켜진다) 소켓 유휴 타이머를 걸면 정상 push 스트림이 주기적으로 끊긴다. slowloris가
       * 실제로 머무는 구간은 요청 **수신** 단계이고, 그건 headersTimeout·requestTimeout이
       * 정확히 그 구간만 잰다 — 응답 스트리밍에는 관여하지 않는다.
       */
      hardenHttpListener(server);
      server.listen(port, host, () => {
        server.removeListener("error", reject);
        this.server = server;
        this.shutdown = shutdown;
        const addr = server.address();
        resolve(typeof addr === "object" && addr !== null ? addr.port : port);
      });
    });
  }

  async close(): Promise<void> {
    // 열린 EventSource 연결 정리(안 하면 server.close()가 영원히 대기)
    for (const c of this.sseConnections) {
      clearInterval(c.timer);
      try {
        c.res.end();
      } catch {
        /* 이미 닫힘 */
      }
    }
    this.sseConnections.clear();
    const shutdown = this.shutdown;
    this.server = null;
    this.shutdown = null;
    if (shutdown) await shutdown.close();
  }

  /**
   * EventSource push (RFC 8620 §7.3) — GET /jmap/eventsource. text/event-stream으로 StateChange를
   * 밀어준다. 상태 변화 감지는 계정 state 폴링(store 이벤트버스 부재 — IMAP IDLE 폴링과 동일 전략).
   * 쿼리: types(콤마 또는 *), closeafter(state|no), ping(초, 0=없음).
   */
  private serveEventSource(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    auth: { accountId: string; email: string },
  ): void {
    const accountId = auth.accountId;
    const typesParam = url.searchParams.get("types") ?? "*";
    const wanted = typesParam === "*" ? new Set(STATE_TYPES.map(([t]) => t)) : new Set(typesParam.split(",").map((s) => s.trim()));
    const activeTypes = STATE_TYPES.filter(([t]) => wanted.has(t));
    const closeAfterState = url.searchParams.get("closeafter") === "state";
    const pingSec = Math.max(0, Number(url.searchParams.get("ping") ?? "0") || 0);
    const pollMs = this.opts.eventSourcePollMs ?? 2000;

    /**
     * 열린 스트림 수 상한 — 각 연결이 자기 타이머로 계정 state를 폴링한다(기본 2초).
     * 상한이 없으면 인증 사용자가 수천 개를 열어 **DB 폴링 부하를 그만큼 곱할 수 있다**
     * (같은 프로세스의 메일 처리까지 밀린다). 초과분은 503으로 돌려보내 재접속을 유도한다.
     */
    if (this.sseConnections.size >= MAX_SSE_CONNECTIONS) {
      res.writeHead(503, { "content-type": "application/json", "retry-after": "5" });
      res.end(JSON.stringify({ type: "about:blank", status: 503, detail: "too many event streams" }));
      return;
    }

    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
    res.write(": jmap eventsource ready\n\n"); // 스트림 확립 코멘트

    let last: JmapStates | null = null;
    let pingAccum = 0;
    let timer: ReturnType<typeof setInterval>;
    const conn = { res, timer: null as unknown as ReturnType<typeof setInterval> };
    const cleanup = () => {
      clearInterval(timer);
      this.sseConnections.delete(conn);
    };

    const tick = async (): Promise<void> => {
      try {
        const states = await this.opts.store.jmapState(accountId);
        if (last === null) {
          last = states; // 첫 폴은 기준선(초기 전체 push 생략 — 클라이언트는 Session state로 시작)
        } else {
          const changed: Record<string, string> = {};
          for (const [t, key] of activeTypes) if (states[key] !== last[key]) changed[t] = states[key];
          if (Object.keys(changed).length > 0) {
            const payload = { "@type": "StateChange", changed: { [accountId]: changed } };
            const idStr = activeTypes.map(([, k]) => states[k]).join(":");
            res.write(`event: state\nid: ${idStr}\ndata: ${JSON.stringify(payload)}\n\n`);
            last = states;
            if (closeAfterState) {
              cleanup();
              res.end();
              return;
            }
          }
        }
        if (pingSec > 0) {
          pingAccum += pollMs;
          if (pingAccum >= pingSec * 1000) {
            pingAccum = 0;
            res.write(`event: ping\ndata: {"interval":${pingSec}}\n\n`);
          }
        }
      } catch {
        /* 폴 오류는 무시 — 다음 tick 재시도 */
      }
    };

    timer = setInterval(() => void tick(), pollMs);
    timer.unref?.();
    conn.timer = timer;
    this.sseConnections.add(conn);
    req.on("close", cleanup);
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      // 인증 실패 스로틀 — JMAP은 요청마다 자격증명을 검증하므로 무제한 대입이 곧 CPU 소모다.
      const ip = clientIpOf(req.headers["x-forwarded-for"], req.socket.remoteAddress);
      const path = new URL(req.url ?? "/", "http://localhost").pathname;
      /** 이 요청의 감사 한 줄 — `action`은 `METHOD path`(예: `POST /jmap/api`). */
      const auditRequest = (outcome: AuditOutcome, extra: Partial<AuditEvent> = {}): void => {
        this.audit.record({
          ts: Date.now(),
          surface: AUDIT_SURFACE.jmap,
          action: `${req.method ?? "?"} ${path}`,
          outcome,
          ip,
          ...extra,
        });
      };
      const retryAfter = this.authThrottle.retryAfterSeconds(ip);
      if (retryAfter > 0) {
        // 차단도 기록한다(소켓 프로토콜 넷과 같은 이유) — 공격 활동이 가장 잘 드러나는 갈래다.
        auditRequest(AUDIT_OUTCOME.throttled);
        res.writeHead(429, { "content-type": "application/json", "retry-after": String(retryAfter) });
        res.end(JSON.stringify({ type: "about:blank", status: 429, detail: "too many failed auth attempts" }));
        return;
      }
      const auth = await this.authenticate(req);
      if (!auth.ok) {
        // **자격증명을 제시한 실패만** 센다. Authorization 헤더가 없는 요청은 공격이 아니라
        // 401을 받고 자격증명을 붙이는 표준 브라우저 흐름이고, NAT/CGNAT 뒤에서는 평범한
        // 요청 몇 개만으로 그 출구 IP 전체가 연쇄 차단됐다.
        if (auth.presented) this.authThrottle.recordFailure({ ip, ...(auth.user !== undefined ? { account: auth.user } : {}) });
        /**
         * `presented`를 detail에 남긴다 — 자격증명 **미제시**(401을 받고 붙이는 표준 브라우저
         * 흐름)와 **오류**를 감사 로그에서도 가를 수 있어야 한다. 스로틀이 이 둘을 구분하는
         * 이유와 같다: 미제시를 공격으로 읽으면 CGNAT 뒤 정상 사용자가 공격자로 보인다.
         */
        auditRequest(AUDIT_OUTCOME.fail, {
          ...(auth.user !== undefined ? { user: auth.user } : {}),
          detail: { presented: auth.presented ? 1 : 0 },
        });
        res.writeHead(401, { "www-authenticate": 'Basic realm="jmap"', "content-type": "application/json" });
        res.end(JSON.stringify({ type: "about:blank", status: 401, detail: "authentication required" }));
        return;
      }
      this.authThrottle.clear({ ip, account: auth.email });
      // 인증된 요청 한 줄. **캐시 히트도 여기로 들어온다**(그게 이 자리에 훅을 건 이유다).
      auditRequest(AUDIT_OUTCOME.ok, {
        user: auth.email,
        accountId: auth.accountId,
        ...(auth.credKind ? { credKind: auth.credKind } : {}),
        detail: { cachedAuth: auth.cached ? 1 : 0 },
      });
      const url = new URL(req.url ?? "/", "http://localhost");
      /**
       * 세션 자원 — 표준 자동발견 경로(RFC 8620 §2.2)와 우리 경로를 **같이** 받는다.
       *
       * ★`/.well-known/jmap`이 없으면 규격대로 발견을 시도하는 클라이언트가 붙지 못한다.
       * 인증 게이트가 라우팅보다 먼저라 자격증명 없이는 401이 나와서 "구현돼 있다"로
       * 오독하기 쉬웠는데(실제로 그렇게 읽었다), 인증을 통과시키면 404였다.
       *
       * 리다이렉트(302) 대신 **세션 객체를 바로 준다**. RFC가 둘 다 허용하고, 왕복이
       * 하나 줄며, 리다이렉트를 따르는 클라이언트도 그대로 동작한다.
       */
      if (req.method === "GET" && (url.pathname === "/jmap/session" || url.pathname === "/.well-known/jmap")) {
        return await this.serveSession(req, res, auth);
      }
      if (req.method === "POST" && url.pathname === "/jmap/api") {
        return await this.serveApi(req, res, auth);
      }
      if (req.method === "POST" && url.pathname.startsWith("/jmap/upload/")) {
        return await this.serveUpload(req, res, auth);
      }
      if (req.method === "GET" && url.pathname.startsWith("/jmap/download/")) {
        return await this.serveDownload(url, res, auth);
      }
      if (req.method === "GET" && url.pathname === "/jmap/eventsource") {
        return this.serveEventSource(req, res, url, auth);
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ type: "about:blank", status: 404, detail: "not found" }));
    } catch (err) {
      if (err instanceof RequestError) {
        res.writeHead(err.status, { "content-type": "application/json" });
        res.end(JSON.stringify({ type: err.problemType, status: err.status, detail: err.message }));
        return;
      }
      this.log.warn("jmap error", { error: err instanceof Error ? err.message : String(err) });
      if (!res.headersSent) res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ type: "about:blank", status: 500, detail: "internal error" }));
    }
  }

  private async authenticate(req: IncomingMessage): Promise<JmapAuthResult> {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Basic ")) return { ok: false, presented: false };

    // 캐시 키는 헤더의 해시 — 평문 자격증명을 프로세스 메모리에 들고 있지 않기 위해서다.
    const cacheKey = sha256hex(header);
    const now = Date.now();
    const hit = this.authCache.get(cacheKey);
    if (hit) {
      // `cached: true` — 감사 로그가 "이 요청은 자격증명을 다시 검증하지 않았다"를 남긴다.
      // 그 구분이 없으면 자격증명 폐기 후 최대 30초간의 접근이 정상 인증처럼 보인다.
      if (hit.expiresAt > now) return { ok: true, accountId: hit.accountId, email: hit.email, cached: true };
      this.authCache.delete(cacheKey);
    }

    let decoded: string;
    try {
      decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
    } catch {
      return { ok: false, presented: true };
    }
    const idx = decoded.indexOf(":");
    if (idx === -1) return { ok: false, presented: true };
    const user = decoded.slice(0, idx);
    const pass = decoded.slice(idx + 1);
    const result = await authenticate(this.opts.db, user, pass, "jmap");
    if (!result) {
      this.log.warn("auth failed", { user });
      return { ok: false, presented: true, user };
    }
    const email = user.toLowerCase();
    this.authCache.set(cacheKey, { accountId: result.accountId, email, expiresAt: now + AUTH_CACHE_TTL_MS });

    /**
     * 상한 방어. 성공만 캐시하므로 무한 증식하려면 유효 자격증명이 그만큼 있어야 하지만,
     * 상한은 그 가정이 틀렸을 때를 위한 것이다.
     *
     * ★예전엔 **만료된 것만** 지웠다. 유효 엔트리가 1만을 넘으면 루프가 아무것도 지우지 않고
     * 맵은 계속 자란다 — 가드로서 성립하지 않았다. 만료분을 먼저 쓸고, 그래도 넘치면
     * 삽입 순서로 버린다(Map은 삽입 순서를 보존한다 — `worker.ts mtaStsCache`와 같은 형태).
     */
    if (this.authCache.size > MAX_AUTH_CACHE) {
      for (const [k, v] of this.authCache) if (v.expiresAt <= now) this.authCache.delete(k);
      while (this.authCache.size > MAX_AUTH_CACHE) {
        const oldest = this.authCache.keys().next();
        if (oldest.done) break;
        this.authCache.delete(oldest.value);
      }
    }
    return { ok: true, accountId: result.accountId, email, credKind: result.credKind, cached: false };
  }

  private baseUrl(req: IncomingMessage): string {
    if (this.opts.externalBaseUrl) return this.opts.externalBaseUrl.replace(/\/$/, "");
    const host = (req.headers.host ?? "").split(":")[0]!.toLowerCase();
    const allowed = this.opts.allowedHosts ?? [this.opts.hostname, "127.0.0.1", "localhost"];
    if (!allowed.map((h) => h.toLowerCase()).includes(host)) throw new RequestError("about:blank", 421, "misdirected host");
    return `http://${host}`;
  }

  private async serveSession(req: IncomingMessage, res: ServerResponse, auth: { accountId: string; email: string }): Promise<void> {
    const base = this.baseUrl(req);
    const context = await principalContext(this.opts.db, auth.accountId);
    const accessible = await this.opts.store.listAccessibleAccounts(context);
    const accounts = accessible.map((account) => ({
      accountId: account.id,
      name: account.email,
      isPersonal: account.kind === 0,
      // shared account의 세부 mayRights는 Mailbox/get에서 계산한다. 세션은 보수적으로 읽기 전용을 광고한다.
      isReadOnly: account.kind !== 0,
      accountCapabilities: {
        [MAIL_CAPABILITY]: { maxMailboxesPerEmail: null, maxMailboxDepth: null, mayCreateTopLevelMailbox: account.kind === 0 },
        [SUBMISSION_CAPABILITY]: { maxDelayedSend: 0, submissionExtensions: {} },
        [QUOTA_CAPABILITY]: {},
        [VACATION_CAPABILITY]: {},
      },
    }));
    const session = buildSession({
      accounts,
      primaryAccountId: auth.accountId,
      username: auth.email,
      apiUrl: `${base}/jmap/api`,
      downloadUrl: `${base}/jmap/download/{accountId}/{blobId}/{name}`,
      uploadUrl: `${base}/jmap/upload/{accountId}`,
      eventSourceUrl: `${base}/jmap/eventsource`,
      state: "0",
      capabilities: this.capabilities,
    });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(session));
  }

  /**
   * 블롭 업로드 (RFC 8620 §6.1) — 본문 바이트를 저장하고 blobId 반환.
   *
   * 파일만 쓰고 끝내면 안 된다. blobs 원장 + blob_refs(upload) 행을 같이 만들어야
   * ① GC가 "누가 붙잡고 있는지"를 알아 방금 올린 블롭을 지우지 않고,
   * ② 다운로드 인가(§9-5 계약: `blob_refs WHERE blob_id=? AND account_id=요청자`)가 성립하고,
   * ③ 메시지로 승격되지 않은 업로드가 TTL로 회수된다.
   * 예전엔 셋 다 없어서 업로드 블롭은 DB에 아무 흔적도 남기지 않았다.
   */
  private async serveUpload(req: IncomingMessage, res: ServerResponse, auth: { accountId: string }): Promise<void> {
    const bytes = await readBodyBytes(req);
    if (bytes.length === 0) throw new RequestError("urn:ietf:params:jmap:error:limit", 400, "empty upload");
    const { blobId, size, generation } = await putBlob(this.opts.db, this.opts.blobs, bytes);
    const now = Date.now();
    await this.opts.db.batch([
      {
        sql: this.opts.db.insertIgnore("blobs", ["id", "size_bytes", "backend", "status", "generation", "created_at"]),
        params: [blobId, size, 0, BLOB_STATUS.live, generation, now],
      },
      {
        sql: "UPDATE blobs SET status = ?, doomed_at = NULL, generation = ? WHERE id = ? AND generation <= ?",
        params: [BLOB_STATUS.live, generation, blobId, generation],
      },
      // 같은 계정이 같은 블롭을 두 번 올릴 수 있다 — ref_id를 blobId로 고정하고 insertIgnore로 멱등하게.
      {
        sql: this.opts.db.insertIgnore("blob_refs", ["blob_id", "account_id", "ref_kind", "ref_id", "created_at"]),
        params: [blobId, auth.accountId, REF_KIND.upload, blobId, now],
      },
    ]);
    const type = typeof req.headers["content-type"] === "string" ? req.headers["content-type"] : "application/octet-stream";
    res.writeHead(201, { "content-type": "application/json" });
    res.end(JSON.stringify({ accountId: auth.accountId, blobId, type, size }));
  }

  /**
   * 블롭 다운로드 (RFC 8620 §6.2) — /jmap/download/{accountId}/{blobId}/{name}.
   *
   * ★인가(SCHEMA.md §9-5 계약): blobId는 내용의 sha256이고 블롭은 전역 dedup된다. 즉 해시를
   * 아는 사람은 남의 메일 본문을 그대로 받아갈 수 있다 — 인증된 아무 계정이나 임의 해시를
   * 요청할 수 있으면 테넌트 격리가 무너진다. 요청자 계정의 blob_refs 존재를 반드시 확인한다.
   */
  private async serveDownload(url: URL, res: ServerResponse, auth: { accountId: string }): Promise<void> {
    const parts = url.pathname.split("/").filter((p) => p.length > 0); // jmap download accountId blobId name
    const requestedAccountId = parts[2] ?? auth.accountId;
    const blobId = parts[3];
    if (!blobId) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: 404, detail: "blob not found" }));
      return;
    }
    const context = await principalContext(this.opts.db, auth.accountId);
    const allowedMailboxIds = await this.opts.store.accessibleMailboxIds(context, requestedAccountId);
    const sharedMessageCondition = requestedAccountId === auth.accountId
      ? ""
      : allowedMailboxIds.length === 0
        ? " AND 1 = 0"
        // lint-allow chunked-in-query: P5의 mailbox 집합은 listing cache 단계에서 유계화하고, 현재는 ACL 결과를 직접 사용한다.
        : ` AND EXISTS (SELECT 1 FROM message_mailbox access_mm WHERE access_mm.message_id = m.id AND access_mm.mailbox_id IN (${allowedMailboxIds.map(() => "?").join(", ")}))`;
    const { rows: refRows } = await this.opts.db.query({
      sql: `SELECT 1 AS x FROM blob_refs br
            LEFT JOIN messages m ON m.id = br.ref_id AND br.ref_kind = ?
            WHERE br.blob_id = ? AND br.account_id = ?${sharedMessageCondition} LIMIT 1`,
      params: [REF_KIND.message, blobId, requestedAccountId, ...(requestedAccountId === auth.accountId ? [] : allowedMailboxIds)],
    });
    if (refRows.length === 0) {
      // 존재 여부를 흘리지 않도록 미인가와 부재를 같은 404로 답한다.
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: 404, detail: "blob not found" }));
      return;
    }
    const ledger = await lookupBlob(this.opts.db, blobId);
    // 원장에 행이 없으면 저장소를 두드릴 것도 없이 부재다(위 인가 검사와 같은 404).
    if (ledger === null) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: 404, detail: "blob not found" }));
      return;
    }
    let bytes: Uint8Array;
    try {
      bytes = await this.opts.blobs.get(blobId, ledger.generation);
    } catch (err) {
      // ★부재(404)와 저장소 장애(503)를 갈라야 한다. 로컬 FS일 땐 오류가 사실상 ENOENT뿐이라
      // 전부 404로 뭉개도 맞았지만, 공유 오브젝트 스토리지에서는 일시적 5xx·타임아웃이 정상
      // 발생한다. 그걸 404로 답하면 **클라이언트가 재시도하지 않아 첨부가 사라진 것처럼 보인다**.
      // 여기까지 왔다는 건 원장에 행이 있다는 뜻이므로, 못 읽은 건 부재가 아니라 장애다.
      this.log.warn("blob 다운로드 실패 — 저장소 오류", {
        blobId,
        error: err instanceof Error ? err.message : String(err),
      });
      res.writeHead(503, { "content-type": "application/json", "retry-after": "5" });
      res.end(JSON.stringify({ status: 503, detail: "blob temporarily unavailable" }));
      return;
    }
    res.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(bytes.length) });
    res.end(Buffer.from(bytes));
  }

  private async serveApi(req: IncomingMessage, res: ServerResponse, auth: { accountId: string }): Promise<void> {
    const body = await readBody(req);
    let request: JmapRequest;
    try {
      request = JSON.parse(body) as JmapRequest;
    } catch {
      throw new RequestError("urn:ietf:params:jmap:error:notJSON", 400, "본문 JSON 파싱 실패");
    }
    const response = await this.engine.handle(request, auth.accountId);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(response));
  }
}

function readBodyBytes(req: IncomingMessage): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > MAX_JMAP_UPLOAD_BYTES) {
        reject(new RequestError("urn:ietf:params:jmap:error:limit", 400, "maxSizeUpload"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(new Uint8Array(Buffer.concat(chunks))));
    req.on("error", reject);
  });
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > MAX_BODY_BYTES) {
        reject(new RequestError("urn:ietf:params:jmap:error:limit", 400, "requestTooLarge"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
