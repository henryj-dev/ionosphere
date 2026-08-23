/**
 * SMTP 소켓 어댑터 — node:net(+node:tls) 위에서 SmtpEngine(순수 상태머신)을 구동한다
 * (PLAN.md §4 설계원칙 1: 소켓/TLS는 얇은 어댑터가 담당).
 */
import { createServer as createNetServer, type Server, type Socket } from "node:net";
import { createServer as createTlsServer, TLSSocket } from "node:tls";
import {
  AUDIT_OUTCOME,
  AUDIT_SURFACE,
  AuthFailureThrottle,
  MAX_LISTENER_CONNECTIONS,
  noopAuditSink,
  normalizeIp,
  trackListener,
  type AuditSink,
  type AuditSurface,
  type ListenerShutdown,
  type ScramStoredKeys,
} from "@ionosphere/core";
import { type DeliverOutcome, type RcptOutcome, SmtpEngine, type SmtpAction } from "./engine.ts";

/** 수신자 검증/배달을 실제로 처리하는 백엔드 훅 — 스토어 연결은 apps/server 몫. */
export interface SmtpBackend {
  verifyRecipient(address: string): Promise<{ ok: true } | { ok: false; code: number; enhanced: string; message: string }>;
  deliver(env: {
    mailFrom: string;
    /** SPF 검증용 — HELO/EHLO 인자 (RFC 7208 HELO identity). */
    heloName: string;
    /** SPF 검증용 — 접속 클라이언트 IP. 어댑터가 소켓에서 채움. */
    clientIp: string;
    rcptTo: string[];
    raw: Uint8Array;
    authenticatedAs: string | null;
    /**
     * TLS 세션 정보 — 평문 세션이면 undefined. Received 헤더의 `with ESMTPS`와
     * `(version=… cipher=…)` 판정 근거(RFC 3848). 소켓을 아는 **어댑터만** 채울 수 있어
     * 여기서 넘긴다 — 엔진은 여전히 I/O를 모른다.
     */
    tls?: { protocol?: string | undefined; cipher?: string | undefined } | undefined;
  }): Promise<{ ok: true; queuedId?: string } | { ok: false; code: number; enhanced: string; message: string }>;
  /**
   * 생략 시 AUTH 비광고(authOffered=false) — Submission 프로파일은 이게 필수.
   *
   * ★반환이 `boolean`이 아니라 객체인 이유: 접근 감사 로그가 자격증명 종류(기본 비번/앱 비번/
   * OAuth)를 남겨야 하는데, 성패만 돌려주면 그 값이 어댑터에 도달할 길이 없다. IMAP·POP3·
   * ManageSieve 백엔드가 이미 객체를 돌려주므로 **네 표면의 계약이 같아진다**(예측 가능성).
   */
  authenticate?(user: string, pass: string): Promise<SmtpAuthResult>;
  /**
   * SCRAM 저장 키 조회 — 없으면 null. **없다고 즉시 실패시키지 않는다**(엔진이 가짜 salt로
   * 교환을 끝까지 진행해 계정 열거를 막는다). 이 메서드가 없으면 SCRAM을 광고하지 않는다.
   */
  scramKeys?(user: string): Promise<ScramStoredKeys | null>;
  /** SCRAM 증명이 통과한 사용자 — 세션을 묶어도 되는지 백엔드가 최종 판단한다(정지 계정 등). */
  scramAuthorize?(user: string): Promise<SmtpAuthResult>;
}

/** AUTH 결과 — `credKind`·`throttled`는 선택(감사 로그 전용, 인증 판정에는 쓰이지 않는다). */
export interface SmtpAuthResult {
  ok: boolean;
  credKind?: string | undefined;
  /**
   * 백엔드가 **자체 스로틀로 거부**했음(자격증명을 검사하지 않았다).
   *
   * ★왜 필요한가: 어댑터의 스로틀은 IP 축인데 조립층(`app.ts authFn`)에는 **계정 축** 스로틀이
   * 따로 있다(봇넷·IPv6 프리픽스 전환으로 IP가 흩어지면 IP 축에 걸리지 않는다). 이 플래그가
   * 없으면 계정 축 차단이 감사 로그에 `fail`로 남아 "비밀번호가 틀림"과 구분되지 않는다 —
   * 즉 분산 대입 공격이 평범한 오타로 보인다.
   */
  throttled?: boolean;
}

export interface SmtpServerOptions {
  /**
   * 인증 실패 스로틀 — **조립층이 만들어 모든 리스너에 같은 인스턴스를 넘긴다.**
   *
   * 왜 주입인가(감사 5차 M-4): 리스너마다 각자 `new`로 만들면 587·465·993·995·4190·JMAP·admin이
   * 각각 한도를 갖게 되어 "IP당 분당 10회" 정책이 **리스너 수만큼 곱해진다**. 갈래마다 옵션을
   * 손으로 재작성하다 한쪽만 빠지는 것이 이 저장소의 반복 사고라(과거 JMAP만 레이트리밋 우회),
   * 공통 값은 한 곳에서 만들어 전달한다.
   *
   * 생략 시 자체 인스턴스를 만든다 — 이 서버를 단독으로 쓰는 테스트가 깨지지 않게 하기 위해서다.
   */
  authThrottle?: AuthFailureThrottle;

  hostname: string;
  maxSizeBytes: number;
  backend: SmtpBackend;
  /** 생략 시 STARTTLS 비광고(및 implicitTls 사용 불가). */
  tls?: { key: string | Buffer; cert: string | Buffer };
  /** 리스너 프로파일. submission(587류)은 MAIL FROM 전 인증 강제. 기본 relay(25류). */
  profile?: "relay" | "submission";
  /** dev 전용: TLS 없이도 AUTH 허용. */
  allowInsecureAuth?: boolean;
  /** true면 STARTTLS 업그레이드 대신 접속 즉시 TLS로 리슨(465류 암시적 TLS). tls 옵션 필수. */
  implicitTls?: boolean;
  /**
   * 접근 감사 싱크 — `authThrottle`과 같은 이유로 **조립층이 하나를 만들어 주입한다**.
   *
   * surface는 `profile`에서 파생한다: submission(587/465)은 `submission`, relay(25)는 `smtp`.
   * 두 리스너가 같은 클래스를 쓰기 때문에, 조립층이 손으로 넘기게 하면 한쪽이 잘못된 표면으로
   * 기록되고도 조용히 통과한다(갈래마다 옵션을 재작성하다 어긋나는 이 저장소의 반복 사고).
   *
   * 생략 시 기록하지 않는다(`noopAuditSink`) — 기존 동작 그대로.
   */
  audit?: AuditSink;
}

/** RFC 5321 §4.5.3.2 — 커맨드 대기 유휴 타임아웃. */
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;

export class SmtpServer {
  private readonly opts: SmtpServerOptions;
  private server: Server | null = null;
  private shutdown: ListenerShutdown | null = null;
  private readonly isImplicitTls: boolean;
  /**
   * TLS를 **구성했는가**(생성 시점 결정, 불변). 자료(currentTls) 유무와 분리하는 이유:
   * 갱신 자료가 들어왔다고 해서 평문으로 시작한 리스너가 STARTTLS를 광고하기 시작하면 안 된다.
   * 런타임이 서버측 업그레이드를 지원하지 않아 의도적으로 끈 구성(app.ts startTlsSupport)이
   * 인증서 갱신 한 번에 되살아나면, 발신자가 STARTTLS를 보고 핸드셰이크에서 멈춰 수신이 깨진다.
   */
  private readonly tlsConfigured: boolean;
  private currentTls?: { key: string | Buffer; cert: string | Buffer };
  private boundPort = 0;
  private boundHost: string | undefined = undefined;
  /** IP별 인증 실패 스로틀 — 연결 간에 공유해야 재접속 반복을 막는다(리스너 수명 = 카운터 수명). */
  private readonly authThrottle: AuthFailureThrottle;
  /** 접근 감사 싱크 — 미주입 시 no-op(호출부가 `?.`를 쓰지 않게). */
  private readonly audit: AuditSink;
  /** 감사 표면 — `profile`에서 파생(조립층이 손으로 넘기면 한쪽이 어긋난다). */
  private readonly auditSurface: AuditSurface;

  constructor(opts: SmtpServerOptions) {
    if (opts.implicitTls && !opts.tls) throw new Error("implicitTls requires tls key/cert");
    this.opts = opts;
    // 조립층이 넘긴 공유 인스턴스를 쓴다(M-4). 단독 사용 시에만 자체 인스턴스.
    this.authThrottle = opts.authThrottle ?? new AuthFailureThrottle();
    this.audit = opts.audit ?? noopAuditSink;
    this.auditSurface = (opts.profile ?? "relay") === "submission" ? AUDIT_SURFACE.submission : AUDIT_SURFACE.smtp;
    this.isImplicitTls = Boolean(opts.implicitTls && opts.tls);
    this.tlsConfigured = opts.tls !== undefined;
    if (opts.tls) this.currentTls = opts.tls;
  }

  private createListener(): Server {
    return this.isImplicitTls && this.currentTls
      ? createTlsServer({ key: this.currentTls.key, cert: this.currentTls.cert }, (socket) => this.handleConnection(socket, true))
      : createNetServer((socket) => this.handleConnection(socket, false));
  }

  listen(port: number, host?: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = this.createListener();
      const shutdown = trackListener(server); // listen 전에 붙여야 그 사이 연결을 놓치지 않는다
      server.once("error", reject);
      // 소켓 고갈 방어 — 초과 연결은 즉시 끊는다(이미 붙은 세션은 살린다).
      server.maxConnections = MAX_LISTENER_CONNECTIONS;
      server.listen(port, host, () => {
        this.server = server;
        this.shutdown = shutdown;
        this.boundHost = host;
        const addr = server.address();
        this.boundPort = typeof addr === "object" && addr !== null ? addr.port : port;
        resolve(this.boundPort);
      });
    });
  }

  /**
   * 리스너를 닫고 **남은 연결을 끊는다**.
   *
   * `server.close()`만 부르면 기존 연결이 끝날 때까지 콜백이 오지 않아, IDLE 세션 하나가
   * 종료 전체를 막는다(2026-07-30 실사고 — systemd가 90초 뒤 SIGKILL). 상세는
   * @ionosphere/core listener-shutdown.ts.
   */
  close(): Promise<void> {
    if (!this.shutdown) return Promise.resolve();
    const shutdown = this.shutdown;
    this.shutdown = null;
    this.server = null;
    return shutdown.close();
  }

  /**
   * 인증서 무중단 교체(핫리로드). TLS를 구성하지 않은 리스너면 no-op(위 tlsConfigured 주석).
   * node는 setSecureContext, **bun은 미지원(실측)이라 리스너 재생성**(close→같은 포트 재listen).
   *
   * ⚠ STARTTLS(25/587)는 리스너가 평문 net 서버라 교체할 secure context가 없다 — `currentTls`를
   * 갱신하는 것이 곧 교체다. **업그레이드 경로가 반드시 `currentTls`를 읽어야** 효과가 있고,
   * 예전엔 `opts.tls`(생성 시점 값)를 읽어서 갱신이 영원히 반영되지 않았다(만료 인증서 계속 제시).
   */
  async reloadTls(material: { key: string | Buffer; cert: string | Buffer }): Promise<void> {
    if (!this.tlsConfigured) return;
    this.currentTls = material;
    if (!this.isImplicitTls || !this.server) return;
    const s = this.server as Server & { setSecureContext?: (o: { key: string | Buffer; cert: string | Buffer }) => void };
    if (typeof s.setSecureContext === "function") {
      s.setSecureContext({ key: material.key, cert: material.cert });
      return;
    }
    // ★추적된 close를 쓴다. 원시 server.close()는 붙어 있는 연결이 끝날 때까지 콜백이 오지 않아
    //   인증서 갱신이 그대로 멈춘다 — 종료 경로와 **같은 버그**다(listener-shutdown.ts).
    await this.close();
    await this.listen(this.boundPort, this.boundHost);
  }

  /** @deprecated reloadTls 사용 — node 전용 즉시 교체(bun no-op). 하위호환 유지. */
  setSecureContext(material: { key: string | Buffer; cert: string | Buffer }): void {
    if (!this.tlsConfigured) return;
    this.currentTls = material;
    const s = this.server as (Server & { setSecureContext?: (o: { key: string | Buffer; cert: string | Buffer }) => void }) | null;
    if (s && typeof s.setSecureContext === "function") {
      s.setSecureContext({ key: material.key, cert: material.cert });
    }
  }

  private handleConnection(rawSocket: Socket | TLSSocket, isImplicitTls: boolean): void {
    const engine = new SmtpEngine({
      hostname: this.opts.hostname,
      maxSizeBytes: this.opts.maxSizeBytes,
      tlsAvailable: this.tlsConfigured,
      profile: this.opts.profile ?? "relay",
      authOffered: this.opts.backend.authenticate !== undefined,
      // SCRAM은 키 조회와 승인이 둘 다 있어야 광고한다 — 하나라도 없으면 교환을 끝낼 수 없다.
      scramOffered: this.opts.backend.scramKeys !== undefined && this.opts.backend.scramAuthorize !== undefined,
      allowInsecureAuth: this.opts.allowInsecureAuth ?? false,
    });
    // 465류 암시적 TLS: STARTTLS 왕복 없이 접속 즉시 TLS이므로 engine에 즉시 통보(재EHLO 요구는 무해 — 아직 아무것도 없음)
    if (isImplicitTls) engine.tlsUpgraded();

    let socket: Socket | TLSSocket = rawSocket;
    let idleTimer: ReturnType<typeof setTimeout> | undefined;

    const resetIdle = (): void => {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        socket.write("421 4.4.2 Idle timeout, closing connection\r\n");
        socket.destroy();
      }, IDLE_TIMEOUT_MS);
    };

    const applyActions = (actions: SmtpAction[]): void => {
      for (const action of actions) {
        switch (action.kind) {
          case "reply":
            socket.write(action.text);
            break;
          case "startTls":
            upgradeTls();
            break;
          case "rcpt":
            void runRcpt(action.address);
            break;
          case "auth":
            void runAuth(action.user, action.pass);
            break;
          case "scramKeys":
            void runScramKeys(action.user);
            break;
          case "authVerified":
            void runScramAuthorize(action.user);
            break;
          case "authFailed":
            recordEngineAuthFailure(action.user, action.mechanism);
            break;
          case "deliver":
            void runDeliver(action.mailFrom, action.heloName, action.rcptTo, action.raw, action.authenticatedAs);
            break;
          case "close":
            socket.end();
            break;
        }
      }
    };

    const runRcpt = async (address: string): Promise<void> => {
      let outcome: RcptOutcome;
      try {
        outcome = await this.opts.backend.verifyRecipient(address);
      } catch {
        outcome = { ok: false, code: 450, enhanced: "4.3.0", message: "Temporary error verifying recipient" };
      }
      applyActions(engine.rcptResult(outcome));
    };

    const runDeliver = async (mailFrom: string, heloName: string, rcptTo: readonly string[], raw: Uint8Array, authenticatedAs: string | null): Promise<void> => {
      let outcome: DeliverOutcome;
      const clientIp = normalizeIp(socket.remoteAddress);
      // STARTTLS 업그레이드 후엔 socket이 교체돼 있다(let socket) — 지금 것을 봐야 한다.
      const tls = tlsInfoOf(socket);
      try {
        outcome = await this.opts.backend.deliver({
          mailFrom,
          heloName,
          clientIp,
          rcptTo: [...rcptTo],
          raw,
          authenticatedAs,
          ...(tls ? { tls } : {}),
        });
      } catch {
        outcome = { ok: false, code: 451, enhanced: "4.3.0", message: "Temporary error processing message" };
      }
      /**
       * 메시지 수락/거절 기록. **25번(relay)은 인증이 없으므로 이 줄이 유일한 접근 기록이다** —
       * `auth`만 기록하면 수신 표면 전체가 감사 로그에서 사라진다.
       *
       * `raw`는 넣지 않는다(크기만) — 넣으면 감사 로그가 메일 사본이 된다(IMAP `appendMessage`와
       * 같은 판단). 수신자는 **수**만 남긴다: 한 트랜잭션에 수백 명이 올 수 있어 줄이 폭발한다.
       */
      this.audit.record({
        ts: Date.now(),
        surface: this.auditSurface,
        action: "deliver",
        outcome: outcome.ok ? AUDIT_OUTCOME.ok : AUDIT_OUTCOME.denied,
        ip: clientIp,
        ...(authenticatedAs !== null ? { user: authenticatedAs } : {}),
        detail: {
          from: mailFrom,
          rcpts: rcptTo.length,
          bytes: raw.byteLength,
          helo: heloName,
          tls: tls ? 1 : 0,
          ...(outcome.ok ? {} : { code: outcome.code }),
        },
      });
      applyActions(engine.deliveryResult(outcome));
    };

    const runAuth = async (user: string, pass: string): Promise<void> => {
      const ip = normalizeIp(rawSocket.remoteAddress);
      // 차단 중이면 **백엔드를 아예 부르지 않는다**. 실패마다 scrypt가 도는 게 브루트포스를
      // 곧 CPU 소모 공격으로 만들던 자리라, 값을 검사하기 전에 끊는 것이 요점이다.
      if (this.authThrottle.blocked(ip)) {
        // 차단도 기록한다(다른 세 표면과 같은 이유) — 공격 활동이 가장 잘 드러나는 갈래다.
        this.audit.record({ ts: Date.now(), surface: this.auditSurface, action: "auth", outcome: AUDIT_OUTCOME.throttled, ip, user });
        applyActions(engine.authResult(false));
        return;
      }
      let result: SmtpAuthResult = { ok: false };
      try {
        result = this.opts.backend.authenticate ? await this.opts.backend.authenticate(user, pass) : { ok: false };
      } catch {
        result = { ok: false };
      }
      if (result.ok) this.authThrottle.clear(ip);
      else this.authThrottle.recordFailure(ip);
      /**
       * ★**어댑터에서 기록한다**. 조립층의 `authFn`(app.ts)에는 IP가 없어서, 거기서 찍는 로그는
       * "누가"만 알고 "어디서"를 모른다 — 이 저장소가 인증 실패의 출처를 짚지 못한 원인이다.
       * 여기에는 소켓이 있으므로 둘이 함께 남는다.
       */
      this.audit.record({
        ts: Date.now(),
        surface: this.auditSurface,
        action: "auth",
        // 백엔드의 계정 축 스로틀은 `throttled`로 남긴다 — `fail`로 뭉개면 분산 대입이 오타로 보인다.
        outcome: result.ok ? AUDIT_OUTCOME.ok : result.throttled ? AUDIT_OUTCOME.throttled : AUDIT_OUTCOME.fail,
        ip,
        user,
        ...(result.credKind ? { credKind: result.credKind } : {}),
      });
      applyActions(engine.authResult(result.ok));
    };

    /**
     * SCRAM 키 조회 — 실패해도 **null로 수렴**시킨다.
     * 여기서 예외를 밖으로 내면 교환이 중간에 끊겨 "그 사용자는 조회가 실패한다"가 드러난다.
     * 없는 것과 못 읽은 것을 같게 다루는 것이 열거 방어의 일부다.
     */
    const runScramKeys = async (user: string): Promise<void> => {
      let keys: ScramStoredKeys | null = null;
      try {
        keys = (await this.opts.backend.scramKeys?.(user)) ?? null;
      } catch {
        /* 없는 것으로 진행 */
      }
      applyActions(engine.scramKeysResult(keys));
    };

    /**
     * SCRAM 증명 통과 후 최종 승인. 백엔드가 **계정 상태**를 한 번 더 본다 —
     * 비밀번호를 증명했어도 정지된 계정이면 들여보내면 안 된다.
     */
    const runScramAuthorize = async (user: string): Promise<void> => {
      const ip = normalizeIp(rawSocket.remoteAddress);
      let result: SmtpAuthResult = { ok: false };
      try {
        result = (await this.opts.backend.scramAuthorize?.(user)) ?? { ok: false };
      } catch {
        /* 실패로 수렴 */
      }
      this.audit.record({
        ts: Date.now(),
        surface: this.auditSurface,
        action: "auth",
        outcome: result.ok ? AUDIT_OUTCOME.ok : AUDIT_OUTCOME.fail,
        ip,
        user,
        // SCRAM으로 들어온 것을 감사에서 구분할 수 있어야 한다 — 평문 경로와 위험이 다르다.
        detail: { mechanism: "SCRAM-SHA-256" },
        ...(result.credKind ? { credKind: result.credKind } : {}),
      });
      applyActions(engine.authResult(result.ok));
    };

    /**
     * ★엔진 안에서 끝난 인증 실패(SCRAM 증명 불일치 등) — **여기서만 기록된다.**
     *
     * SCRAM 검증은 순수 계산이라 백엔드 왕복이 없다. 그래서 실패가 `auth`도 `authVerified`도
     * 거치지 않고 535만 내고 끝났고, 아래 두 줄이 실행되지 않았다. 결과는 **SCRAM으로 무제한
     * 대입이 무기록으로 가능**한 상태였다. 응답은 엔진이 이미 냈으므로 재개하지 않는다.
     */
    const recordEngineAuthFailure = (user: string | undefined, mechanism: string): void => {
      const ip = normalizeIp(rawSocket.remoteAddress);
      this.authThrottle.recordFailure(ip);
      this.audit.record({
        ts: Date.now(),
        surface: this.auditSurface,
        action: "auth",
        outcome: AUDIT_OUTCOME.fail,
        ip,
        ...(user ? { user } : {}),
        detail: { mechanism },
      });
    };

    const attachDataHandler = (s: Socket | TLSSocket): void => {
      s.on("data", (chunk: Buffer) => {
        resetIdle();
        applyActions(engine.feed(chunk));
      });
      s.on("error", () => {
        /* 소켓 레벨 오류는 close로 수렴 — 여기선 프로세스 크래시 방지만 */
      });
      s.on("close", () => {
        if (idleTimer) clearTimeout(idleTimer);
      });
    };

    const upgradeTls = (): void => {
      // ★반드시 currentTls — opts.tls(생성 시점 값)를 읽으면 갱신된 인증서가 STARTTLS에
      // 영원히 반영되지 않는다(만료 후 재시작 전까지 만료 인증서를 계속 제시했다).
      const tlsOpts = this.currentTls;
      if (!tlsOpts) return;
      // 업그레이드 전 raw 소켓의 data 리스너를 떼어 TLSSocket이 언더라잉 스트림을 단독으로 소비하게 함
      rawSocket.removeAllListeners("data");
      let tlsSocket: TLSSocket;
      try {
        tlsSocket = new TLSSocket(rawSocket, { isServer: true, key: tlsOpts.key, cert: tlsOpts.cert });
      } catch {
        // 자료가 깨졌거나 key/cert 쌍이 어긋나면 **동기 throw**다(BoringSSL/OpenSSL).
        // 여기서 잡지 않으면 소켓 data 핸들러에서 터져 프로세스가 죽는다.
        // 이미 220을 보냈으므로 평문으로 되돌릴 수 없다(RFC 3207) — 연결을 끊는 것이 유일한 안전한 처분.
        rawSocket.destroy();
        return;
      }
      socket = tlsSocket;
      attachDataHandler(tlsSocket);
      tlsSocket.once("secure", () => {
        engine.tlsUpgraded();
      });
      tlsSocket.on("error", () => {
        tlsSocket.destroy();
      });
    };

    attachDataHandler(rawSocket);
    resetIdle();
    applyActions(engine.greeting());
  }
}

/**
 * 소켓에서 TLS 세션 정보를 뽑는다. 평문이면 undefined.
 *
 * `getProtocol()`은 핸드셰이크 전/평문에서 null을 준다 — 그때는 TLS가 아닌 것으로 본다.
 * Received의 `with` 키워드가 여기서 갈리므로, 확실하지 않으면 **낮은 쪽(ESMTP)** 으로 떨어뜨린다.
 */
function tlsInfoOf(socket: Socket | TLSSocket): { protocol?: string; cipher?: string } | undefined {
  if (!(socket instanceof TLSSocket)) return undefined;
  const protocol = socket.getProtocol();
  if (!protocol) return undefined;
  const cipher = socket.getCipher()?.name;
  return { protocol, ...(cipher ? { cipher } : {}) };
}
