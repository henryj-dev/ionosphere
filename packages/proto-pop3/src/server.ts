/**
 * POP3 소켓 어댑터 — 얇은 I/O 레이어. 상태머신은 전부 ./engine.ts에 있고,
 * 여기는 net/tls 소켓과 Pop3Backend 호출을 엔진 액션에 연결만 한다(PLAN.md §4).
 */

import * as net from "node:net";
import * as tls from "node:tls";
import {
  AUDIT_OUTCOME,
  AUDIT_SURFACE,
  AuthFailureThrottle,
  MAX_LISTENER_CONNECTIONS,
  PeerConnectionLimiter,
  noopAuditSink,
  normalizeIp,
  POP3_IDLE_TIMEOUT_MS,
  trackListener,
  type AuditOutcome,
  type AuditSink,
  type ListenerShutdown,
  type MaildropLock,
  type ScramStoredKeys,
} from "@ionosphere/core";
import { Pop3Engine, type Pop3Action, type Pop3EngineMessage } from "./engine.ts";

/** maildrop 메시지 한 건 — 백엔드가 openMaildrop()에서 돌려준다. */
export interface Pop3MaildropMessage {
  uidl: string;
  sizeBytes: number;
  /** 백엔드 전용 불투명 토큰(예: message row id) — 어댑터/엔진은 내용을 해석하지 않는다. */
  ref: unknown;
}

export interface Pop3Backend {
  /**
   * SCRAM 저장 키 조회 — 없으면 null. **없다고 즉시 실패시키지 않는다**(엔진이 가짜 salt로
   * 교환을 끝까지 진행해 계정 열거를 막는다). 이 메서드가 없으면 SCRAM을 광고하지 않는다.
   */
  scramKeys?(user: string): Promise<ScramStoredKeys | null>;
  /** SCRAM 증명 통과 뒤 계정 상태 확인 — 증명했어도 정지 계정이면 들여보내지 않는다. */
  scramAuthorize?(user: string): Promise<{ accountId: string; credKind?: string } | null>;
  /** `credKind`는 선택 — 접근 감사 로그가 자격증명 종류를 남길 때만 쓴다(IMAP과 같은 계약). */
  authenticate(user: string, pass: string): Promise<{ accountId: string; credKind?: string | undefined } | null>;
  openMaildrop(
    accountId: string,
  ): Promise<{ ok: true; messages: Pop3MaildropMessage[] } | { ok: false; inUse: boolean }>;
  retrieve(accountId: string, msg: Pop3MaildropMessage): Promise<Uint8Array>;
  /** QUIT — SCHEMA.md §7-5: DELE 마크를 하나의 Expunge 배치로 커밋. */
  commitDeletions(accountId: string, msgs: Pop3MaildropMessage[]): Promise<void>;
  /** QUIT 또는 연결 종료 시 항상 호출 — maildrop 잠금을 반드시 해제. */
  releaseMaildrop(accountId: string): Promise<void>;
}

export interface Pop3ServerOptions {
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
  /**
   * IP 프리픽스별 동시 연결 상한 — 조립층이 만든 **하나**를 모든 리스너가 공유해야 한다.
   * 전역 상한(MAX_LISTENER_CONNECTIONS)만으로는 한 주소가 혼자 소진할 수 있다.
   */
  peerLimit?: PeerConnectionLimiter;

  hostname: string;
  backend: Pop3Backend;
  /** 지정 시 암시적 TLS(995 등)로 리슨 — STLS는 Phase 0 제외(PROTOCOLS.md §3). */
  /** 암시적 TLS(995) — 지정 시 리스너 자체가 TLS다. */
  tls?: { key: string | Buffer; cert: string | Buffer };
  /**
   * STLS 업그레이드용 인증서(110 전용, RFC 2595). `tls`와 **구분한다** — 이걸 `tls`로 넘기면
   * 평문 리스너가 암시적 TLS가 되어 110에 붙는 클라이언트가 전부 끊긴다.
   */
  starttls?: { key: string | Buffer; cert: string | Buffer };
  /**
   * 평문 회선에서도 인증을 허용(dev/테스트). 기본 false —
   * POP3는 비밀번호를 그대로 실어 보내므로 TLS 없이 받으면 경로상 누구나 읽는다.
   * IMAP 143·SMTP 587과 같은 정책(RFC 8314 §4.1).
   */
  allowInsecureAuth?: boolean;
  /**
   * 접근 감사 싱크 — `authThrottle`과 같은 이유로 **조립층이 하나를 만들어 주입한다**.
   *
   * ★왜 백엔드가 아니라 어댑터가 기록하는가: **IP는 여기에만 있다**(`socket.remoteAddress`).
   * 백엔드(`apps/server/src/backend.ts`)는 `db/store/blobs/log`만 들고 있어서 "누가 어디서"의
   * 절반을 모른다 — IMAP과 같은 구조적 공백이었다.
   *
   * 생략 시 기록하지 않는다(`noopAuditSink`) — 기존 동작 그대로.
   */
  audit?: AuditSink;
}

/**
 * RFC 1939 최소 10분 — 유휴 연결 타임아웃.
 * 정본은 @ionosphere/core(limits.ts) — maildrop 락 TTL이 이 값에서 파생되기 때문이다.
 */
const IDLE_TIMEOUT_MS = POP3_IDLE_TIMEOUT_MS;

/**
 * 인프로세스 maildrop 배타 잠금 유틸 — SCHEMA.md §7-5 "인프로세스 세션 관리".
 * 잠금 정책은 백엔드 소관이라 어댑터에 내장하지 않고, 백엔드 구현이 조합해 쓰도록 노출한다.
 *
 * ⚠ 배타성이 **이 프로세스 안에서만** 성립한다. MRA를 2대 이상 띄우거나 백엔드 인스턴스를
 * 둘 만들면(110/995를 따로 배선하는 경우) 서로를 못 본다 — 그 구성에서는 DB 락
 * (@ionosphere/store DbMaildropLock)을 주입할 것. 여기 구현은 DB 없는 구성과 테스트용으로 남긴다.
 *
 * 만료가 없는 이유(refreshIntervalMs = 0): 락 수명이 프로세스 수명에 묶여 있어 프로세스가
 * 죽으면 Set도 함께 사라진다. 즉 "크래시한 소유자가 계정을 영원히 잠그는" 문제가 없다.
 */
export class InProcessMaildropLock implements MaildropLock {
  /** accountId → owner. owner를 들고 있어야 해제·갱신을 자기 락으로 한정할 수 있다. */
  private readonly owners = new Map<string, string>();

  readonly refreshIntervalMs = 0;

  async acquire(accountId: string, owner: string): Promise<boolean> {
    if (this.owners.has(accountId)) return false;
    this.owners.set(accountId, owner);
    return true;
  }

  async refresh(accountId: string, owner: string): Promise<boolean> {
    return this.owners.get(accountId) === owner;
  }

  async release(accountId: string, owner: string): Promise<void> {
    if (this.owners.get(accountId) !== owner) return;
    this.owners.delete(accountId);
  }
}

export class Pop3Server {
  private readonly hostname: string;
  private readonly backend: Pop3Backend;
  private tlsOpts: { key: string | Buffer; cert: string | Buffer } | undefined;
  /** STLS 업그레이드용 자재(110). tlsOpts와 분리 — 리스너 종류를 바꾸지 않는다. */
  private starttlsOpts: { key: string | Buffer; cert: string | Buffer } | undefined;
  private readonly allowInsecureAuth: boolean;
  private server: net.Server | tls.Server | null = null;
  private shutdown: ListenerShutdown | null = null;
  private boundPort = 0;
  private boundHost: string | undefined = undefined;
  /** IP별 인증 실패 스로틀 — 연결 간에 공유해야 재접속 반복을 막는다. */
  private readonly authThrottle: AuthFailureThrottle;
  /**
   * IP 프리픽스별 동시 연결 상한 — **조립층이 하나를 만들어 모든 리스너에 넘긴다.**
   * 리스너마다 새로 만들면 "IP당 N개"가 리스너 수만큼 곱해진다(authThrottle과 같은 이유).
   * 생략 시 자체 인스턴스 — 단독 사용 테스트가 깨지지 않게.
   */
  private readonly peerLimit: PeerConnectionLimiter;
  /** 접근 감사 싱크 — 미주입 시 no-op(호출부가 `?.`를 쓰지 않게). */
  private readonly audit: AuditSink;

  constructor(opts: Pop3ServerOptions) {
    this.hostname = opts.hostname;
    // 조립층이 넘긴 공유 인스턴스를 쓴다(M-4). 단독 사용 시에만 자체 인스턴스.
    this.authThrottle = opts.authThrottle ?? new AuthFailureThrottle();
    this.peerLimit = opts.peerLimit ?? new PeerConnectionLimiter();
    this.audit = opts.audit ?? noopAuditSink;
    this.backend = opts.backend;
    this.tlsOpts = opts.tls;
    // 평문 리스너의 STLS 자재. tlsOpts와 분리해 둬야 리스너 종류를 바꾸지 않는다.
    this.starttlsOpts = opts.starttls;
    this.allowInsecureAuth = opts.allowInsecureAuth ?? false;
  }

  listen(port: number, host?: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const onConnection = (socket: net.Socket): void => this.handleConnection(socket);
      const server = this.tlsOpts
        ? tls.createServer({ key: this.tlsOpts.key, cert: this.tlsOpts.cert }, onConnection)
        : net.createServer(onConnection);
      const shutdown = trackListener(server); // listen 전에 붙여야 그 사이 연결을 놓치지 않는다
      const onError = (err: Error): void => reject(err);
      // 소켓 고갈 방어 — 초과 연결은 즉시 끊는다(이미 붙은 세션은 살린다).
      server.maxConnections = MAX_LISTENER_CONNECTIONS;
      server.once("error", onError);
      server.listen(port, host, () => {
        server.removeListener("error", onError);
        this.server = server;
        this.shutdown = shutdown;
        const addr = server.address();
        const bound = typeof addr === "object" && addr !== null ? addr.port : port;
        this.boundPort = bound;
        this.boundHost = host;
        resolve(bound);
      });
    });
  }

  /**
   * 인증서 무중단 교체 — 993/465와 동형(node=setSecureContext, bun=리스너 재생성).
   * 이게 없으면 갱신 때 **995만 옛 인증서로 남아** 클라이언트가 만료 경고를 본다.
   * 평문 리스너(110)에서는 no-op.
   */
  async reloadTls(material: { key: string | Buffer; cert: string | Buffer }): Promise<void> {
    if (this.tlsOpts === undefined) {
      // 평문 리스너라도 STLS 자재는 갱신해야 한다 — 안 하면 만료 인증서를 계속 제시한다
      // (proto-smtp에서 실제로 겪은 자리).
      if (this.starttlsOpts !== undefined) this.starttlsOpts = material;
      return;
    }
    this.tlsOpts = material;
    if (!this.server) return;
    if ("setSecureContext" in this.server) {
      (this.server as tls.Server).setSecureContext({ key: material.key, cert: material.cert });
      return;
    }
    // setSecureContext가 없는 리스너: 재생성(수락 중단 → 같은 포트로 새 인증서 서버). 기존 연결은 그대로 드레인.
    // ★추적된 close를 쓴다. 원시 server.close()는 붙어 있는 연결이 끝날 때까지 콜백이 오지 않아
    //   인증서 갱신이 그대로 멈춘다 — 종료 경로와 **같은 버그**다(listener-shutdown.ts).
    await this.close();
    await this.listen(this.boundPort, this.boundHost);
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

  private handleConnection(rawSocket: net.Socket): void {
    /**
     * IP 프리픽스별 동시 연결 상한 — 전역 상한(MAX_LISTENER_CONNECTIONS)만으로는
     * **한 주소가 혼자 소진**할 수 있어 정상 사용자도 접속하지 못한다(peer-limit.ts).
     * 자리를 못 잡으면 즉시 끊는다 — 이미 붙은 세션은 건드리지 않는다.
     */
    if (!this.peerLimit.tryAcquire(rawSocket.remoteAddress)) {
      rawSocket.destroy();
      return;
    }
    rawSocket.once("close", () => this.peerLimit.release(rawSocket.remoteAddress));

    // STLS 업그레이드 후엔 socket이 TLSSocket으로 교체된다 — 쓰기는 항상 **지금 것**으로.
    let socket: net.Socket | tls.TLSSocket = rawSocket;
    // 암시적 TLS 리스너(995)면 secure. 평문 110은 allowInsecureAuth가 켜져 있을 때만 인증을 받는다.
    const engine = new Pop3Engine({
      hostname: this.hostname,
      secure: this.tlsOpts !== undefined,
      allowInsecureAuth: this.allowInsecureAuth,
      // 평문(110)이고 인증서가 있을 때만 STLS를 제공한다. 995는 이미 secure라 무의미.
      tlsAvailable: this.tlsOpts === undefined && this.starttlsOpts !== undefined,
      // SCRAM은 키 조회와 승인이 **둘 다** 있을 때만 광고한다 — 하나라도 없으면 교환을 끝낼 수 없다.
      scramOffered: this.backend.scramKeys !== undefined && this.backend.scramAuthorize !== undefined,
    });
    const backend = this.backend;
    let accountId: string | null = null;
    let sessionMessages: readonly Pop3MaildropMessage[] = [];
    let released = false;
    let ended = false;

    socket.setTimeout(IDLE_TIMEOUT_MS);

    const release = async (): Promise<void> => {
      if (released || accountId === null) return;
      released = true;
      const id = accountId;
      accountId = null;
      try {
        await backend.releaseMaildrop(id);
      } catch {
        // 해제 실패는 연결 종료를 막지 않음 — 백엔드가 자체 로깅 책임.
      }
    };

    const finish = async (): Promise<void> => {
      if (ended) return;
      ended = true;
      await release();
      if (!socket.destroyed) socket.end();
    };

    const write = (bytes: Uint8Array): void => {
      if (!socket.destroyed) socket.write(bytes);
    };
    const writeText = (text: string): void => write(new TextEncoder().encode(`${text}\r\n`));

    /**
     * 인증 이후 명령의 감사 기록 — 세션 공통 필드(IP·accountId)를 여기서 한 번만 채운다.
     *
     * ★`accountId`를 호출 시점에 읽는 것이 요점이다(클로저 캡처가 아니라). `openMaildrop` 실패는
     * `accountId`를 null로 되돌리므로, 미리 캡처해 두면 그 뒤 기록이 이미 폐기된 계정을 가리킨다.
     * IMAP은 `auth`/`backend` 두 갈래뿐이어서 인라인으로 됐지만 POP3는 액션이 넷이라 헬퍼로 묶는다.
     */
    const audit = (
      action: string,
      outcome: AuditOutcome,
      detail?: Record<string, string | number>,
    ): void => {
      this.audit.record({
        ts: Date.now(),
        surface: AUDIT_SURFACE.pop3,
        action,
        outcome,
        ip: normalizeIp(socket.remoteAddress),
        ...(accountId !== null ? { accountId } : {}),
        ...(detail && Object.keys(detail).length > 0 ? { detail } : {}),
      });
    };

    const runActions = async (actions: Pop3Action[]): Promise<void> => {
      for (const action of actions) {
        switch (action.kind) {
          case "reply":
            writeText(action.text);
            break;
          case "replyBinary":
            write(action.bytes);
            break;
          case "startTls":
            await upgradeTls();
            break;
          case "close":
            await finish();
            break;
          case "scramKeys": {
            /**
             * 조회 실패를 **null로 수렴**시킨다. 예외를 밖으로 내면 교환이 중간에 끊겨
             * "그 사용자는 조회가 실패한다"가 드러난다 — 없는 것과 못 읽은 것을 같게 다룬다.
             */
            let keys = null;
            try {
              keys = (await backend.scramKeys?.(action.user)) ?? null;
            } catch {
              /* 없는 것으로 진행 */
            }
            await runActions(engine.scramKeysResult(keys));
            break;
          }
          case "authVerified": {
            const ip = normalizeIp(socket.remoteAddress);
            const ok = (await backend.scramAuthorize?.(action.user)) ?? null;
            if (ok) {
              accountId = ok.accountId;
              this.authThrottle.clear(ip);
            } else {
              this.authThrottle.recordFailure(ip);
            }
            this.audit.record({
              ts: Date.now(),
              surface: AUDIT_SURFACE.pop3,
              action: "auth",
              outcome: ok ? AUDIT_OUTCOME.ok : AUDIT_OUTCOME.fail,
              ip,
              user: action.user,
              // SCRAM으로 들어온 것을 감사에서 구분할 수 있어야 한다 — 평문 경로와 위험이 다르다.
              detail: { mechanism: "SCRAM-SHA-256" },
            });
            await runActions(engine.authResult(ok));
            break;
          }
          /**
           * ★엔진 안에서 끝난 인증 실패(SCRAM 증명 불일치 등) — **여기서만 기록된다.**
           *
           * SCRAM 검증은 순수 계산이라 백엔드 왕복이 없다. 그래서 실패가 `auth`도
           * `authVerified`도 거치지 않고 거절 응답만 내고 끝났고, 아래 두 줄이 실행되지 않았다.
           * 결과는 **SCRAM으로 무제한 대입이 무기록으로 가능**한 상태였다. 응답은 엔진이 이미
           * 냈으므로 여기서 재개(`authResult`)하지 않는다.
           */
          case "authFailed": {
            const ip = normalizeIp(socket.remoteAddress);
            this.authThrottle.recordFailure(ip);
            this.audit.record({
              ts: Date.now(),
              surface: AUDIT_SURFACE.pop3,
              action: "auth",
              outcome: AUDIT_OUTCOME.fail,
              ip,
              ...(action.user ? { user: action.user } : {}),
              detail: { mechanism: action.mechanism },
            });
            break;
          }
          case "auth": {
            const ip = normalizeIp(socket.remoteAddress);
            // 차단 중이면 백엔드를 부르지 않는다 — 실패마다 scrypt가 도는 걸 막는 게 요점.
            if (this.authThrottle.blocked(ip)) {
              /**
               * ★차단도 **기록한다**. 예전에는 이 갈래가 조기 반환해 로그가 한 줄도 없었다 —
               * 공격 활동이 가장 잘 드러나는 갈래가 무기록이었다(IMAP과 같은 공백).
               * `fail`(비밀번호 불일치)과 구분해야 "거부됨"과 "틀림"을 가를 수 있다.
               */
              this.audit.record({
                ts: Date.now(),
                surface: AUDIT_SURFACE.pop3,
                action: "auth",
                outcome: AUDIT_OUTCOME.throttled,
                ip,
                user: action.user,
              });
              await runActions(engine.authResult(null));
              break;
            }
            const result = await backend.authenticate(action.user, action.pass);
            if (result) {
              accountId = result.accountId;
              this.authThrottle.clear(ip);
            } else {
              this.authThrottle.recordFailure(ip);
            }
            this.audit.record({
              ts: Date.now(),
              surface: AUDIT_SURFACE.pop3,
              action: "auth",
              outcome: result ? AUDIT_OUTCOME.ok : AUDIT_OUTCOME.fail,
              ip,
              user: action.user,
              ...(result ? { accountId: result.accountId } : {}),
              ...(result?.credKind ? { credKind: result.credKind } : {}),
            });
            await runActions(engine.authResult(result));
            break;
          }
          case "openMaildrop": {
            if (accountId === null) break; // 방어적 — auth 성공 없이 도달 불가
            const result = await backend.openMaildrop(accountId);
            /**
             * 실패 사유를 구분해 남긴다: `inUse`는 다른 세션이 잠금을 들고 있는 정상 경합이고
             * (RFC 1939 §3 `-ERR maildrop already locked`), 그 외는 백엔드 오류다. 이 구분이 없으면
             * "POP3가 안 된다"는 신고를 받았을 때 경합인지 장애인지 로그로 가릴 수 없다.
             */
            audit("openMaildrop", result.ok ? AUDIT_OUTCOME.ok : AUDIT_OUTCOME.denied, {
              ...(result.ok ? { messages: result.messages.length } : { reason: result.inUse ? "inUse" : "error" }),
            });
            if (result.ok) {
              sessionMessages = result.messages;
            } else {
              accountId = null;
            }
            await runActions(engine.openMaildropResult(result));
            break;
          }
          case "retrieve": {
            const msg = sessionMessages[action.msgnum - 1];
            if (!msg || accountId === null) {
              audit("retrieve", AUDIT_OUTCOME.denied, { msgnum: action.msgnum });
              await runActions(engine.retrieveResult({ ok: false }));
              break;
            }
            try {
              const bytes = await backend.retrieve(accountId, msg);
              // ★본문(`bytes`)은 넣지 않는다 — 넣으면 감사 로그가 메일 사본이 되고 보존기간·
              //   접근권한 설계가 전부 어긋난다(IMAP `auditDetailOf`와 같은 규율). 규모만 남긴다.
              audit("retrieve", AUDIT_OUTCOME.ok, { msgnum: action.msgnum, uidl: msg.uidl, bytes: bytes.byteLength });
              await runActions(engine.retrieveResult({ ok: true, bytes }));
            } catch {
              audit("retrieve", AUDIT_OUTCOME.fail, { msgnum: action.msgnum, uidl: msg.uidl });
              await runActions(engine.retrieveResult({ ok: false }));
            }
            break;
          }
          case "commitDeletions": {
            if (accountId === null) {
              await runActions(engine.commitDeletionsResult(false));
              break;
            }
            const deleted = action.messages.length;
            try {
              await backend.commitDeletions(accountId, toBackendMessages(action.messages));
              audit("commitDeletions", AUDIT_OUTCOME.ok, { messages: deleted });
              await runActions(engine.commitDeletionsResult(true));
            } catch {
              // ★삭제 커밋 실패는 **반드시** 남는다. POP3 클라이언트는 QUIT에 +OK를 못 받으면
              //   다음 접속에서 같은 메일을 또 받아간다 — 중복 수신 신고의 근거가 이 줄이다.
              audit("commitDeletions", AUDIT_OUTCOME.fail, { messages: deleted });
              await runActions(engine.commitDeletionsResult(false));
            }
            break;
          }
        }
      }
    };

    const safeRun = (actions: Pop3Action[]): void => {
      runActions(actions).catch(() => {
        try {
          writeText("-ERR [SYS/TEMP] internal error");
        } catch {
          // ignore — 소켓이 이미 죽었을 수 있음
        }
        void release();
        if (!socket.destroyed) socket.destroy();
      });
    };

    const attachData = (t: net.Socket | tls.TLSSocket): void => {
      t.on("data", (chunk: Buffer) => safeRun(engine.feed(chunk)));
    };

    /**
     * STLS 업그레이드(RFC 2595 §4). IMAP·ManageSieve 어댑터와 같은 절차·같은 함정 회피.
     * +OK를 이미 보냈으므로 실패하면 평문으로 되돌릴 수 없다 — 끊는 것이 유일한 안전한 처분.
     */
    const upgradeTls = async (): Promise<void> => {
      const material = this.starttlsOpts;
      if (!material) {
        rawSocket.destroy();
        return;
      }
      rawSocket.removeAllListeners("data");
      let tlsSocket: tls.TLSSocket;
      try {
        tlsSocket = new tls.TLSSocket(rawSocket, { isServer: true, key: material.key, cert: material.cert });
      } catch {
        // key/cert가 어긋나면 동기 throw다. 잡지 않으면 data 핸들러에서 터져 프로세스가 죽는다.
        rawSocket.destroy();
        return;
      }
      socket = tlsSocket;
      attachData(tlsSocket);
      await new Promise<void>((resolve) => {
        tlsSocket.once("secure", () => resolve());
        tlsSocket.once("error", () => {
          tlsSocket.destroy();
          resolve();
        });
      });
      if (tlsSocket.destroyed) return;
      safeRun(engine.tlsEstablished());
    };

    attachData(rawSocket);
    socket.on("timeout", () => void finish());
    socket.on("error", () => void release());
    socket.on("close", () => void release());

    safeRun(engine.greeting());
  }
}

function toBackendMessages(messages: readonly Pop3EngineMessage[]): Pop3MaildropMessage[] {
  return messages.map((m) => ({ uidl: m.uidl, sizeBytes: m.sizeBytes, ref: m.ref }));
}
