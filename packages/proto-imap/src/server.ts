/**
 * IMAP 소켓 어댑터 — 얇은 I/O 레이어 (proto-pop3/server.ts와 동일 패턴, PLAN.md §4).
 * 상태머신은 전부 ./engine.ts에 있고, 여기는 net/tls 소켓과 ImapBackend를 액션에 연결한다.
 *
 * STARTTLS는 미제공 — Bun 서버측 TLS 업그레이드 버그(oven-sh/bun#25044)로 SMTP와 동일하게
 * 평문(143) + 암시적 TLS(993, tls 옵션 지정 시) 2리스너 구성.
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
  trackListener,
  type AuditSink,
  type ListenerShutdown,
  type ScramStoredKeys,
} from "@ionosphere/core";
import { ImapEngine, type ImapAction, type ImapBackendRequest, type ImapBackendResponse } from "./engine.ts";

export interface ImapBackend {
  /**
   * SCRAM 저장 키 조회 — 없으면 null. **없다고 즉시 실패시키지 않는다**(엔진이 가짜 salt로
   * 교환을 끝까지 진행해 계정 열거를 막는다). 이 메서드가 없으면 SCRAM을 광고하지 않는다.
   */
  scramKeys?(user: string): Promise<ScramStoredKeys | null>;
  /** SCRAM 증명 통과 뒤 계정 상태 확인 — 증명했어도 정지 계정이면 들여보내지 않는다. */
  scramAuthorize?(user: string): Promise<{ accountId: string; credKind?: string } | null>;
  /**
   * `credKind`는 **선택**이다 — 접근 감사 로그가 자격증명 종류를 남길 때만 쓴다.
   * 없어도 인증은 성립하므로 이 필드를 채우지 않는 백엔드(테스트 스텁 등)도 그대로 동작한다.
   */
  authenticate(user: string, pass: string): Promise<{ accountId: string; credKind?: string | undefined } | null>;
  /** 엔진 백엔드 요청 단일 디스패치 — 응답 kind는 요청 kind별 계약(engine.ts 참조). */
  request(accountId: string, req: ImapBackendRequest): Promise<ImapBackendResponse>;
}

export interface ImapServerOptions {
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
  backend: ImapBackend;
  /** 지정 시 암시적 TLS(993)로 리슨. */
  /** 암시적 TLS(993) — 지정 시 리스너 자체가 TLS다. */
  tls?: { key: string | Buffer; cert: string | Buffer };
  /**
   * STARTTLS 업그레이드용 인증서(143 전용). `tls`와 **구분한다** — 이걸 `tls`로 넘기면
   * 평문 리스너가 암시적 TLS가 되어 143에 붙는 클라이언트가 전부 끊긴다.
   */
  starttls?: { key: string | Buffer; cert: string | Buffer };
  /** dev 전용 — 평문에서 LOGIN/AUTH 허용. */
  allowInsecureAuth?: boolean;
  /** IDLE 중 새 메일/변경 폴링 주기(ms). 기본 15초. 0이면 비활성. */
  idlePollMs?: number;
  logger?: { warn: (msg: string, fields?: Record<string, unknown>) => void };
  /**
   * 접근 감사 싱크 — `authThrottle`과 같은 이유로 **조립층이 하나를 만들어 주입한다**.
   *
   * ★왜 백엔드가 아니라 어댑터가 기록하는가: **IP는 여기에만 있다**(`socket.remoteAddress`).
   * 백엔드(`imap-backend.ts`)는 `db/store/blobs/log`만 들고 있어서 "누가 어디서"의 절반을 모른다.
   * 그래서 인증 실패 156건이 쌓이는 동안 출처를 짚을 수 없었다(2026-08-04).
   *
   * 생략 시 기록하지 않는다(`noopAuditSink`) — 기존 동작 그대로.
   */
  audit?: AuditSink;
}

/** RFC 9051 §5.4 — 최소 30분 유휴 타임아웃. */
const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
const DEFAULT_IDLE_POLL_MS = 15_000;

/**
 * 백엔드 요청 → 감사 로그 `detail` 필드.
 *
 * ★**허용 목록(allowlist)이다.** 요청 객체를 그대로 펼치면(`...req`) `appendMessage.raw`가
 * 감사 로그에 실린다 — 즉 **메일 본문 전체가 평문으로 파일에 남고 오브젝트 스토리지로 올라간다.**
 * 그건 감사 로그가 아니라 메일 사본이고, 보존기간·접근권한 설계가 전부 어긋난다.
 * 그래서 "무엇을 뺄지"가 아니라 **"무엇을 넣을지"**를 고른다. 새 요청 종류가 추가되면 detail이
 * 비어 있을 뿐(안전) 본문이 새지 않는다.
 *
 * 담는 것은 **대상과 규모**뿐이다: 메일함 이름, 영향받은 UID 수, 플래그 모드. 개별 UID를 넣지
 * 않는 이유는 FETCH 하나가 수천 개일 수 있어 줄이 폭발하기 때문이다(볼륨이 이 설계의 실질 위험).
 */
function auditDetailOf(req: ImapBackendRequest): { detail?: Record<string, string | number> } {
  switch (req.kind) {
    case "listMailboxes":
      return {};
    case "createMailbox":
    case "deleteMailbox":
    case "selectMailbox":
    case "expungeMailbox":
      return { detail: { mailbox: req.name } };
    case "setSubscribed":
      return { detail: { mailbox: req.name, subscribed: req.subscribed ? 1 : 0 } };
    case "renameMailbox":
      return { detail: { from: req.from, to: req.to } };
    case "fetchMessages":
      return { detail: { mailbox: req.name, uids: req.uids.length, raw: req.needRaw ? 1 : 0 } };
    case "storeFlags":
      return { detail: { mailbox: req.name, uids: req.uids.length, mode: req.mode, flags: req.flags.join(" ") } };
    case "syncSince":
      return { detail: { mailbox: req.name, sinceModseq: req.sinceModseq } };
    case "expunge":
      return { detail: { mailbox: req.name, uids: req.uids ? req.uids.length : 0 } };
    case "appendMessage":
      // ★`raw`는 넣지 않는다(위 주석). 크기만 남겨 규모를 알 수 있게 한다.
      return { detail: { mailbox: req.name, bytes: req.raw.byteLength } };
    case "copyMessages":
    case "moveMessages":
      return { detail: { from: req.from, to: req.to, uids: req.uids.length } };
  }
}

export class ImapServer {
  private readonly opts: ImapServerOptions;
  private server: net.Server | tls.Server | null = null;
  private shutdown: ListenerShutdown | null = null;
  private readonly isTls: boolean;
  private currentTls?: { key: string | Buffer; cert: string | Buffer };
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

  constructor(opts: ImapServerOptions) {
    this.opts = opts;
    // 조립층이 넘긴 공유 인스턴스를 쓴다(M-4). 단독 사용 시에만 자체 인스턴스.
    this.authThrottle = opts.authThrottle ?? new AuthFailureThrottle();
    this.peerLimit = opts.peerLimit ?? new PeerConnectionLimiter();
    this.audit = opts.audit ?? noopAuditSink;
    this.isTls = opts.tls !== undefined;
    // 암시적 TLS면 그 자재를, 평문이면 STARTTLS용 자재를 든다. 둘 다 핫리로드 대상이다.
    if (opts.tls) this.currentTls = opts.tls;
    else if (opts.starttls) this.currentTls = opts.starttls;
  }

  private createListener(): net.Server | tls.Server {
    const onConnection = (socket: net.Socket): void => this.handleConnection(socket, this.isTls);
    return this.isTls && this.currentTls
      ? tls.createServer({ key: this.currentTls.key, cert: this.currentTls.cert }, onConnection)
      : net.createServer(onConnection);
  }

  listen(port: number, host?: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = this.createListener();
      const shutdown = trackListener(server); // listen 전에 붙여야 그 사이 연결을 놓치지 않는다
      const onError = (err: Error): void => reject(err);
      // 소켓 고갈 방어 — 초과 연결은 즉시 끊는다(이미 붙은 세션은 살린다).
      server.maxConnections = MAX_LISTENER_CONNECTIONS;
      server.once("error", onError);
      server.listen(port, host, () => {
        server.removeListener("error", onError);
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
   * 인증서 무중단 교체(갱신·핫리로드). 평문 서버(143)면 no-op.
   * node는 setSecureContext로 진짜 무중단, **bun은 setSecureContext 미지원(실측)이라 리스너 재생성**
   * (close→같은 포트 재listen — 두 런타임 모두 검증됨). 기존 연결은 유지, 새 연결부터 새 인증서.
   */
  async reloadTls(material: { key: string | Buffer; cert: string | Buffer }): Promise<void> {
    this.currentTls = material;
    if (!this.isTls || !this.server) return;
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

  /** @deprecated reloadTls 사용 — node 전용 즉시 교체(bun no-op). 하위호환 유지. */
  setSecureContext(material: { key: string | Buffer; cert: string | Buffer }): void {
    this.currentTls = material;
    if (this.server && "setSecureContext" in this.server) {
      (this.server as tls.Server).setSecureContext({ key: material.key, cert: material.cert });
    }
  }

  private handleConnection(rawSocket: net.Socket, secure: boolean): void {
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

    const engine = new ImapEngine({
      hostname: this.opts.hostname,
      secure,
      allowInsecureAuth: this.opts.allowInsecureAuth ?? false,
      // 평문 리스너(143)이고 인증서가 있으면 STARTTLS를 제공한다. 993은 이미 secure라 무의미.
      tlsAvailable: !secure && this.currentTls !== undefined,
      // SCRAM은 키 조회와 승인이 **둘 다** 있을 때만 광고한다 — 하나라도 없으면 교환을 끝낼 수 없다.
      scramOffered: this.opts.backend.scramKeys !== undefined && this.opts.backend.scramAuthorize !== undefined,
    });
    // STARTTLS 업그레이드 후엔 socket이 TLSSocket으로 교체된다 — 쓰기는 항상 **지금 것**으로.
    let socket: net.Socket | tls.TLSSocket = rawSocket;
    const backend = this.opts.backend;
    let accountId: string | null = null;

    socket.setTimeout(IDLE_TIMEOUT_MS);

    const write = (bytes: Uint8Array): void => {
      if (!socket.destroyed) socket.write(bytes);
    };
    const writeText = (text: string): void => write(new TextEncoder().encode(`${text}\r\n`));

    const runActions = async (actions: ImapAction[]): Promise<void> => {
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
            if (!socket.destroyed) socket.end();
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
              surface: AUDIT_SURFACE.imap,
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
              surface: AUDIT_SURFACE.imap,
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
               * ★차단도 **기록한다**. 예전에는 이 갈래가 백엔드를 부르지 않고 조기 반환해서
               * 로그가 한 줄도 남지 않았다 — 공격 활동이 가장 잘 드러나는 갈래가 무기록이었다.
               * `fail`(자격증명 불일치)과 구분해야 "시도가 거부됨"과 "비밀번호가 틀림"을 가를 수 있다.
               */
              this.audit.record({
                ts: Date.now(),
                surface: AUDIT_SURFACE.imap,
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
              surface: AUDIT_SURFACE.imap,
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
          case "backend": {
            if (accountId === null) {
              // 방어적 — 인증 전 백엔드 요청은 도달 불가(엔진이 상태 게이트)
              await runActions(engine.backendResult({ kind: "no", message: "not authenticated" }));
              break;
            }
            let res: ImapBackendResponse;
            try {
              res = await backend.request(accountId, action.req);
            } catch (err) {
              this.opts.logger?.warn("imap backend error", { error: err instanceof Error ? err.message : String(err) });
              res = { kind: "no", message: "internal error" };
            }
            /**
             * ★명령을 **여기 한 곳에서** 기록한다. 명령마다 손으로 넣으면 새 명령이 추가될 때
             * 빠지고, 그 누락은 "감사 로그에 없으니 일어나지 않았다"는 잘못된 결론으로 이어진다.
             * `action.req.kind`가 곧 감사 action 이름이므로 엔진이 명령을 늘려도 자동으로 따라온다.
             */
            this.audit.record({
              ts: Date.now(),
              surface: AUDIT_SURFACE.imap,
              action: action.req.kind,
              outcome: res.kind === "no" ? AUDIT_OUTCOME.denied : AUDIT_OUTCOME.ok,
              ip: normalizeIp(socket.remoteAddress),
              accountId,
              ...auditDetailOf(action.req),
            });
            await runActions(engine.backendResult(res));
            break;
          }
        }
      }
    };

    const safeRun = (actions: ImapAction[]): void => {
      runActions(actions).catch(() => {
        try {
          writeText("* BYE internal error");
        } catch {
          // 소켓이 이미 죽었을 수 있음
        }
        if (!socket.destroyed) socket.destroy();
      });
    };

    // IDLE 알림 폴링(RFC 2177) — IDLE 중 주기적으로 EXISTS/EXPUNGE/FLAGS 델타를 푸시.
    // 엔진이 게이트(isIdling·pending·selected)를 판단하므로 여기선 주기 호출만.
    const idlePollMs = this.opts.idlePollMs ?? DEFAULT_IDLE_POLL_MS;
    let idlePoller: ReturnType<typeof setInterval> | null = null;
    if (idlePollMs > 0) {
      idlePoller = setInterval(() => {
        if (socket.destroyed) return;
        if (engine.isIdling()) safeRun(engine.idleTick());
      }, idlePollMs);
      idlePoller.unref?.();
    }

    /**
     * STARTTLS 업그레이드. ManageSieve 어댑터와 같은 절차이고, 같은 함정을 피한다.
     *
     * ★`this.currentTls`를 읽는다 — 생성 시점 `opts.tls`를 읽으면 갱신된 인증서가 STARTTLS에
     *   영원히 반영되지 않는다(proto-smtp에서 실제로 만료 인증서를 계속 제시했던 자리).
     * ★OK를 이미 보냈으므로 평문으로 되돌릴 수 없다 — 실패하면 끊는 것이 유일한 안전한 처분.
     */
    const upgradeTls = async (): Promise<void> => {
      const tlsOpts = this.currentTls;
      if (!tlsOpts) {
        rawSocket.destroy();
        return;
      }
      // 업그레이드 전 raw 소켓의 data 리스너를 뗀다 — TLSSocket이 언더라잉 스트림을 단독 소비해야 한다.
      rawSocket.removeAllListeners("data");
      let tlsSocket: tls.TLSSocket;
      try {
        tlsSocket = new tls.TLSSocket(rawSocket, { isServer: true, key: tlsOpts.key, cert: tlsOpts.cert });
      } catch {
        // key/cert가 어긋나면 **동기 throw**다. 잡지 않으면 data 핸들러에서 터져 프로세스가 죽는다.
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

    const attachData = (s: net.Socket | tls.TLSSocket): void => {
      s.on("data", (chunk: Buffer) => safeRun(engine.feed(chunk)));
    };
    attachData(rawSocket);
    socket.on("timeout", () => {
      writeText("* BYE idle timeout");
      if (!socket.destroyed) socket.end();
    });
    socket.on("error", () => {
      // 연결 오류 — 세션 종료 외 처리 없음(잠금류 자원 없음)
    });
    socket.on("close", () => {
      if (idlePoller) clearInterval(idlePoller);
    });

    safeRun(engine.greeting());
  }
}
