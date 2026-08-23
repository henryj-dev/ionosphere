/**
 * ManageSieve 소켓 어댑터 (RFC 5804, 포트 4190) — 얇은 I/O 레이어(proto-pop3 패턴).
 * 상태머신은 engine.ts, 여기는 net 소켓 ↔ 백엔드 호출을 액션에 연결.
 *
 * TLS는 **STARTTLS 업그레이드**(RFC 5804 §2.2, 표준 경로)로 제공한다 — proto-smtp의 25/587과
 * 같은 방식이고, 조립층이 `tls`를 넘겼을 때만 켜진다. 넘기지 않으면 엔진이 광고도 수락도 하지
 * 않아 평문 세션이 되고, 평문에서는 인증이 막혀 있다(fail closed).
 *
 * 왜 별도 암시적 TLS 포트가 아닌가: RFC 5804는 4190(평문+STARTTLS)만 등록했고 implicit TLS
 * 포트를 표준화하지 않았다 — 별도 포트를 쓰면 모든 클라이언트에 수동 설정을 요구하게 된다.
 */
import * as net from "node:net";
import { TLSSocket } from "node:tls";
import {
  AUDIT_OUTCOME,
  AUDIT_SURFACE,
  AuthFailureThrottle,
  MAX_LISTENER_CONNECTIONS,
  noopAuditSink,
  normalizeIp,
  trackListener,
  type AuditOutcome,
  type AuditSink,
  type ListenerShutdown,
  type ScramStoredKeys,
} from "@ionosphere/core";
import { ManageSieveEngine, type ManageSieveAction } from "./engine.ts";

export interface ManageSieveBackend {
  /**
   * SCRAM 저장 키 조회 — 없으면 null. **없다고 즉시 실패시키지 않는다**(엔진이 가짜 salt로
   * 교환을 끝까지 진행해 계정 열거를 막는다). 이 메서드가 없으면 SCRAM을 광고하지 않는다.
   */
  scramKeys?(user: string): Promise<ScramStoredKeys | null>;
  /** SCRAM 증명 통과 뒤 계정 상태 확인 — 증명했어도 정지 계정이면 들여보내지 않는다. */
  scramAuthorize?(user: string): Promise<{ accountId: string; credKind?: string } | null>;
  /** `credKind`는 선택 — 접근 감사 로그가 자격증명 종류를 남길 때만 쓴다(IMAP·POP3와 같은 계약). */
  authenticate(user: string, pass: string): Promise<{ accountId: string; credKind?: string | undefined } | null>;
  /** 스크립트 저장(검증 통과 전제). 실패 시 사유. */
  putScript(accountId: string, name: string, content: string): Promise<{ ok: true } | { ok: false; code?: string; message: string }>;
  /** 스크립트 문법 검증(저장 안 함). */
  checkScript(content: string): { ok: true } | { ok: false; message: string };
  listScripts(accountId: string): Promise<{ name: string; active: boolean }[]>;
  getScript(accountId: string, name: string): Promise<string | null>;
  deleteScript(accountId: string, name: string): Promise<{ ok: true } | { ok: false; code?: string; message: string }>;
  setActive(accountId: string, name: string): Promise<{ ok: true } | { ok: false; code?: string; message: string }>;
  renameScript(accountId: string, from: string, to: string): Promise<{ ok: true } | { ok: false; code?: string; message: string }>;
}

export interface ManageSieveServerOptions {
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
  backend: ManageSieveBackend;
  allowInsecureAuth?: boolean;
  /**
   * STARTTLS용 인증서. 생략 시 STARTTLS **비광고·비수락**(engine tlsAvailable=false).
   *
   * ⚠ 조립층은 런타임이 서버측 업그레이드를 지원할 때만 넘겨야 한다 — 미지원 런타임
   * (bun ≤1.3.14, oven-sh/bun#25044)에서 광고하면 클라이언트가 OK를 받고 핸드셰이크에서
   * 멈춘다. 판정은 apps/server/src/starttls-support.ts가 소유한다.
   */
  tls?: { key: string | Buffer; cert: string | Buffer };
  /**
   * 접근 감사 싱크 — `authThrottle`과 같은 이유로 **조립층이 하나를 만들어 주입한다**.
   *
   * ★이 표면은 **로그가 아예 없었다**. 4190은 사용자의 필터 규칙을 바꾸는 자리라
   * (`fileinto`·`redirect`가 곧 메일 행방이다) 누가 무엇을 바꿨는지 남지 않는 것이 가장 나쁘다.
   * 다른 프로토콜은 최소한 백엔드가 `auth ok/failed`를 찍었지만 여기는 그것조차 없었다.
   *
   * 생략 시 기록하지 않는다(`noopAuditSink`) — 기존 동작 그대로.
   */
  audit?: AuditSink;
}

const IDLE_TIMEOUT_MS = 30 * 60 * 1000;

export class ManageSieveServer {
  private readonly opts: ManageSieveServerOptions;
  private server: net.Server | null = null;
  private shutdown: ListenerShutdown | null = null;
  /** IP별 인증 실패 스로틀 — 연결 간에 공유해야 재접속 반복을 막는다. */
  private readonly authThrottle: AuthFailureThrottle;
  /**
   * TLS를 **구성했는가**(생성 시점 결정, 불변). 자료(currentTls) 유무와 분리하는 이유는
   * proto-smtp server.ts와 같다: 인증서 갱신이 들어왔다고 해서 평문으로 시작한 리스너가
   * STARTTLS를 광고하기 시작하면 안 된다(런타임 미지원으로 의도적으로 끈 구성이 되살아난다).
   */
  private readonly tlsConfigured: boolean;
  private currentTls?: { key: string | Buffer; cert: string | Buffer };
  /** 접근 감사 싱크 — 미주입 시 no-op(호출부가 `?.`를 쓰지 않게). */
  private readonly audit: AuditSink;

  constructor(opts: ManageSieveServerOptions) {
    this.opts = opts;
    // 조립층이 넘긴 공유 인스턴스를 쓴다(M-4). 단독 사용 시에만 자체 인스턴스.
    this.authThrottle = opts.authThrottle ?? new AuthFailureThrottle();
    this.audit = opts.audit ?? noopAuditSink;
    this.tlsConfigured = opts.tls !== undefined;
    if (opts.tls) this.currentTls = opts.tls;
  }

  /**
   * 인증서 무중단 교체 — 4190은 평문 net 리스너라 교체할 secure context가 없다.
   * `currentTls`를 갱신하는 것이 곧 교체이고, **업그레이드 경로가 반드시 `currentTls`를 읽어야**
   * 효과가 있다(proto-smtp에서 `opts.tls`를 읽어 갱신이 영원히 반영되지 않았던 버그와 같은 자리).
   * TLS 미구성 리스너면 no-op — 조립층이 무조건 불러도 안전하다.
   */
  reloadTls(material: { key: string | Buffer; cert: string | Buffer }): Promise<void> {
    if (this.tlsConfigured) this.currentTls = material;
    return Promise.resolve();
  }

  listen(port: number, host?: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = net.createServer((sock) => this.handle(sock));
      const shutdown = trackListener(server); // listen 전에 붙여야 그 사이 연결을 놓치지 않는다
      server.once("error", reject);
      // 소켓 고갈 방어 — 초과 연결은 즉시 끊는다(이미 붙은 세션은 살린다).
      server.maxConnections = MAX_LISTENER_CONNECTIONS;
      server.listen(port, host, () => {
        server.removeListener("error", reject);
        this.server = server;
        this.shutdown = shutdown;
        const addr = server.address();
        resolve(typeof addr === "object" && addr !== null ? addr.port : port);
      });
    });
  }

  /** 리스너를 닫고 남은 연결을 끊는다 — 상세는 @ionosphere/core listener-shutdown.ts. */
  close(): Promise<void> {
    if (!this.shutdown) return Promise.resolve();
    const shutdown = this.shutdown;
    this.shutdown = null;
    this.server = null;
    return shutdown.close();
  }

  private handle(rawSocket: net.Socket): void {
    // 기본값은 **막는 쪽**이다(다른 4개 프로토콜 어댑터와 동일). 예전엔 여기만 `?? true`라,
    // 옵션을 빠뜨린 호출부가 생기면 4190만 평문 AUTHENTICATE PLAIN을 여는 구조였다.
    // 보안 기본값은 "명시하지 않았을 때 안전한 쪽"이어야 한다.
    const engine = new ManageSieveEngine({
      hostname: this.opts.hostname,
      allowInsecureAuth: this.opts.allowInsecureAuth ?? false,
      // 광고와 수락을 한 값이 지배한다 — 구성 시점 판정(tlsConfigured)이지 자료 유무가 아니다.
      tlsAvailable: this.tlsConfigured,
      // SCRAM은 키 조회와 승인이 **둘 다** 있을 때만 광고한다 — 하나라도 없으면 교환을 끝낼 수 없다.
      scramOffered: this.opts.backend.scramKeys !== undefined && this.opts.backend.scramAuthorize !== undefined,
    });
    const backend = this.opts.backend;
    let accountId: string | null = null;
    // STARTTLS 업그레이드 후엔 socket이 TLSSocket으로 교체된다 — 쓰기는 항상 **지금 것**으로.
    let socket: net.Socket | TLSSocket = rawSocket;
    rawSocket.setTimeout(IDLE_TIMEOUT_MS);

    const write = (s: string): void => {
      if (!socket.destroyed) socket.write(s.endsWith("\r\n") ? s : s + "\r\n");
    };

    /**
     * 인증 이후 명령의 감사 기록 — 세션 공통 필드(IP·accountId)를 한 번만 채운다.
     * `accountId`는 호출 시점에 읽는다(캡처가 아니라) — POP3 헬퍼와 같은 이유.
     */
    const audit = (
      action: string,
      outcome: AuditOutcome,
      detail?: Record<string, string | number>,
    ): void => {
      this.audit.record({
        ts: Date.now(),
        surface: AUDIT_SURFACE.managesieve,
        action,
        outcome,
        ip: normalizeIp(socket.remoteAddress),
        ...(accountId !== null ? { accountId } : {}),
        ...(detail && Object.keys(detail).length > 0 ? { detail } : {}),
      });
    };

    /** `{ok} | {ok:false,…}` 형태의 백엔드 결과를 기록하고 그대로 돌려준다(엔진에 넘기기 위해). */
    const auditOp = <T extends { ok: boolean }>(action: string, detail: Record<string, string | number>, r: T): T => {
      audit(action, r.ok ? AUDIT_OUTCOME.ok : AUDIT_OUTCOME.denied, detail);
      return r;
    };

    const run = async (actions: ManageSieveAction[]): Promise<void> => {
      for (const a of actions) {
        switch (a.kind) {
          case "reply":
            write(a.text);
            break;
          case "replyBytes":
            if (!socket.destroyed) socket.write(Buffer.from(a.bytes));
            break;
          case "close":
            if (!socket.destroyed) socket.end();
            break;
          case "startTls":
            await upgradeTls();
            break;
          case "scramKeys": {
            /**
             * 조회 실패를 **null로 수렴**시킨다. 예외를 밖으로 내면 교환이 중간에 끊겨
             * "그 사용자는 조회가 실패한다"가 드러난다 — 없는 것과 못 읽은 것을 같게 다룬다.
             */
            let keys = null;
            try {
              keys = (await backend.scramKeys?.(a.user)) ?? null;
            } catch {
              /* 없는 것으로 진행 */
            }
            await run(engine.scramKeysResult(keys));
            break;
          }
          case "authVerified": {
            const ip = normalizeIp(socket.remoteAddress);
            const ok = (await backend.scramAuthorize?.(a.user)) ?? null;
            if (ok) {
              accountId = ok.accountId;
              this.authThrottle.clear(ip);
            } else {
              this.authThrottle.recordFailure(ip);
            }
            this.audit.record({
              ts: Date.now(),
              surface: AUDIT_SURFACE.managesieve,
              action: "auth",
              outcome: ok ? AUDIT_OUTCOME.ok : AUDIT_OUTCOME.fail,
              ip,
              user: a.user,
              // SCRAM으로 들어온 것을 감사에서 구분할 수 있어야 한다 — 평문 경로와 위험이 다르다.
              detail: { mechanism: "SCRAM-SHA-256" },
            });
            await run(engine.authResult(ok));
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
              surface: AUDIT_SURFACE.managesieve,
              action: "auth",
              outcome: AUDIT_OUTCOME.fail,
              ip,
              ...(a.user ? { user: a.user } : {}),
              detail: { mechanism: a.mechanism },
            });
            break;
          }
          case "auth": {
            const ip = normalizeIp(socket.remoteAddress);
            // 차단 중이면 백엔드를 부르지 않는다 — 실패마다 scrypt가 도는 걸 막는 게 요점.
            if (this.authThrottle.blocked(ip)) {
              // 차단도 기록한다(IMAP·POP3와 같은 이유) — 공격 활동이 가장 잘 드러나는 갈래다.
              this.audit.record({
                ts: Date.now(),
                surface: AUDIT_SURFACE.managesieve,
                action: "auth",
                outcome: AUDIT_OUTCOME.throttled,
                ip,
                user: a.user,
              });
              await run(engine.authResult(null));
              break;
            }
            const r = await backend.authenticate(a.user, a.pass);
            if (r) {
              accountId = r.accountId;
              this.authThrottle.clear(ip);
            } else {
              this.authThrottle.recordFailure(ip);
            }
            this.audit.record({
              ts: Date.now(),
              surface: AUDIT_SURFACE.managesieve,
              action: "auth",
              outcome: r ? AUDIT_OUTCOME.ok : AUDIT_OUTCOME.fail,
              ip,
              user: a.user,
              ...(r ? { accountId: r.accountId } : {}),
              ...(r?.credKind ? { credKind: r.credKind } : {}),
            });
            await run(engine.authResult(r));
            break;
          }
          case "putScript": {
            if (accountId === null) break;
            const check = backend.checkScript(a.content);
            if (!check.ok) {
              // 문법 오류로 저장에 이르지 못한 것도 남긴다 — "왜 필터가 안 바뀌었나"의 답이 된다.
              audit("putScript", AUDIT_OUTCOME.denied, { script: a.name, reason: "syntax" });
              await run(engine.opResult({ ok: false, message: check.message }));
              break;
            }
            // ★스크립트 **본문은 넣지 않는다**(`bytes`만). 시브 스크립트에는 전달 주소·조건이 들어
            //   있어 감사 로그가 곧 사용자 규칙 사본이 된다 — IMAP `appendMessage.raw`와 같은 판단.
            await run(engine.opResult(auditOp("putScript", { script: a.name, bytes: a.content.length }, await backend.putScript(accountId, a.name, a.content))));
            break;
          }
          case "checkScript": {
            const check = backend.checkScript(a.content);
            // 저장하지 않는 검증 — 상태를 바꾸지 않으므로 크기만 남긴다.
            audit("checkScript", check.ok ? AUDIT_OUTCOME.ok : AUDIT_OUTCOME.denied, { bytes: a.content.length });
            await run(engine.opResult(check.ok ? { ok: true } : { ok: false, message: check.message }));
            break;
          }
          case "listScripts": {
            if (accountId === null) break;
            const scripts = await backend.listScripts(accountId);
            audit("listScripts", AUDIT_OUTCOME.ok, { scripts: scripts.length });
            await run(engine.listResult(scripts));
            break;
          }
          case "getScript": {
            if (accountId === null) break;
            const content = await backend.getScript(accountId, a.name);
            // 본문은 넣지 않는다(putScript와 같은 이유) — 이름·크기만.
            audit("getScript", content === null ? AUDIT_OUTCOME.denied : AUDIT_OUTCOME.ok, {
              script: a.name,
              ...(content === null ? {} : { bytes: content.length }),
            });
            await run(engine.getResult(content === null ? { ok: false } : { ok: true, content }));
            break;
          }
          case "deleteScript":
            if (accountId === null) break;
            await run(engine.opResult(auditOp("deleteScript", { script: a.name }, await backend.deleteScript(accountId, a.name))));
            break;
          case "setActive":
            if (accountId === null) break;
            // ★가장 중요한 한 줄. 활성 스크립트가 바뀌면 그 순간부터 **모든 수신 메일의 행방이
            //   달라진다**(redirect·discard). 이름이 빈 문자열이면 비활성화(RFC 5804 §2.8).
            await run(engine.opResult(auditOp("setActive", { script: a.name === "" ? "(none)" : a.name }, await backend.setActive(accountId, a.name))));
            break;
          case "renameScript":
            if (accountId === null) break;
            await run(engine.opResult(auditOp("renameScript", { from: a.from, to: a.to }, await backend.renameScript(accountId, a.from, a.to))));
            break;
        }
      }
    };

    const safeRun = (actions: ManageSieveAction[]): void => {
      run(actions).catch(() => {
        try {
          write('NO "internal error"');
        } catch {
          /* 소켓이 이미 죽음 */
        }
        if (!socket.destroyed) socket.destroy();
      });
    };

    const attachDataHandler = (s: net.Socket | TLSSocket): void => {
      s.on("data", (chunk: Buffer) => safeRun(engine.feed(chunk)));
      s.on("error", () => {
        /* 소켓 레벨 오류는 close로 수렴 — 여기선 프로세스 크래시 방지만 */
      });
    };

    const upgradeTls = async (): Promise<void> => {
      // ★반드시 currentTls를 읽는다 — 생성 시점 opts.tls를 읽으면 갱신된 인증서가 STARTTLS에
      //   영원히 반영되지 않는다(proto-smtp에서 실제로 만료 인증서를 계속 제시했던 자리).
      const tlsOpts = this.currentTls;
      if (!tlsOpts) {
        // 이미 OK를 보냈으므로 평문으로 되돌릴 수 없다 — 끊는 것이 유일한 안전한 처분.
        rawSocket.destroy();
        return;
      }
      // 업그레이드 전 raw 소켓의 data 리스너를 떼어 TLSSocket이 언더라잉 스트림을 단독 소비하게 함
      rawSocket.removeAllListeners("data");
      let tlsSocket: TLSSocket;
      try {
        tlsSocket = new TLSSocket(rawSocket, { isServer: true, key: tlsOpts.key, cert: tlsOpts.cert });
      } catch {
        // key/cert가 어긋나면 **동기 throw**다(BoringSSL/OpenSSL). 잡지 않으면 data 핸들러에서
        // 터져 프로세스가 죽는다. 이미 OK를 보냈으니 되돌릴 수 없으므로 연결을 끊는다.
        rawSocket.destroy();
        return;
      }
      socket = tlsSocket;
      attachDataHandler(tlsSocket);
      await new Promise<void>((resolve) => {
        tlsSocket.once("secure", () => resolve());
        tlsSocket.once("error", () => {
          tlsSocket.destroy();
          resolve();
        });
      });
      if (tlsSocket.destroyed) return;
      // RFC 5804 §2.2: 업그레이드 직후 능력 목록을 다시 보낸다(엔진이 만든다).
      await run(engine.tlsUpgraded());
    };

    attachDataHandler(rawSocket);
    rawSocket.on("timeout", () => {
      write('BYE "idle timeout"');
      if (!socket.destroyed) socket.end();
    });

    safeRun(engine.greeting());
  }
}
