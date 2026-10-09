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
  PREAUTH_DEADLINE_MS,
  PeerConnectionLimiter,
  SESSION_PROGRESS_INTERVAL_MS,
  SessionMeter,
  noopAuditSink,
  noopSessionReporter,
  normalizeIp,
  trackListener,
  type AuditSink,
  type ListenerShutdown,
  type ScramStoredKeys,
  type SessionReporter,
} from "@ionosphere/core";
import { ImapEngine, type ImapAction, type ImapBackendRequest, type ImapBackendResponse } from "./engine.ts";
import type { ImapCommandLabel } from "./command-label.ts";
import * as zlib from "node:zlib";

/** 명령 결과 — 태그 달린 응답의 상태(RFC 9051 §7.1). */
export type ImapCommandResult = "ok" | "no" | "bad";

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
  /**
   * 경고 로그 — 백엔드 예외와 BAD 원문 표본(`imap BAD 표본`)이 여기로 간다.
   * ★조립층이 넘기지 않으면 둘 다 조용히 사라진다. 2026-10-05까지 실제로 넘기지 않아, 백엔드 예외
   * 경고가 운영 journal에 한 번도 찍히지 않았다(app.ts).
   */
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
  /**
   * 세션 종료 요약 — 조립층이 **하나를 만들어** 모든 리스너에 넘긴다(core session-meter.ts).
   * 생략 시 남기지 않는다. 인증 전 마감은 이것과 무관하게 항상 걸린다.
   */
  sessions?: SessionReporter;
  /** 인증 전 마감(ms) — 테스트용 재정의. 기본 `PREAUTH_DEADLINE_MS`. */
  preauthDeadlineMs?: number;
  /**
   * 명령이 끝날 때마다(태그 달린 OK/NO/BAD) 알린다 — 메트릭 배선용(`ionosphere_imap_commands_total`).
   * `unparsed`는 파싱조차 못 해 태그 없이 `* BAD`로 답한 줄이다.
   * ★감사 이벤트는 백엔드 요청에만 남아 IDLE·NOOP·BAD 루프가 지표에 보이지 않았다(command-label.ts).
   */
  onCommandResult?: (command: ImapCommandLabel | "unparsed", result: ImapCommandResult) => void;
  /** 진행 중 세션 요약 주기(ms) — 테스트용 재정의. 기본 `SESSION_PROGRESS_INTERVAL_MS`, 0이면 끈다. */
  sessionProgressIntervalMs?: number;
  /** BAD 표본의 리스너당 상한(창당 줄 수) — 테스트용 재정의. 기본 `MAX_BAD_SAMPLES_PER_WINDOW`. */
  badSamplesPerWindow?: number;
}

/**
 * 결과를 기다리는 명령 수 상한 — 메모리 방어용 안전판이다.
 *
 * 엔진은 한 청크의 줄을 동기로 모두 처리하므로 대량 파이프라인이면 결과가 나가기 전에 명령이
 * 한꺼번에 쌓인다. 처음 256으로 잡았더니 NOOP 300개를 한 번에 보내면 44개 결과가 빠졌다(검수 재현).
 * 실제 상한은 입력 청크 크기·`MAX_QUEUED_LINE_BYTES`가 먼저 묶으므로 넉넉히 잡고, 넘치면 **가장
 * 오래된** 대기 항목을 밀어낸다(새 명령을 버리면 지금 도는 루프가 안 보인다).
 */
const MAX_PENDING_COMMANDS = 4096;
/** 태그 달린 완료 응답 — `tag OK|NO|BAD ...`. */
const TAGGED_RESULT = /^(\S+) (OK|NO|BAD)(?: |$)/;

/**
 * BAD 원문 표본(command-sample.ts)의 속도 상한 — journal을 BAD 루프의 증폭기로 만들지 않기 위해서다.
 *
 * 리스너당 상한이라 143·993을 함께 열면 합계는 두 배다.
 * ★두 겹인 이유: 세션당 상한만 두면 연결을 계속 새로 여는 상대가 줄 수를 무한히 늘린다. 리스너
 * 상한만 두면 BAD를 쏟는 세션 하나가 창을 다 써서 다른 클라이언트의 표본이 안 보인다.
 * 세션당 몇 줄이면 "무엇이 BAD인가"에 답하기 충분하다 — 같은 클라이언트는 같은 명령을 반복한다.
 */
const MAX_BAD_SAMPLES_PER_SESSION = 3;
const MAX_BAD_SAMPLES_PER_WINDOW = 30;
const BAD_SAMPLE_WINDOW_MS = 10 * 60 * 1000;
/** BAD 응답 문구의 최대 길이 — 엔진 문구는 짧지만 클라이언트 값을 되풀이하는 문구가 있을 수 있다. */
const MAX_BAD_REPLY_CHARS = 160;
/**
 * 백엔드 예외 경고("imap backend error")의 상한. 조립층이 logger를 넘기기 시작하면서(2026-10-05) 처음
 * 켜지는 경로다 — 장애 중 인증된 세션이 요청을 반복하면 BAD 예산과 무관하게 줄이 쏟아진다(독립 리뷰).
 * 예외 문구에는 외부 응답 본문(S3 오류 앞부분 등)이 섞일 수 있어 길이도 자른다.
 */
const MAX_BACKEND_ERRORS_PER_WINDOW = 30;
const MAX_BACKEND_ERROR_CHARS = 200;

/**
 * 리스너당 BAD 표본 예산 — 고정 창. 창 안에서 상한을 넘긴 줄은 버리고 수만 센다.
 * 버린 수는 다음 창의 첫 줄에 `suppressed`로 싣는다 — 조용히 사라지면 "BAD가 멎었다"로 읽힌다.
 */
export class BadSampleBudget {
  private windowStart = 0;
  private used = 0;
  private suppressed = 0;
  private readonly limit: number;
  constructor(limit: number) {
    this.limit = limit;
  }

  /** 쓸 수 있으면 직전 창에서 버린 수(없으면 0)를, 없으면 null을 돌려준다. */
  take(now: number): number | null {
    if (now - this.windowStart >= BAD_SAMPLE_WINDOW_MS) {
      this.windowStart = now;
      this.used = 0;
    }
    if (this.used >= this.limit) {
      this.suppressed++;
      return null;
    }
    this.used++;
    const dropped = this.suppressed;
    this.suppressed = 0;
    return dropped;
  }
}

/** 출력 가능한 ASCII만 남기고 자른다 — 남의 문자열이 섞여도 journal 줄을 깨거나 키우지 못하게. */
function cleanText(text: string, max: number): string {
  return text.slice(0, max).replace(/[^\x20-\x7e]/g, "?");
}

/** RFC 9051 §5.4 — 최소 30분 유휴 타임아웃. */
const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
/**
 * COMPRESS 세션에서 **푼 뒤** 누적 바이트 상한.
 *
 * 압축 해제는 증폭이라 작은 입력이 큰 출력이 된다(deflate 폭탄). 리더의 라인·리터럴 상한은
 * 푼 뒤에 걸리므로 그 앞에서 끊어야 한다. 한 세션이 정상적으로 주고받는 양보다 넉넉하되
 * 프로세스 메모리를 위협하지 않는 값이다.
 */
const MAX_INFLATED_BYTES = 512 * 1024 * 1024;
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
    // 쿼터 조회는 대상도 규모도 없다 — 남길 detail이 없다.
    case "getQuota":
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
    case "getAcl":
    case "myRights":
      return { detail: { mailbox: req.name } };
    case "setAcl":
    case "deleteAcl":
    case "listRights":
      return { detail: { mailbox: req.name, identifier: req.identifier } };
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
    case "replaceMessage":
      // 넣기와 지우기가 함께 도는 명령이라 **양쪽 메일함과 지워질 uid**를 남긴다 —
      // 사본이 남는 실패 모드를 사후에 추적할 수 있어야 한다.
      return { detail: { from: req.from, to: req.to, oldUid: req.oldUid, bytes: req.raw.byteLength } };
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
  /** BAD 표본 리스너당 예산 — 리스너(143·993)마다 하나다. */
  private readonly badSamples: BadSampleBudget;
  /** 백엔드 예외 경고 예산 — 같은 고정 창 방식, BAD 표본과 따로 센다. */
  private readonly backendErrors = new BadSampleBudget(MAX_BACKEND_ERRORS_PER_WINDOW);

  constructor(opts: ImapServerOptions) {
    this.opts = opts;
    // 조립층이 넘긴 공유 인스턴스를 쓴다(M-4). 단독 사용 시에만 자체 인스턴스.
    this.authThrottle = opts.authThrottle ?? new AuthFailureThrottle();
    this.peerLimit = opts.peerLimit ?? new PeerConnectionLimiter();
    this.audit = opts.audit ?? noopAuditSink;
    this.badSamples = new BadSampleBudget(opts.badSamplesPerWindow ?? MAX_BAD_SAMPLES_PER_WINDOW);
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

    /**
     * 결과를 아직 못 본 명령 — 태그별 **FIFO**. 같은 태그를 다시 쓰는 클라이언트가 있다(RFC는
     * SHOULD NOT일 뿐). 태그당 하나만 들면, 앞 명령의 응답이 나가기 전에 큐에 있던 같은 태그 명령이
     * 들어와 덮어써 결과가 엉뚱한 명령에 붙었다(검수 재현: LIST 결과가 NOOP으로 집계).
     */
    type PendingCommand = { label: ImapCommandLabel; sample: string };
    const pendingTags = new Map<string, PendingCommand[]>();
    let pendingCount = 0;
    const onCommandResult = this.opts.onCommandResult;
    const rememberPending = (tag: string, entry: PendingCommand): void => {
      if (pendingCount >= MAX_PENDING_COMMANDS) {
        // 가장 먼저 들어온 **태그**의 첫 항목을 민다(Map은 태그 삽입 순서를 지킨다). 전체에서 가장 오래된
        // 명령과 다를 수 있어, 상한을 넘긴 채 태그를 재사용하면 결과가 어긋날 수 있다 — 정상 트래픽은
        // 4096에 닿지 않으므로 정확한 전역 순서를 위해 구조를 키우지 않았다.
        const oldest = pendingTags.keys().next();
        if (!oldest.done) {
          const q = pendingTags.get(oldest.value)!;
          q.shift();
          pendingCount--;
          if (q.length === 0) pendingTags.delete(oldest.value);
        }
      }
      const q = pendingTags.get(tag);
      if (q) q.push(entry);
      else pendingTags.set(tag, [entry]);
      pendingCount++;
    };

    const engine = new ImapEngine({
      // 명령마다 센다 — meter는 아래에서 만들지만 이 콜백은 데이터가 들어온 뒤에만 불린다.
      onCommand: (tag, label, summaryName, sample) => {
        meter.command(label);
        if (label === "unknown") meter.unknownCommand(summaryName);
        // 태그에 `*`·`%`는 파서가 거부한다(parser.ts) — 여기까지 오는 태그는 untagged 줄과 헷갈리지 않는다.
        rememberPending(tag, { label, sample });
      },
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

    /**
     * COMPRESS=DEFLATE (RFC 4978) 상태. 켜지면 나가는 바이트는 `deflate`를, 들어오는
     * 바이트는 `inflate`를 거친다.
     *
     * ★`Z_SYNC_FLUSH`가 이 기능의 **고전적 버그**다. 스트림 압축은 기본적으로 블록이 찰
     * 때까지 출력을 모으는데, IMAP은 서버가 한 줄 보내고 클라이언트 응답을 기다리는
     * 대화형이라 그 버퍼링이 곧 **양쪽이 서로를 기다리는 교착**이 된다. 쓸 때마다 flush해야
     * 한다 — 압축률을 조금 잃고 프로토콜을 얻는 교환이다.
     */
    let deflate: zlib.DeflateRaw | null = null;
    let inflate: zlib.InflateRaw | null = null;

    const write = (bytes: Uint8Array): void => {
      if (socket.destroyed) return;
      if (deflate === null) {
        socket.write(bytes);
        return;
      }
      deflate.write(Buffer.from(bytes));
      deflate.flush(zlib.constants.Z_SYNC_FLUSH);
    };
    const writeText = (text: string): void => write(new TextEncoder().encode(`${text}\r\n`));

    /**
     * BAD 원문 표본 한 줄(command-sample.ts). 세션당·리스너당 상한 안에서만 남긴다.
     * 계정과 주소를 함께 싣는다 — "어느 클라이언트가"를 세션 요약 줄과 맞춰 볼 수 있게.
     * `suppressed`는 **리스너 예산**에 막혀 버린 수만 센다 — 세션당 상한을 넘긴 반복은 같은 클라이언트의
     * 같은 BAD라 세지 않는다(그 양은 imap_commands_total에 있다).
     * 한계: 대기 명령이 MAX_PENDING_COMMANDS를 넘겨 밀려나면 그 태그의 다음 응답이 다음 표본과 짝지어질
     * 수 있다(결과 집계와 같은 한계). 같은 세션의 명령끼리라 누출은 아니고, 정상 트래픽은 닿지 않는다.
     */
    let badSamplesLeft = MAX_BAD_SAMPLES_PER_SESSION;
    const logBadSample = (command: ImapCommandLabel | "unparsed", sample: string | null, reply: string): void => {
      const logger = this.opts.logger;
      if (!logger || badSamplesLeft <= 0) return;
      const dropped = this.badSamples.take(Date.now());
      if (dropped === null) return;
      badSamplesLeft--;
      logger.warn("imap BAD 표본", {
        command,
        ...(sample !== null ? { sample } : {}),
        reply: cleanText(reply, MAX_BAD_REPLY_CHARS),
        ip: normalizeIp(rawSocket.remoteAddress),
        ...(accountId !== null ? { accountId } : {}),
        ...(dropped > 0 ? { suppressed: dropped } : {}),
      });
    };

    /** 나가는 줄에서 명령 완료를 읽는다 — 결과(ok/no/bad)는 태그 달린 응답에만 있다. */
    const observeReply = (text: string): void => {
      // untagged·continuation 줄은 결과가 아니다('+'는 파서가 태그로 받지 않는다. '*' 태그는 위 한계 참조).
      const first = text.charCodeAt(0);
      if (first === 42 /* * */) {
        // `* BAD`는 파싱 전에 거절된 줄 — 파싱 실패 또는 리더 한도 초과(줄·리터럴이 너무 큼).
        if (text.startsWith("* BAD ")) {
          meter.command("unparsed");
          onCommandResult?.("unparsed", "bad");
          // 파싱 전에 거절돼 원문 모양이 없다 — 응답 문구(무엇이 깨졌는지)만 남긴다.
          logBadSample("unparsed", null, text.slice("* BAD ".length));
        }
        return;
      }
      if (first === 43 /* + */) return;
      const m = TAGGED_RESULT.exec(text);
      if (!m) return;
      const q = pendingTags.get(m[1]!);
      const entry = q?.shift();
      if (entry === undefined) return;
      pendingCount--;
      if (q!.length === 0) pendingTags.delete(m[1]!);
      const result = m[2]!.toLowerCase() as ImapCommandResult;
      onCommandResult?.(entry.label, result);
      if (result === "bad") logBadSample(entry.label, entry.sample, text.slice(m[0].length));
    };

    const meter = new SessionMeter({
      surface: AUDIT_SURFACE.imap,
      socket: rawSocket,
      reporter: this.opts.sessions ?? noopSessionReporter,
      countCommands: true,
      progressIntervalMs: this.opts.sessionProgressIntervalMs ?? SESSION_PROGRESS_INTERVAL_MS,
      preauthDeadlineMs: this.opts.preauthDeadlineMs ?? PREAUTH_DEADLINE_MS,
      onPreauthDeadline: () => {
        writeText("* BYE login timeout");
        if (!socket.destroyed) socket.end();
      },
    });

    const runActions = async (actions: ImapAction[]): Promise<void> => {
      for (const action of actions) {
        switch (action.kind) {
          case "reply":
            observeReply(action.text);
            writeText(action.text);
            break;
          case "replyBinary":
            write(action.bytes);
            break;
          case "startTls":
            await upgradeTls();
            break;
          case "startCompress":
            startCompress();
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
            // ★백엔드를 기다리는 사이 인증 전 마감이 발동했으면 결과를 버린다 — 연결은 이미 끊기는
            //   중이고 여기서 재개하면 닫힌 세션이 계정 상태로 넘어간다(코드 검수 지적).
            if (meter.deadlinePassed) break;
            meter.attempted(action.user);
            if (ok) {
              accountId = ok.accountId;
              meter.authenticated(ok.accountId);
              this.authThrottle.clear(ip);
            } else {
              meter.authFailed();
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
            meter.attempted(action.user);
            meter.authFailed();
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
            meter.attempted(action.user);
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
              meter.authFailed();
              await runActions(engine.authResult(null));
              break;
            }
            const result = await backend.authenticate(action.user, action.pass);
            // ★백엔드를 기다리는 사이 인증 전 마감이 발동했으면 결과를 버린다 — 연결은 이미 끊기는
            //   중이고 여기서 재개하면 닫힌 세션이 계정 상태로 넘어간다(코드 검수 지적).
            if (meter.deadlinePassed) break;
            if (result) {
              accountId = result.accountId;
              meter.authenticated(result.accountId);
              this.authThrottle.clear(ip);
            } else {
              meter.authFailed();
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
            meter.request();
            let res: ImapBackendResponse;
            try {
              res = await backend.request(accountId, action.req);
            } catch (err) {
              const dropped = this.opts.logger ? this.backendErrors.take(Date.now()) : null;
              if (dropped !== null) {
                this.opts.logger?.warn("imap backend error", {
                  error: cleanText(err instanceof Error ? err.message : String(err), MAX_BACKEND_ERROR_CHARS),
                  ...(dropped > 0 ? { suppressed: dropped } : {}),
                });
              }
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

    /**
     * 압축을 켠다 — **이 시점 이후의** 바이트에만 적용된다(태그 OK는 이미 평문으로 나갔다).
     *
     * ★`inflate`에도 상한이 필요하다. 압축 해제는 **증폭**이라 작은 입력이 큰 출력이 되고
     * (deflate 폭탄), 상한이 없으면 인증된 사용자 하나가 프로세스 메모리를 채운다.
     * 리더의 라인·리터럴 상한은 **푼 뒤**에 걸리므로 그 앞에서 끊어야 한다.
     */
    const startCompress = (): void => {
      if (deflate !== null) return;
      const d = zlib.createDeflateRaw({ level: zlib.constants.Z_DEFAULT_COMPRESSION });
      const i = zlib.createInflateRaw();
      d.on("data", (chunk: Buffer) => {
        if (!socket.destroyed) socket.write(chunk);
      });
      // 스트림 오류는 회선을 못 쓰게 만든다 — 되살릴 방법이 없으므로 끊는다.
      d.on("error", () => socket.destroy());
      i.on("error", () => socket.destroy());
      let inflated = 0;
      i.on("data", (chunk: Buffer) => {
        inflated += chunk.length;
        if (inflated > MAX_INFLATED_BYTES) {
          socket.destroy();
          return;
        }
        safeRun(engine.feed(chunk));
      });
      deflate = d;
      inflate = i;
    };

    const attachData = (s: net.Socket | tls.TLSSocket): void => {
      s.on("data", (chunk: Buffer) => {
        meter.read();
        // 압축이 켜졌으면 **푼 뒤에** 엔진으로 간다.
        if (inflate !== null) inflate.write(chunk);
        else safeRun(engine.feed(chunk));
      });
    };
    attachData(rawSocket);
    socket.on("timeout", () => {
      meter.idleTimedOut();
      writeText("* BYE idle timeout");
      if (!socket.destroyed) socket.end();
    });
    socket.on("error", () => {
      // 연결 오류 — 세션 종료 외 처리 없음(잠금류 자원 없음)
    });
    socket.on("close", () => {
      if (idlePoller) clearInterval(idlePoller);
      // 스트림을 남기면 이벤트 루프에 핸들이 남아 종료가 늦어진다.
      deflate?.destroy();
      inflate?.destroy();
    });

    safeRun(engine.greeting());
  }
}
