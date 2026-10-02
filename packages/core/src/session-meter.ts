/**
 * 연결 세션 계측 — 인증 전 마감 + 세션 종료 요약. 소켓 프로토콜 어댑터(IMAP·POP3·ManageSieve) 공용.
 *
 * ★왜 필요한가(2026-09-30 사서함 호스트 조사): 993/995에 **바이트를 거의 주고받지 않는 연결
 * 161개**가 붙어 있었고, 같은 기간 IMAP 트래픽이 하루 1 GB로 튀었는데 그 정체를 끝까지
 * 특정하지 못했다. 원인은 둘이었다.
 *  1. 인증 전 연결에도 인증 후와 같은 유휴 타임아웃(IMAP 30분·POP3 10분)을 줬다. 그 사이에
 *     NOOP 한 줄씩만 보내면 연결을 무기한 붙들 수 있다.
 *  2. journal에는 `auth ok`만 남았다. 감사 카운터는 42만 건을 셌지만 **어느 계정·어느 주소가
 *     얼마를 옮겼는지** 되짚을 줄이 없었고, 연결별 바이트 계수는 소켓과 함께 사라졌다.
 *
 * 세 어댑터에 손으로 따로 넣으면 한쪽이 빠진다(이 저장소의 반복 사고). 그래서 여기서 한 번 정의하고
 * 어댑터는 `authenticated()`·`request()` 같은 사건만 알린다.
 */
import type * as net from "node:net";
import type { AuditSurface } from "./audit.ts";
import { normalizeIp } from "./auth-throttle.ts";
import { noopLogger, type Logger } from "./log.ts";

/** 세션이 끝난 이유 — 메트릭 라벨로도 쓰이므로 값 집합을 닫아 둔다. */
export const SESSION_CLOSE_REASON = {
  /** 상대가 끊었거나 정상 로그아웃. */
  closed: "closed",
  /** 인증 후 유휴 타임아웃. */
  idle: "idle",
  /** 인증 전 마감(`PREAUTH_DEADLINE_MS`)을 넘겼다. */
  preauth: "preauth",
} as const;
export type SessionCloseReason = (typeof SESSION_CLOSE_REASON)[keyof typeof SESSION_CLOSE_REASON];

export interface SessionSummary {
  surface: AuditSurface;
  ip: string;
  /** 마지막으로 시도한 사용자명 — 인증에 실패한 세션도 누구를 노렸는지 남긴다. */
  user?: string;
  /** 인증에 성공했을 때만 있다. */
  accountId?: string;
  /** 인증 뒤 백엔드 요청 수 — 감사 이벤트 수와 같은 단위라 서로 대조할 수 있다. */
  requests: number;
  /**
   * 받은 명령 수(백엔드를 부르지 않는 명령 포함). **명령을 세는 표면(IMAP)에서만** 있다.
   * `requests`와 따로 두는 이유(2026-10-01): IDLE/DONE·NOOP·BAD 루프는 백엔드를 부르지 않아
   * `requests`가 0에 가까운데 회선은 초당 수십 번 왕복했다 — 둘의 차이가 곧 그 신호다.
   */
  commands?: number;
  /**
   * 명령 라벨별 횟수(0은 생략). 라벨은 표면이 정한 **닫힌 집합**이라 크기가 유계다.
   * ★2026-10-01: 118 MB를 옮긴 세션들의 `requests`가 합 36이었다 — 무엇이 옮겼는지 이 분포가 답한다.
   */
  commandCounts?: Record<string, number>;
  /**
   * 엔진이 모르는 명령 이름 표본(세션당 최대 `MAX_UNKNOWN_SAMPLES`개, 정제·절단). **로그 전용**이다 —
   * 메트릭 라벨로 쓰면 상대가 아무 문자열로 라벨을 무한히 늘린다. "어떤 명령이 BAD로 도는가"의 답.
   */
  unknownCommands?: string[];
  /**
   * 소켓에서 데이터를 읽은 횟수(명령을 세는 표면에서만). 2026-10-01 루프 소켓은 바이트도 명령도
   * 작은데 **왕복 횟수만** 컸다 — 명령으로 세어지지 않는 작은 쓰기까지 이 값이 잡는다.
   */
  reads?: number;
  /**
   * 태그에 `*`·`%`를 쓴 명령 수(RFC 9051상 태그에 올 수 없는 문자). 지금은 **거부하지 않고 센다** —
   * 거부는 새 BAD 경로라 "BAD를 받으면 재시도하는 루프" 가설과 같은 방향으로 작동할 수 있다.
   * 실제로 쓰는 클라이언트가 있는지 이 값으로 본 뒤 정한다(관측기와 관측 대상을 한 배포에 섞지 않는다).
   */
  wildcardTags?: number;
  authFailures: number;
  /**
   * 연결 시점 소켓이 읽고 쓴 바이트 — **리스너마다 단위가 다르다**:
   *  - 암시적 TLS(993·995): 복호화된 평문(node `TLSSocket`의 계수).
   *  - 평문 리스너에서 STARTTLS한 세션(143·110·4190): 업그레이드 뒤로는 TLS 레코드·핸드셰이크 포함.
   *  - IMAP COMPRESS 세션: 켜진 뒤로는 압축된 바이트.
   * "누가 얼마나 옮겼나"의 규모를 가리는 용도다. 세션끼리 정밀 비교할 값은 아니다.
   */
  bytesIn: number;
  bytesOut: number;
  durationMs: number;
  reason: SessionCloseReason;
}

/**
 * 살아 있는 세션의 중간 요약 — 누계(SessionSummary의 값)에 **이번 주기의 증분**을 더한다.
 *
 * ★왜 필요한가(2026-10-01): 종료 요약은 소켓이 닫힐 때만 나온다. 며칠씩 열린 채 초당 수십 번
 * 왕복하는 세션은 끝날 때까지 journal에 아무것도 없었고, 커널 소켓 계수는 소켓과 함께 사라져
 * 09-29 조사가 거기서 막혔다. 주기마다 한 줄이면 "지금 누가 얼마나"를 볼 수 있다.
 */
export interface SessionProgress extends Omit<SessionSummary, "reason"> {
  intervalMs: number;
  /** 이번 주기에 받은 명령 수(명령을 세는 표면에서만). IDLE은 들어갈 때 하나, DONE은 명령이 아니다. */
  commandsDelta?: number;
  /** 이번 주기의 읽기 횟수(명령을 세는 표면에서만). */
  readsDelta?: number;
  bytesInDelta: number;
  bytesOutDelta: number;
}

/** 요약을 받아 내보내는 쪽 — 조립층이 **하나를 만들어** 모든 리스너에 넘긴다(authThrottle과 같은 이유). */
export interface SessionReporter {
  report(summary: SessionSummary): void;
  /** 진행 중 요약 — 없으면 보내지 않는다(기존 구현과 테스트 스텁이 그대로 동작하게). */
  progress?(summary: SessionProgress): void;
}

export const noopSessionReporter: SessionReporter = { report: () => {} };

/** 진행 중 요약 주기 기본값. 2026-10-01에 본 반복 주기(약 11.5분)보다 짧아야 그 모양이 줄마다 보인다. */
export const SESSION_PROGRESS_INTERVAL_MS = 10 * 60 * 1000;

/**
 * 진행 줄을 남길 최소 증분 — 이 아래면 그 주기는 건너뛴다.
 *
 * ★문턱이 없으면 정상 세션도 줄을 남긴다(검수 지적): IDLE 클라이언트는 서버 유휴 타임아웃(30분)
 * 전에 DONE/IDLE을 다시 보내고, 몇 분마다 NOOP으로 폴링하는 클라이언트도 있고, 새 메일 푸시도
 * 바이트를 움직인다. 그 정도는 주기당 명령 몇 개·수십 KB다. 보려는 것은 초당 수십 번 도는 루프
 * (주기당 수만 명령)와 주기마다 MB 단위로 옮기는 세션이라, 두 문턱 중 하나만 넘어도 남긴다.
 */
export const SESSION_PROGRESS_MIN_COMMANDS = 30;
/** 바이트 갈래는 **in+out 합**으로 본다. */
export const SESSION_PROGRESS_MIN_BYTES = 1024 * 1024;
/**
 * 읽기 횟수 갈래 — 주기당 600회(평균 초당 1회). 바이트·명령 갈래만으로는 2026-10-01 루프 소켓
 * 하나(10분에 0.93 MiB, 명령인지 불분명한 11바이트 세그먼트를 초당 수십 회)를 놓쳤다(stardust 실측).
 * 정상 IDLE 세션의 읽기는 주기당 몇 회다.
 */
export const SESSION_PROGRESS_MIN_READS = 600;

/** 세션당 남길 모르는 명령 이름 표본 수와 이름 길이 — 로그 한 줄이 상대 입력으로 부풀지 않게. */
const MAX_UNKNOWN_SAMPLES = 5;
const MAX_UNKNOWN_NAME_CHARS = 32;

/**
 * 로그 한 줄 + 선택적 훅(메트릭 배선용). 훅으로 받는 이유는 `AuditFileSink.onRecord`와 같다 —
 * core가 @ionosphere/metrics를 알지 않아도 계측이 붙는다.
 *
 * ★세션마다 **닫힐 때 한 줄**이다. 명령마다 찍으면 IMAP 동기화 한 번이 수천 줄이 되고,
 * 그 볼륨은 이미 감사 파일이 감당한다. journal에 필요한 것은 "누가 어디서 얼마나"의 요약이다.
 */
export function createLogSessionReporter(logger: Logger, onReport?: (s: SessionSummary) => void): SessionReporter {
  const log = logger.child({ component: "session" });
  return {
    report(s) {
      log.info("세션 종료", { ...s });
      onReport?.(s);
    },
    progress(s) {
      // 메트릭 훅은 부르지 않는다 — sessions_total은 **닫힌** 세션 수다. 진행 줄이 세어지면 두 번 센다.
      log.info("세션 진행", { ...s });
    },
  };
}

/**
 * 작별 인사(`end()`) 뒤 강제 종료까지의 유예.
 *
 * ★`end()`는 FIN만 보내는 반쪽 닫기다. 상대가 FIN을 무시하면 소켓이 `readOnly`로 남아 `close`가
 * 오지 않고, IP당 상한·리스너 상한 자리도 풀리지 않는다 — 마감이 막으려던 점유가 그대로 남는다
 * (POP3는 유휴 타이머의 `finish()`가 이미 끝난 것으로 보고 반환해 **무기한**이었다, 코드 검수에서 재현).
 * 정상 클라이언트는 FIN을 받으면 곧 닫으므로 몇 초면 충분하다.
 */
const CLOSE_GRACE_MS = 5_000;

export interface SessionMeterOptions {
  surface: AuditSurface;
  /** 연결 시점의 소켓. STARTTLS로 바뀌어도 이 소켓의 `close`가 곧 세션 종료다. */
  socket: net.Socket;
  reporter: SessionReporter;
  /** 인증 전 마감(ms). 0이면 걸지 않는다. */
  preauthDeadlineMs: number;
  /** 마감이 지났을 때 — 어댑터가 프로토콜에 맞는 작별 인사를 하고 끊는다. */
  onPreauthDeadline: () => void;
  now?: () => number;
  /** 강제 종료 유예(ms) — 테스트용 재정의. */
  closeGraceMs?: number;
  /** 명령 수를 센다(`command()` 호출). 이 표면만 요약에 `commands`가 들어간다. */
  countCommands?: boolean;
  /** 진행 중 요약 주기(ms). 0이거나 없으면 보내지 않는다. */
  progressIntervalMs?: number;
  /** 진행 줄 문턱 — 테스트용 재정의. 기본 `SESSION_PROGRESS_MIN_COMMANDS`·`SESSION_PROGRESS_MIN_BYTES`. */
  progressMinCommands?: number;
  progressMinBytes?: number;
  progressMinReads?: number;
}

export class SessionMeter {
  private readonly opts: SessionMeterOptions;
  private readonly startedAt: number;
  private readonly now: () => number;
  private deadline: ReturnType<typeof setTimeout> | null = null;
  private grace: ReturnType<typeof setTimeout> | null = null;
  private expired = false;
  private user: string | undefined;
  private accountId: string | undefined;
  private requests = 0;
  private authFailures = 0;
  private reason: SessionCloseReason = SESSION_CLOSE_REASON.closed;
  private reported = false;
  private commands = 0;
  private readonly commandCounts = new Map<string, number>();
  private readonly unknownSamples = new Set<string>();
  private reads = 0;
  private wildcardTags = 0;
  private progressTimer: ReturnType<typeof setInterval> | null = null;
  /** 지난 진행 요약 시점의 누계 — 증분 계산용. */
  private lastProgress = { commands: 0, reads: 0, bytesIn: 0, bytesOut: 0 };

  constructor(opts: SessionMeterOptions) {
    this.opts = opts;
    this.now = opts.now ?? Date.now;
    this.startedAt = this.now();
    if (opts.preauthDeadlineMs > 0) {
      /**
       * ★유휴 타이머가 아니라 **절대 마감**이다. 유휴 타이머는 NOOP 한 줄로 계속 연장되므로
       * 인증하지 않고 버티는 연결을 막지 못한다. 정상 클라이언트는 접속 직후 인증하므로
       * 활동 여부와 무관하게 "접속부터 인증까지"를 재는 쪽이 오탐 없이 좁다.
       */
      this.deadline = setTimeout(() => {
        this.deadline = null;
        this.expired = true;
        this.reason = SESSION_CLOSE_REASON.preauth;
        opts.onPreauthDeadline();
        this.forceCloseAfterGrace();
      }, opts.preauthDeadlineMs);
      this.deadline.unref?.();
    }
    const every = opts.progressIntervalMs ?? 0;
    if (every > 0 && opts.reporter.progress) {
      this.progressTimer = setInterval(() => this.reportProgress(every), every);
      this.progressTimer.unref?.();
    }
    opts.socket.once("close", () => this.finish());
  }

  /** 명령 하나를 받았다. `label`은 표면이 정한 닫힌 집합의 값이어야 한다(사용자 입력 그대로 금지). */
  command(label: string): void {
    this.commands++;
    this.commandCounts.set(label, (this.commandCounts.get(label) ?? 0) + 1);
  }

  /** 소켓에서 데이터를 한 번 읽었다(명령 경계와 무관 — 작은 왕복 횟수를 잡는다). */
  read(): void {
    this.reads++;
  }

  /** 태그에 `*`·`%`가 든 명령을 받았다(RFC 위반이지만 거부하지 않고 센다 — 필드 주석 참조). */
  wildcardTag(): void {
    this.wildcardTags++;
  }

  /** 엔진이 모르는 명령 이름을 표본으로 남긴다 — 정제(대문자·영숫자와 `-_.`만)·절단하고 개수를 묶는다. */
  unknownCommand(raw: string): void {
    if (this.unknownSamples.size >= MAX_UNKNOWN_SAMPLES) return;
    const clean = raw.toUpperCase().replace(/[^A-Z0-9_.-]/g, "?").slice(0, MAX_UNKNOWN_NAME_CHARS);
    if (clean.length > 0) this.unknownSamples.add(clean);
  }

  /** 누계 필드 — 종료 요약과 진행 요약이 같은 모양을 쓰게 한 곳에서 만든다. */
  private totals(): Omit<SessionSummary, "reason"> {
    const s = this.opts.socket;
    return {
      surface: this.opts.surface,
      ip: normalizeIp(s.remoteAddress),
      ...(this.user !== undefined ? { user: this.user } : {}),
      ...(this.accountId !== undefined ? { accountId: this.accountId } : {}),
      requests: this.requests,
      ...(this.opts.countCommands
        ? { commands: this.commands, commandCounts: Object.fromEntries([...this.commandCounts].sort(([a], [b]) => a.localeCompare(b))) }
        : {}),
      ...(this.unknownSamples.size > 0 ? { unknownCommands: [...this.unknownSamples] } : {}),
      ...(this.opts.countCommands ? { reads: this.reads } : {}),
      ...(this.wildcardTags > 0 ? { wildcardTags: this.wildcardTags } : {}),
      authFailures: this.authFailures,
      bytesIn: s.bytesRead,
      bytesOut: s.bytesWritten,
      durationMs: this.now() - this.startedAt,
    };
  }

  private reportProgress(intervalMs: number): void {
    if (this.reported) return;
    const t = this.totals();
    const commandsDelta = this.commands - this.lastProgress.commands;
    const readsDelta = this.reads - this.lastProgress.reads;
    const bytesInDelta = t.bytesIn - this.lastProgress.bytesIn;
    const bytesOutDelta = t.bytesOut - this.lastProgress.bytesOut;
    this.lastProgress = { commands: this.commands, reads: this.reads, bytesIn: t.bytesIn, bytesOut: t.bytesOut };
    // 문턱 아래 주기는 건너뛴다(위 SESSION_PROGRESS_MIN_* 주석) — 정상 세션이 주기마다 줄을 쏟지 않게.
    const minCommands = this.opts.progressMinCommands ?? SESSION_PROGRESS_MIN_COMMANDS;
    const minBytes = this.opts.progressMinBytes ?? SESSION_PROGRESS_MIN_BYTES;
    const busyCommands = this.opts.countCommands === true && commandsDelta >= minCommands;
    const busyBytes = bytesInDelta + bytesOutDelta >= minBytes;
    const busyReads = this.opts.countCommands === true && readsDelta >= (this.opts.progressMinReads ?? SESSION_PROGRESS_MIN_READS);
    if (!busyCommands && !busyBytes && !busyReads) return;
    this.opts.reporter.progress?.({
      ...t,
      intervalMs,
      ...(this.opts.countCommands ? { commandsDelta, readsDelta } : {}),
      bytesInDelta,
      bytesOutDelta,
    });
  }

  /** 인증 시도(성공·실패 무관) — 사용자명을 요약에 남기기 위해. */
  attempted(user: string | undefined): void {
    if (user) this.user = user;
  }

  authFailed(): void {
    this.authFailures++;
  }

  /**
   * 마감이 이미 지났는가 — 백엔드 인증을 기다리는 사이 마감이 발동할 수 있다. 그 뒤 도착한
   * 성공은 **받아들이지 않아야** 한다(연결은 이미 끊기는 중이고, POP3는 maildrop 잠금을 잡으면
   * 풀어 줄 세션이 없다).
   */
  get deadlinePassed(): boolean {
    return this.expired;
  }

  /** 인증 성공 — 마감을 풀고 계정을 기록한다. 마감 뒤 도착한 성공은 무시한다. */
  authenticated(accountId: string): void {
    if (this.expired) return;
    this.accountId = accountId;
    if (this.deadline) {
      clearTimeout(this.deadline);
      this.deadline = null;
    }
  }

  request(): void {
    this.requests++;
  }

  /**
   * 유휴 타임아웃으로 끊을 때 어댑터가 부른다. 강제 종료 유예도 함께 건다.
   * ★먼저 기록된 사유를 덮지 않는다 — 마감으로 끊긴 연결에 뒤늦게 유휴 타이머가 돌면
   * `preauth`가 `idle`로 바뀌어 정작 사고 유형이 과소 집계된다.
   */
  idleTimedOut(): void {
    if (this.reason === SESSION_CLOSE_REASON.closed) this.reason = SESSION_CLOSE_REASON.idle;
    this.forceCloseAfterGrace();
  }

  private forceCloseAfterGrace(): void {
    if (this.grace || this.reported) return;
    this.grace = setTimeout(() => {
      this.grace = null;
      // raw 소켓을 부수면 그 위의 TLSSocket도 함께 닫힌다.
      if (!this.opts.socket.destroyed) this.opts.socket.destroy();
    }, this.opts.closeGraceMs ?? CLOSE_GRACE_MS);
    this.grace.unref?.();
  }

  private finish(): void {
    if (this.reported) return;
    this.reported = true;
    if (this.deadline) {
      clearTimeout(this.deadline);
      this.deadline = null;
    }
    if (this.grace) {
      clearTimeout(this.grace);
      this.grace = null;
    }
    if (this.progressTimer) {
      clearInterval(this.progressTimer);
      this.progressTimer = null;
    }
    this.opts.reporter.report({ ...this.totals(), reason: this.reason });
  }
}
