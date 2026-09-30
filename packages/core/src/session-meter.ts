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

/** 요약을 받아 내보내는 쪽 — 조립층이 **하나를 만들어** 모든 리스너에 넘긴다(authThrottle과 같은 이유). */
export interface SessionReporter {
  report(summary: SessionSummary): void;
}

export const noopSessionReporter: SessionReporter = { report: () => {} };

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
    opts.socket.once("close", () => this.finish());
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
    const s = this.opts.socket;
    this.opts.reporter.report({
      surface: this.opts.surface,
      ip: normalizeIp(s.remoteAddress),
      ...(this.user !== undefined ? { user: this.user } : {}),
      ...(this.accountId !== undefined ? { accountId: this.accountId } : {}),
      requests: this.requests,
      authFailures: this.authFailures,
      bytesIn: s.bytesRead,
      bytesOut: s.bytesWritten,
      durationMs: this.now() - this.startedAt,
      reason: this.reason,
    });
  }
}
