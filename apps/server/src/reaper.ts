/**
 * 메일함 삭제 2단계 리퍼(§7-7) — 툼스톤(status=2) 메일함을 주기적으로 수거.
 * deleteMailbox는 1단계(툼스톤)만 하고, 실제 membership/메시지 정리·행 하드삭제는 여기서.
 * WebhookWorker/MtaWorker와 동형(interval + 재진입 가드 + 수동 tick).
 */
import { noopLogger, type Logger } from "@ionosphere/core";
import type { Store } from "@ionosphere/store";

export interface MailboxReaperOptions {
  store: Store;
  logger?: Logger;
  /** 폴링 주기(ms). 기본 5분. */
  intervalMs?: number;
  /** 한 tick에 처리할 최대 메일함 수. 기본 50. */
  batchSize?: number;
  /**
   * maildrop 락 — 지정 시 만료된 지 오래된 락 행을 함께 정리한다.
   *
   * 왜 리퍼가 하는가: `acquire`는 만료 락을 덮어쓰므로 **다시 로그인하는 계정의 행은 누수가
   * 아니다**. 문제는 다시 로그인하지 않는 계정(폐기·이전)의 행이고, 그건 주기적 정리 담당이
   * 치우는 게 맞다. 리퍼가 이미 "주기적으로 남은 것을 치우는" 역할이라 여기 둔다.
   */
  maildropLock?: { sweepExpired(now?: number, graceMs?: number): Promise<number> };
}

const DEFAULT_INTERVAL_MS = 5 * 60 * 1000;

export class MailboxReaper {
  private readonly store: Store;
  private readonly log: Logger;
  private readonly intervalMs: number;
  private readonly batchSize: number;
  private readonly maildropLock?: { sweepExpired(now?: number, graceMs?: number): Promise<number> };
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  constructor(opts: MailboxReaperOptions) {
    this.store = opts.store;
    this.log = (opts.logger ?? noopLogger).child({ component: "reaper" });
    this.intervalMs = opts.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.batchSize = opts.batchSize ?? 50;
    if (opts.maildropLock) this.maildropLock = opts.maildropLock;
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), this.intervalMs);
    this.timer.unref?.();
  }

  async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    while (this.running) await new Promise((r) => setTimeout(r, 10));
  }

  /** 한 사이클(수동 구동 가능) — 수거한 메일함 수 반환. */
  async tick(): Promise<number> {
    if (this.running) return 0;
    this.running = true;
    try {
      const targets = await this.store.listReapableMailboxes(this.batchSize);
      let reaped = 0;
      for (const t of targets) {
        try {
          const r = await this.store.reapMailbox(t.accountId, t.id);
          reaped++;
          if (r.purged > 0 || r.detached > 0) {
            this.log.info("mailbox reaped", { mailboxId: t.id, purged: r.purged, detached: r.detached });
          }
        } catch (err) {
          this.log.warn("reap failed", { mailboxId: t.id, error: err instanceof Error ? err.message : String(err) });
        }
      }
      // 만료 락 정리 — 실패해도 메일함 수거는 이미 끝났으므로 삼킨다(부가 작업).
      if (this.maildropLock) {
        try {
          const swept = await this.maildropLock.sweepExpired();
          if (swept > 0) this.log.info("maildrop 만료 락 정리", { swept });
        } catch (err) {
          this.log.warn("maildrop 락 정리 실패", { error: err instanceof Error ? err.message : String(err) });
        }
      }
      return reaped;
    } finally {
      this.running = false;
    }
  }
}
