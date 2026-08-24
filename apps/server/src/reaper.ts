/**
 * 메일함 삭제 2단계 리퍼(§7-7) — 툼스톤(status=2) 메일함을 주기적으로 수거.
 * deleteMailbox는 1단계(툼스톤)만 하고, 실제 membership/메시지 정리·행 하드삭제는 여기서.
 * WebhookWorker/MtaWorker와 동형(interval + 재진입 가드 + 수동 tick).
 */
import { noopLogger, type Logger } from "@ionosphere/core";
import { runRetention, type RetentionOptions, type Store } from "@ionosphere/store";
import { runReports, type ReportOptions } from "./reports.ts";
import type { DbDriver } from "@ionosphere/db";

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
  /**
   * 보존창 스윕 — 지정 시 `change_log`·`thread_refs`·종료된 `mta_queue` 행을 잘라낸다.
   * **생략하면 돌지 않는다**(기존 배포와 하위호환 — 보존 정책은 운영자가 켜는 것이다).
   *
   * 왜 리퍼가 하는가: 이미 "주기적으로 남은 것을 치우는" 역할이고 maildrop 만료 락도 여기서
   * 쓸고 있다. 워커를 하나 더 만들면 주기·재진입 가드가 또 한 벌 생긴다.
   */
  retention?: RetentionOptions & { db: DbDriver };
  /**
   * 대외 리포트(DMARC rua · TLS-RPT) 하루 한 번 발송.
   *
   * ★리퍼에 붙이는 이유: 이미 도는 주기 작업이라 타이머를 하나 더 만들 이유가 없다.
   * **하루 한 번**은 `report_sends`가 보장한다(같은 기간을 두 번 보내지 않는다) —
   * 리퍼 주기(5분)와 무관하게 정확히 한 번이다.
   */
  reports?: Omit<ReportOptions, "now">;
}

const DEFAULT_INTERVAL_MS = 5 * 60 * 1000;

export class MailboxReaper {
  private readonly store: Store;
  private readonly log: Logger;
  private readonly intervalMs: number;
  private readonly batchSize: number;
  private readonly maildropLock?: { sweepExpired(now?: number, graceMs?: number): Promise<number> };
  private readonly retention?: RetentionOptions & { db: DbDriver };
  private readonly reports?: Omit<ReportOptions, "now">;
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  constructor(opts: MailboxReaperOptions) {
    this.store = opts.store;
    this.log = (opts.logger ?? noopLogger).child({ component: "reaper" });
    this.intervalMs = opts.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.batchSize = opts.batchSize ?? 50;
    if (opts.maildropLock) this.maildropLock = opts.maildropLock;
    if (opts.retention) this.retention = opts.retention;
    if (opts.reports) this.reports = opts.reports;
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
      /**
       * 보존창 스윕 — 메일함 수거와 별개다. 실패해도 삼킨다(부가 작업이고, 다음 주기에
       * 다시 돈다). 첫 스윕은 누적분을 지우느라 길 수 있다 — `runRetention` 주석 참조.
       */
      if (this.retention) {
        try {
          const r = await runRetention(this.retention.db, this.retention);
          // 하나라도 움직였으면 남긴다 — 항목이 늘 때 여기를 고치는 것을 잊지 않도록
          // 값의 합으로 판정한다(이름을 하나씩 나열하다 `expunged`를 빠뜨릴 뻔했다).
          if (Object.values(r).some((v) => v > 0)) {
            this.log.info("보존창 스윕", { ...r });
          }
        } catch (err) {
          this.log.warn("보존창 스윕 실패", { error: err instanceof Error ? err.message : String(err) });
        }
      }
      /**
       * 대외 리포트 — **보존창 스윕 뒤에** 돈다. 스윕이 집계 행을 지우기 전에 보내야
       * 하는 것이 아니라, 리포트가 자기 보존창을 따로 갖기 때문에 순서는 무관하다.
       * 실패는 삼킨다 — 리포트가 리퍼의 본 일(파기된 메일함 회수)을 막으면 안 된다.
       */
      if (this.reports) {
        try {
          const r = await runReports(this.reports);
          if (r.dmarcSent > 0 || r.tlsrptSent > 0 || r.purged > 0) this.log.info("대외 리포트", { ...r });
        } catch (err) {
          this.log.warn("대외 리포트 실패", { error: err instanceof Error ? err.message : String(err) });
        }
      }
      return reaped;
    } finally {
      this.running = false;
    }
  }
}
