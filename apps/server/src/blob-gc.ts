/**
 * 블롭 GC 워커 — 주기적으로 `runBlobGc`를 돌린다.
 * WebhookWorker/MtaWorker/MailboxReaper와 동형(interval + 재진입 가드 + 수동 tick).
 */
import { noopLogger, type Logger } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import { runBlobGc, type BlobGcMode, type BlobGcOptions, type BlobGcResult, type BlobStore } from "@ionosphere/store";

export interface BlobGcWorkerOptions extends BlobGcOptions {
  db: DbDriver;
  blobs: BlobStore;
  /** 동작 수위 — 기본 "mark"(파일 삭제 없음). BlobGcMode 주석 참조. */
  mode?: BlobGcMode;
  logger?: Logger;
  /** 폴링 주기(ms). 기본 1시간 — 유예가 시간 단위라 더 자주 돌 이유가 없다. */
  intervalMs?: number;
  /** 관측 훅. @ionosphere/metrics 의존 없이 콜백만 받는다(MtaWorker.onResult와 같은 의존성 역전). */
  onSweep?: (result: BlobGcResult) => void;
}

const DEFAULT_INTERVAL_MS = 60 * 60 * 1000;

export class BlobGcWorker {
  private readonly db: DbDriver;
  private readonly blobs: BlobStore;
  private readonly mode: BlobGcMode;
  private readonly log: Logger;
  private readonly intervalMs: number;
  private readonly gcOpts: BlobGcOptions;
  private readonly onSweep?: (result: BlobGcResult) => void;
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  constructor(opts: BlobGcWorkerOptions) {
    this.db = opts.db;
    this.blobs = opts.blobs;
    this.mode = opts.mode ?? "mark";
    this.log = (opts.logger ?? noopLogger).child({ component: "blob-gc" });
    this.intervalMs = opts.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.gcOpts = {
      ...(opts.graceMs !== undefined ? { graceMs: opts.graceMs } : {}),
      ...(opts.uploadTtlMs !== undefined ? { uploadTtlMs: opts.uploadTtlMs } : {}),
      ...(opts.batchSize !== undefined ? { batchSize: opts.batchSize } : {}),
    };
    if (opts.onSweep) this.onSweep = opts.onSweep;
  }

  start(): void {
    if (this.timer || this.mode === "off") return;
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

  /** 한 사이클(수동 구동 가능). GC 실패는 서비스에 영향을 주면 안 되므로 삼키고 로그만 남긴다. */
  async tick(): Promise<BlobGcResult | null> {
    if (this.running) return null;
    this.running = true;
    try {
      const r = await runBlobGc(this.db, this.blobs, this.mode, this.gcOpts);
      if (r.releasedQueue > 0 || r.expiredUploads > 0 || r.doomed > 0 || r.swept > 0) {
        this.log.info("blob gc", { mode: this.mode, ...r });
      }
      this.onSweep?.(r);
      return r;
    } catch (err) {
      this.log.warn("blob gc failed", { error: err instanceof Error ? err.message : String(err) });
      return null;
    } finally {
      this.running = false;
    }
  }
}
