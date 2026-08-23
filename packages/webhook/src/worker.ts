/**
 * WebhookWorker — webhook_deliveries 배달 워커 (수신 웹훅, Phase 4).
 * mta 워커와 동형: 조건부 UPDATE 리스(영향 행 수===1), 지수 백오프, 상태 전이.
 * fetch는 주입식(테스트 결정성 + 런타임 중립). 페이로드에 HMAC-SHA256 서명 헤더 부착.
 * SSRF 방어는 `url-guard.ts`(표기 판정)와 `http-client.ts`(연결 단계 검사)에 있다.
 */
import { createHmac } from "node:crypto";
import { noopLogger, type Logger } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import { createGuardedFetch, type FetchFn } from "./http-client.ts";
import { BlockedAddressError, isAllowedWebhookUrl } from "./url-guard.ts";

/** 웹훅 HMAC 서명 헤더. 수신자와의 계약이라 이름을 바꾸면 남의 검증이 깨진다. */
const SIGNATURE_HEADER = "x-ionosphere-signature";
/** 개명(mailer → ionosphere) 전 이름. 전환 유예 동안 같은 값을 함께 보낸다. */
const LEGACY_SIGNATURE_HEADER = "x-mailer-signature";

/** webhook_deliveries.status. */
const STATUS = { queued: 0, inFlight: 1, done: 2, failed: 3 } as const;

/**
 * 종료 상태(재시도가 더 없는 상태) — 시크릿을 계속 보관할 이유가 사라지는 경계다.
 *
 * ★시크릿을 종료 시점에 비우는 이유(감사 §8-10):
 * 적재 시점 스냅샷이라 `webhook_deliveries.secret`은 엔드포인트 시크릿의 **평문 사본**이다.
 * 사본 자체는 필요하다 — 재시도는 최대 6회에 걸쳐 수십 분 이어지고 그 사이 엔드포인트가
 * 삭제되거나 시크릿이 회전될 수 있는데, 배달은 적재 당시 계약대로 서명돼야 한다. 그래서
 * 조인으로 읽지 않고 복사한다. 하지만 **서명은 발송 시점에만 필요하므로** done/failed에
 * 도달한 뒤의 사본은 순수한 부채다(정리 주체가 없으면 평문 시크릿이 무한히 쌓인다).
 *
 * ★`queued`/`deferred`에서는 절대 비우지 않는다: 비우면 다음 재시도가 서명 없이 나가
 * 수신측이 거절한다(= 배달 실패). 그래서 상태 전이 SQL 중 **종료 전이에만** `secret = ''`을 붙인다.
 *
 * ★NULL이 아니라 빈 문자열인 이유: 컬럼이 `VARCHAR(128) NOT NULL DEFAULT ''`(마이그레이션 002)이라
 * NULL을 넣을 수 없다. 스키마는 동결이므로 컬럼 정의를 바꾸지 않고 기본값과 같은 값으로 비운다.
 * 워커의 `if (secret)` 가드가 이미 빈 시크릿을 "서명 없음"으로 다루므로 의미도 일관된다.
 */
const TERMINAL_STATUSES = `${STATUS.done}, ${STATUS.failed}`;

/**
 * 완료·영구실패 배달 행의 보존 기간.
 *
 * 왜 행을 즉시 지우지 않는가: `last_error`가 유일한 배달 실패 진단 자료다(조회 API가 없어
 * 운영자만 본다). "지난주 웹훅이 안 왔다"는 문의를 받고 나서 볼 수 있어야 한다.
 * 왜 30일인가: 이 저장소가 이미 진단용 이력에 쓰는 창과 같다(SCHEMA.md §5-3의
 * change_log·expunged 30일). 재시도 전 구간은 최대 6회 백오프 합계가 30분 미만이므로
 * 30일은 재시도 수명보다 3자릿수 여유가 있다 — 살아 있는 배달을 지울 위험이 없다.
 */
const DEFAULT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * 보존 스윕 주기 — 배달 tick(15초)마다 돌릴 일이 아니다. 30일 창에 분 단위 정확도는
 * 의미가 없고, 새 타이머를 만들지 않고 tick에 얹기 위해 "마지막 스윕 시각" 하나로 조절한다.
 */
const DEFAULT_SWEEP_INTERVAL_MS = 60 * 60 * 1000;

export type { FetchFn };

export interface WebhookWorkerOptions {
  db: DbDriver;
  /** 주입식 — 미지정 시 SSRF 가드가 걸린 클라이언트(`createGuardedFetch`). */
  fetch?: FetchFn;
  logger?: Logger;
  intervalMs?: number;
  /** 최대 시도 횟수(초과 시 failed). 기본 6. */
  maxAttempts?: number;
  /** 요청 타임아웃(ms). 기본 10초. */
  timeoutMs?: number;
  /** 한 tick이 리스를 잡을 최대 행 수. 기본 100. */
  batchSize?: number;
  /** 동시 배달 수. 기본 8. */
  concurrency?: number;
  /** 종료된 배달 행의 보존 기간(ms). 기본 30일 — DEFAULT_RETENTION_MS 근거 참조. */
  retentionMs?: number;
  /** 보존 스윕을 다시 돌리기까지의 최소 간격(ms). 기본 1시간. */
  sweepIntervalMs?: number;
}

const DEFAULT_INTERVAL_MS = 15_000;
const DEFAULT_MAX_ATTEMPTS = 6;
/** 한 tick이 리스를 잡을 최대 행 수 — runTick의 LIMIT 근거 참조. */
const DEFAULT_BATCH_SIZE = 100;
/** 동시 배달 수 — 느린 엔드포인트가 뒤를 막지 않게, 그러나 소켓을 다 쓰지도 않게. */
const DEFAULT_CONCURRENCY = 8;
/** 요청 전체 타임아웃 — 리스(60초)보다 충분히 짧아야 동시성 상한이 의미를 갖는다. */
const DEFAULT_TIMEOUT_MS = 10_000;
const LEASE_MS = 60_000;

/** 지수 백오프: min(2^attempts × 10s, 1h) ±20% 지터. */
function backoffMs(attempts: number): number {
  const base = Math.min(2 ** attempts * 10_000, 3_600_000);
  const jitter = base * 0.2 * (Math.random() * 2 - 1);
  return Math.max(1_000, Math.round(base + jitter));
}

function sign(secret: string, body: string): string {
  return "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
}

export class WebhookWorker {
  private readonly db: DbDriver;
  private readonly fetchFn: FetchFn;
  private readonly log: Logger;
  private readonly intervalMs: number;
  private readonly maxAttempts: number;
  private readonly timeoutMs: number;
  private readonly batchSize: number;
  private readonly concurrency: number;
  private readonly retentionMs: number;
  private readonly sweepIntervalMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;
  /**
   * 마지막 보존 스윕 시각 — 새 타이머 없이 tick에 얹기 위한 상태.
   *
   * 생성 시각으로 초기화한다(0이 아니다): 첫 tick에 곧바로 큰 DELETE를 던지면 **기동 직후**,
   * 즉 밀린 큐를 배달해야 할 시점에 DB를 잡는다. 30일 창에 한 주기(1시간) 지연은 무의미하다.
   */
  private lastSweepAt = Date.now();

  constructor(opts: WebhookWorkerOptions) {
    this.db = opts.db;
    this.log = (opts.logger ?? noopLogger).child({ component: "webhook" });
    this.intervalMs = opts.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.maxAttempts = opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    // timeoutMs를 먼저 확정한 뒤 만든다 — 가드 fetch는 생성 시점에 타임아웃을 받는다
    this.fetchFn = opts.fetch ?? createGuardedFetch({ timeoutMs: this.timeoutMs });
    this.batchSize = opts.batchSize ?? DEFAULT_BATCH_SIZE;
    this.concurrency = Math.max(1, opts.concurrency ?? DEFAULT_CONCURRENCY);
    this.retentionMs = opts.retentionMs ?? DEFAULT_RETENTION_MS;
    this.sweepIntervalMs = opts.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS;
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

  /** 한 사이클(테스트/수동 구동) — 이번에 리스 획득해 처리한 건수. */
  async tick(): Promise<number> {
    if (this.running) return 0;
    this.running = true;
    try {
      const delivered = await this.runTick();
      // 보존 스윕은 배달 뒤에 얹는다 — 별도 타이머를 만들지 않으려는 선택이고(MailboxReaper가
      // 만료 락 정리를 얹는 것과 같은 방식), 실패해도 배달은 이미 끝났으므로 삼킨다(부가 작업).
      await this.maybeSweepRetention();
      return delivered;
    } finally {
      this.running = false;
    }
  }

  /** 스윕 간격이 지났을 때만 실제로 스윕한다. 실패는 삼킨다(배달 진행을 막지 않는다). */
  private async maybeSweepRetention(): Promise<void> {
    const now = Date.now();
    if (this.lastSweepAt !== 0 && now - this.lastSweepAt < this.sweepIntervalMs) return;
    this.lastSweepAt = now;
    try {
      const purged = await this.sweepRetention(now);
      if (purged > 0) this.log.info("보존 기간 지난 배달 행 정리", { purged });
    } catch (err) {
      this.log.warn("배달 행 정리 실패", { error: err instanceof Error ? err.message : String(err) });
    }
  }

  /**
   * 보존 기간이 지난 **종료 상태** 배달 행을 지운다(테스트·수동 구동 가능). 지운 행 수 반환.
   *
   * `status IN (done, failed)` 가드가 안전장치다: 시각 기준만으로 지우면 오래 deferred 중인
   * (=아직 살아 있는) 배달을 지워 **메일 이벤트를 유실**시킨다. 두 조건을 한 문장에 넣어
   * 판정과 삭제 사이에 상태가 바뀔 틈을 없앤다(다른 스토어 경로와 같은 단일 문장 규율).
   * 기준 시각은 `created_at`이다 — 종료 시각 컬럼이 없고(스키마 동결) 재시도 전 구간이
   * 30분 미만이라 30일 창에서 둘의 차이는 무의미하다.
   */
  async sweepRetention(now: number = Date.now()): Promise<number> {
    const [res] = await this.db.batch([
      {
        sql: `DELETE FROM webhook_deliveries WHERE status IN (${TERMINAL_STATUSES}) AND created_at < ?`,
        params: [now - this.retentionMs],
      },
    ]);
    return res?.changes ?? 0;
  }

  private async runTick(): Promise<number> {
    const now = Date.now();
    // ★LIMIT — 없으면 큐가 클 때 한 tick이 전량을 메모리에 올린다. 남은 건 다음 tick이 가져간다.
    const { rows } = await this.db.query({
      sql: `SELECT id, url, secret, payload, attempts FROM webhook_deliveries
            WHERE (status = ${STATUS.queued} AND next_attempt <= ?) OR (status = ${STATUS.inFlight} AND lease_until < ?)
            ORDER BY next_attempt ASC
            LIMIT ${this.batchSize}`,
      params: [now, now],
    });
    if (rows.length === 0) return 0;

    // 리스 획득은 순차로 둔다 — 단일 문장 CAS라 싸고, 경합 판정(영향 행 수)이 단순하다.
    const leased: { id: string; url: string; secret: string; payload: string; attempts: number }[] = [];
    for (const row of rows) {
      const id = String(row.id);
      const leaseUntil = Date.now() + LEASE_MS;
      const lease = await this.db.batch([
        {
          sql: `UPDATE webhook_deliveries SET status = ${STATUS.inFlight}, lease_until = ? WHERE id = ?
                AND ((status = ${STATUS.queued} AND next_attempt <= ?) OR (status = ${STATUS.inFlight} AND lease_until < ?))`,
          params: [leaseUntil, id, now, now],
        },
      ]);
      if (lease[0]?.changes !== 1) continue; // 경합 패자
      leased.push({
        id,
        url: String(row.url),
        secret: String(row.secret),
        payload: String(row.payload),
        attempts: Number(row.attempts),
      });
    }
    if (leased.length === 0) return 0;

    /**
     * 배달만 제한된 동시성으로 돌린다.
     *
     * 예전엔 완전 순차라 **응답이 느린 엔드포인트 하나가 뒤의 전부를 막았다** — 타임아웃이
     * 10초이므로 그런 대상 10개면 한 tick이 100초다. 그 사이 리스(60초)가 만료되기 시작한다.
     * 무제한 병렬로 하지 않는 이유: 소켓·메모리를 한 번에 다 쓰면 같은 프로세스의 메일
     * 처리까지 밀린다.
     */
    let cursor = 0;
    const runners = Array.from({ length: Math.min(this.concurrency, leased.length) }, async () => {
      for (;;) {
        const item = leased[cursor++];
        if (!item) return;
        await this.deliver(item.id, item.url, item.secret, item.payload, item.attempts);
      }
    });
    await Promise.all(runners);
    return leased.length;
  }

  /** 차단 대상은 재시도해도 결과가 같으므로 즉시 failed로 닫는다(백오프로 계속 두드리지 않는다). */
  private async markBlocked(id: string, url: string, reason: string): Promise<void> {
    await this.db.batch([
      {
        // 종료 전이 → 시크릿 사본 폐기(TERMINAL_STATUSES 주석). 이 경로는 재시도가 없다.
        sql: `UPDATE webhook_deliveries SET status = ${STATUS.failed}, secret = '', last_error = ? WHERE id = ?`,
        params: [reason, id],
      },
    ]);
    this.log.warn("blocked webhook url", { id, url, reason });
  }

  private async deliver(id: string, url: string, secret: string, payload: string, attempts: number): Promise<void> {
    if (!isAllowedWebhookUrl(url)) {
      await this.markBlocked(id, url, "blocked url (private/loopback/invalid)");
      return;
    }
    let ok = false;
    let error = "";
    try {
      const headers: Record<string, string> = { "content-type": "application/json", "user-agent": "ionosphere-webhook/1" };
      if (secret) {
        const signature = sign(secret, payload);
        headers[SIGNATURE_HEADER] = signature;
        // ★개명 전 헤더도 같이 보낸다 — 수신자 코드가 옛 이름을 검사하도록 이미 배포돼 있다.
        // 우리가 이름을 바꿨다고 남의 엔드포인트가 조용히 서명 검증에 실패하게 둘 수는 없다.
        // 걷어내는 시점은 수신자들이 새 이름으로 옮긴 뒤다(공지 → 유예 → 제거).
        headers[LEGACY_SIGNATURE_HEADER] = signature;
      }
      const res = await this.fetchFn(url, { method: "POST", headers, body: payload });
      ok = res.status >= 200 && res.status < 300;
      if (!ok) error = `HTTP ${res.status}`;
    } catch (err) {
      /**
       * 이름이 사설 IP로 해석돼 연결 단계에서 막힌 경우다(DNS 리바인딩). URL 문자열은 멀쩡하므로
       * 위 관문을 통과하지만 결과는 같은 "내부 자원 대상"이니 같은 처분을 한다.
       */
      if (err instanceof BlockedAddressError) {
        await this.markBlocked(id, url, err.message);
        return;
      }
      error = err instanceof Error ? err.message : String(err);
    }

    if (ok) {
      // 종료 전이 → 시크릿 사본 폐기(TERMINAL_STATUSES 주석).
      await this.db.batch([{ sql: `UPDATE webhook_deliveries SET status = ${STATUS.done}, secret = '', last_error = NULL WHERE id = ?`, params: [id] }]);
      this.log.info("delivered", { id, url });
      return;
    }
    const nextAttempts = attempts + 1;
    if (nextAttempts >= this.maxAttempts) {
      // 종료 전이 → 시크릿 사본 폐기. 시도 상한에 걸렸으므로 이 행은 다시 발송되지 않는다.
      await this.db.batch([{ sql: `UPDATE webhook_deliveries SET status = ${STATUS.failed}, secret = '', attempts = ?, last_error = ? WHERE id = ?`, params: [nextAttempts, error, id] }]);
      this.log.warn("failed (max attempts)", { id, url, error });
    } else {
      const next = Date.now() + backoffMs(nextAttempts);
      // ★여기서는 secret을 건드리지 않는다 — 재시도가 남아 있고, 비우면 다음 발송이 서명 없이 나간다.
      await this.db.batch([
        { sql: `UPDATE webhook_deliveries SET status = ${STATUS.queued}, attempts = ?, next_attempt = ?, lease_until = NULL, last_error = ? WHERE id = ?`, params: [nextAttempts, next, error, id] },
      ]);
      this.log.info("deferred", { id, url, attempts: nextAttempts, error });
    }
  }
}
