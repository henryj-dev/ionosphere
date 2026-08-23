/**
 * Abuse 모니터링 — PLAN.md §8 통제 ④(AUP + abuse 대응)의 코드 축: 신고율/바운스율 임계
 * 초과 시 자동 발송 정지. §8 헤더 원칙("운영자는 메일 내용을 열람하지 않는다")을 그대로
 * 따른다 — 여기서 보는 신호는 mta_queue.status(발송 성공/바운스)뿐, 본문은 전혀 읽지 않는다.
 *
 * 판정(checkAccountAbuse)과 집행(suspendAccount)을 분리한다: 판정은 순수 조회라 단위테스트가
 * 쉽고, 집행은 단일 조건부 UPDATE라 재현 가능한 부작용만 남는다.
 */
import { MTA_QUEUE_STATUS, type DbDriver } from "@ionosphere/db";

/** mta_queue.status (SCHEMA.md §9-1) — 판정에 쓰는 "해소된(resolved)" 발송 결과만. */


/** accounts.status (SCHEMA.md §4). */
const ACCOUNT_STATUS_SUSPENDED = 0;
const ACCOUNT_STATUS_ACTIVE = 1;

/** 평가 창 기본값 — MtaWorker의 "최근 발송 있는 계정" 스윕 질의도 이 기본을 공유한다. */
export const DEFAULT_ABUSE_WINDOW_MS = 24 * 60 * 60 * 1000;
const DEFAULT_MIN_SAMPLE = 20;
const DEFAULT_BOUNCE_RATE_THRESHOLD = 0.1;
/**
 * 신고율 임계 기본값 — 바운스율보다 **한 자릿수 낮다**(0.1% vs 10%).
 *
 * 두 신호의 뜻이 다르기 때문이다. 바운스는 주소가 틀린 것이고(목록 위생 문제), 신고는
 * 사람이 "이건 스팸이다"를 누른 것이다. 업계 관행도 0.1%를 위험선으로 본다
 * (docs/PROTOCOLS.md의 발송 적격 표에 이미 "스팸 신고율 <0.3%, 목표 <0.1%"로 적혀 있다).
 * 같은 임계를 쓰면 신고가 사실상 집계되지 않는다.
 */
const DEFAULT_COMPLAINT_RATE_THRESHOLD = 0.003;

export interface AbuseOptions {
  /** 평가 창(ms). 기본 24h. */
  windowMs?: number;
  /** 최소 표본. 이 미만이면 판정 보류("ok") — 작은 표본으로 정지하지 않는다. 기본 20. */
  minSample?: number;
  /** 바운스율 임계. 초과(strict >) 시 정지. 기본 0.10(10%). */
  bounceRateThreshold?: number;
  /** 신고율 임계. 초과 시 정지. 기본 0.003(0.3%) — 위 상수 주석 참조. */
  complaintRateThreshold?: number;
  /** 테스트 결정성용 시각 주입. 생략 시 Date.now(). */
  now?: number;
}

export type AbuseVerdict =
  | { action: "ok"; sent: number; bounced: number; complained: number; rate: number; complaintRate: number }
  | {
      action: "suspend";
      sent: number;
      bounced: number;
      complained: number;
      rate: number;
      complaintRate: number;
      reason: string;
    };

/**
 * 계정의 최근 windowMs 발송 결과를 mta_queue에서 집계해 판정한다.
 * sent = 해소된 발송(status IN (done, bounced)) 수, bounced = status=bounced 수.
 * accounts를 갱신하지 않는다 — 집행은 suspendAccount로 별도 호출(테스트 격리 목적).
 */
export async function checkAccountAbuse(db: DbDriver, accountId: string, opts: AbuseOptions = {}): Promise<AbuseVerdict> {
  const now = opts.now ?? Date.now();
  const windowMs = opts.windowMs ?? DEFAULT_ABUSE_WINDOW_MS;
  const minSample = opts.minSample ?? DEFAULT_MIN_SAMPLE;
  const threshold = opts.bounceRateThreshold ?? DEFAULT_BOUNCE_RATE_THRESHOLD;
  const complaintThreshold = opts.complaintRateThreshold ?? DEFAULT_COMPLAINT_RATE_THRESHOLD;
  const windowStart = now - windowMs;

  const { rows } = await db.query({
    sql: `SELECT
            COUNT(*) AS sent,
            SUM(CASE WHEN status = ${MTA_QUEUE_STATUS.bounced} THEN 1 ELSE 0 END) AS bounced,
            SUM(CASE WHEN complained_at IS NOT NULL THEN 1 ELSE 0 END) AS complained
          FROM mta_queue
          WHERE account_id = ? AND created_at > ? AND status IN (${MTA_QUEUE_STATUS.done}, ${MTA_QUEUE_STATUS.bounced})`,
    params: [accountId, windowStart],
  });
  const row = rows[0];
  const sent = Number(row?.sent ?? 0);
  const bounced = Number(row?.bounced ?? 0);
  const complained = Number(row?.complained ?? 0);
  const rate = sent > 0 ? bounced / sent : 0;
  const complaintRate = sent > 0 ? complained / sent : 0;

  if (sent < minSample) {
    return { action: "ok", sent, bounced, complained, rate, complaintRate };
  }
  /**
   * ★신고율을 **먼저** 본다. 둘 다 넘겼을 때 어느 쪽을 사유로 적을지의 문제인데,
   * 신고는 사람이 직접 "스팸이다"를 누른 것이라 바운스(주소 오류)보다 강한 신호다.
   * 사유 문구는 운영자가 그다음에 무엇을 할지 정하는 근거라 정확해야 한다.
   */
  if (complaintRate > complaintThreshold) {
    return {
      action: "suspend",
      sent,
      bounced,
      complained,
      rate,
      complaintRate,
      reason: `complaint rate ${(complaintRate * 100).toFixed(2)}% exceeds threshold ${(complaintThreshold * 100).toFixed(2)}% (${complained}/${sent} over window)`,
    };
  }
  if (rate > threshold) {
    return {
      action: "suspend",
      sent,
      bounced,
      complained,
      rate,
      complaintRate,
      reason: `bounce rate ${(rate * 100).toFixed(1)}% exceeds threshold ${(threshold * 100).toFixed(1)}% (${bounced}/${sent} over window)`,
    };
  }
  return { action: "ok", sent, bounced, complained, rate, complaintRate };
}

/**
 * accounts.status를 0(suspended)로 전환한다 — 단일 조건부 UPDATE(WHERE status=1)라
 * 멱등: 이미 정지됐거나(0) 삭제 중인(2) 계정은 건드리지 않는다.
 *
 * 정지 **사유는 받지 않는다**. SCHEMA.md §4 accounts에 저장할 컬럼이 없어서 예전엔
 * reason/now를 인자로 받아 두고 아무 데도 쓰지 않았다 — 쓰이지 않는 인자는 "언젠가 저장하나
 * 보다"는 오해를 만든다. 감사 기록은 호출자가 로그로 남긴다(MtaWorker.sweepAbuse).
 *
 * 배선 위치(이 패키지 스코프 밖): 아웃바운드 게이트(enqueue.ts)는 발신 **도메인**의
 * `domains.status=1`만 보고 계정 status는 보지 않는다. 그래서 정지된 계정 자신의 제출을
 * 거부하는 일은 apps/server의 submission 경로가 맡는다 — `backend.ts`의 `submitOutbound`가
 * `account.status !== 1`을 거부한다. (예전 이 주석은 "그 배선이 없다"고 적혀 있었는데
 * 배선이 들어온 뒤에도 갱신되지 않았다 — 감사 5차 I-3.)
 */
export async function suspendAccount(db: DbDriver, accountId: string): Promise<void> {
  await db.batch([
    {
      sql: `UPDATE accounts SET status = ${ACCOUNT_STATUS_SUSPENDED} WHERE id = ? AND status = ${ACCOUNT_STATUS_ACTIVE}`,
      params: [accountId],
    },
  ]);
}


/**
 * 신고를 기록한다 — ARF 리포트에서 되찾은 발송 한 건에 표시.
 *
 * ★`status`를 덮지 않는다. 신고는 배달 **이후에** 오므로 "배달됐다"와 "신고당했다"가 둘 다
 * 참이어야 하고, status를 덮으면 분모(발송 수)가 무너져 신고율 자체가 틀린다.
 *
 * ★이미 기록된 건은 갱신하지 않는다(`complained_at IS NULL` 조건). 같은 리포트가 두 번
 * 오는 일이 실제로 있고(FBL 재전송), 시각이 밀리면 "언제 신고당했는지"가 흐려진다.
 * 멱등이라 재처리에 안전하다.
 *
 * 돌려주는 값은 **실제로 표시한 행 수**다 — 0이면 상관관계 실패(우리 발송이 아니거나 이미
 * 기록됨)이고, 호출부가 그 둘을 로그로 구분할 수 있어야 한다.
 */
export async function recordComplaint(db: DbDriver, queueId: string, at: number): Promise<number> {
  const res = await db.batch([
    {
      sql: "UPDATE mta_queue SET complained_at = ? WHERE id = ? AND complained_at IS NULL",
      params: [at, queueId],
    },
  ]);
  const changed = res?.[0]?.changes;
  return typeof changed === "number" ? changed : 0;
}
