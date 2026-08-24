import type { Migration } from "../migrate.ts";

/**
 * 011 — 시스템 relay 상한 조회용 `mta_queue(tenant_id, created_at)` 인덱스.
 *
 * 이 질의가 **풀스캔**이었다(`EXPLAIN QUERY PLAN` → `SCAN mta_queue`). 포워딩·Sieve
 * redirect·바운스 relay **한 건마다** 돈다(`mta/enqueue.ts`):
 *
 *     SELECT COUNT(*) FROM mta_queue WHERE tenant_id = ? AND created_at > ?
 *
 * 기존 인덱스는 `ix_queue_account(account_id, created_at)`인데 **relay는 정의상
 * `account_id`가 NULL이다**(003이 그래서 컬럼을 nullable로 바꿨다). 즉 이 갈래에는 쓸 수 있는
 * 인덱스가 하나도 없었다. 그리고 이 상한은 계정 축 레이트리밋이 걸리지 않는 relay 갈래의
 * **유일한** 증폭 방어라(`enqueue.ts` SystemRelay 주석), 그 판정이 느려지면 곧 수신이 느려진다.
 *
 * ★왜 지금 아픈가: `mta_queue`에 **보존 GC가 없다**(2026-08-23 검수). done/bounced 행이
 * 영구히 쌓이므로 풀스캔 비용이 시간에 비례해 자란다 — 원인이 드러나기 어려운 형태로
 * 포워딩이 계속 느려진다.
 *
 * ★`(created_at)` 단독 인덱스는 **일부러 만들지 않았다.** 어뷰즈 스윕
 * (`worker.ts runAbuseSweep`, 기본 1시간)의
 *     SELECT DISTINCT account_id FROM mta_queue WHERE created_at > ? AND account_id IS NOT NULL
 * 이 후보였는데, 실측 플랜이 이미
 *     SEARCH mta_queue USING COVERING INDEX ix_queue_account (account_id>?)
 * 라 테이블을 건드리지 않는다. 인덱스는 공짜가 아니고 `mta_queue`는 **수신자마다 한 행이
 * 들어오는 쓰기 편중 테이블**이라, 플래너가 고르지 않을 인덱스는 순수 비용이다.
 * (같은 이유로 나중에 큐 보존 GC를 넣을 때는 그 GC의 실제 플랜을 보고 필요한 것만 더한다.)
 *
 * DDL만 있고 데이터를 건드리지 않으므로 재실행 안전하다(`IF NOT EXISTS`; MySQL은 드라이버가
 * ER_DUP_KEYNAME을 멱등 no-op으로 흡수한다 — `db/mysql.ts` translate 주석).
 */
export const m011QueueIndexes: Migration = {
  version: 11,
  name: "queue-indexes",
  statements: [`CREATE INDEX IF NOT EXISTS ix_queue_tenant ON mta_queue(tenant_id, created_at)`],
};
