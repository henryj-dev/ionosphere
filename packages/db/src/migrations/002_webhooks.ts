import type { Migration } from "../migrate.ts";

/**
 * 002 — 수신 웹훅 (Phase 4). Postmark inbound 스타일: 메일 수신 시 설정된 URL로 POST.
 * - webhook_endpoints: 계정별 웹훅 설정(URL·서명 시크릿·활성).
 * - webhook_deliveries: 재시도 배달 큐(mta_queue §9-1 규율과 동형 — 리스·백오프·상태).
 *   URL/시크릿/페이로드는 적재 시점 스냅샷(엔드포인트 삭제·변경과 무관하게 배달 일관).
 */
export const m002Webhooks: Migration = {
  version: 2,
  name: "webhooks",
  statements: [
    `CREATE TABLE IF NOT EXISTS webhook_endpoints (
      id            VARCHAR(26) PRIMARY KEY,
      account_id    VARCHAR(26) NOT NULL,
      url           TEXT NOT NULL,
      secret        VARCHAR(128) NOT NULL DEFAULT '',
      active        SMALLINT NOT NULL DEFAULT 1,
      created_at    BIGINT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS ix_webhook_ep_account ON webhook_endpoints(account_id)`,

    `CREATE TABLE IF NOT EXISTS webhook_deliveries (
      id            VARCHAR(26) PRIMARY KEY,
      account_id    VARCHAR(26) NOT NULL,
      endpoint_id   VARCHAR(26) NOT NULL,
      url           TEXT NOT NULL,
      secret        VARCHAR(128) NOT NULL DEFAULT '',
      payload       TEXT NOT NULL,
      status        SMALLINT NOT NULL DEFAULT 0,
      attempts      INTEGER NOT NULL DEFAULT 0,
      next_attempt  BIGINT NOT NULL,
      lease_until   BIGINT,
      last_error    TEXT,
      created_at    BIGINT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS ix_webhook_deliv_due ON webhook_deliveries(status, next_attempt)`,
  ],
};
