import type { Migration } from "../migrate.ts";

/**
 * 003 — 포워딩(forward_to 알리아스 + 바운스 reverse) 지원 (Phase 5, SRS).
 *
 * mta_queue.account_id를 nullable로 바꾼다. 포워딩·바운스 relay는 귀속 계정이 없는
 * 시스템 발송이므로(스키마가 이미 submission_id NULL = 시스템 발송을 인정) account_id도
 * NULL을 허용해야 일관된다. FK가 없어(스키마 전반 FK 미사용) 재빌드는 데이터만 보존하면 됨.
 *
 * 재빌드 패턴(CREATE 신규 → INSERT SELECT → DROP → RENAME)은 SQLite/PG/MySQL 모두 유효.
 * ⚠ D1(비트랜잭셔널 DDL) 재개 안전성은 이 마이그레이션에 한해 보장하지 않는다 — 단일 실행
 *   전제(라이브는 SQLite). D1 배포 시 별도 재작성 필요(§9-4 러너 규율 예외).
 */
export const m003Forwarding: Migration = {
  version: 3,
  name: "forwarding",
  statements: [
    // 부분 실패 재실행 대비(신규 임시 테이블 잔재 제거)
    `DROP TABLE IF EXISTS mta_queue_rebuild`,
    // account_id를 nullable로 한 새 정의
    `CREATE TABLE mta_queue_rebuild (
      id            VARCHAR(26) PRIMARY KEY,
      tenant_id     VARCHAR(26) NOT NULL,
      account_id    VARCHAR(26),
      submission_id VARCHAR(26),
      blob_id       VARCHAR(64) NOT NULL,
      env_from      VARCHAR(255) NOT NULL,
      verp_token    VARCHAR(32),
      rcpt          VARCHAR(255) NOT NULL,
      rcpt_domain   VARCHAR(255) NOT NULL,
      status        SMALLINT NOT NULL DEFAULT 0,
      attempts      SMALLINT NOT NULL DEFAULT 0,
      next_attempt  BIGINT NOT NULL,
      lease_until   BIGINT,
      last_error    TEXT,
      created_at    BIGINT NOT NULL
    )`,
    // 기존 데이터 보존(컬럼 명시 — 순서 의존 제거)
    `INSERT INTO mta_queue_rebuild
       (id, tenant_id, account_id, submission_id, blob_id, env_from, verp_token, rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, last_error, created_at)
     SELECT id, tenant_id, account_id, submission_id, blob_id, env_from, verp_token, rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, last_error, created_at
     FROM mta_queue`,
    `DROP TABLE mta_queue`,
    `ALTER TABLE mta_queue_rebuild RENAME TO mta_queue`,
    // 인덱스 재생성(§9-1 원본과 동일)
    `CREATE INDEX IF NOT EXISTS ix_queue_due ON mta_queue(status, next_attempt)`,
    `CREATE INDEX IF NOT EXISTS ix_queue_domain ON mta_queue(rcpt_domain, status)`,
    `CREATE INDEX IF NOT EXISTS ix_queue_account ON mta_queue(account_id, created_at)`,
    `CREATE INDEX IF NOT EXISTS ix_queue_verp ON mta_queue(verp_token)`,
  ],
};
