import type { Migration } from "../migrate.ts";

/**
 * 006 — 알리아스 팬아웃: 수신 주소 1개 → 로컬 계정 N개.
 *
 * 왜: addresses는 행당 목적지가 하나(account_id 단일 컬럼)라 `sales@`를 두 사람에게 동시에
 * 배달할 수 없었다. forward_to로 우회하면 내부 계정인데도 **외부 SMTP를 한 바퀴 돌아** 들어온다
 * (SRS 재작성·루프가드·MAX_RELAY_TARGETS 소모, SRS 미설정이면 아예 배달되지 않는다).
 *
 * account_id를 남겨 두지 않고 **옮기는** 이유: 목적지의 진실 원천이 둘이 되면 한쪽만 고쳐서
 * 조용히 깨진다. accounts.email과 addresses가 갈라져 크로스 테넌트 수신 탈취를 만든 것이 바로
 * 직전 사고다. 팬아웃 이후 로컬 목적지의 유일한 원천은 address_targets다.
 * (forward_to는 성격이 다르다 — 외부 릴레이 대상이라 그대로 addresses에 남는다.)
 *
 * 재빌드 패턴(CREATE 신규 → INSERT SELECT → DROP → RENAME)은 003과 동일 — SQLite/PG/MySQL 공통.
 * ⚠ D1(비트랜잭셔널 DDL) 재개 안전성은 003과 같은 이유로 보장하지 않는다(단일 실행 전제, 라이브는
 *   SQLite). DROP addresses와 RENAME 사이에서 죽으면 수동 복구가 필요하다.
 */
export const m006AddressFanout: Migration = {
  version: 6,
  name: "address-fanout",
  statements: [
    `CREATE TABLE IF NOT EXISTS address_targets (
      address_id  VARCHAR(26) NOT NULL,
      account_id  VARCHAR(26) NOT NULL,
      PRIMARY KEY (address_id, account_id)
    )`,
    // 역방향 조회(계정 삭제 시 이 계정을 가리키는 주소 정리)용
    `CREATE INDEX IF NOT EXISTS ix_address_targets_account ON address_targets(account_id)`,

    // 기존 단일 목적지 이관. NOT EXISTS 가드로 재개 안전(PK 충돌 없이 다시 돌 수 있다).
    `INSERT INTO address_targets (address_id, account_id)
       SELECT ad.id, ad.account_id FROM addresses ad
       WHERE ad.account_id IS NOT NULL
         AND NOT EXISTS (SELECT 1 FROM address_targets t WHERE t.address_id = ad.id)`,

    // ── addresses 재빌드(account_id 제거) ──────────────────────────
    // 부분 실패 재실행 대비(신규 임시 테이블 잔재 제거) — 003과 같은 형태
    `DROP TABLE IF EXISTS addresses_rebuild`,
    `CREATE TABLE addresses_rebuild (
      id            VARCHAR(26) PRIMARY KEY,
      tenant_id     VARCHAR(26) NOT NULL,
      domain_id     VARCHAR(26) NOT NULL,
      localpart     VARCHAR(255) NOT NULL,
      forward_to    TEXT,
      created_at    BIGINT NOT NULL
    )`,
    // 컬럼 명시 — 순서 의존 제거
    `INSERT INTO addresses_rebuild (id, tenant_id, domain_id, localpart, forward_to, created_at)
     SELECT id, tenant_id, domain_id, localpart, forward_to, created_at FROM addresses`,
    `DROP TABLE addresses`,
    `ALTER TABLE addresses_rebuild RENAME TO addresses`,
    // 인덱스 재생성(§9-1 원본과 동일) — 라우팅 유일성은 여전히 (도메인, 로컬파트)다
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_addresses_route ON addresses(domain_id, localpart)`,
  ],
};
