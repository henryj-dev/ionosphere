import type { Migration } from "../migrate.ts";

/**
 * 공유 메일함의 주체·ACL·그룹 멤버십을 추가한다.
 *
 * FK를 두지 않는 저장소 정책을 따르므로 삭제·테넌트 경계는 Store의 단일
 * 원자 배치와 조회 조건이 보장한다. provider/external_key는 LDAP·AD 동기화
 * 식별자를 보존하기 위한 값이며, account_id가 있는 행은 로컬 계정 주체다.
 */
export const m020MailboxAcl: Migration = {
  version: 20,
  name: "mailbox acl",
  statements: [
    `CREATE TABLE IF NOT EXISTS principals (
      id            VARCHAR(26) PRIMARY KEY,
      tenant_id     VARCHAR(26) NOT NULL,
      kind          SMALLINT NOT NULL,
      account_id    VARCHAR(26),
      provider      VARCHAR(32),
      external_key  VARCHAR(255),
      display_name  VARCHAR(255),
      created_at    BIGINT NOT NULL
    )`,
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_principals_account ON principals(tenant_id, account_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_principals_external ON principals(tenant_id, kind, provider, external_key)",
    `CREATE TABLE IF NOT EXISTS mailbox_acl (
      mailbox_id    VARCHAR(26) NOT NULL,
      principal_id  VARCHAR(26) NOT NULL,
      rights        VARCHAR(32) NOT NULL,
      negative      SMALLINT NOT NULL DEFAULT 0,
      created_at    BIGINT NOT NULL,
      updated_at    BIGINT NOT NULL,
      PRIMARY KEY (mailbox_id, principal_id)
    )`,
    "CREATE INDEX IF NOT EXISTS ix_mailbox_acl_principal ON mailbox_acl(principal_id, mailbox_id)",
    `CREATE TABLE IF NOT EXISTS account_memberships (
      account_id    VARCHAR(26) NOT NULL,
      principal_id  VARCHAR(26) NOT NULL,
      source        VARCHAR(32) NOT NULL,
      created_at    BIGINT NOT NULL,
      PRIMARY KEY (account_id, principal_id)
    )`,
    "CREATE INDEX IF NOT EXISTS ix_account_memberships_principal ON account_memberships(principal_id, account_id)",
    "ALTER TABLE accounts ADD COLUMN permissions_version BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE mailboxes ADD COLUMN acl_version BIGINT NOT NULL DEFAULT 0",
  ],
};
