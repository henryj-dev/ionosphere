import type { Migration } from "../migrate.ts";

/** LDAP/AD immutable identity와 nested group 동기화 원장. 외부 장애 때 기존 매핑을 임의 삭제하지 않는다. */
export const m021DirectoryIdentity: Migration = {
  version: 21,
  name: "directory identity",
  statements: [
    `CREATE TABLE IF NOT EXISTS directory_identities (
      id            VARCHAR(26) PRIMARY KEY,
      tenant_id     VARCHAR(26) NOT NULL,
      provider      VARCHAR(32) NOT NULL,
      external_key  VARCHAR(512) NOT NULL,
      account_id    VARCHAR(26),
      login_names   TEXT NOT NULL,
      email         VARCHAR(255),
      display_name  VARCHAR(255),
      last_seen_at  BIGINT NOT NULL,
      status        SMALLINT NOT NULL DEFAULT 1
    )`,
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_directory_identity ON directory_identities(tenant_id, provider, external_key)",
    "CREATE INDEX IF NOT EXISTS ix_directory_identity_login ON directory_identities(tenant_id, provider, email)",
    `CREATE TABLE IF NOT EXISTS directory_group_members (
      tenant_id          VARCHAR(26) NOT NULL,
      provider            VARCHAR(32) NOT NULL,
      group_external_key  VARCHAR(512) NOT NULL,
      member_external_key VARCHAR(512) NOT NULL,
      last_seen_at        BIGINT NOT NULL,
      PRIMARY KEY (tenant_id, provider, group_external_key, member_external_key)
    )`,
  ],
};
