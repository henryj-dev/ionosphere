import type { Migration } from "../migrate.ts";

/**
 * 초기 스키마 — docs/SCHEMA.md v2.1 (동결본) 전사.
 * 규약(§2): id=VARCHAR(26) ULID, 시각=epoch millis BIGINT, 불리언=SMALLINT 0/1,
 * FK 없음(§1-4), 모든 문장 멱등(IF NOT EXISTS — D1 비트랜잭셔널 DDL 대응).
 * MySQL 다이얼렉트 변환(utf8mb4_bin, ascii charset for ids)은 어댑터의 DDL 생성기 몫 — Phase 2.
 */
export const m001Init: Migration = {
  version: 1,
  name: "init",
  statements: [
    // ── 테넌시/신원 (SCHEMA.md §4) ─────────────────────────────
    `CREATE TABLE IF NOT EXISTS tenants (
      id            VARCHAR(26) PRIMARY KEY,
      name          VARCHAR(190) NOT NULL,
      status        SMALLINT NOT NULL DEFAULT 1,
      created_at    BIGINT NOT NULL
    )`,

    `CREATE TABLE IF NOT EXISTS domains (
      id            VARCHAR(26) PRIMARY KEY,
      tenant_id     VARCHAR(26) NOT NULL,
      name          VARCHAR(255) NOT NULL,
      name_utf8     TEXT,
      status        SMALLINT NOT NULL DEFAULT 0,
      verify_token  VARCHAR(64),
      claimed_at    BIGINT NOT NULL,
      created_at    BIGINT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS ix_domains_name ON domains(name)`,

    `CREATE TABLE IF NOT EXISTS domain_name_claims (
      name          VARCHAR(255) PRIMARY KEY,
      domain_id     VARCHAR(26) NOT NULL
    )`,

    `CREATE TABLE IF NOT EXISTS accounts (
      id                VARCHAR(26) PRIMARY KEY,
      tenant_id         VARCHAR(26) NOT NULL,
      email             VARCHAR(255) NOT NULL,
      display_name      TEXT,
      kind              SMALLINT NOT NULL DEFAULT 0,
      status            SMALLINT NOT NULL DEFAULT 1,
      modseq            BIGINT NOT NULL DEFAULT 0,
      changelog_floor   BIGINT NOT NULL DEFAULT 0,
      uidvalidity_last  BIGINT NOT NULL DEFAULT 0,
      quota_bytes       BIGINT NOT NULL DEFAULT 0,
      used_bytes        BIGINT NOT NULL DEFAULT 0,
      message_count     BIGINT NOT NULL DEFAULT 0,
      state_email       BIGINT NOT NULL DEFAULT 0,
      state_mailbox     BIGINT NOT NULL DEFAULT 0,
      state_thread      BIGINT NOT NULL DEFAULT 0,
      state_submission  BIGINT NOT NULL DEFAULT 0,
      state_sieve       BIGINT NOT NULL DEFAULT 0,
      created_at        BIGINT NOT NULL
    )`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_accounts_email ON accounts(email)`,
    `CREATE INDEX IF NOT EXISTS ix_accounts_tenant ON accounts(tenant_id)`,

    `CREATE TABLE IF NOT EXISTS addresses (
      id            VARCHAR(26) PRIMARY KEY,
      tenant_id     VARCHAR(26) NOT NULL,
      domain_id     VARCHAR(26) NOT NULL,
      localpart     VARCHAR(255) NOT NULL,
      account_id    VARCHAR(26),
      forward_to    TEXT,
      created_at    BIGINT NOT NULL
    )`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_addresses_route ON addresses(domain_id, localpart)`,

    `CREATE TABLE IF NOT EXISTS credentials (
      id            VARCHAR(26) PRIMARY KEY,
      account_id    VARCHAR(26) NOT NULL,
      kind          SMALLINT NOT NULL,
      label         VARCHAR(190),
      secret        TEXT NOT NULL,
      scopes        VARCHAR(190),
      last_used_at  BIGINT,
      created_at    BIGINT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS ix_credentials_account ON credentials(account_id)`,

    `CREATE TABLE IF NOT EXISTS api_keys (
      id            VARCHAR(26) PRIMARY KEY,
      tenant_id     VARCHAR(26) NOT NULL,
      label         VARCHAR(190),
      key_hash      VARCHAR(64) NOT NULL,
      scopes        VARCHAR(190) NOT NULL,
      created_at    BIGINT NOT NULL,
      revoked_at    BIGINT
    )`,
    `CREATE INDEX IF NOT EXISTS ix_api_keys_tenant ON api_keys(tenant_id)`,

    // ── 메일 스토어 코어 (§5) ──────────────────────────────────
    `CREATE TABLE IF NOT EXISTS mailboxes (
      id            VARCHAR(26) PRIMARY KEY,
      account_id    VARCHAR(26) NOT NULL,
      parent_id     VARCHAR(26) NOT NULL DEFAULT '',
      name          VARCHAR(255) NOT NULL,
      role          VARCHAR(20),
      status        SMALLINT NOT NULL DEFAULT 1,
      uidvalidity   BIGINT NOT NULL,
      uidnext       BIGINT NOT NULL DEFAULT 1,
      highestmodseq BIGINT NOT NULL DEFAULT 0,
      subscribed    SMALLINT NOT NULL DEFAULT 1,
      sort_order    BIGINT NOT NULL DEFAULT 0,
      total_count   BIGINT NOT NULL DEFAULT 0,
      unread_count  BIGINT NOT NULL DEFAULT 0,
      total_bytes   BIGINT NOT NULL DEFAULT 0,
      created_at    BIGINT NOT NULL
    )`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_mailboxes_name ON mailboxes(account_id, parent_id, name)`,
    `CREATE INDEX IF NOT EXISTS ix_mailboxes_account ON mailboxes(account_id)`,

    `CREATE TABLE IF NOT EXISTS messages (
      id            VARCHAR(26) PRIMARY KEY,
      account_id    VARCHAR(26) NOT NULL,
      blob_id       VARCHAR(64) NOT NULL,
      thread_id     VARCHAR(26) NOT NULL,
      modseq        BIGINT NOT NULL,
      size_bytes    BIGINT NOT NULL,
      received_at   BIGINT NOT NULL,
      subject       TEXT,
      subject_base  VARCHAR(190),
      msgid_hash    VARCHAR(32),
      sent_at       BIGINT,
      preview       TEXT,
      has_attachment SMALLINT NOT NULL DEFAULT 0,
      created_at    BIGINT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS ix_messages_account_received ON messages(account_id, received_at)`,
    `CREATE INDEX IF NOT EXISTS ix_messages_thread ON messages(account_id, thread_id)`,
    `CREATE INDEX IF NOT EXISTS ix_messages_msgid ON messages(account_id, msgid_hash)`,
    `CREATE INDEX IF NOT EXISTS ix_messages_modseq ON messages(account_id, modseq)`,

    `CREATE TABLE IF NOT EXISTS message_mailbox (
      mailbox_id    VARCHAR(26) NOT NULL,
      uid           BIGINT NOT NULL,
      message_id    VARCHAR(26) NOT NULL,
      savedate      BIGINT NOT NULL,
      deleted       SMALLINT NOT NULL DEFAULT 0,
      PRIMARY KEY (mailbox_id, uid)
    )`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_mm_message ON message_mailbox(mailbox_id, message_id)`,
    `CREATE INDEX IF NOT EXISTS ix_mm_by_message ON message_mailbox(message_id)`,

    `CREATE TABLE IF NOT EXISTS message_keywords (
      account_id    VARCHAR(26) NOT NULL,
      message_id    VARCHAR(26) NOT NULL,
      keyword       VARCHAR(190) NOT NULL,
      PRIMARY KEY (message_id, keyword)
    )`,
    `CREATE INDEX IF NOT EXISTS ix_keywords_reverse ON message_keywords(account_id, keyword)`,

    `CREATE TABLE IF NOT EXISTS message_addresses (
      account_id    VARCHAR(26) NOT NULL,
      message_id    VARCHAR(26) NOT NULL,
      kind          SMALLINT NOT NULL,
      pos           SMALLINT NOT NULL,
      name          TEXT,
      email         VARCHAR(255) NOT NULL,
      PRIMARY KEY (message_id, kind, pos)
    )`,
    `CREATE INDEX IF NOT EXISTS ix_maddr_email ON message_addresses(account_id, email, kind)`,

    `CREATE TABLE IF NOT EXISTS thread_refs (
      account_id    VARCHAR(26) NOT NULL,
      ref_hash      VARCHAR(32) NOT NULL,
      thread_id     VARCHAR(26) NOT NULL,
      created_at    BIGINT NOT NULL,
      PRIMARY KEY (account_id, ref_hash, thread_id)
    )`,

    // ── 동시성/변경로그/툼스톤 (§3, §6) ────────────────────────
    `CREATE TABLE IF NOT EXISTS modseq_claims (
      account_id  VARCHAR(26) NOT NULL,
      modseq      BIGINT   NOT NULL,
      PRIMARY KEY (account_id, modseq)
    )`,

    `CREATE TABLE IF NOT EXISTS change_log (
      account_id    VARCHAR(26) NOT NULL,
      modseq        BIGINT NOT NULL,
      entity        SMALLINT NOT NULL,
      object_id     VARCHAR(26) NOT NULL,
      kind          SMALLINT NOT NULL,
      created_at    BIGINT NOT NULL,
      PRIMARY KEY (account_id, modseq, entity, object_id)
    )`,
    `CREATE INDEX IF NOT EXISTS ix_chlog_entity ON change_log(account_id, entity, modseq)`,

    `CREATE TABLE IF NOT EXISTS expunged (
      mailbox_id    VARCHAR(26) NOT NULL,
      uid           BIGINT NOT NULL,
      modseq        BIGINT NOT NULL,
      created_at    BIGINT NOT NULL,
      PRIMARY KEY (mailbox_id, uid)
    )`,
    `CREATE INDEX IF NOT EXISTS ix_expunged_modseq ON expunged(mailbox_id, modseq)`,

    // ── 검색 (§8) ─────────────────────────────────────────────
    `CREATE TABLE IF NOT EXISTS message_text (
      message_id    VARCHAR(26) NOT NULL,
      field         SMALLINT NOT NULL,
      content       TEXT NOT NULL,
      PRIMARY KEY (message_id, field)
    )`,

    `CREATE TABLE IF NOT EXISTS search_index (
      account_id    VARCHAR(26) NOT NULL,
      token         VARCHAR(16) NOT NULL,
      field         SMALLINT NOT NULL,
      message_id    VARCHAR(26) NOT NULL,
      PRIMARY KEY (account_id, token, field, message_id)
    )`,

    // ── 발송 (§9-1) ───────────────────────────────────────────
    `CREATE TABLE IF NOT EXISTS email_submissions (
      id            VARCHAR(26) PRIMARY KEY,
      account_id    VARCHAR(26) NOT NULL,
      identity_id   VARCHAR(26) NOT NULL,
      message_id    VARCHAR(26),
      blob_id       VARCHAR(64) NOT NULL,
      env_from      VARCHAR(255) NOT NULL,
      send_at       BIGINT NOT NULL,
      undo_status   SMALLINT NOT NULL DEFAULT 0,
      created_at    BIGINT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS ix_subm_account ON email_submissions(account_id, created_at)`,

    `CREATE TABLE IF NOT EXISTS mta_queue (
      id            VARCHAR(26) PRIMARY KEY,
      tenant_id     VARCHAR(26) NOT NULL,
      account_id    VARCHAR(26) NOT NULL,
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
    `CREATE INDEX IF NOT EXISTS ix_queue_due ON mta_queue(status, next_attempt)`,
    `CREATE INDEX IF NOT EXISTS ix_queue_domain ON mta_queue(rcpt_domain, status)`,
    `CREATE INDEX IF NOT EXISTS ix_queue_account ON mta_queue(account_id, created_at)`,
    `CREATE INDEX IF NOT EXISTS ix_queue_verp ON mta_queue(verp_token)`,

    `CREATE TABLE IF NOT EXISTS identities (
      id            VARCHAR(26) PRIMARY KEY,
      account_id    VARCHAR(26) NOT NULL,
      email         VARCHAR(255) NOT NULL,
      name          TEXT,
      reply_to      TEXT,
      text_sig      TEXT,
      html_sig      TEXT,
      created_at    BIGINT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS ix_identities_account ON identities(account_id)`,

    // ── 보조 (§9-2, §9-3) ─────────────────────────────────────
    `CREATE TABLE IF NOT EXISTS suppressions (
      tenant_id     VARCHAR(26) NOT NULL,
      email         VARCHAR(255) NOT NULL,
      reason        SMALLINT NOT NULL,
      source        TEXT,
      created_at    BIGINT NOT NULL,
      PRIMARY KEY (tenant_id, email)
    )`,

    `CREATE TABLE IF NOT EXISTS dkim_keys (
      id            VARCHAR(26) PRIMARY KEY,
      domain_id     VARCHAR(26) NOT NULL,
      selector      VARCHAR(190) NOT NULL,
      algo          SMALLINT NOT NULL,
      private_key   TEXT NOT NULL,
      key_version   SMALLINT NOT NULL DEFAULT 1,
      active        SMALLINT NOT NULL DEFAULT 1,
      created_at    BIGINT NOT NULL
    )`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_dkim_selector ON dkim_keys(domain_id, selector)`,

    `CREATE TABLE IF NOT EXISTS sieve_scripts (
      id            VARCHAR(26) PRIMARY KEY,
      account_id    VARCHAR(26) NOT NULL,
      name          VARCHAR(190) NOT NULL,
      content       TEXT NOT NULL,
      active        SMALLINT NOT NULL DEFAULT 0,
      created_at    BIGINT NOT NULL
    )`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_sieve_name ON sieve_scripts(account_id, name)`,

    `CREATE TABLE IF NOT EXISTS dedup_tracking (
      account_id    VARCHAR(26) NOT NULL,
      scope         SMALLINT NOT NULL,
      key_hash      VARCHAR(32) NOT NULL,
      expires_at    BIGINT NOT NULL,
      PRIMARY KEY (account_id, scope, key_hash)
    )`,
    `CREATE INDEX IF NOT EXISTS ix_dedup_expiry ON dedup_tracking(expires_at)`,

    `CREATE TABLE IF NOT EXISTS push_subscriptions (
      id            VARCHAR(26) PRIMARY KEY,
      credential_id VARCHAR(26) NOT NULL,
      device_id     VARCHAR(190) NOT NULL,
      url           TEXT NOT NULL,
      keys_p256dh   TEXT,
      keys_auth     TEXT,
      types         VARCHAR(190),
      verified      SMALLINT NOT NULL DEFAULT 0,
      expires_at    BIGINT,
      created_at    BIGINT NOT NULL
    )`,

    `CREATE TABLE IF NOT EXISTS message_auth (
      message_id    VARCHAR(26) PRIMARY KEY,
      spf           SMALLINT,
      dkim          SMALLINT,
      dmarc         SMALLINT,
      spam_score    BIGINT,
      auth_details  TEXT
    )`,

    // ── 인프라 (§9-4) ─────────────────────────────────────────
    `CREATE TABLE IF NOT EXISTS background_jobs (
      id            VARCHAR(26) PRIMARY KEY,
      kind          SMALLINT NOT NULL,
      target_id     VARCHAR(26),
      cursor        TEXT,
      status        SMALLINT NOT NULL DEFAULT 0,
      lease_until   BIGINT,
      created_at    BIGINT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS ix_jobs_due ON background_jobs(status, lease_until)`,

    // ── 블롭 (§9-5) ───────────────────────────────────────────
    `CREATE TABLE IF NOT EXISTS blobs (
      id            VARCHAR(64) PRIMARY KEY,
      size_bytes    BIGINT NOT NULL,
      backend       SMALLINT NOT NULL DEFAULT 0,
      status        SMALLINT NOT NULL DEFAULT 0,
      generation    BIGINT NOT NULL DEFAULT 0,
      doomed_at     BIGINT,
      created_at    BIGINT NOT NULL
    )`,

    `CREATE TABLE IF NOT EXISTS blob_refs (
      blob_id       VARCHAR(64) NOT NULL,
      account_id    VARCHAR(26) NOT NULL,
      ref_kind      SMALLINT NOT NULL,
      ref_id        VARCHAR(26) NOT NULL,
      created_at    BIGINT NOT NULL,
      PRIMARY KEY (blob_id, ref_kind, ref_id)
    )`,
    `CREATE INDEX IF NOT EXISTS ix_blob_refs_account ON blob_refs(account_id, blob_id)`,
  ],
};
