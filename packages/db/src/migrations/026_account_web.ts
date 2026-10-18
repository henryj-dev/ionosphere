import type { Migration } from "../migrate.ts";

/**
 * 메일 계정 셀프서비스 — 두 번째 요소와 서버측 세션 (2026-10-18 회원 정책 E2).
 *
 * 규칙은 관리자(025)와 같고 정본도 하나다(`store/web-mfa.ts`의 영역 `ACCOUNT_REALM`). 칸 이름을 025와 똑같이 둔 이유가
 * 그것이다 — 같은 SQL이 두 영역에서 돈다.
 *
 * MFA 칸을 `accounts`에 붙이지 않고 따로 둔 이유: `accounts`는 메일 스토어의 핵심 행이라 매 배달·클레임 배치가 건드린다.
 * 셀프서비스를 쓰는 계정은 일부라 대부분의 행에 빈 칸만 늘어나고, 핫 행에 쓰기가 끼면 경합만 커진다.
 *
 * 계정이 정지·삭제 중이면 모든 경로가 `accounts.status = 1`을 보므로 이 행들은 쓰이지 않는다. 지우는 것은
 * 삭제 드레인의 몫이다(credentials와 같은 처지 — 지금 리퍼는 둘 다 정리하지 않는다).
 */
export const m026AccountWeb: Migration = {
  version: 26,
  name: "account web self-service",
  statements: [
    `CREATE TABLE IF NOT EXISTS account_mfa (
      account_id             VARCHAR(26) PRIMARY KEY,
      totp_secret            TEXT,
      totp_pending_secret    TEXT,
      totp_last_step         BIGINT,
      totp_failures          INTEGER NOT NULL DEFAULT 0,
      totp_locked_until      BIGINT,
      enroll_code_hash       VARCHAR(64),
      enroll_code_expires_at BIGINT,
      updated_at             BIGINT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS account_sessions (
      id             VARCHAR(64) PRIMARY KEY,
      account_id     VARCHAR(26) NOT NULL,
      csrf_hash      VARCHAR(64) NOT NULL,
      created_at     BIGINT NOT NULL,
      last_seen_at   BIGINT NOT NULL,
      mfa_at         BIGINT,
      revoked_at     BIGINT
    )`,
    "CREATE INDEX IF NOT EXISTS ix_account_sessions_account ON account_sessions(account_id)",
    `CREATE TABLE IF NOT EXISTS account_recovery_codes (
      account_id     VARCHAR(26) NOT NULL,
      code_hash      VARCHAR(64) NOT NULL,
      created_at     BIGINT NOT NULL,
      used_at        BIGINT,
      PRIMARY KEY (account_id, code_hash)
    )`,
  ],
};
