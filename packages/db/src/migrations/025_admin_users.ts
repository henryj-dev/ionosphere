import type { Migration } from "../migrate.ts";

/**
 * 관리 콘솔 사람 주체와 서버측 세션 (2026-10-18 회원 정책 E1, 결정 D1).
 *
 * ★메일 계정(`accounts`)과 **분리한다.** 메일 비밀번호는 IMAP·SMTP 클라이언트마다 저장되어 새기 쉬운
 * 자격증명이라, 그것이 곧 관리 권한이면 메일 클라이언트 하나가 털릴 때 테넌트 관리가 함께 넘어간다.
 * 반대로 메일 계정을 정지·삭제해도 관리자 접근이 같이 끊기지 않는다.
 *
 * ★세션은 서버에 둔다. 서명 토큰만으로는 로그아웃·정지·역할 하향을 "다음 보호 요청부터" 반영할 수
 * 없고(공통 기준 3), 인스턴스가 여럿이면 프로세스 메모리로도 안 된다. 토큰 원문은 저장하지 않는다 —
 * `id`가 sha256(토큰)이라 DB가 새어도 세션을 가로챌 수 없다(api_keys.key_hash와 같은 규율).
 */
export const m025AdminUsers: Migration = {
  version: 25,
  name: "admin users and sessions",
  statements: [
    `CREATE TABLE IF NOT EXISTS admin_users (
      id                  VARCHAR(26) PRIMARY KEY,
      tenant_id           VARCHAR(26),
      username            VARCHAR(255) NOT NULL,
      display_name        VARCHAR(255),
      role                SMALLINT NOT NULL,
      status              SMALLINT NOT NULL DEFAULT 1,
      password_hash       TEXT,
      totp_secret         TEXT,
      totp_pending_secret TEXT,
      totp_last_step      BIGINT,
      created_at          BIGINT NOT NULL,
      updated_at          BIGINT NOT NULL
    )`,
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_admin_users_username ON admin_users(username)",
    "CREATE INDEX IF NOT EXISTS ix_admin_users_tenant ON admin_users(tenant_id)",
    `CREATE TABLE IF NOT EXISTS admin_sessions (
      id             VARCHAR(64) PRIMARY KEY,
      admin_user_id  VARCHAR(26) NOT NULL,
      csrf_hash      VARCHAR(64) NOT NULL,
      created_at     BIGINT NOT NULL,
      last_seen_at   BIGINT NOT NULL,
      mfa_at         BIGINT,
      revoked_at     BIGINT
    )`,
    "CREATE INDEX IF NOT EXISTS ix_admin_sessions_user ON admin_sessions(admin_user_id)",
  ],
};
