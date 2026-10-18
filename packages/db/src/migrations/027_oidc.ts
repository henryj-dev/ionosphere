import type { Migration } from "../migrate.ts";

/**
 * 외부 OIDC 웹 로그인 (2026-10-18 회원 정책 E3).
 *
 * - `admin_identities`: 관리 콘솔 관리자의 외부 신원(issuer 설정 id + sub) → admin_users. 사용자 결정으로 따로 둔다 —
 *   `directory_identities`는 메일 계정(account_id)과 테넌트를 전제하는데, 운영자 관리자는 테넌트가 없다.
 *   메일 계정 쪽은 결정 D5대로 `directory_identities`(provider=`oidc:<id>`)를 쓴다.
 * - 연결은 관리자가 명시적으로 한다(자동 연결·JIT 없음). 이메일 클레임으로 찾지 않는다 — 키는 언제나 sub다.
 * - `oidc_login_states`: 인가 요청 하나의 state·nonce·PKCE verifier. 1회용이고 짧게 만료된다. 서버에 두는 이유는
 *   인스턴스가 여럿이어도 콜백이 어느 인스턴스로 와도 되게 하기 위해서다(프로세스 메모리는 안 된다).
 */
export const m027Oidc: Migration = {
  version: 27,
  name: "oidc web login",
  statements: [
    `CREATE TABLE IF NOT EXISTS admin_identities (
      provider       VARCHAR(64) NOT NULL,
      subject        VARCHAR(255) NOT NULL,
      admin_user_id  VARCHAR(26) NOT NULL,
      created_at     BIGINT NOT NULL,
      PRIMARY KEY (provider, subject)
    )`,
    // 한 관리자는 한 공급자에 신원 하나만 — 둘 이상이면 어느 sub가 그 사람인지 흐려진다(directory 024와 같은 이유).
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_admin_identities_user ON admin_identities(provider, admin_user_id)",
    `CREATE TABLE IF NOT EXISTS oidc_login_states (
      state_hash     VARCHAR(64) PRIMARY KEY,
      provider       VARCHAR(64) NOT NULL,
      realm          VARCHAR(16) NOT NULL,
      nonce          VARCHAR(64) NOT NULL,
      code_verifier  VARCHAR(128) NOT NULL,
      created_at     BIGINT NOT NULL,
      expires_at     BIGINT NOT NULL
    )`,
  ],
};
