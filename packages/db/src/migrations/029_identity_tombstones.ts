import type { Migration } from "../migrate.ts";

/**
 * 외부 SSO 연결 식별자 묘비 (2026-10-18 회원 공통 수치 결정 9: "SSO 연결 식별자(iss+sub)는 재사용 방지를 위해 남긴다").
 *
 * 연결을 끊으면 예전에는 행을 지웠다. 그러면 같은 sub를 **다른 주체**(다른 관리자·다른 메일 계정)에 다시 연결할 수 있었다 —
 * IdP 쪽에서 계정이 재활용되거나(퇴사자 sub를 신입에게) 운영자가 실수하면, 예전 사람의 IdP 로그인이 새 주체로 들어온다.
 * 그래서 끊을 때 (영역, 공급자, sub, 원래 주인)을 남기고, 다른 주체에 다시 연결하는 것을 거절한다. 원래 주인에게 다시
 * 연결하는 것은 허용한다(실수로 끊은 것을 되돌릴 수 있어야 한다).
 *
 * - `realm`: "admin"(관리 콘솔 관리자, `admin_identities`) 또는 "account"(메일 계정, `directory_identities`의 `oidc:` 행).
 * - `provider`: 설정의 공급자 id다. issuer는 공급자 설정이 고정하므로(설정 하나 = issuer 하나) 결정의 "iss"는 이것으로 대신한다.
 * - 개인정보가 아니라 IdP의 불투명 식별자뿐이다 — 탈퇴 뒤에도 남겨 둔다(같은 결정).
 */
export const m029IdentityTombstones: Migration = {
  version: 29,
  name: "sso identity tombstones",
  statements: [
    `CREATE TABLE IF NOT EXISTS identity_tombstones (
      realm        VARCHAR(16) NOT NULL,
      provider     VARCHAR(64) NOT NULL,
      subject      VARCHAR(255) NOT NULL,
      owner_id     VARCHAR(26) NOT NULL,
      retired_at   BIGINT NOT NULL,
      PRIMARY KEY (realm, provider, subject)
    )`,
  ],
};
