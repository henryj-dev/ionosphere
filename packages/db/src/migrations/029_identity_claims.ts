import type { Migration } from "../migrate.ts";

/**
 * 외부 SSO 연결 식별자의 최초 주인 기록 (2026-10-18 회원 공통 수치 결정 9: "SSO 연결 식별자(iss+sub)는 재사용 방지를 위해 남긴다").
 *
 * 연결을 끊으면 예전에는 행을 지웠다. 그러면 같은 sub를 **다른 주체**(다른 관리자·다른 메일 계정)에 다시 연결할 수 있었다 —
 * IdP 쪽에서 계정이 재활용되거나(퇴사자 sub를 신입에게) 운영자가 실수하면, 예전 사람의 IdP 로그인이 새 주체로 들어온다.
 *
 * 그래서 sub를 **처음 연결할 때** 주인을 기록하고 지우지 않는다. 연결은 그 기록의 주인이 나일 때만 들어간다 — 같은 배치 안의
 * 판정이라, "묘비를 읽은 뒤 연결을 넣는" 사이에 해제가 끼어 재사용되는 경합이 없다(2026-10-19 리뷰). 원래 주인에게 다시 잇는
 * 것은 허용한다(실수로 끊은 것을 되돌릴 수 있어야 한다).
 *
 * - `realm`: "admin"(관리 콘솔 관리자), "account"(메일 계정 OIDC), "directory"(LDAP/AD 외부 키 묘비).
 * - `provider`: 설정의 공급자 id다. issuer는 공급자 설정이 고정하고, 같은 영역에서 같은 issuer를 두 id로 쓰는 설정은 기동이
 *   거부한다(`oidc-config.ts`). 그래서 결정의 "iss"는 이것으로 대신한다. ⚠ 공급자 id를 바꾸거나 다른 IdP에 다시 쓰지 말 것.
 * - account 영역도 테넌트와 무관하게 전역이다 — 공급자의 테넌트를 옮겨도 "iss+sub는 하나"라는 결정을 그대로 지킨다.
 * - 개인정보가 아니라 IdP의 불투명 식별자뿐이다 — 탈퇴 뒤에도 남겨 둔다(같은 결정).
 * - 2026-10-19부터 LDAP/AD 디렉터리 연결도 같은 표에 realm="directory"로 남긴다. 계정 드레인·연결 해제 뒤
 *   다음 동기화가 같은 외부 키를 다른 계정에 잇는 것을 막는다. 외부 키 원문 대신 SHA-256만 저장한다.
 *   029 당시 연결은 별도 backfill하지 않는다 — 해제·드레인이 행을 지우는 같은 배치에서 먼저 기록한다.
 *
 * 이미 있는 연결은 그 주인으로 옮겨 적는다(account 영역은 테넌트가 달라도 같은 sub면 하나만 — 가장 작은 계정 id).
 * 마이그레이션은 문장 단위로 다시 돌 수 있으므로 옮겨 적기는 NOT EXISTS로 멱등이다.
 */
export const m029IdentityClaims: Migration = {
  version: 29,
  name: "sso identity claims",
  statements: [
    `CREATE TABLE IF NOT EXISTS identity_claims (
      realm        VARCHAR(16) NOT NULL,
      provider     VARCHAR(64) NOT NULL,
      subject      VARCHAR(255) NOT NULL,
      owner_id     VARCHAR(26) NOT NULL,
      claimed_at   BIGINT NOT NULL,
      PRIMARY KEY (realm, provider, subject)
    )`,
    `INSERT INTO identity_claims (realm, provider, subject, owner_id, claimed_at)
       SELECT 'admin', a.provider, a.subject, a.admin_user_id, a.created_at FROM admin_identities a
        WHERE NOT EXISTS (SELECT 1 FROM identity_claims c WHERE c.realm = 'admin' AND c.provider = a.provider AND c.subject = a.subject)`,
    `INSERT INTO identity_claims (realm, provider, subject, owner_id, claimed_at)
       SELECT 'account', d.provider, d.external_key, MIN(d.account_id), COALESCE(MIN(d.last_seen_at), 0)
         FROM directory_identities d
        WHERE d.provider LIKE 'oidc:%' AND d.account_id IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM identity_claims c WHERE c.realm = 'account' AND c.provider = d.provider AND c.subject = d.external_key)
        GROUP BY d.provider, d.external_key`,
  ],
};
