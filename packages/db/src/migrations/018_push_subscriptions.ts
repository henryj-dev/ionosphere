import type { Migration } from "../migrate.ts";

/**
 * 018 — JMAP `PushSubscription` (RFC 8620 §7.2)을 **실제로 쓸 수 있는 모양**으로 만든다.
 *
 * ## 이 테이블은 001부터 있었지만 죽어 있었다
 *
 * `push_subscriptions`는 초기 스키마에 DDL만 있고 **읽지도 쓰지도 않았다** — `credentials.scopes`
 * (감사 G1)와 같은 부류다. 기능을 붙이면서 두 번째 테이블을 만들면 그 죽은 것이 영원히 남고,
 * 다음 사람이 어느 쪽이 진짜인지 알 수 없다. 그래서 **이것을 고쳐 쓴다.**
 *
 * ★`DROP` 후 재생성이 안전한 이유: 어떤 코드도 이 테이블에 행을 넣은 적이 없다(위 문단).
 * 003·006의 재빌드처럼 데이터를 옮길 필요가 없다 — 옮길 데이터가 없다.
 *
 * ## 컬럼이 왜 이렇게 바뀌나
 *
 *  · `credential_id` → `subject_id`. 구독은 **사용자**에 묶인다(§7.2: "not tied to an
 *    Account"). 자격증명에 묶으면 앱 비밀번호를 바꿀 때마다 구독이 끊긴다.
 *  · `device_id` → `device_client_id`. 규격의 이름 그대로다(§7.2.1). 이름이 다르면 다음
 *    사람이 "규격의 그 값이 맞나"를 매번 확인해야 한다.
 *  · `verified`(불리언) → `verified_at`(시각). 언제 확인됐는지가 진단에 필요하다 —
 *    `last_used_at`·`delay_notified_at`이 시각인 것과 같은 규율이다.
 *  · **`verification_code` 추가.** 이게 없어서 §7.2.2의 확인 절차 자체를 구현할 수 없었다.
 *    그 절차가 "이 URL이 정말 구독자의 것인가"를 증명하는 유일한 장치다 — 없으면 우리는
 *    **누구든 지정한 URL로 POST하는 도구**가 된다.
 *  · `expires_at`(NULL 허용) → `expires`(NOT NULL). 만료가 없으면 죽은 엔드포인트로 영원히
 *    POST하게 되고, 그건 우리가 남에게 보내는 무한 트래픽이다. §7.2.1이 서버 상한을 허용한다.
 *
 * ★`(subject_id, device_client_id)` 유일 인덱스가 새로 생긴다. 같은 기기가 다시 등록하면
 * 새 구독이 아니라 **교체**여야 한다(§7.2.1) — 아니면 앱을 다시 깔 때마다 죽은 구독이 쌓이고
 * 우리는 그 전부에 POST를 계속한다.
 */
export const m018PushSubscriptions: Migration = {
  version: 18,
  name: "push_subscriptions",
  statements: [
    // 부분 실패 재실행 대비(003·006과 같은 형태) — 남은 잔재를 먼저 치운다.
    `DROP TABLE IF EXISTS push_subscriptions`,
    `CREATE TABLE push_subscriptions (
      id                VARCHAR(26) PRIMARY KEY,
      subject_id        VARCHAR(26) NOT NULL,
      device_client_id  VARCHAR(255) NOT NULL,
      url               TEXT NOT NULL,
      keys_p256dh       VARCHAR(128),
      keys_auth         VARCHAR(32),
      verification_code VARCHAR(64) NOT NULL,
      verified_at       BIGINT,
      expires           BIGINT NOT NULL,
      types             TEXT,
      created_at        BIGINT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS ix_push_subject ON push_subscriptions(subject_id)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_push_device ON push_subscriptions(subject_id, device_client_id)`,
    `CREATE INDEX IF NOT EXISTS ix_push_expires ON push_subscriptions(expires)`,
  ],
};
