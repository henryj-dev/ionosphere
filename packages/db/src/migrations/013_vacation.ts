import type { Migration } from "../migrate.ts";

/**
 * 013 — Sieve `vacation`(RFC 5230)의 **중복 억제** 기록.
 *
 * ★이 테이블이 vacation의 절반이다. 자동 응답은 "보내는 것"보다 **안 보내는 것**이 어렵다:
 * 같은 사람에게 계속 답하면 그건 자동 응답이 아니라 스팸이고, 상대도 자동 응답이면 둘이
 * 무한히 주고받는다. RFC 5230 §4.5가 `:days`(기본 7일) 안에는 **같은 수신자에게 한 번만**
 * 보내라고 요구하는 이유다.
 *
 * 컬럼 선택:
 *  · `recipient_hash` — 원 발신자 주소를 **해시로** 둔다. 이 테이블은 "누가 이 사람에게
 *    메일을 보냈나"의 목록이라 평문으로 두면 그 자체가 열람 대상이 된다. 판정에 필요한 것은
 *    동일성뿐이고 원문은 필요 없다(§8의 "운영자는 사용자 메일 내용을 열람하지 않는다"와
 *    같은 취지 — `bayes_tokens`가 토큰을 해시로 두는 것과 같은 규율).
 *  · `handle_hash` — `:handle`은 "같은 부재 응답인가"를 사용자가 정하는 값이다. 스크립트를
 *    고쳐도 핸들이 같으면 억제가 이어져야 하고(§4.4), 다르면 새로 센다.
 *  · PK가 셋 다 — 계정 경계를 넘지 않고(다른 계정의 응답 이력이 판정에 섞이면 안 된다)
 *    같은 (핸들, 수신자)는 한 행이다.
 *
 * `expires_at`을 따로 두는 이유: `:days`가 스크립트마다 다르므로 "언제까지 억제인가"를
 * 기록 시점에 확정해야 한다. 조회가 `expires_at > now` 하나로 끝나고, 보존 스윕도 같은
 * 컬럼으로 자른다.
 */
export const m013Vacation: Migration = {
  version: 13,
  name: "vacation",
  statements: [
    `CREATE TABLE IF NOT EXISTS vacation_sent (
      account_id     VARCHAR(26) NOT NULL,
      handle_hash    VARCHAR(32) NOT NULL,
      recipient_hash VARCHAR(32) NOT NULL,
      sent_at        BIGINT NOT NULL,
      expires_at     BIGINT NOT NULL,
      PRIMARY KEY (account_id, handle_hash, recipient_hash)
    )`,
    `CREATE INDEX IF NOT EXISTS ix_vacation_expiry ON vacation_sent(expires_at)`,
  ],
};
