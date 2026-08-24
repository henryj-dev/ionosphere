import type { Migration } from "../migrate.ts";

/**
 * 015 — JMAP `VacationResponse`(RFC 8621 §8)의 저장. 계정당 **한 행**(싱글턴 객체다).
 *
 * ★Sieve `vacation`과 **같은 게이트를 쓴다.** 두 벌로 두면 Sieve 스크립트에도 vacation이
 * 있고 여기에도 켜져 있는 계정이 상대에게 **답장을 두 번** 보낸다. 그래서 이 테이블은
 * "설정"만 갖고, 보낼지 말지의 판정(RFC 5230 §4.6 루프 방지)과 중복 억제(`vacation_sent`)는
 * 배달 경로가 이미 가진 것을 그대로 쓴다.
 *
 * ★Sieve 스크립트를 **생성하지 않는다.** 생성해 두면 `/get`에서 그걸 다시 파싱해야 하고,
 * 그러면 사용자가 손으로 고친 스크립트를 우리가 덮어쓰거나 잘못 읽는 갈래가 생긴다.
 * 구조화된 값은 구조화된 채로 둔다.
 *
 * 우선순위: **Sieve 스크립트가 이긴다.** 스크립트는 사용자가 명시적으로 쓴 규칙이고
 * 조건 분기까지 담을 수 있어 더 구체적이다. 이 테이블은 그런 스크립트가 없을 때의 설정이다.
 *
 * `from_date`/`to_date`는 JMAP에만 있는 개념이라(§8: 이 창 밖에서는 응답하지 않는다)
 * 여기서만 검사한다. NULL은 "제한 없음"이다.
 */
export const m015VacationResponse: Migration = {
  version: 15,
  name: "vacation_response",
  statements: [
    `CREATE TABLE IF NOT EXISTS vacation_response (
      account_id  VARCHAR(26) NOT NULL,
      is_enabled  SMALLINT NOT NULL DEFAULT 0,
      from_date   BIGINT,
      to_date     BIGINT,
      subject     TEXT,
      text_body   TEXT,
      html_body   TEXT,
      updated_at  BIGINT NOT NULL,
      PRIMARY KEY (account_id)
    )`,
  ],
};
