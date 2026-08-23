import type { Migration } from "../migrate.ts";

/**
 * 010 — 계정별 베이즈 토큰 카운트.
 *
 * PLAN §3이 점수 엔진의 축으로 적은 Bayes를 위한 저장소다. §8의 "운영자는 사용자 메일
 * 내용을 열람하지 않는다"와 양립시키는 장치가 스키마에 들어 있다:
 *
 *  ① `token`은 **해시**다(HMAC + 계정별 솔트, 16자). DB를 열어도 읽을 수 있는 단어가
 *     없어서 남의 메일 내용을 복원할 수 없다. 이것이 "열람하지 않는다"의 실질이다.
 *  ② PK가 `(account_id, token)`이라 **계정 경계를 넘지 않는다**. 전역 코퍼스를 만들면
 *     한 사람의 메일이 다른 사람의 판정에 영향을 준다.
 *
 * ★계정별 솔트는 별도 컬럼이 아니라 `accounts.id`에서 유도한다 — 새 비밀을 관리 대상에
 * 추가하지 않으려는 것이다. 솔트의 목적은 **계정 간 사전 재사용 차단**이지 비밀 유지가
 * 아니라, 계정 식별자로 충분하다.
 *
 * `bayes_totals`가 따로 있는 이유: 사전 확률과 "학습 부족" 판정에 **메시지 건수**가 필요한데,
 * 토큰 테이블에서 세면 토큰 수를 세는 것이지 메시지 수를 세는 게 아니다.
 */
export const m010BayesTokens: Migration = {
  version: 10,
  name: "bayes-tokens",
  statements: [
    `CREATE TABLE IF NOT EXISTS bayes_tokens (
      account_id  VARCHAR(26) NOT NULL,
      token       VARCHAR(24) NOT NULL,
      spam_count  INTEGER NOT NULL DEFAULT 0,
      ham_count   INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (account_id, token)
    )`,
    `CREATE TABLE IF NOT EXISTS bayes_totals (
      account_id  VARCHAR(26) PRIMARY KEY,
      spam_msgs   INTEGER NOT NULL DEFAULT 0,
      ham_msgs    INTEGER NOT NULL DEFAULT 0
    )`,
  ],
};
