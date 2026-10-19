import type { Migration } from "../migrate.ts";

/**
 * 인증 실패 카운터 — 서버 여러 대가 함께 센다 (2026-10-18 회원 공통 수치 1차, 결정 3).
 *
 * 예전 스로틀은 프로세스 메모리였다. 서버가 세 대면 공격자는 한도를 세 배로 받았다 — 요청이
 * 어느 인스턴스에 닿느냐에 따라 따로 셌기 때문이다. 그래서 카운터를 공유 DB로 옮긴다.
 *
 * - `bucket`: 축 접두사가 붙은 키(`ip|<프리픽스>`, `account|<사용자명>`). `key`라는 이름은 MySQL 예약어라 피했다.
 * - 쓰기는 **실패할 때만** 한다. 성공한 로그인은 카운터가 있을 때만 지운다 — 정상 로그인마다 쓰기가 끼지 않게.
 * - 오래된 행은 스로틀이 주기적으로 지운다(마지막 실패 뒤 초기화 시간이 지난 것).
 */
export const m028AuthFailures: Migration = {
  version: 28,
  name: "shared auth failure counters",
  statements: [
    `CREATE TABLE IF NOT EXISTS auth_failures (
      bucket        VARCHAR(300) PRIMARY KEY,
      fails         INTEGER NOT NULL,
      last_fail_at  BIGINT NOT NULL
    )`,
    "CREATE INDEX IF NOT EXISTS ix_auth_failures_last ON auth_failures(last_fail_at)",
  ],
};
