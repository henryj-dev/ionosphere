import type { Migration } from "../migrate.ts";

/**
 * 005 — POP3 maildrop 배타 잠금 테이블(계정당 1행).
 *
 * 왜 필요한가: 지금까지 배타성은 프로세스 메모리의 `Set` 하나(InProcessMaildropLock)였다.
 * MRA를 2대 이상 띄우거나 같은 프로세스에서 110/995 백엔드를 따로 만드는 순간(현 app.ts가 그렇다)
 * 락이 서로를 못 본다 → RFC 1939 §3의 배타 접근 계약이 깨지고 `[IN-USE]`가 영영 안 나온다.
 * 그 결과가 조용한 데이터 사고다: 세션 A가 QUIT하며 DELE·expunge한 메시지를 세션 B가 RETR하면
 * 백엔드가 "message vanished"로 터진다(apps/server/src/backend.ts).
 *
 * 스키마 결정:
 *  · account_id를 PK로 둔다 — "계정당 최대 하나"라는 불변식을 **DB가** 강제하게 만들어야
 *    획득이 단일 문장 check-and-set(INSERT 충돌 = 패배)으로 원자화된다. 애플리케이션이
 *    SELECT 후 INSERT하는 방식은 두 MRA 사이에서 항상 진다.
 *  · owner — 세션 식별자. 해제·갱신을 `AND owner = ?`로 가드해 **자기 락만** 건드리게 한다.
 *    POP3 어댑터는 연결이 끊기면 항상 release를 부르므로, 가드가 없으면 락을 못 잡은 세션이
 *    끊길 때 남의 락을 푼다.
 *  · expires_at — 크래시한 MRA가 계정을 영원히 잠그는 것을 막는 TTL. 살아 있는 세션을
 *    뺏지 않도록 값 선택 근거는 packages/store/src/maildrop-lock.ts 주석 참고.
 *
 * schema_lock(마이그레이션 락)과 형태가 같지만 별도 테이블인 이유: 수명(부팅 몇 초 vs 세션 수십 분)과
 * 키(단일 상수 vs 계정)가 다르고, 마이그레이션 락 행이 계정 락 트래픽에 섞이면 안 된다.
 *
 * D1(비트랜잭셔널 DDL) 재개 안전: 문장이 IF NOT EXISTS 하나뿐이라 멱등.
 */
export const m005MaildropLock: Migration = {
  version: 5,
  name: "maildrop_lock",
  statements: [
    `CREATE TABLE IF NOT EXISTS maildrop_locks (
      account_id VARCHAR(26) PRIMARY KEY,
      owner      VARCHAR(64) NOT NULL,
      expires_at BIGINT NOT NULL
    )`,
  ],
};
