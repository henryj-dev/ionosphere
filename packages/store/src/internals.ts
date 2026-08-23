/**
 * 스토어 내부 공유 표면 — 하위 스토어 모듈(Sieve·웹훅·과금·JMAP)이 받는 **최소 계약**.
 *
 * Store 한 클래스가 1700줄을 넘기며 메일함/메시지뿐 아니라 JMAP 프로토콜 의미론·Sieve 스크립트
 * 저장소·웹훅 엔드포인트·SaaS 과금까지 담고 있었다. 그 결과 "JMAP 필터 추가" 같은 프로토콜
 * 변경이 IMAP/POP3까지 쓰는 스토어 파일을 건드리게 됐다(응집도 문제).
 *
 * 관심사별로 파일을 나누되 **공개 API는 그대로 유지**한다 — Store가 얇게 위임하므로
 * 호출부는 바뀌지 않는다(대규모 호출부 변경은 그 자체가 위험).
 */
import type { DbDriver } from "@ionosphere/db";
import type { WriterQueue } from "./writer-queue.ts";

/** 계정의 낙관적 락·쿼터 스냅샷(§7-1). */
export interface AccountSnapshot {
  modseq: number;
  quotaBytes: number;
  usedBytes: number;
  uidvalidityLast: number;
}

/** 하위 모듈이 쓰는 Store 내부 자원. Store가 생성자에서 자신을 어댑팅해 넘긴다. */
export interface StoreInternals {
  readonly db: DbDriver;
  /**
   * DB 보관 비밀의 봉인 키(secretbox). undefined면 `plain$` 평문 저장 —
   * 하위 모듈은 이 값을 그대로 `seal()`/`open()`에 넘긴다(자체 판단 금지).
   */
  readonly masterKey: string | undefined;
  /** 계정별 쓰기 직렬화 큐. */
  readonly writer: WriterQueue;
  /** 낙관적 락 충돌 시 재시도. */
  withRetry<T>(fn: () => Promise<T>): Promise<T>;
  /** 계정 스냅샷 조회(없으면 StoreError). */
  mustGetAccount(accountId: string): Promise<AccountSnapshot>;
}
