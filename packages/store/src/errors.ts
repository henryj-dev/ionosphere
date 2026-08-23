/**
 * 스토어 에러 표면 — SCHEMA.md §3-3/§7-8 재시도 계약의 코드 표면.
 *
 * 두 종류의 실패를 명확히 구분한다 (§7-8):
 * - 재시도 가능한 클레임 경합(BatchConflictError) → 상한(N회) 소진 시 StoreConflictError
 * - 스냅샷에서 재검증한 전제조건 자체가 실패(이름 충돌·쿼터 초과 등) → 즉시 StoreError 계열,
 *   재시도 루프에 진입하지 않음(무한 재시도 방지)
 */
export class StoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StoreError";
  }
}

/** 재시도 상한(§3-3) 도달 — 배치 클레임 경합이 지속됨. */
export class StoreConflictError extends StoreError {
  override readonly cause: unknown;

  constructor(message: string, cause: unknown) {
    super(message);
    this.name = "StoreConflictError";
    this.cause = cause;
  }
}

/** 쿼터 초과 (§7-1: used_bytes + size <= quota_bytes, quota_bytes > 0일 때만 강제). */
export class StoreQuotaError extends StoreError {
  constructor(message: string) {
    super(message);
    this.name = "StoreQuotaError";
  }
}
