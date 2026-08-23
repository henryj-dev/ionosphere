/**
 * suppression(수신자 차단)의 수명 정책 — **정하는 쪽과 판정하는 쪽을 같이 둔다.**
 *
 * 만료 시각은 워커가 적재할 때 쓰고(worker.ts), 만료 여부는 게이트가 발송 전에 본다
 * (enqueue.ts). 둘이 떨어져 있으면 한쪽만 고쳐져 "만료를 넣었는데 아무도 안 본다"거나
 * 그 반대가 된다 — 이 저장소가 반복해 겪은 종류다.
 */
import { SUPPRESSION_REASON, type SuppressionReason } from "@ionosphere/db";

/**
 * `exhausted` 차단의 수명.
 *
 * 7일인 이유: 이 사유는 **상대의 영구 거절이 아니라 우리가 포기한 것**이다(재시도 상한 소진).
 * 원인이 우리 쪽 DNS·네트워크 장애일 수 있는데, 지금까지는 hardBounce와 똑같이 영구로 남아
 * 장애가 복구돼도 그때 큐에 있던 정상 수신자가 영영 막혔다.
 *
 * 재시도 자체가 이미 하루 이상 걸린다(기본 8회 × 최대 4h 백오프). 그 위에 7일을 얹으면
 * 웬만한 일시 장애보다는 길고, 정상 수신자를 영구히 잠그지는 않는 길이가 된다.
 * 더 짧으면 장애가 이어지는 동안 같은 주소로 큐를 계속 채우고, 더 길면 오탐의 대가가 커진다.
 */
export const SUPPRESSION_EXHAUSTED_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * 이 사유의 차단이 언제 풀려야 하는가. `null`이면 만료 없음(영구).
 *
 * hardBounce는 상대가 5xx로 영구 거절한 것이라 다시 보내도 같은 답이다 — 만료시키지 않는다.
 * 운영자가 판단해 해제 API로 지우는 경로는 그대로 남아 있다.
 */
export function suppressionExpiresAt(reason: SuppressionReason, now: number): number | null {
  return reason === SUPPRESSION_REASON.exhausted ? now + SUPPRESSION_EXHAUSTED_TTL_MS : null;
}

/**
 * "아직 유효한 차단인가"를 묻는 WHERE 절 조각.
 *
 * 문자열로 내보내는 이유: 이 조건이 게이트 질의에 인라인돼야 하는데, 조건을 호출부가 직접
 * 적으면 `expires_at IS NULL`을 빠뜨린 순간 **만료되지 않은 차단까지 통과**한다.
 * 자리표시자 하나(`?`)를 쓰며 현재 시각을 받는다.
 */
export const ACTIVE_SUPPRESSION_CLAUSE = "(expires_at IS NULL OR expires_at > ?)";
