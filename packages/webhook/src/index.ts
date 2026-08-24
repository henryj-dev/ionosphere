// @ionosphere/webhook — 수신 웹훅 배달 워커(재시도·HMAC 서명). Phase 4.
export { WebhookWorker, type WebhookWorkerOptions, type FetchFn } from "./worker.ts";
// 등록 API를 만들 때 **등록 시점에도** 이 관문을 통과시킬 것(배달 시점 검사는 워커가 별도로 한다).
export { isAllowedWebhookUrl, isBlockedAddress, BlockedAddressError } from "./url-guard.ts";
/**
 * 가드가 걸린 fetch — **사용자가 준 URL로 나가는 모든 경로**가 이것을 써야 한다.
 *
 * ★JMAP `PushSubscription`(RFC 8620 §7.2)도 사용자 URL로 POST한다. 거기서 가드를 새로
 * 구현하면 두 벌이 되고, 우회 표기가 하나 발견될 때 한쪽만 고쳐진다 — `url-guard.ts` 머리
 * 주석이 적은 우회 목록이 그 위험의 크기다.
 */
export { createGuardedFetch, createGuardedLookup, type GuardedFetchOptions, type ResolveHostFn } from "./http-client.ts";
