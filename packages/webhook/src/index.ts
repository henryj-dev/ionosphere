// @ionosphere/webhook — 수신 웹훅 배달 워커(재시도·HMAC 서명). Phase 4.
export { WebhookWorker, type WebhookWorkerOptions, type FetchFn } from "./worker.ts";
// 등록 API를 만들 때 **등록 시점에도** 이 관문을 통과시킬 것(배달 시점 검사는 워커가 별도로 한다).
export { isAllowedWebhookUrl, isBlockedAddress, BlockedAddressError } from "./url-guard.ts";
