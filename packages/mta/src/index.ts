// @ionosphere/mta — 발신(outbound) 메일: 큐 적재, 워커, SMTP 클라이언트, DKIM 훅, abuse 모니터링.
export {
  enqueueMessage,
  OutboundRejectedError,
  DEFAULT_RATE_LIMIT,
  DEFAULT_RELAY_PER_HOUR,
  type SystemRelay,
  type EnqueueInput,
  type EnqueueOptions,
  type EnqueueResult,
  type EnqueueSkipped,
  type OutboundPolicy,
  type RateLimitConfig,
} from "./enqueue.ts";
export { sendSmtp, type RcptOutcome, type SmtpAuth, type SmtpClientOptions, type SmtpClientResult, type TlsMode } from "./smtp-client.ts";
export {
  MtaWorker,
  type BlobReader,
  type DeliveryOutcome,
  type DkimHook,
  type DkimKeyLookup,
  type MtaWorkerOptions,
  type MxRecord,
  type TlsaLookup,
} from "./worker.ts";
export {
  SMARTHOST_TLS_CODE,
  SMARTHOST_TLS_MODE,
  type SmarthostOptions,
  type SmarthostResolver,
} from "./smarthost.ts";
export { SUPPRESSION_EXHAUSTED_TTL_MS, suppressionExpiresAt, ACTIVE_SUPPRESSION_CLAUSE } from "./suppression.ts";
export { checkAccountAbuse, suspendAccount, type AbuseOptions, type AbuseVerdict } from "./abuse.ts";
/**
 * 봉투 주소 안전성 — **정본 검사는 `enqueueMessage` 안에 그대로 있다.** 이건 조기 실패용이다.
 *
 * 왜 내보내는가: JMAP `EmailSubmission/set`은 큐에 넣기 **전에** `email_submissions` 행을
 * 만든다(행 id가 큐 입력에 필요하다). 그래서 봉투가 거부되면 CRLF 주입 페이로드가 담긴
 * 행이 DB에 남았다. 호출자가 미리 걸러 그 행을 아예 만들지 않게 하려면 같은 판정이 필요하다.
 *
 * ★게이트 안의 검사를 대체하지 **않는다** — 이걸 호출하지 않는 갈래가 생겨도 게이트가 막는다.
 * "가드가 조립 함수 안에 있어 호출자가 우회할 수 없다"는 성질은 유지된다(감사 5차 §5 항목 7).
 */
export { isSafeEnvelopeAddress, findUnsafeAddress } from "./envelope.ts";
export { parseArf, isCountableComplaint, FEEDBACK_ID_HEADER, type ArfReport } from "./arf.ts";
export { recordComplaint } from "./abuse.ts";
