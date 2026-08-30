export { ulid, isUlid } from "./ulid.ts";
export { sha256hex, sha256hex32 } from "./hash.ts";
export {
  HTTP_HEADERS_TIMEOUT_MS,
  HTTP_REQUEST_TIMEOUT_MS,
  LMTP_IDLE_TIMEOUT_MS,
  MAX_ADDRESSES_PER_HEADER,
  MAX_ALIAS_TARGETS,
  MAX_COMMAND_LINE,
  MAX_IMAP_LINE_BYTES,
  MAX_LISTENER_CONNECTIONS,
  MAX_MESSAGE_BYTES,
  MAX_MIME_DEPTH,
  MAX_MIME_PARTS,
  MAX_PIPELINE_PENDING_BYTES,
  MAX_PREAUTH_LITERAL_BYTES,
  MAX_QUEUED_LINE_BYTES,
  MAX_JMAP_UPLOAD_BYTES,
  MAX_RCPT_PER_SESSION,
  MAX_RELAY_TARGETS,
  MAX_SMTP_ERRORS_PER_SESSION,
  MAX_THREAD_REFS,
  MAX_HEADER_LINE_BYTES,
  MAX_HEADER_SECTION_BYTES,
  POP3_IDLE_TIMEOUT_MS,
  MAX_RECEIVED_HOPS,
} from "./limits.ts";
export type { MaildropLock } from "./maildrop-lock.ts";
export {
  decodeSaslBase64,
  decodeSaslPlain,
  isOAuthMechanism,
  parseSaslOAuth,
  parseSaslPlain,
  type SaslOAuthCreds,
} from "./sasl.ts";
export { open, openAsync, seal } from "./secretbox.ts";
export { trackListener, type ListenerShutdown } from "./listener-shutdown.ts";
export { hardenHttpListener, type HardenableHttpServer } from "./http-listener.ts";
export { buildReceivedHeader, headerSafeToken, rfc5322Date, type ReceivedInfo, type ReceivedTransport } from "./received.ts";
export {
  AuthFailureThrottle,
  clientIpOf,
  normalizeIp,
  throttleKeyOf,
  trustLoopbackOnly,
  type AuthSubject,
  type AuthThrottleOptions,
  type AuthThrottleSubject,
  type PeerTrustPolicy,
} from "./auth-throttle.ts";
export {
  createLogger,
  noopLogger,
  type CreateLoggerOptions,
  type LogFields,
  type Logger,
  type LogLevel,
} from "./log.ts";
export {
  AUDIT_OUTCOME,
  AUDIT_SURFACE,
  auditDayUtc,
  formatAuditLine,
  noopAuditSink,
  type AuditEvent,
  type AuditOutcome,
  type AuditSink,
  type AuditSurface,
} from "./audit.ts";
export {
  buildServerFirst,
  deriveScramKeys,
  normalizePassword,
  parseClientFirst,
  serverNonce,
  verifyClientFinal,
  SCRAM_DEFAULT_ITERATIONS,
  type ClientFirst,
  type ClientFinalVerdict,
  type ScramKeys,
} from "./scram.ts";
export { ScramServerSession, type ScramStep, type ScramStoredKeys } from "./scram-session.ts";
export { applyLegacyEnvAliases, LegacyEnvConflictError } from "./env-legacy.ts";
export { PeerConnectionLimiter, DEFAULT_MAX_CONNECTIONS_PER_PEER } from "./peer-limit.ts";
export {
  PRINCIPAL_KIND,
  type MailboxOperation,
  type PrincipalContext,
  type PrincipalKind,
} from "./principal.ts";
export {
  STANDARD_MAILBOX_RIGHTS,
  MAILBOX_OPERATION_RIGHT,
  combineMailboxRights,
  formatMailboxRights,
  parseMailboxRights,
  type MailboxRight,
  type StandardMailboxRight,
} from "./rights.ts";
export { DIRECTORY_TRANSPORT, DirectoryError, externalIdentityKey, mapDirectoryIdentity, resolveNestedGroups, validateDirectoryConfig, type DirectoryConfig, type DirectoryEntry, type DirectoryGroup, type DirectoryIdentity, type DirectoryTransport } from "./directory.ts";
export {
  compileGlob,
  globCaptures,
  globMatch,
  imapListSyntax,
  SIEVE_MATCH_SYNTAX,
  type GlobSyntax,
} from "./glob.ts";
// 역추적 없는 정규식 엔진 — Sieve `:regex`가 쓴다. 사용자 패턴을 `RegExp`으로 돌리면
// 단일 프로세스 서버에서 ReDoS 하나가 메일 서비스 전체를 멈춘다(regex.ts 머리 주석).
export { compileRegex, execRegex, regexMatch, RegexSyntaxError, type CompiledRegex, type RegexMatch } from "./regex.ts";
// Web Push 암호화(RFC 8291) — JMAP PushSubscription이 쓴다. 중계자가 남이라 암호화가 필수다.
export { encryptWebPush, type EncryptResult, type WebPushKeys } from "./webpush.ts";
