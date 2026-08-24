/** @ionosphere/proto-smtp — Phase 0 SMTP 수신(25). 순수 엔진 + 소켓 어댑터. */
export {
  type DeliverOutcome,
  type RcptOutcome,
  SmtpEngine,
  type SmtpAction,
  type SmtpDsnParams,
  type SmtpEngineOptions,
} from "./engine.ts";
export { type SmtpAuthResult, type SmtpBackend, SmtpServer, type SmtpServerOptions } from "./server.ts";
