// @ionosphere/proto-lmtp — LMTP 수신(RFC 2033). 순수 엔진 + 소켓 어댑터.
export {
  LmtpEngine,
  type LmtpAction,
  type LmtpDelivery,
  type LmtpDeliverEnv,
  type LmtpEngineOptions,
} from "./engine.ts";
export { LmtpServer, type LmtpBackend, type LmtpServerOptions } from "./server.ts";
