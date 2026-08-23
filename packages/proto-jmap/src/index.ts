// @ionosphere/proto-jmap — JMAP Core(RFC 8620) 디스패치 엔진 + Session (Phase 4). HTTP 어댑터는 상위 계층.
export { JmapEngine, type JmapEngineOptions } from "./engine.ts";
export {
  MethodError,
  RequestError,
  type CapabilityModule,
  type Invocation,
  type JmapRequest,
  type JmapResponse,
  type MethodContext,
  type MethodHandler,
  type SetError,
} from "./types.ts";
export { asResultReference, evalPointer, type ResultReference } from "./pointer.ts";
export {
  buildSession,
  CORE_CAPABILITY,
  DEFAULT_CORE_LIMITS,
  MAIL_CAPABILITY,
  SUBMISSION_CAPABILITY,
  type CoreCapabilityLimits,
  type SessionAccount,
  type SessionOptions,
} from "./session.ts";
export { coreModule } from "./core.ts";
export {
  requireAccountId,
  standardChanges,
  standardGet,
  type ChangesResult,
  type ChangesSource,
  type GetResult,
  type GetSource,
  type JmapObject,
} from "./standard.ts";
export { standardSet, SetItemError, type SetSource } from "./set.ts";
