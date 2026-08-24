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
  standardQueryChanges,
  type ChangesResult,
  type ChangesSource,
  type GetResult,
  type GetSource,
  type JmapObject,
} from "./standard.ts";
export { standardSet, SetItemError, type SetSource } from "./set.ts";
// 클라이언트 문자열을 객체 키로 쓰는 자리의 **정본 가드**. 상위 계층(Email/import 등)이
// 같은 판정을 다시 적으면 목록이 갈린다 — 한쪽만 키가 늘어나는 형태의 사고다.
export { isUnsafeKey } from "./safe-key.ts";
