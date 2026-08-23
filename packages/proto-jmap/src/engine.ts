/**
 * JMAP 메서드 디스패치 엔진 (RFC 8620 §3.2~3.7). 순수 조립 — 스토어 I/O는 주입된 핸들러가.
 *
 * 처리 순서(메서드 호출마다):
 *  1) 백레퍼런스(ResultReference) 해석 — 앞선 응답에서 JSON 포인터로 값 치환
 *  2) using에 없는 capability의 메서드 → unknownMethod, 미등록 메서드도 unknownMethod
 *  3) 핸들러 실행 → 응답 인자. MethodError throw 시 ["error", {type}, callId]로 치환
 *  4) methodResponses에 누적(다음 호출의 백레퍼런스가 참조 가능)
 */
import { asResultReference, evalPointer } from "./pointer.ts";
import { isUnsafeKey } from "./safe-key.ts";
import {
  MethodError,
  RequestError,
  type CapabilityModule,
  type Invocation,
  type JmapRequest,
  type JmapResponse,
  type MethodHandler,
} from "./types.ts";

export interface JmapEngineOptions {
  modules: readonly CapabilityModule[];
  /** 서버가 지원하는 전체 capability(urn) 집합 — Session·요청 using 검증. */
  capabilities: readonly string[];
  /** sessionState 문자열 공급자(스토어 state 요약 등). */
  sessionState: () => string;
  /** 최대 methodCalls 수(RFC 8620 maxCallsInRequest, 기본 50). 초과 시 requestTooLarge. */
  maxCalls?: number;
}

const DEFAULT_MAX_CALLS = 50;

export class JmapEngine {
  private readonly methodMap: Map<string, { capability: string; handler: MethodHandler }>;
  private readonly capabilities: Set<string>;
  private readonly sessionState: () => string;
  private readonly maxCalls: number;

  constructor(opts: JmapEngineOptions) {
    this.capabilities = new Set(opts.capabilities);
    this.sessionState = opts.sessionState;
    this.maxCalls = opts.maxCalls ?? DEFAULT_MAX_CALLS;
    this.methodMap = new Map();
    for (const mod of opts.modules) {
      for (const [name, handler] of Object.entries(mod.methods)) {
        this.methodMap.set(name, { capability: mod.capability, handler });
      }
    }
  }

  /**
   * 요청 처리. 요청 레벨 위반은 RequestError를 throw(어댑터가 problem+json 400).
   * 메서드 레벨 오류는 methodResponses 안의 ["error", ...] invocation으로 담긴다.
   */
  async handle(request: JmapRequest, accountId: string): Promise<JmapResponse> {
    if (!Array.isArray(request.methodCalls)) {
      throw new RequestError("urn:ietf:params:jmap:error:notRequest", 400, "methodCalls 누락");
    }
    if (!Array.isArray(request.using)) {
      throw new RequestError("urn:ietf:params:jmap:error:notRequest", 400, "using 누락");
    }
    for (const cap of request.using) {
      if (!this.capabilities.has(cap)) {
        throw new RequestError("urn:ietf:params:jmap:error:unknownCapability", 400, `미지원 capability: ${cap}`);
      }
    }
    if (request.methodCalls.length > this.maxCalls) {
      throw new RequestError("urn:ietf:params:jmap:error:limit", 400, "requestTooLarge");
    }

    const using = new Set(request.using);
    const createdIds: Record<string, string> = { ...(request.createdIds ?? {}) };
    const methodResponses: Invocation[] = [];

    for (const call of request.methodCalls) {
      const [name, rawArgs, callId] = call;
      // 1) 백레퍼런스 해석
      let args: Record<string, unknown>;
      try {
        args = this.resolveReferences(rawArgs, name, callId, methodResponses);
      } catch (err) {
        if (err instanceof MethodError) {
          methodResponses.push(["error", { type: err.type, ...err.detail }, callId]);
          continue;
        }
        throw err;
      }

      // 2) capability/메서드 게이트
      const entry = this.methodMap.get(name);
      if (!entry || !using.has(entry.capability)) {
        methodResponses.push(["error", { type: "unknownMethod" }, callId]);
        continue;
      }

      // 3) 핸들러 실행
      try {
        const result = await entry.handler(args, { accountId, createdIds });
        methodResponses.push([name, result, callId]);
      } catch (err) {
        if (err instanceof MethodError) {
          methodResponses.push(["error", { type: err.type, ...err.detail }, callId]);
        } else if (err instanceof RequestError) {
          throw err;
        } else {
          // 예기치 못한 예외 — 서버 오류로 메서드 레벨 표면화(요청 전체를 죽이지 않음)
          methodResponses.push(["error", { type: "serverFail" }, callId]);
        }
      }
    }

    return { methodResponses, createdIds, sessionState: this.sessionState() };
  }

  /** 인자 최상위 키의 ResultReference(#키)를 앞선 응답에서 치환. */
  private resolveReferences(
    rawArgs: Record<string, unknown>,
    _name: string,
    _callId: string,
    prior: readonly Invocation[],
  ): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(rawArgs ?? {})) {
      // 백레퍼런스는 인자 키에 '#' 접두(예: "#ids"→"ids"), 값이 ResultReference (RFC 8620 §3.7)
      if (!key.startsWith("#")) {
        // 심층방어: 인자 이름이 그대로 `out[key] = …`이 되므로 프로토타입 체인에 닿는 이름은
        // 거부한다(safe-key.ts). RFC 8620의 어떤 인자도 이 이름을 쓰지 않는다.
        if (isUnsafeKey(key)) throw new MethodError("invalidArguments", { description: `허용되지 않는 인자 이름: ${key}` });
        out[key] = value;
        continue;
      }
      const ref = asResultReference(value);
      if (!ref) {
        throw new MethodError("invalidArguments", { description: `잘못된 ResultReference: ${key}` });
      }
      const source = findResult(prior, ref.resultOf, ref.name);
      if (source === undefined) {
        throw new MethodError("invalidResultReference", { description: `resultOf=${ref.resultOf} name=${ref.name}` });
      }
      const resolved = evalPointer(source, ref.path);
      if (resolved === undefined) {
        throw new MethodError("invalidResultReference", { description: `path=${ref.path}` });
      }
      const name = key.slice(1);
      if (isUnsafeKey(name)) throw new MethodError("invalidArguments", { description: `허용되지 않는 인자 이름: ${name}` });
      // `in`을 쓰는 것이 여기서는 **의도적**이다 — 중복 지정을 막는 검사라 상속 이름까지 걸리는
      // 쪽이 더 보수적이다(위 isUnsafeKey가 이미 그 이름들을 걸러 실질 차이는 없다).
      if (name in out || name in rawArgs) {
        // 같은 인자를 일반값과 백레퍼런스로 동시 지정 — 모호(RFC 8620: 서버가 거부)
        throw new MethodError("invalidArguments", { description: `중복 인자: ${name}` });
      }
      out[name] = resolved;
    }
    return out;
  }
}

/** callId + 메서드명이 일치하는 앞선 응답의 인자를 반환(에러 응답은 제외). */
function findResult(prior: readonly Invocation[], resultOf: string, name: string): Record<string, unknown> | undefined {
  for (const [n, args, cid] of prior) {
    if (cid === resultOf) {
      if (n !== name) return undefined; // 이름 불일치 = invalidResultReference
      return args;
    }
  }
  return undefined;
}
