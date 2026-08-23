/**
 * JMAP Core 프로토콜 타입 (RFC 8620). 순수 데이터 — I/O 없음.
 *
 * JMAP은 IMAP/POP3/SMTP와 달리 소켓 상태머신이 아니라 HTTP 위 JSON 요청/응답이다.
 * 이 패키지는 파싱된 Request를 받아 Response를 만드는 "메서드 디스패치 엔진"이고,
 * 실제 HTTP 어댑터와 스토어 연동 핸들러는 상위 계층(apps/server, api)이 주입한다.
 */

/** 메서드 호출 한 건: [메서드명, 인자, 클라이언트 콜 id] (RFC 8620 §3.2). */
export type Invocation = [name: string, args: Record<string, unknown>, callId: string];

/** 클라이언트 요청 (RFC 8620 §3.3). */
export interface JmapRequest {
  using: readonly string[];
  methodCalls: readonly Invocation[];
  /** 생성 id 참조맵(#creationId → 실제 id) — 요청 간 이어받기. */
  createdIds?: Record<string, string>;
}

/** 서버 응답 (RFC 8620 §3.4). */
export interface JmapResponse {
  methodResponses: Invocation[];
  createdIds?: Record<string, string>;
  sessionState: string;
}

/** SetError (RFC 8620 §5.3) — /set 응답의 notCreated/notUpdated/notDestroyed 값. */
export interface SetError {
  type: string;
  description?: string;
  /** invalidProperties 등 타입별 부가 필드. */
  [key: string]: unknown;
}

/** 메서드 레벨 에러 (RFC 8620 §3.6.1) — invocation을 ["error", {...}, callId]로 치환. */
export class MethodError extends Error {
  readonly type: string;
  readonly detail: Record<string, unknown>;
  constructor(type: string, detail: Record<string, unknown> = {}) {
    super(type);
    this.name = "MethodError";
    this.type = type;
    this.detail = detail;
  }
}

/** 요청 레벨 에러 (RFC 8620 §3.6.1) — HTTP 400 problem+json으로 표면화. */
export class RequestError extends Error {
  readonly status: number;
  readonly problemType: string;
  constructor(problemType: string, status = 400, message?: string) {
    super(message ?? problemType);
    this.name = "RequestError";
    this.problemType = problemType;
    this.status = status;
  }
}

/**
 * 메서드 핸들러 — 해석된 인자(백레퍼런스 치환 완료)를 받아 응답 인자를 반환.
 * MethodError를 throw하면 엔진이 ["error", ...]로 치환한다.
 * ctx.response는 지금까지 누적된 methodResponses(백레퍼런스가 이미 참조한 것) — 대개 불필요.
 */
export type MethodHandler = (args: Record<string, unknown>, ctx: MethodContext) => Promise<Record<string, unknown>>;

export interface MethodContext {
  /** 인증된 주 계정 id(accountId 인자 검증에 사용). */
  accountId: string;
  /** 요청의 createdIds(#creationId 해석) — 핸들러가 /set에서 갱신 가능. */
  createdIds: Record<string, string>;
}

/** capability(urn) → { 메서드명 → 핸들러 } 레지스트리. */
export interface CapabilityModule {
  capability: string;
  methods: Record<string, MethodHandler>;
}
