/**
 * 클라이언트가 정하는 문자열을 **객체 키로 쓰기 전에** 거르는 가드 — 심층방어.
 *
 * JMAP은 요청 JSON의 키를 그대로 서버 객체의 키로 쓰는 자리가 여럿이다(메서드 인자 이름,
 * `creationId`, ResultReference의 JSON 포인터 토큰). 그 자리에 `__proto__`가 들어오면
 * `obj[key] = v`는 프로퍼티 추가가 아니라 **프로토타입 교체**가 되고, `obj[key]` 읽기는
 * `Object.prototype`을 돌려준다 — 타입이 `string`이라고 적혀 있는데 실제로는 객체가 흐른다.
 *
 * 2026-07-30 감사 판정은 "현재 영향 없음"이다(전부 per-call 객체라 전역 `Object.prototype`은
 * 무사하고, 이 값으로 뒤집을 보안 플래그·상한이 없다). 그래도 막아 두는 이유는 **지금 없는
 * 것이 앞으로도 없다는 보장이 아니기** 때문이다. 인자 객체에 플래그 하나만 추가되면 그날부터
 * 우회 경로가 된다.
 *
 * ⚠ 반대 방향 주의: `packages/mime/src/headers.ts`의 `if (!(key in params))`처럼 **`in`이
 * 프로토타입 체인을 보기 때문에 오히려 덮어쓰기를 막는** 코드가 있다. 그런 자리를
 * `hasOwnProperty`로 "고치면" 오히려 쓰기를 여는 셈이 된다. 여기 가드는 `in`이 **읽기**에
 * 쓰여 상속 값을 그대로 돌려주는 자리(pointer.ts)에만 적용한다.
 */

/** 프로토타입 체인에 닿는 키 이름 — 객체 키로 받지 않는다. */
const UNSAFE_KEYS: ReadonlySet<string> = new Set(["__proto__", "constructor", "prototype"]);

/** 클라이언트가 준 문자열을 객체 키로 써도 되는가. */
export function isUnsafeKey(key: string): boolean {
  return UNSAFE_KEYS.has(key);
}

/**
 * 상속 프로퍼티를 보지 않는 소유 키 조회.
 *
 * `key in obj`를 쓰면 `"__proto__"`·`"constructor"`가 언제나 참이라 클라이언트가 지정한 경로가
 * `Object.prototype`이나 생성자 함수로 해석된다. JSON에서 온 객체에는 의미 있는 상속
 * 프로퍼티가 없으므로 소유 키만 보는 것이 정확하기도 하다.
 */
export function hasOwnKey(obj: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}
