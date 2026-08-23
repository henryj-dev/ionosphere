/**
 * 접근 감사 이벤트 — **프로토콜 공용**(IMAP·POP3·ManageSieve·SMTP·JMAP·관리 API).
 *
 * 왜 core가 소유하는가: 감사 로그가 답해야 하는 질문("누가 어디서 무엇을 했는가")은 프로토콜을
 * 가로지른다. 표면마다 자체 형식으로 남기면 상관관계를 볼 수 없고 — 같은 IP가 993에서 실패한 뒤
 * 587에서 성공했다는 것을 알아야 하는데, 형식이 다르면 그 조회가 불가능하다.
 * `AuthFailureThrottle`·`sasl`을 core로 올린 것과 같은 이유다(갈래마다 만들면 한쪽이 빠진다).
 *
 * ★이 모듈은 **인터페이스와 형식만** 정의한다. 파일 쓰기·오브젝트 스토리지 업로드는 조립층
 * (`apps/server`)의 몫이다 — core가 fs/네트워크를 알면 의존 방향(core → db → store → apps)이 깨지고,
 * 프로토콜 패키지가 감사 저장 방식에 묶인다.
 *
 * ★이 모듈은 **비밀번호를 받지 않는다.** 받을 자리가 없는 것이 유일하게 확실한 방어다
 * (`auth-throttle.ts`와 같은 규율). 인증 실패를 기록할 때도 남기는 것은 사용자명과 주소뿐이다.
 */

/**
 * 감사 대상 표면 — 리스너/프로토콜 단위.
 *
 * `as const` + 유니온인 이유: `erasableSyntaxOnly` 규약상 `enum`을 쓸 수 없고, 문자열 리터럴을
 * 호출부에서 직접 쓰면 오타(`"imaps"`, `"IMAP"`)가 조용히 새 표면 값이 되어 조회에서 누락된다.
 *
 * `submission`(587·465)과 `smtp`(25)를 나누는 이유: 전자는 **인증된 사용자의 발송**이고 후자는
 * **외부에서 들어온 수신**이다. 감사 질문이 다르다 — 발송은 "누가 보냈나", 수신은 "어디서 왔나".
 */
export const AUDIT_SURFACE = {
  imap: "imap",
  pop3: "pop3",
  managesieve: "managesieve",
  /** 587·465 — 인증된 발송. */
  submission: "submission",
  /** 25 — 외부 수신(인증 없음). */
  smtp: "smtp",
  lmtp: "lmtp",
  jmap: "jmap",
  /** 관리 REST API — rootToken 하나가 전 테넌트 권한이라 특히 감사가 필요하다. */
  api: "api",
} as const;

export type AuditSurface = (typeof AUDIT_SURFACE)[keyof typeof AUDIT_SURFACE];

/**
 * 판정 결과.
 *
 * `fail`과 `throttled`를 나누는 이유: 전자는 자격증명이 틀린 것이고 후자는 **시도 자체가 거부된**
 * 것이다. 스로틀 차단은 지금 어느 로그에도 남지 않는데(어댑터가 백엔드를 부르지 않고 조기 반환),
 * 공격 활동이 가장 잘 드러나는 갈래가 바로 그것이다.
 *
 * `denied`는 인증은 됐지만 **권한이 없어** 거부된 경우(관리 API 스코프 부족 등) — 인증 실패와
 * 섞으면 "자격증명 탈취 시도"와 "권한 밖 접근 시도"를 구분할 수 없다.
 */
export const AUDIT_OUTCOME = {
  ok: "ok",
  /** 자격증명 불일치. */
  fail: "fail",
  /** 스로틀에 걸려 검증조차 하지 않음. */
  throttled: "throttled",
  /** 인증은 됐으나 권한 부족. */
  denied: "denied",
} as const;

export type AuditOutcome = (typeof AUDIT_OUTCOME)[keyof typeof AUDIT_OUTCOME];

/** 감사 이벤트 한 건. 직렬화되면 JSONL 한 줄이 된다. */
export interface AuditEvent {
  /** epoch millis. 싱크가 채우지 않고 **호출부가 채운다** — 버퍼에 머무는 시간이 시각을 흐리지 않게. */
  ts: number;
  surface: AuditSurface;
  /**
   * 무엇을 했는가. `auth`·`session.open`·`session.close`·`select`·`fetch`·`expunge`·`putscript` 등.
   *
   * 자유 문자열인 이유: 프로토콜마다 명령 집합이 다르고 새 명령이 계속 붙는다. 유니온으로 묶으면
   * 명령을 추가할 때마다 core를 고쳐야 하고, 그러면 "감사에 안 남는 새 명령"이 생기기 쉽다.
   * 점 표기(`session.open`)로 계층을 표현한다.
   */
  action: string;
  outcome: AuditOutcome;
  /** `normalizeIp`/`clientIpOf` 결과. 판정 불가 시 `"unknown"`(그 값도 기록해야 공백과 구분된다). */
  ip: string;
  /** 인증 **시도 대상**. 실패했어도 남긴다 — 어느 계정이 노려지는지가 감사의 핵심이다. */
  user?: string | undefined;
  accountId?: string | undefined;
  tenantId?: string | undefined;
  /**
   * 어떤 자격증명이 쓰였는가 — `@ionosphere/db`의 `CredentialKindName`
   * (`password`·`appPassword`·`oauthToken`)을 넘긴다.
   *
   * ★타입을 `string`으로 둔 이유: core는 `@ionosphere/db`를 import할 수 없다(의존 방향). 유니온을
   * 여기에 복제하면 인코딩이 두 곳에 생겨 한쪽만 바뀌는 그 사고를 다시 만든다 — 대신 호출부가
   * `CredentialKindName` 타입 값을 넘기므로 오타는 호출부에서 잡힌다.
   */
  credKind?: string | undefined;
  /**
   * 프로토콜별 부가정보 — 메일함 이름, 메시지 수, HTTP 메서드·경로, 거부 사유 등.
   *
   * 값이 `string | number`로 제한된 이유: 중첩 객체를 허용하면 호출부가 옵션 객체를 통째로
   * 넘기는 실수가 생기고(로그 마스킹 M-9와 같은 형태), 그때 비밀이 섞여 들어온다.
   */
  detail?: Record<string, string | number> | undefined;
}

/**
 * 감사 싱크 — 조립층이 구현하고 프로토콜 어댑터에 주입한다.
 *
 * ★`record`는 **동기이고 `void`를 반환한다.** 이유가 둘이다:
 *  ① `Promise`를 돌려주면 호출부가 `await`하게 되고, 그 순간 감사 쓰기가 **인증·조회 응답 지연**이
 *     된다("모든 작업" 범위라 IMAP FETCH마다 걸린다).
 *  ② `void`를 붙이는 것을 잊으면 미처리 거부(unhandled rejection)가 되어 프로세스가 죽을 수 있다 —
 *     감사 실패가 서비스를 멈추는 최악의 형태다.
 *
 * ★구현은 **던지지 않는다.** 디스크가 차거나 권한이 틀려도 메일 처리는 계속돼야 한다. 실패는
 * 내부에서 삼키고 자체 로그로 남긴다(`blob-gc.ts`의 GC 실패 처리와 같은 판단).
 */
export interface AuditSink {
  record(e: AuditEvent): void;
}

/** 감사 비활성 시의 싱크 — 호출부가 `?.`나 조건 분기를 하지 않게 한다(`noopLogger`와 같은 이유). */
export const noopAuditSink: AuditSink = {
  record: () => undefined,
};

/**
 * 감사 이벤트 → JSONL 한 줄(개행 포함).
 *
 * ★**표준 로거(`createLogger`)를 경유하지 않는다.** `log.ts`의 `SENSITIVE_KEY_PARTS`가
 * `"auth"`·`"key"`·`"token"`·`"credential"`을 **필드명 기준으로 재귀 마스킹**하는데, 그 목록이
 * `credKind`를 덮는다(`"credential"` 부분 일치). 감사 로그에서 자격증명 **종류**가 `<redacted>`가
 * 되면 "이 실패가 앱 비밀번호인가 OAuth인가"를 알 수 없어 기록의 의미가 사라진다.
 *
 * 마스킹을 우회하는 대신 **비밀이 애초에 들어올 수 없게** 타입을 좁혀 뒀다(`AuditEvent`에
 * 비밀번호 필드가 없고 `detail`은 스칼라만 받는다). 마스킹은 실수를 막는 그물이고, 여기서는
 * 그물 대신 구멍을 없앤 것이다.
 *
 * 키 순서를 고정하는 이유: 같은 종류의 줄이 같은 순서를 가지면 gzip 압축률이 오르고(이관 시
 * 부피가 1/10 수준) 사람이 `grep`으로 읽을 때도 열이 맞는다. `undefined` 필드는 아예 넣지 않아
 * (`exactOptionalPropertyTypes`) 줄이 짧아진다.
 */
export function formatAuditLine(e: AuditEvent): string {
  const out: Record<string, string | number | Record<string, string | number>> = {
    ts: new Date(e.ts).toISOString(),
    surface: e.surface,
    action: e.action,
    outcome: e.outcome,
    ip: e.ip,
  };
  if (e.user !== undefined) out.user = e.user;
  if (e.accountId !== undefined) out.accountId = e.accountId;
  if (e.tenantId !== undefined) out.tenantId = e.tenantId;
  if (e.credKind !== undefined) out.credKind = e.credKind;
  if (e.detail !== undefined && Object.keys(e.detail).length > 0) out.detail = e.detail;
  return `${JSON.stringify(out)}\n`;
}

/**
 * UTC 기준 일자 문자열(`YYYY-MM-DD`) — 파일명과 이관 키가 공유하는 정본.
 *
 * ★**UTC로 고정한다.** 로컬 타임존을 쓰면 서버 설정에 따라 파일 경계가 달라져, 세 인스턴스가
 * 같은 버킷에 올릴 때 "같은 날짜"가 서로 다른 시간 범위를 담는다. 그러면 시간대를 가로지르는
 * 조회가 틀린다. 운영자 편의보다 경계의 일관성이 중요하다.
 */
export function auditDayUtc(ts: number): string {
  return new Date(ts).toISOString().slice(0, 10);
}
