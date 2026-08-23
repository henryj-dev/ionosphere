/**
 * DB 컬럼의 정수 인코딩 — **스키마를 소유한 db 패키지가 함께 소유한다**(SCHEMA.md).
 *
 * 이전엔 이 값들이 생 숫자로 여러 패키지에 흩어져 있었다:
 *  - `message_addresses.kind`: backend.ts·imap-backend.ts·jmap-backend.ts에 4가지 형태로 복제 +
 *    `kind === 1 || kind === 2 || kind === 3` 같은 리터럴. 타입이 `number`라 하나만 빠뜨려도
 *    컴파일 에러 없이 수신자가 뒤바뀌었다.
 *  - `mta_queue.status`: mta 내부 3곳에 각각 정의 + store(과금 집계)·app(메트릭)은 생 숫자.
 *    status 값을 하나 바꾸면 청구서와 대시보드가 조용히 틀어졌다.
 *
 * erasableSyntaxOnly 규약상 enum을 쓸 수 없어 `as const` 객체 + 유니온 타입으로 표현한다.
 * 값을 바꾸면 유니온이 바뀌어 **모든 사용처가 컴파일 에러로 드러난다**.
 */

/** `message_addresses.kind` — 주소 헤더 종류. */
export const ADDRESS_KIND = {
  from: 0,
  to: 1,
  cc: 2,
  bcc: 3,
  replyTo: 4,
  sender: 5,
} as const;

/** 주소 헤더 이름(ADDRESS_KIND의 키). */
export type AddressField = keyof typeof ADDRESS_KIND;

/** `message_addresses.kind`에 저장되는 정수. */
export type AddressKind = (typeof ADDRESS_KIND)[AddressField];

/** 헤더 이름 순서 = kind 값 순서. 인덱스 기반 순회용(ADDRESS_KIND와 항상 일치). */
export const ADDRESS_FIELDS: readonly AddressField[] = ["from", "to", "cc", "bcc", "replyTo", "sender"];

/** 봉투 수신자로 취급하는 헤더(to/cc/bcc) — EmailSubmission 봉투 유도에 사용. */
export const RECIPIENT_KINDS: readonly AddressKind[] = [ADDRESS_KIND.to, ADDRESS_KIND.cc, ADDRESS_KIND.bcc];

/** 주어진 수가 유효한 주소 kind인지. DB 행 → 타입 경계에서 사용. */
export function isAddressKind(n: number): n is AddressKind {
  return (Object.values(ADDRESS_KIND) as number[]).includes(n);
}

/** `mta_queue.status` — 아웃바운드 큐 항목 상태. */
export const MTA_QUEUE_STATUS = {
  queued: 0,
  inFlight: 1,
  done: 2,
  bounced: 3,
  deferred: 4,
  canceled: 5,
} as const;

/** 큐 상태 이름. */
export type MtaQueueStatusName = keyof typeof MTA_QUEUE_STATUS;

/** `mta_queue.status`에 저장되는 정수. */
export type MtaQueueStatus = (typeof MTA_QUEUE_STATUS)[MtaQueueStatusName];

/** 아직 배달이 끝나지 않은 상태(과금·큐 깊이 집계에서 "대기 중"으로 세는 것들). */
export const PENDING_QUEUE_STATUSES: readonly MtaQueueStatus[] = [
  MTA_QUEUE_STATUS.queued,
  MTA_QUEUE_STATUS.inFlight,
  MTA_QUEUE_STATUS.deferred,
];

/** 배달이 끝난 상태 — 큐 블롭을 더 붙잡아 둘 이유가 없는 것들(블롭 GC의 참조 해제 기준). */
export const TERMINAL_QUEUE_STATUSES: readonly MtaQueueStatus[] = [
  MTA_QUEUE_STATUS.done,
  MTA_QUEUE_STATUS.bounced,
  MTA_QUEUE_STATUS.canceled,
];

/** 주어진 수가 유효한 큐 상태인지. 외부 입력(API 필터) 검증용. */
export function isMtaQueueStatus(n: number): n is MtaQueueStatus {
  return (Object.values(MTA_QUEUE_STATUS) as number[]).includes(n);
}

/**
 * `blob_refs.ref_kind` — 블롭을 붙잡고 있는 주체 (SCHEMA.md §9-5).
 *
 * store 안에만 있던 값을 db로 올린 이유: 블롭 참조를 만드는 주체가 store만이 아니다.
 * 아웃바운드 큐 적재(@ionosphere/mta)와 JMAP 업로드도 참조를 만들어야 GC가 그 블롭을 보호할 수
 * 있다. 예전엔 이 둘이 참조를 전혀 만들지 않아, 포워딩·바운스·제출 블롭은 `blobs` 행조차
 * 없는 순수 고아 파일로 쌓였다 — GC를 붙이는 순간 "안 보여서 안 지워지거나, 보여서 발송
 * 대기 중인 걸 지우거나" 둘 중 하나가 되는 자리였다.
 */
export const REF_KIND = {
  /** 저장된 메시지(messages.id) — 사용자가 지우면 사라진다. */
  message: 0,
  /** 아웃바운드 큐 항목(mta_queue.id) — 배달이 끝나면 사라진다. */
  queue: 1,
  /** 클라이언트 업로드(JMAP) — 메시지로 승격되지 않으면 TTL로 만료된다. */
  upload: 2,
} as const;

/** 참조 종류 이름. */
export type RefKindName = keyof typeof REF_KIND;

/** `blob_refs.ref_kind`에 저장되는 정수. */
export type RefKind = (typeof REF_KIND)[RefKindName];

/**
 * 계정에 귀속되지 않는 시스템 참조의 `blob_refs.account_id` 센티널.
 *
 * blob_refs.account_id는 NOT NULL인데(인가 축이라 그렇다) 포워딩·SRS 바운스 relay 같은
 * 시스템 발송은 귀속 계정이 없다(mta_queue.account_id는 NULL 허용). 빈 문자열을 센티널로
 * 쓰면 인가 질의(`account_id = 요청자`)에 **어떤 실제 계정과도 매칭되지 않는다** —
 * 계정 id는 26자 ULID라 빈 문자열이 될 수 없기 때문. NULL을 허용해 인가 질의가
 * 3값 논리로 새는 것보다 안전하다.
 */
export const SYSTEM_ACCOUNT_REF = "";

/** `blobs.status` — 2단계 GC 상태 (SCHEMA.md §9-5). */
export const BLOB_STATUS = {
  /** 참조가 있거나 아직 판정 전. */
  live: 0,
  /** 참조 0으로 판정됨 — 유예 기간 후 파일 삭제 대상. 라이터는 이 상태를 보면 generation+1로 부활시킨다. */
  doomed: 1,
  /**
   * 파일 삭제까지 끝난 툼스톤. **행을 지우지 않고 남기는 게 핵심**이다 —
   * 행이 사라지면 라이터가 "새 블롭"으로 알고 generation 0에 쓰는데, 그 경로는 방금 GC가
   * 지운 경로라 GC/라이터 레이스가 되살아난다. 수십 바이트를 남겨 레이스를 원천 차단한다.
   */
  swept: 2,
} as const;

/** 블롭 상태 이름. */
export type BlobStatusName = keyof typeof BLOB_STATUS;

/** `blobs.status`에 저장되는 정수. */
export type BlobStatus = (typeof BLOB_STATUS)[BlobStatusName];

/**
 * `credentials.kind` — 자격증명 종류 (SCHEMA.md §4).
 *
 * 리터럴 `1`/`2`가 store(auth.ts)·api(server.ts)·CLI에 흩어져 있었다. 값을 바꾸면 어디가
 * 안 바뀌었는지 컴파일러가 알려주지 않아, 앱 비밀번호가 기본 비밀번호로 저장되거나 폐기가
 * 조용히 실패하는 종류의 사고가 가능했다. 스키마 소유 패키지로 올려 유니온으로 강제한다.
 */
export const CREDENTIAL_KIND = {
  /** 계정 기본 비밀번호. **폐기 금지** — 지우면 계정이 잠긴다. */
  password: 0,
  /** 앱 비밀번호(클라이언트별 발급·개별 폐기). */
  appPassword: 1,
  /** 자체 발급 OAuth 토큰(XOAUTH2/OAUTHBEARER). */
  oauthToken: 2,
} as const;

/** 자격증명 종류 이름. */
export type CredentialKindName = keyof typeof CREDENTIAL_KIND;

/** `credentials.kind`에 저장되는 정수. */
export type CredentialKind = (typeof CREDENTIAL_KIND)[CredentialKindName];

/**
 * 저장 정수 → 이름. **DB 행을 사람이 읽는 자리로 옮길 때** 쓴다(접근 감사 로그의 `credKind`).
 *
 * 왜 소유 패키지에 두는가: 역매핑을 호출부에서 만들면 `0`/`1`/`2` 리터럴이 다시 흩어진다 —
 * 이 객체를 만든 이유가 바로 그것이었다. 인코딩을 바꿀 때 한 곳만 보면 되게 여기 둔다.
 *
 * 알 수 없는 값은 `undefined`다(throw하지 않는다). 감사 로그를 남기다 예외가 나면 안 되고,
 * 미래에 새 kind가 추가된 뒤 옛 코드가 그 행을 읽는 경우가 정상적으로 있을 수 있다.
 */
export function credentialKindName(n: number): CredentialKindName | undefined {
  for (const [name, value] of Object.entries(CREDENTIAL_KIND)) {
    if (value === n) return name as CredentialKindName;
  }
  return undefined;
}

/**
 * `suppressions.reason` — 수신자를 차단 목록에 올린 근거 (SCHEMA.md §9-2).
 *
 * 왜 갈라야 하는가: 예전엔 리터럴 0 하나뿐이라 **"상대가 영구 거절했다"와 "우리가 며칠간
 * 못 보냈다"가 같은 값**으로 기록됐다. 후자는 우리 쪽 DNS·네트워크 장애로도 발생하는데,
 * 그때 큐에 있던 정상 수신자가 전부 영구 차단됐다. 근거가 다르면 값도 달라야 운영자가
 * 무엇을 지워도 되는지 판단할 수 있다.
 */
export const SUPPRESSION_REASON = {
  /** 상대 서버의 영구 거절(5xx) — 다시 보내도 같은 답이다. */
  hardBounce: 0,
  /** 재시도 상한 소진(상대가 계속 4xx) — 영구 판정이 아니라 **포기**다. 해제 가능. */
  exhausted: 1,
} as const;

/** 차단 사유 이름. */
export type SuppressionReasonName = keyof typeof SUPPRESSION_REASON;

/** `suppressions.reason`에 저장되는 정수. */
export type SuppressionReason = (typeof SUPPRESSION_REASON)[SuppressionReasonName];

/**
 * `accounts.status` — 계정 생명주기 (SCHEMA.md §4, §7-7).
 *
 * ★관리 콘솔이 이 값을 **자기 사본으로 들고 있다가 스키마와 어긋났다**. 콘솔은 `0`을 "대기",
 * `2`를 "비활성"으로 표시했는데 실제로는 `0`이 정지(suspended)이고 `2`는 **삭제 드레인 중**
 * (deleting)이다. 운영자가 화면만 보고 "비활성화했다가 나중에 되살리면 되겠지"라고 읽으면
 * 실제로는 되돌릴 수 없는 삭제를 누른 것이 된다 — 표시가 틀리면 판단이 틀린다.
 *
 * 그래서 인코딩을 스키마 소유 패키지로 올린다(`MTA_QUEUE_STATUS`가 같은 이유로 여기 있다).
 *
 * ⚠ `deleting`은 편도다. §7-7 계약상 읽기 경로가 `status=1`만 노출하고 리퍼가 메일함·자격증명을
 * 드레인하므로, 값을 되돌려도 이미 지워진 것은 돌아오지 않는다.
 */
export const ACCOUNT_STATUS = {
  /** 로그인·수신 정지. 되돌릴 수 있다(데이터는 그대로). */
  suspended: 0,
  /** 정상. 읽기 경로가 노출하는 유일한 값(§7-7). */
  active: 1,
  /** 삭제 드레인 중 — 리퍼가 진행 중이다. **되돌릴 수 없다.** */
  deleting: 2,
} as const;

/** 계정 상태 이름. */
export type AccountStatusName = keyof typeof ACCOUNT_STATUS;

/** `accounts.status`에 저장되는 정수. */
export type AccountStatus = (typeof ACCOUNT_STATUS)[AccountStatusName];

/**
 * `domains.status` — 도메인 검증 상태 (SCHEMA.md §4).
 *
 * 콘솔이 `0`/`1`만 알고 `2`를 몰라 비활성 도메인이 생 숫자로 보였다(위 `ACCOUNT_STATUS`와 같은
 * 사고). `active`만이 `domain_name_claims`에 이름을 잡고 있다 — 인바운드 라우팅의 정본이다.
 */
export const DOMAIN_STATUS = {
  /** DNS 검증 전. claimed_at + TTL 후 스위퍼가 정리한다(스쿼팅 차단). */
  unverified: 0,
  /** 검증 완료 — `domain_name_claims`에 이름을 점유한다. */
  active: 1,
  /** 비활성 — 점유를 놓았다. 같은 이름을 다른 테넌트가 검증할 수 있다. */
  disabled: 2,
} as const;

/** 도메인 상태 이름. */
export type DomainStatusName = keyof typeof DOMAIN_STATUS;

/** `domains.status`에 저장되는 정수. */
export type DomainStatus = (typeof DOMAIN_STATUS)[DomainStatusName];

/**
 * `smarthosts.tls_mode` — 릴레이 연결의 TLS 요구 수준 (마이그레이션 007).
 *
 * 이름은 @ionosphere/mta의 `TlsMode` 문자열 유니온과 **일부러 1:1로 맞췄다**. 인코딩은 스키마를
 * 소유한 여기(db)에 두어야 하는데 db는 mta를 import할 수 없어(의존 방향 core → db → store),
 * 두 표현을 잇는 코덱은 mta 쪽(`packages/mta/src/smarthost.ts`)에 둔다. 그 코덱이 양방향
 * `Record`라, **어느 쪽에 값이 늘어도 반대쪽이 컴파일 에러로 드러난다** — 문자열을 그대로
 * 저장해 오타가 런타임까지 가는 것보다 이쪽이 낫다.
 */
export const SMARTHOST_TLS = {
  /** STARTTLS 필수 — 실패 시 발송 포기. 자격증명을 평문에 얹지 않기 위한 기본값. */
  required: 0,
  /** 되면 쓰고 안 되면 평문. 자체서명 릴레이용 명시적 강등. */
  opportunistic: 1,
  /** 첫 바이트부터 TLS(SMTPS, 보통 465). Cloudflare Email Service가 이것만 받는다. */
  implicit: 2,
  /** 평문 고정. 루프백 릴레이 외에는 쓰지 말 것. */
  never: 3,
} as const;

/** TLS 요구 수준 이름. */
export type SmarthostTlsName = keyof typeof SMARTHOST_TLS;

/** `smarthosts.tls_mode`에 저장되는 정수. */
export type SmarthostTls = (typeof SMARTHOST_TLS)[SmarthostTlsName];

/** 주어진 수가 유효한 TLS 요구 수준인지. DB 행 → 타입 경계에서 사용. */
export function isSmarthostTls(n: number): n is SmarthostTls {
  return (Object.values(SMARTHOST_TLS) as number[]).includes(n);
}

/**
 * `smarthosts.domain`의 "테넌트 기본" 센티널.
 *
 * NULL을 쓰지 않는 이유: 이 컬럼은 PK의 일부인데 **SQL에서 NULL은 NULL과 같지 않다** —
 * 테넌트 기본 행을 두 번 넣어도 UNIQUE가 막지 못해 어느 쪽이 이길지 조회 순서에 달리게 된다.
 * 빈 문자열은 유효한 도메인 이름이 될 수 없으므로 실제 도메인과 충돌하지 않는다.
 */
export const SMARTHOST_TENANT_DEFAULT = "";
