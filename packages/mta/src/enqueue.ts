/**
 * MTA 큐 적재 — SCHEMA.md §9-1 mta_queue DDL + §7-9 Submit 레시피(수신자별 행)의 Phase 1 구현.
 *
 * ★편차/설계 메모: Phase 1 범위에서는 env_from을 원본 그대로 저장·발송한다. verp_token은
 * 행마다 16-hex 난수로 생성해 저장만 해 두고(§9-1 "★바운스 역상관"), 실제 VERP 주소
 * 렌더링(`bounce+<token>@<domain>` 형태로 MAIL FROM을 바꿔치기하는 것)은 이번 스코프에
 * 포함하지 않는다 — 바운스 파싱 파이프라인이 붙는 단계에서 verp_token → mta_queue.rcpt
 * 역조회에 쓰일 준비만 해 둔다. submissionId는 email_submissions와의 연계 지점이며 JMAP
 * Email/set·EmailSubmission/set 배선은 Phase 4에서 붙는다(§7-9 Submit 레시피 전체는
 * 아직 구현하지 않음 — change_log/modseq_claims 갱신 없이 mta_queue 행만 적재).
 */
import { randomBytes } from "node:crypto";
import { ulid } from "@ionosphere/core";
import { BLOB_STATUS, MTA_QUEUE_STATUS, REF_KIND, SYSTEM_ACCOUNT_REF, canSendFromDomain, isLocallyRoutableDomain, type DbDriver, type Statement } from "@ionosphere/db";
import { multiRowInsertStatements } from "./chunk.ts";
import { ACTIVE_SUPPRESSION_CLAUSE } from "./suppression.ts";
import { findUnsafeAddress, isSafeEnvelopeAddress } from "./envelope.ts";

export interface EnqueueInput {
  tenantId: string;
  /** 미터링·레이트리밋 귀속 계정. 시스템 발송(포워딩·바운스 relay)은 생략 → NULL(§9-1). */
  accountId?: string;
  /** email_submissions 연계 (JMAP은 Phase 4에서 연결). 시스템 발송(DSN 등)은 생략 → NULL. */
  submissionId?: string;
  blobId: string;
  /** 블롭 바이트 수 — blobs 원장 행(§9-5)을 같은 배치에서 만들기 위해 필요하다. */
  sizeBytes: number;
  /** putBlob()이 기록한 세대. 생략 시 0. GC doomed 블롭 부활 시에만 0이 아니다. */
  blobGeneration?: number;
  /** 반송 주소 (VERP 인코딩 전 원본 — 위 편차 메모 참조). */
  envFrom: string;
  rcpts: readonly string[];
  /** 예약 발송 → next_attempt. 생략 시 즉시(now). */
  sendAt?: number;
  /**
   * 시스템 relay(포워딩·Sieve redirect·바운스 반송) 선언 — PLAN.md §8 ② 아웃바운드 게이트를 우회한다.
   * 사용자 제출(submission)은 반드시 생략해 게이트를 통과시켜야 함.
   */
  system?: SystemRelay;
}

/**
 * 시스템 relay 선언 — **예전의 `internal: true` 불리언을 대체한다.**
 *
 * ★왜 불리언을 없앴나(감사 5차 C-1): `internal: true` 하나가 도메인 검증·발신자 소유권·
 * relay 상한·계정 레이트리밋·localOnly **다섯 게이트를 한꺼번에** 껐다. 그래서 옵션을 넘기지
 * 않은 호출부(`relayBounce`) **하나**가 미인증 오픈 릴레이가 됐다 — 게이트를 끄는 데 필요한
 * 것이 "true 한 글자"뿐이라 무엇으로 대체할지 아무도 적지 않아도 통과했기 때문이다.
 *
 * 이제 게이트를 끄려면 **무엇이 대신 지킬지**를 타입이 요구한다. 필드가 전부 필수라
 * 새 호출자가 빠뜨리면 컴파일 에러가 된다 — CLAUDE.md "새 규약은 되도록 타입으로 강제할 것".
 */
export interface SystemRelay {
  /**
   * 이 갈래의 테넌트별 시간당 상한. **필수** — 계정 축 레이트리밋은 `accountId`가 있을 때만
   * 걸리는데 relay는 귀속 계정이 없어(§9-1 NULL) 여기가 **유일한 상한**이다.
   */
  relayPerHour: number;
  /**
   * 봉투발신자 규율. 호출자가 정한 `envFrom`을 그대로 믿지 않고 이 선언에 따라 검사·강제한다.
   *
   *  - `"null-sender"`: `<>`로 **강제한다**(호출자 값을 버린다). 바운스 반송이 여기 속한다 —
   *    RFC 5321 §4.5.5가 DSN의 reverse-path를 null로 요구하고, 이중 바운스도 이것으로 끊긴다.
   *    ★C-1의 DKIM 서명 탈취가 닫히는 자리: 워커는 **봉투발신자 도메인**으로 서명 키를 고르는데
   *    `relayBounce`가 공격자의 MAIL FROM을 그대로 넘겨 임의 호스팅 도메인의 키로 서명됐다.
   *    도메인이 없는 `<>`는 어떤 키도 고르지 못한다.
   *  - `"srs"`: 호출자가 SRS로 재작성한 **우리 도메인** 주소. 포워딩·Sieve redirect가 여기 속한다.
   *    도메인부가 비어 있으면 거부한다(재작성이 실패한 채로 나가는 것을 막는다).
   */
  envFrom: "null-sender" | "srs";
}

export interface EnqueueSkipped {
  rcpt: string;
  reason: string;
}

export interface EnqueueResult {
  queuedIds: string[];
  skipped: EnqueueSkipped[];
}

/**
 * PLAN.md §8 ②③ 정책 위반 — 개별 수신자 skip이 아니라 요청 전체를 거부한다.
 * "domain-unverified"(발신 도메인 미검증/미소유)는 정책상 영구 실패이므로 제출 백엔드가
 * 5xx(예: 553 5.7.1)로 매핑해야 하고, "rate-limited"(계정별 레이트리밋 초과)는 일시적
 * 배압이므로 4xx(예: 452 4.3.2)로 매핑해 클라이언트가 재시도하도록 해야 한다. 두 사유를
 * EnqueueResult.skipped 목록에 섞지 않고 별도 타입 에러로 던지는 이유: skipped는 "이
 * 수신자만 빠짐(부분 성공)"을 뜻하는데, 게이트/레이트리밋 거부는 "요청 자체가 무효"라는
 * 다른 의미이며 호출자가 서로 다른 SMTP 응답 코드로 매핑해야 하기 때문 — 타입으로 구분해
 * 두면 호출자가 skipped 배열을 순회하며 이유 문자열을 비교할 필요 없이 catch로 분기 가능.
 */
export class OutboundRejectedError extends Error {
  readonly reason: OutboundRejectReason;

  constructor(reason: OutboundRejectReason, message: string) {
    super(message);
    this.name = "OutboundRejectedError";
    this.reason = reason;
  }
}

/**
 * 발송 거부 사유.
 *  - `domain-unverified` / `external-disabled`: 정책상 영구 실패 → 5xx
 *  - `rate-limited`: 일시적 배압 → 4xx (클라이언트가 재시도해야 한다)
 */
export type OutboundRejectReason =
  | "domain-unverified"
  | "rate-limited"
  | "external-disabled"
  | "invalid-address"
  | "sender-not-owned";

/**
 * envFrom이 그 계정의 주소인가 — 계정 자신의 email이거나, 그 계정을 목적지로 갖는 알리아스.
 * 캐치올(`*`)은 세지 않는다(허용하면 도메인 전체 사칭이 되어 검사가 무의미해진다).
 *
 * ★subaddress(`user+tag@`)는 tag를 떼고 본다(감사 5차 L-9). 수신 경로(`resolveRoute`)는
 * 예전부터 tag를 떼고 매칭하는데 **발신 경로만 안 뗐다** — 정규화가 갈라져서 `user+tag@`로
 * 보내는 정상 사용자가 550을 받았다. fail-closed 방향이라 보안 우회는 아니지만, 같은 값에
 * 대해 두 경로가 다른 답을 내는 것은 이 저장소가 반복해 겪은 결함 형태다.
 */
async function senderOwnedByAccount(db: DbDriver, accountId: string, envFrom: string): Promise<boolean> {
  const addr = envFrom.trim().toLowerCase();
  const at = addr.lastIndexOf("@");
  if (at <= 0) return false;
  const rawLocalpart = addr.slice(0, at);
  const domain = addr.slice(at + 1);
  // `+`가 선두면 그건 tag가 아니라 localpart 자체다(수신 경로의 `plus > 0`과 같은 판정).
  const plus = rawLocalpart.indexOf("+");
  const localpart = plus > 0 ? rawLocalpart.slice(0, plus) : rawLocalpart;
  const baseAddr = `${localpart}@${domain}`;

  const { rows: own } = await db.query({
    sql: "SELECT 1 AS x FROM accounts WHERE id = ? AND email = ?",
    params: [accountId, baseAddr],
  });
  if (own.length > 0) return true;

  const { rows: alias } = await db.query({
    sql: `SELECT 1 AS x FROM address_targets t
          JOIN addresses ad ON ad.id = t.address_id
          JOIN domains d ON d.id = ad.domain_id
          WHERE t.account_id = ? AND d.name = ? AND ad.localpart = ?`,
    params: [accountId, domain, localpart],
  });
  return alias.length > 0;
}

/** 계정별 슬라이딩 윈도우 레이트리밋 한도 (수신자 수 기준, PLAN.md §8 ③). */
export interface RateLimitConfig {
  perMinute?: number;
  perHour?: number;
  perDay?: number;
}

/** 미지정 필드에 적용되는 기본 한도. */
export const DEFAULT_RATE_LIMIT: Required<RateLimitConfig> = {
  perMinute: 30,
  perHour: 500,
  perDay: 2000,
};

/**
 * 시스템 relay의 기본 시간당 상한 — 운영자가 `relayPerHour`를 지정하지 않았을 때 쓴다.
 *
 * 왜 기본값이 필요한가: 예전엔 미지정이 곧 **무제한**이었다. 그래서 설정을 안 건드린 배포가
 * 곧 무제한 증폭 채널이었고, 미인증 원격이 그 채널에 도달했다(감사 5차 C-1). 상한의 기본값은
 * "없음"이 아니라 "넉넉하지만 유한"이어야 한다 — CLAUDE.md "보안은 fail closed".
 * 정상 포워딩 트래픽을 막지 않을 만큼 넉넉하게 두되, 무제한 증폭은 끊는다.
 */
export const DEFAULT_RELAY_PER_HOUR = 1000;

/**
 * 발송 정책 — 제출 갈래(SMTP submission·JMAP EmailSubmission)가 **공유해야 하는** 설정.
 *
 * 갈래마다 손으로 재작성하면 한쪽만 빠진다(과거 JMAP만 레이트리밋을 우회했던 원인).
 * 조립부에서 한 번 만들어 두 갈래에 그대로 넘긴다.
 */
export interface OutboundPolicy {
  /** 지정 시 계정별 레이트리밋 검사를 수행. 생략하면 기존 동작과 동일(레이트리밋 없음). */
  rateLimit?: RateLimitConfig;
  /**
   * 내부 전용 모드 — 이 서버가 호스팅하지 않는 도메인으로의 발송을 **적재 시점에 거절**한다.
   *
   * 왜 필요한가: 아웃바운드 25가 막힌 환경(예: 클라우드 사업자 차단)에서 스마트호스트가 없으면
   * 외부 수신자는 큐에 적재된 뒤 재시도만 반복하다 몇 시간 뒤에야 바운스된다. 사용자는 그동안
   * "보냈다"고 믿는다 — **조용한 실패**다. 어차피 나갈 수 없다면 보낸 순간 알려주는 게 낫다.
   *
   * 시스템 relay(`system` 선언 — 포워딩·바운스 relay)는 게이트를 적용하지 않는다.
   * 관리자가 의도적으로 건 경로이고, 막으면 바운스 반송조차 사라지기 때문.
   */
  localOnly?: boolean;
  /**
   * `localOnly`의 예외 — **이 발신 도메인으로 나갈 릴레이가 실제로 있는가**.
   *
   * localOnly를 켠 이유는 "정책상 외부를 막고 싶다"가 아니라 **"나갈 길이 없다"**였다
   * (아웃바운드 25 차단). 그래서 릴레이를 붙인 도메인까지 막는 건 원래 의도가 아니다.
   * 게이트를 플래그가 아니라 **실제 능력**에 묶어, 릴레이를 등록하는 것만으로 그 도메인의
   * 외부 발송이 열리게 한다(설정을 두 군데 맞출 필요가 없다).
   *
   * 주입식인 이유: 릴레이 해석은 봉인 복호까지 포함해 apps/server가 소유한다.
   * 생략하면 종전 동작(로컬 도메인만 허용)과 완전히 같다.
   */
  hasRelayFor?: (tenantId: string, senderDomain: string) => Promise<boolean>;
  /**
   * 시스템 relay(포워딩·Sieve redirect·바운스 반송)의 테넌트별 시간당 상한.
   *
   * 왜 별도 축인가: 레이트리밋(위 rateLimit)은 `accountId`가 있을 때만 걸리는데, relay는
   * 귀속 계정이 없어(§9-1 NULL) **한도가 아예 없었다.** 무인증 발신자가 알리아스로 밀어넣는
   * 만큼 그대로 외부로 재발송되는 증폭 채널이라, 계정 축과 무관한 상한이 하나 필요하다.
   *
   * 세는 대상은 그 테넌트의 mta_queue 전체다(제출분 포함) — relay만 따로 세려면 컬럼이 필요한데,
   * 총량 상한으로도 증폭은 충분히 묶인다.
   *
   * ★이 값은 **조립층이 정하는 정책**이고, 실제 강제는 `SystemRelay.relayPerHour`(필수 필드)가
   * 한다. 예전엔 이 옵션이 없으면 상한이 통째로 사라졌고 `relayBounce`가 정확히 그 갈래였다
   * (감사 5차 C-1). 미지정 시 relay 경로는 아래 기본값으로 떨어진다 — **무제한이 아니다.**
   */
  relayPerHour?: number;
  /**
   * 발신자 소유 검증 — envFrom이 **인증 계정에 할당된 주소인지**까지 본다. **기본 on**
   * (`undefined`는 켜짐. 끄려면 명시적으로 `false`).
   *
   * 왜 필요한가: 도메인 게이트는 envFrom의 도메인이 테넌트 소유·검증됨인지만 본다. 그래서
   * 같은 테넌트 안에서는 아무 계정이나 **다른 계정을 사칭해** 보낼 수 있었다(ceo@ 사칭 등).
   *
   * 허용 범위: ① 계정 자신의 email ② 그 계정을 목적지로 갖는 알리아스 주소(address_targets).
   * 캐치올(`*`)은 **허용하지 않는다** — 허용하면 그 도메인 전체를 사칭할 수 있어 검사가 무의미해진다.
   *
   * ★기본값을 조립층(app.ts)이 아니라 **여기** 두는 이유: 조립층에만 두면 `enqueueMessage`를
   * 직접 부르는 다른 갈래(테스트·새 호출자)가 검사 없이 지나간다. 이 저장소의 반복 사고가
   * 정확히 "게이트가 한 갈래에만 있다"라서, 게이트 자신이 fail closed 기본값을 갖는다.
   */
  requireSenderOwnership?: boolean;
}

/**
 * 이 발신자에게 외부로 나갈 경로가 있는가(localOnly 게이트의 예외 판정).
 *
 * 조회가 **실패하면 던진다**. "모르겠다"를 "없다"로 뭉개면 릴레이를 붙여 둔 도메인의 메일이
 * DB가 잠깐 흔들리는 동안 550으로 영구 거절된다 — 사용자에게는 설정이 사라진 것으로 보인다.
 * 던지면 호출자(백엔드)가 4xx로 돌려 클라이언트가 재시도한다.
 */
async function hasExternalRoute(opts: OutboundPolicy, input: EnqueueInput): Promise<boolean> {
  if (!opts.hasRelayFor) return false;
  return opts.hasRelayFor(input.tenantId, domainPart(input.envFrom));
}

export interface EnqueueOptions extends OutboundPolicy {
  /** 테스트 결정성용 시각 주입. 생략 시 Date.now(). */
  now?: number;
}

const MTA_QUEUE_COLUMNS = [
  "id",
  "tenant_id",
  "account_id",
  "submission_id",
  "blob_id",
  "env_from",
  "verp_token",
  "rcpt",
  "rcpt_domain",
  "status",
  "attempts",
  "next_attempt",
  "lease_until",
  "last_error",
  "created_at",
] as const;

/** 주소의 "@" 이후 도메인부를 소문자로 추출. "@" 없으면 빈 문자열. */
function domainPart(address: string): string {
  const at = address.lastIndexOf("@");
  return at === -1 ? "" : address.slice(at + 1).toLowerCase();
}

function rcptDomain(rcpt: string): string {
  return domainPart(rcpt);
}

/** 밀리초 단위 슬라이딩 윈도우 폭. */
const WINDOW_MS = {
  perMinute: 60_000,
  perHour: 3_600_000,
  perDay: 86_400_000,
} as const;

/** verp_token — 16-hex 난수 (VARCHAR(32) 컬럼 여유분 안에서 충돌 무시 가능한 64bit). */
function verpToken(): string {
  return randomBytes(8).toString("hex");
}

/**
 * 수신자별 mta_queue 행을 적재한다. suppression에 걸린 수신자는 건너뛰고 skipped에 사유와
 * 함께 기록한다. 나머지는 한 배치(§7-6 청크 규율)로 적재한다.
 *
 * PLAN.md §8 정책 게이트(요청 전체 거부, OutboundRejectedError로 던짐 — 위 클래스 주석 참조):
 *   ② 발신 도메인(envFrom의 "@" 뒷부분)이 input.tenantId 소유의 status=1(검증됨) domains
 *      행이 아니면 거부. input.internal=true(시스템 발송, 예: DSN 바운스)는 우회.
 *   ③ opts.rateLimit이 주어지면 계정별 분/시/일 슬라이딩 윈도우를 검사 — mta_queue를
 *      재사용해 `COUNT(*) WHERE account_id=? AND created_at > now-window`로 기존 물량을
 *      세고 이번 요청의 수신자 수(각 rcpt=1 unit, suppression 필터 이전 값)를 더해 한도
 *      초과 시 거부. ★한계: mta_queue 행이 윈도우보다 빨리 GC되면 카운트가 과소평가됨 —
 *      v1에서는 허용(문서화된 트레이드오프), 정확한 카운터가 필요해지면 별도 테이블/컬럼
 *      도입 검토.
 */
export async function enqueueMessage(
  db: DbDriver,
  input: EnqueueInput,
  opts?: EnqueueOptions,
): Promise<EnqueueResult> {
  const now = opts?.now ?? Date.now();
  const nextAttempt = input.sendAt ?? now;
  const skipped: EnqueueSkipped[] = [];
  const accepted: string[] = [];
  const system = input.system;

  /**
   * 봉투발신자 확정 — **호출자 값을 그대로 쓰지 않는다.**
   *
   * `"null-sender"`는 호출자가 무엇을 넘겼든 `<>`로 덮어쓴다. 이 한 줄이 C-1의 DKIM 서명
   * 탈취를 닫는다(SystemRelay.envFrom 주석 참조) — 방어를 호출부에 맡기면 다음 호출자가
   * 또 빠뜨린다. 게이트 자신이 강제해야 갈래가 늘어나도 유지된다.
   */
  const envFrom = system?.envFrom === "null-sender" ? "" : input.envFrom;

  // 봉투 주소 안전성 — 큐에 들어가는 순간 나중에 SMTP 명령 줄로 나갈 값이 확정된다.
  // 여기서 막아야 오염된 값이 DB에 남지 않는다(envelope.ts 주석: bare-LF 명령 주입).
  if (!isSafeEnvelopeAddress(envFrom)) {
    throw new OutboundRejectedError("invalid-address", `unsafe envelope-from: ${JSON.stringify(envFrom)}`);
  }
  const unsafeRcpt = findUnsafeAddress(input.rcpts);
  if (unsafeRcpt !== null) {
    throw new OutboundRejectedError("invalid-address", `unsafe recipient: ${JSON.stringify(unsafeRcpt)}`);
  }

  // SRS relay는 우리 도메인으로 재작성돼 있어야 한다 — 재작성이 실패한 값이 그대로 나가면
  // 봉투발신자가 제3자 도메인인 채로 발송돼 바운스가 엉뚱한 곳으로 간다.
  if (system?.envFrom === "srs" && !domainPart(envFrom)) {
    throw new OutboundRejectedError(
      "invalid-address",
      `system relay envelope-from is not rewritten: ${JSON.stringify(envFrom)}`,
    );
  }

  if (!system) {
    const domain = domainPart(envFrom);
    if (!domain) {
      throw new OutboundRejectedError(
        "domain-unverified",
        `envelope-from domain missing: ${envFrom}`,
      );
    }
    // 판정 정본은 @ionosphere/db가 소유한다(domain-lookup.ts) — 같은 판정을 원시 SQL로 흩뿌리다
    // status를 빠뜨린 조회가 나온 것이 H-4다. scripts/lint.ts가 이 규약을 기계로 강제한다.
    if (!(await canSendFromDomain(db, domain, input.tenantId))) {
      throw new OutboundRejectedError("domain-unverified", `sender domain not verified: ${domain}`);
    }
  }

  /**
   * 발신자 소유 검증(기본 on, `false`로 명시해야 꺼진다) — 도메인 게이트만으로는 테넌트 내
   * 사칭을 막지 못한다.
   *
   * ★`&& input.accountId`가 남아 있는 이유와 그 한계: 이 검사는 "이 **계정**이 이 주소를
   * 쓸 자격이 있나"라서 계정이 없으면 물을 대상이 없다. 감사 5차 C-1이 지적한 대로 이
   * 조건은 "**옵션** 누락"은 막아도 "**입력** 누락(accountId 없음)"은 막지 못했다 —
   * 그 구멍은 이제 `system` 선언이 **필수 필드로** 대체 방어를 요구해 닫는다.
   * 계정도 없고 system 선언도 없는 입력은 위 도메인 게이트에서 이미 걸린다.
   */
  if (opts?.requireSenderOwnership !== false && input.accountId && !system) {
    if (!(await senderOwnedByAccount(db, input.accountId, envFrom))) {
      throw new OutboundRejectedError(
        "sender-not-owned",
        `envelope-from not owned by account: ${envFrom}`,
      );
    }
  }

  /**
   * 시스템 relay 상한 — accountId가 없어 아래 계정 축 레이트리밋이 걸리지 않는 갈래를 덮는다.
   *
   * ★예전 조건은 `input.internal && opts?.relayPerHour !== undefined`였다. 즉 **옵션을 안 넘기면
   * 상한이 사라졌고**, 실제로 `relayCopy`는 넘기고 `relayBounce`는 안 넘겨 비대칭이 생겼다 —
   * 그 비대칭이 C-1의 핵심이었다. 이제 상한은 `SystemRelay`의 **필수 필드**라 조건이 없다:
   * 시스템 relay를 선언하는 순간 상한도 함께 선언된다(fail closed).
   */
  if (system) {
    const windowStart = now - WINDOW_MS.perHour;
    const { rows } = await db.query({
      sql: "SELECT COUNT(*) AS c FROM mta_queue WHERE tenant_id = ? AND created_at > ?",
      params: [input.tenantId, windowStart],
    });
    const existing = Number(rows[0]?.c ?? 0);
    if (existing + input.rcpts.length > system.relayPerHour) {
      throw new OutboundRejectedError(
        "rate-limited",
        `relay rate limit exceeded (${existing + input.rcpts.length} > ${system.relayPerHour})`,
      );
    }
  }

  if (opts?.rateLimit && input.accountId) {
    const accountId = input.accountId;
    const limits = { ...DEFAULT_RATE_LIMIT, ...opts.rateLimit };
    const cost = input.rcpts.length;
    for (const key of ["perMinute", "perHour", "perDay"] as const) {
      const cap = limits[key];
      const windowStart = now - WINDOW_MS[key];
      const { rows: countRows } = await db.query({
        sql: "SELECT COUNT(*) AS c FROM mta_queue WHERE account_id = ? AND created_at > ?",
        params: [accountId, windowStart],
      });
      const existing = Number(countRows[0]?.c ?? 0);
      if (existing + cost > cap) {
        throw new OutboundRejectedError(
          "rate-limited",
          `rate limit exceeded (${key}: ${existing + cost} > ${cap})`,
        );
      }
    }
  }

  // 내부 전용 게이트(§8과 같은 자리) — 여기 한 곳에 두어야 SMTP·JMAP 어느 갈래로 와도 동일하게 걸린다.
  // (과거 JMAP만 레이트리밋을 우회했던 사고와 같은 종류를 구조적으로 막는다.)
  if (opts?.localOnly && !system && !(await hasExternalRoute(opts, input))) {
    for (const domain of new Set(input.rcpts.map((r) => domainPart(r)))) {
      /**
       * ★`status`를 보지 않는 원시 조회였다(감사 5차 H-4 ②). `domains.name`에 UNIQUE 제약이
       * 없어 **아무 테넌트나 미검증 행을 만들 수 있으므로**, 그 행 하나로 내부 전용 배포에서
       * 외부 도메인으로 메일이 나갔다 — 이 게이트의 존재 이유가 정확히 그것을 막는 것이다.
       * 판정 정본은 @ionosphere/db가 소유한다(domain-lookup.ts).
       */
      if (!(await isLocallyRoutableDomain(db, domain, input.tenantId))) {
        throw new OutboundRejectedError(
          "external-disabled",
          `external delivery is not configured (recipient domain: ${domain})`,
        );
      }
    }
  }

  for (const rcpt of input.rcpts) {
    const email = rcpt.toLowerCase();
    // 만료된 차단은 없는 것으로 본다 — exhausted는 "우리가 포기한 것"이라 영구가 아니다(008).
    const { rows } = await db.query({
      sql: `SELECT 1 AS x FROM suppressions WHERE tenant_id = ? AND email = ? AND ${ACTIVE_SUPPRESSION_CLAUSE}`,
      params: [input.tenantId, email, now],
    });
    if (rows.length > 0) {
      skipped.push({ rcpt, reason: "suppressed" });
      continue;
    }
    accepted.push(rcpt);
  }

  if (accepted.length === 0) {
    return { queuedIds: [], skipped };
  }

  const queuedIds: string[] = [];
  const rows: unknown[][] = accepted.map((rcpt) => {
    const id = ulid();
    queuedIds.push(id);
    return [
      id,
      input.tenantId,
      input.accountId ?? null,
      input.submissionId ?? null,
      input.blobId,
      envFrom,
      verpToken(),
      rcpt,
      rcptDomain(rcpt),
      MTA_QUEUE_STATUS.queued,
      0,
      nextAttempt,
      null,
      null,
      now,
    ];
  });

  // 큐 행 + 블롭 원장을 **한 배치**로. 큐 행만 넣고 블롭 참조를 빠뜨리면 GC가 발송 대기 중인
  // 본문을 지운다(예전 상태: 포워딩·바운스·제출 블롭은 blobs 행조차 없는 고아 파일이었다).
  const blobStmts: Statement[] = [
    {
      sql: db.insertIgnore("blobs", ["id", "size_bytes", "backend", "status", "generation", "created_at"]),
      params: [input.blobId, input.sizeBytes, 0, BLOB_STATUS.live, input.blobGeneration ?? 0, now],
    },
    // 부활 규칙(SCHEMA.md §9-5) — appendMessage와 동일. doomed 상태로 남으면 GC가 파일을 지운다.
    {
      sql: "UPDATE blobs SET status = ?, doomed_at = NULL, generation = ? WHERE id = ? AND generation <= ?",
      params: [BLOB_STATUS.live, input.blobGeneration ?? 0, input.blobId, input.blobGeneration ?? 0],
    },
    ...multiRowInsertStatements(
      "blob_refs",
      ["blob_id", "account_id", "ref_kind", "ref_id", "created_at"],
      // 시스템 발송(포워딩·바운스)은 귀속 계정이 없어 센티널을 쓴다 — account_id는 NOT NULL(인가 축).
      queuedIds.map((id) => [input.blobId, input.accountId ?? SYSTEM_ACCOUNT_REF, REF_KIND.queue, id, now]),
    ),
  ];

  await db.batch([...multiRowInsertStatements("mta_queue", [...MTA_QUEUE_COLUMNS], rows), ...blobStmts]);

  return { queuedIds, skipped };
}
