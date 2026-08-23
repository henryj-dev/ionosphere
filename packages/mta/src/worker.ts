/**
 * MtaWorker — mta_queue 발송 워커 (SCHEMA.md §9-1 큐, §9-4 리스 규율, §7-9 Finalize 개념).
 *
 * ★편차: §7-9 "Finalize" 레시피 전문은 email_submissions.undo_status + change_log 갱신까지
 * 요구하지만(EmailSubmission이 계정 스코프 JMAP 객체이므로), 그 배선(스토어 라이터큐 경유)은
 * JMAP EmailSubmission이 실제로 붙는 Phase 4 몫이다. 이 워커는 mta_queue 행 자체의 상태
 * 전이(§9-1 status 컬럼)만 책임진다 — enqueue.ts와 동일한 스코프 절제.
 */
import { type Logger, noopLogger } from "@ionosphere/core";
import { isLocallyRoutableDomain, lookupBlob, MTA_QUEUE_STATUS, SUPPRESSION_REASON, type DbDriver, type Statement } from "@ionosphere/db";
import { dkimSign, RELAY_SAFE_SIGNED_HEADERS, type DkimAlgorithm } from "@ionosphere/mail-auth";

import { fetchMtaStsPolicy, mxMatchesPolicy, stsEnforcement, type MtaStsFetchDeps, type MtaStsLookup } from "@ionosphere/mta-sts";
import type { SmarthostOptions, SmarthostResolver } from "./smarthost.ts";
import { suppressionExpiresAt } from "./suppression.ts";
import { sendSmtp, type SmtpClientResult, type TlsMode } from "./smtp-client.ts";
import type { DaneTlsaSet } from "@ionosphere/mail-auth";

/**
 * TLSA 조회 결과.
 *
 * ★`none`과 `bogus`를 가른다. "TLSA가 없다"는 평소대로 보내면 되지만, "서명이 있는데 맞지
 * 않는다"는 **조작 신호**다. 뭉개서 둘 다 미적용으로 처리하면, DNS를 만질 수 있는 공격자가
 * TLSA를 망가뜨리는 것만으로 DANE를 끌 수 있다.
 */
export type TlsaLookup =
  | { kind: "none" }
  | { kind: "tlsa"; set: DaneTlsaSet }
  | { kind: "bogus"; reason: string };
import { checkAccountAbuse, DEFAULT_ABUSE_WINDOW_MS, suspendAccount, type AbuseOptions } from "./abuse.ts";

export interface MxRecord {
  exchange: string;
  priority: number;
}

export interface DkimKeyLookup {
  selector: string;
  privateKey: string;
  algorithm: DkimAlgorithm;
}

export interface DkimHook {
  /**
   * 도메인의 활성 서명 키 **전부**를 돌려준다 — 하나가 아니다.
   *
   * ★왜 배열인가(2026-08-01 실측): 예전에는 키 하나만 골라 **Ed25519 단독 서명**을 했다.
   * 그런데 Ed25519(RFC 8463)는 SHOULD이고 검증 지원이 고르지 않다 — Gmail은 우리 서명에
   * `dkim=neutral (no key)`를 냈다(서명·키·DNS는 전부 정상임을 확인했다. `fail`이 아니라
   * `neutral`인 것이 신호다 — 검증을 **시도하지 않았다**는 뜻이다).
   * 즉 Ed25519만 붙이면 그 검증자들에게는 우리 서명이 **아예 없는 것과 같다.**
   * `docs/PROTOCOLS.md`가 이미 "RSA2048 + Ed25519 이중 서명 권장(Ed25519 단독 금지)"라고
   * 적어 둔 이유가 이것이다. RFC 8463 §5도 같은 취지다.
   *
   * 빈 배열은 "서명할 키가 없다"는 뜻이고 null과 같게 취급된다.
   */
  selectorFor(domain: string): Promise<readonly DkimKeyLookup[]>;
}

export interface BlobReader {
  get(blobId: string, generation?: number): Promise<Uint8Array>;
}

/** 릴레이 설정·해석기는 smarthost.ts가 소유한다(코덱과 같이 두기 위해). */
export type { SmarthostOptions, SmarthostResolver } from "./smarthost.ts";

/** 배달 결과 관측 아웃컴(관측성 훅). */
export type DeliveryOutcome = "sent" | "bounced" | "deferred" | "suspended";

export interface MtaWorkerOptions {
  db: DbDriver;
  blobs: BlobReader;
  /** MX 리졸버 — 주입식(테스트·재귀 리졸버 교체 대비). */
  resolveMx: (domain: string) => Promise<MxRecord[]>;
  /**
   * DANE(RFC 7672) TLSA 조회 — 주입식. **미지정이면 DANE를 쓰지 않는다.**
   *
   * ★`dnssecValidated`가 계약의 전부다. 검증 없이 참을 넣으면 DNS를 속인 공격자가 우리의
   * 인증서 검증을 무력화할 수 있다 — 구현은 `@ionosphere/dns`의 ValidatingResolver를 쓴다.
   * 조회 실패는 던지지 말고 `none`으로 돌려야 한다. 상대 DNS가 흔들릴 때마다 배달이 멈추면 안 된다.
   */
  resolveTlsa?: (mxHost: string, port: number) => Promise<TlsaLookup>;
  dkim?: DkimHook;
  logger?: Logger;
  ehloName: string;
  /** 기본 25. 테스트용 오버라이드. */
  port?: number;
  /**
   * 전역 릴레이 — 지정 시 MX 직접 발송 대신 스마트호스트로 보낸다.
   * `smarthostResolver`가 이 발신자에 대해 아무것도 돌려주지 않을 때의 **폴백**이다.
   */
  smarthost?: SmarthostOptions;
  /**
   * 테넌트/발신 도메인별 릴레이 해석기(주입식) — 전역 설정보다 우선한다.
   *
   * 순서를 좁은 것부터 두는 이유: 릴레이는 "이 도메인을 이 계정으로 보낼 수 있는가"라는
   * 제공자 계약에 묶여 있어, 도메인별 지정이 테넌트 기본이나 전역보다 항상 정확하다.
   */
  smarthostResolver?: SmarthostResolver;
  intervalMs?: number;
  /** 기본 8. */
  maxAttempts?: number;
  /**
   * 한 tick이 리스를 잡을 최대 행 수. 기본 200.
   *
   * 상한이 없으면 큐가 클 때 한 사이클이 전량을 메모리에 올리고 행마다 왕복해 tick이 끝나지
   * 않는다. 그러면 리스(5분)가 도는 도중 만료되기 시작하고 재기동 시 진행이 통째로 날아간다.
   */
  batchSize?: number;
  /**
   * Abuse 모니터링(PLAN.md §8 통제 ④) — 주기적으로 계정별 바운스율을 검사해 임계
   * 초과 시 자동 정지한다. 생략(기본값) 시 완전히 비활성 — 기존 워커 동작·테스트와
   * 하위호환.
   */
  abuse?: AbuseOptions & {
    enabled: boolean;
    /** 스윕 주기(ms). 기본 1h. */
    sweepIntervalMs?: number;
  };
  /**
   * 배달 결과 관측 훅 — 각 수신자 상태 전이(sent/bounced/deferred)와 계정 자동
   * 정지(suspended) 시 호출. @ionosphere/metrics 의존 없이 콜백만 받는다(의존성 역전).
   * 던져도 워커 진행을 막지 않도록 호출부에서 감싼다.
   */
  onResult?: (outcome: DeliveryOutcome) => void;
  /**
   * MTA-STS 발신측 강제(RFC 8461, opt-in) — 지정 시 수신 도메인 정책을 조회해 enforce면 TLS 필수 +
   * MX가 정책 mx에 일치해야 발송(불일치·TLS 실패는 deferred, 다운그레이드 배달 금지). testing/none은
   * 관측만(기존 동작). 스마트호스트 릴레이 경로엔 적용 안 함. I/O(DNS TXT/HTTPS)는 주입.
   */
  mtaSts?: MtaStsFetchDeps & { cacheTtlMs?: number };
}

/** mta_queue.status (SCHEMA.md §9-1). */
/** mta_queue.status — 정의는 @ionosphere/db(스키마 소유)에 있다. 별칭만 둔다. */
const STATUS = MTA_QUEUE_STATUS;

const DEFAULT_PORT = 25;
const DEFAULT_INTERVAL_MS = 30_000;
const DEFAULT_MAX_ATTEMPTS = 8;
/** 한 tick이 처리할 기본 행 수 — runTick 주석의 LIMIT 근거 참조. */
const DEFAULT_BATCH_SIZE = 200;
const LEASE_MS = 5 * 60 * 1000;
/** MTA-STS 정책 캐시 상한 — 발송 대상 도메인 수는 무제한이라 축출이 없으면 계속 자란다. */
const MAX_STS_CACHE_ENTRIES = 4096;
/**
 * 정책 조회 실패·부재의 캐시 수명 — 성공(정책의 max_age)보다 **훨씬 짧아야 한다**.
 * 실패를 오래 캐시하면 공격자가 드물게 개입하는 것만으로 enforce를 계속 꺼 둘 수 있다(M-2).
 */
const STS_NEGATIVE_TTL_MS = 5 * 60 * 1000;
/** RFC 8461 §3.2 max_age 상한(1년). 정책이 더 큰 값을 줘도 여기서 자른다. */
const MAX_STS_MAX_AGE_S = 31_557_600;
/** max_age 하한 — 너무 짧으면 도메인마다 매 배달이 재조회가 된다. */
const MIN_STS_MAX_AGE_S = 300;
/** 로컬 도메인 판정 캐시 — 도메인 추가가 곧바로 반영돼야 하므로 짧게 잡는다. */
const LOCAL_DOMAIN_TTL_MS = 60_000;
const MAX_LOCAL_DOMAIN_CACHE = 1024;
const DEFAULT_ABUSE_SWEEP_INTERVAL_MS = 60 * 60 * 1000;

interface QueueRow {
  id: string;
  tenantId: string;
  rcpt: string;
  rcptDomain: string;
  envFrom: string;
  blobId: string;
  attempts: number;
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * 큐 실패 사유 — **테넌트에게 보일 문구와 운영자용 상세를 분리한다.**
 *
 * ★왜 쪼갰나(감사 5차 M-11): `mta_queue.last_error`는 `GET /v1/queue`로 **테넌트에게 그대로
 * 반환된다.** 그런데 여기 들어가던 문자열은 `blob load failed: ...`(fs 절대경로·S3 응답 본문),
 * `MX resolve failed: ...`(내부 리졸버 주소), `smarthost resolve failed: ...`(릴레이 구성)처럼
 * **우리 인프라 내부**를 담고 있었다. 임의 테넌트가 존재하지 않는 도메인으로 한 통 보내
 * 인프라를 열람할 수 있었다.
 *
 * 문자열 하나를 받아 양쪽에 쓰던 구조라 호출부가 무심코 상세를 흘렸다. 필드를 둘로 나눠
 * **어느 쪽에 쓸지 고르게 하면** 새 호출부가 생겨도 같은 실수를 반복하지 않는다.
 */
interface QueueFailure {
  /** 테넌트에게 보이는 문구(last_error). 내부 경로·주소·응답 본문을 넣지 말 것. */
  tenant: string;
  /** 운영자용 상세 — 로그로만 간다. */
  detail: string;
}

/** 테넌트 노출 문자열 상한 — 응답 본문이 통째로 실려 오는 것을 길이로도 한 번 막는다. */
const MAX_TENANT_ERROR_LEN = 200;

/**
 * 테넌트 노출 문자열의 마지막 안전망 — 절대경로·IP 리터럴을 지우고 길이를 자른다.
 *
 * 왜 호출부 규율만으로 부족한가: 원격 MTA의 거절 문구(`attempt.message`)는 테넌트에게 보여야
 * 하는 정보인데, 그 안에 우리 쪽 주소가 섞여 들어오는 경우가 있다(연결 실패 메시지 등).
 * 사람이 고른 문구가 아니라 **외부에서 들어온 문자열**이라 기계적으로 한 번 더 훑는다.
 */
function redactForTenant(message: string): string {
  const cleaned = message
    .replace(/(^|\s)\/[^\s:]+/g, "$1<path>")
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, "<ip>")
    .replace(/\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}\b/g, "<ip>");
  return cleaned.length > MAX_TENANT_ERROR_LEN ? `${cleaned.slice(0, MAX_TENANT_ERROR_LEN)}…` : cleaned;
}

/**
 * 원격 MTA의 거절 문구를 코드와 함께 남긴다 — **사유가 진단의 전부다.**
 *
 * 왜 필요한가(2026-08-03 라이브 포워딩 사고): `last_error`가 `"550 rejected"`뿐이라
 * 왜 거절됐는지 알 수 없었다. 실제 문구는 `550 5.6.0 From: header does not match mail from`
 * 이었고 — 그 한 줄이 원인 전체였다(스마트호스트가 From: 헤더와 envelope MAIL FROM의 도메인
 * 일치를 요구하는데, SRS 포워딩에서는 구조적으로 어긋난다). 그것을 알아내려고 별도 프로브로
 * 같은 세션을 재현해야 했다. 운영자가 매번 그럴 수는 없다.
 *
 * 코드만 남기는 것은 "실패했다"를 두 번 말하는 것에 가깝다 — `status=bounced`가 이미 그 뜻이다.
 * 사유를 남겨야 다음 행동이 갈린다(우리 설정 문제인지, 수신자 문제인지, 상대 정책인지).
 *
 * `redactForTenant`를 통과시키는 이유: 이 값은 `GET /v1/queue`로 테넌트에게 그대로 간다(M-11).
 * 원격 문구는 **외부에서 들어온 문자열**이라 우리 쪽 주소·경로가 섞여 오는 경우가 있다.
 */
function rejectionText(code: number, message: string): string {
  const detail = message.trim();
  return detail === "" ? `${code} rejected` : redactForTenant(`${code} ${detail}`);
}

/** 지수 백오프: min(2^attempts × 60s, 4h) ±20% 지터. */
function backoffMs(attempts: number): number {
  const base = Math.min(2 ** attempts * 60_000, 4 * 60 * 60 * 1000);
  const jitter = base * 0.2 * (Math.random() * 2 - 1);
  return Math.max(1_000, Math.round(base + jitter));
}

import { FEEDBACK_ID_HEADER } from "./arf.ts";

function prependHeader(raw: Uint8Array, header: string): Uint8Array {
  const headerBytes = new TextEncoder().encode(header + "\r\n");
  const out = new Uint8Array(headerBytes.length + raw.length);
  out.set(headerBytes, 0);
  out.set(raw, headerBytes.length);
  return out;
}

/**
 * 한 SMTP 연결에 묶을 수 있는 단위.
 *
 * tenant_id가 키에 들어가는 이유: 릴레이와 그 자격증명이 **테넌트별로 다르다**(마이그레이션 007).
 * 테넌트가 키에 없으면 서로 다른 테넌트의 수신자가 한 그룹이 되고, 그 그룹은 첫 행의
 * 테넌트로 해석한 릴레이를 타고 나간다 — 남의 릴레이 한도를 쓰고 남의 청구서에 얹힌다.
 */
function groupKey(row: QueueRow): string {
  return `${row.tenantId}\u0000${row.rcptDomain}\u0000${row.envFrom}\u0000${row.blobId}`;
}

export class MtaWorker {
  private readonly db: DbDriver;
  private readonly blobs: BlobReader;
  private readonly resolveMxFn: (domain: string) => Promise<MxRecord[]>;
  private readonly resolveTlsaFn: ((mxHost: string, port: number) => Promise<TlsaLookup>) | undefined;
  private readonly dkim: DkimHook | undefined;
  private readonly logger: Logger;
  private readonly ehloName: string;
  private readonly port: number;
  private readonly smarthost: SmarthostOptions | undefined;
  private readonly smarthostResolver: SmarthostResolver | undefined;
  private readonly intervalMs: number;
  private readonly maxAttempts: number;
  private readonly batchSize: number;
  private readonly abuseOptions: AbuseOptions | undefined;
  private readonly abuseSweepIntervalMs: number;
  private readonly onResult: ((outcome: DeliveryOutcome) => void) | undefined;
  private readonly mtaSts: (MtaStsFetchDeps & { cacheTtlMs?: number }) | undefined;
  /**
   * MTA-STS 조회 캐시. `policy`는 **마지막으로 본문까지 성공한** 조회로, 재조회가 실패했을 때
   * 강제를 유지하는 근거다(RFC 8461 §5 — M-1). `expiresAt`은 재조회 시점만 정한다.
   */
  private readonly mtaStsCache = new Map<
    string,
    { lookup: MtaStsLookup; expiresAt: number; policy?: { lookup: MtaStsLookup; expiresAt: number } }
  >();
  /** 수신 도메인이 우리 것인지 — 그룹마다 조회하지 않도록 짧게 캐시한다. 키는 `테넌트 도메인`. */
  private readonly localDomainCache = new Map<string, { value: boolean; expiresAt: number }>();

  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;
  private abuseTimer: ReturnType<typeof setInterval> | null = null;
  private abuseSweepRunning = false;

  constructor(opts: MtaWorkerOptions) {
    this.db = opts.db;
    this.blobs = opts.blobs;
    this.resolveMxFn = opts.resolveMx;
    this.resolveTlsaFn = opts.resolveTlsa;
    this.dkim = opts.dkim;
    this.logger = (opts.logger ?? noopLogger).child({ component: "mta" });
    this.ehloName = opts.ehloName;
    this.port = opts.port ?? DEFAULT_PORT;
    this.smarthost = opts.smarthost;
    this.smarthostResolver = opts.smarthostResolver;
    this.intervalMs = opts.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.maxAttempts = opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.batchSize = opts.batchSize ?? DEFAULT_BATCH_SIZE;
    this.abuseOptions = opts.abuse?.enabled ? opts.abuse : undefined;
    this.abuseSweepIntervalMs = opts.abuse?.sweepIntervalMs ?? DEFAULT_ABUSE_SWEEP_INTERVAL_MS;
    this.onResult = opts.onResult;
    this.mtaSts = opts.mtaSts;
  }

  /**
   * 우리가 호스팅하는 도메인인가(릴레이 우회 판정).
   *
   * 미검증(status=0) 도메인도 **그 테넌트 자신의 것이면** 로컬로 친다: 미검증 도메인을
   * "외부"로 보내면 릴레이가 MX를 조회해 결국 우리에게 오고, 수신 라우팅이 거절해도 그 거절을
   * **우리가 못 본다**(제공자가 대신 받는다). 로컬로 취급해 직접 보내야 같은 거절을 동기
   * 응답으로 받아 hardBounce로 기록할 수 있다.
   *
   * ★그러나 예전엔 `status`도 `tenant_id`도 보지 않아 **아무 테넌트의 미검증 행이나** 판정을
   * 뒤집었다(감사 5차 H-4 ①). `domains.name`에 UNIQUE 제약이 없으므로 공격 테넌트가
   * `gmail.com` status=0 행을 하나 만들면 `isLocalDomain("gmail.com")`이 true가 되어
   * **전 테넌트의 gmail 발송이 스마트호스트 릴레이 밖으로 밀려났다.** 위 이점은 발신 테넌트
   * 자신의 도메인에만 필요하므로, 판정을 테넌트로 좁혀 둘을 동시에 만족시킨다.
   *
   * 판정을 못 하면(조회 실패) 로컬이 아닌 쪽으로 답한다 — 릴레이 경로가 기존 동작이다.
   */
  private async isLocalDomain(domain: string, tenantId: string): Promise<boolean> {
    const now = Date.now();
    // 캐시 키에 테넌트를 넣어야 한다 — 판정이 테넌트마다 다르므로 도메인만으로 캐시하면
    // 한 테넌트의 결과가 다른 테넌트에 새어 위 수정이 무의미해진다.
    const cacheKey = `${tenantId}\u0000${domain}`;
    const cached = this.localDomainCache.get(cacheKey);
    if (cached && cached.expiresAt > now) return cached.value;
    let value = false;
    try {
      value = await isLocallyRoutableDomain(this.db, domain, tenantId);
    } catch (err) {
      // 조회 실패는 판정 불가 — 기존 경로(릴레이)로 흘려보내고 기록만 남긴다.
      this.logger.warn("local domain lookup failed", { domain, error: errMsg(err) });
      return false;
    }
    if (this.localDomainCache.size >= MAX_LOCAL_DOMAIN_CACHE) {
      for (const [k, v] of this.localDomainCache) if (v.expiresAt <= now) this.localDomainCache.delete(k);
      while (this.localDomainCache.size >= MAX_LOCAL_DOMAIN_CACHE) {
        const oldest = this.localDomainCache.keys().next();
        if (oldest.done) break;
        this.localDomainCache.delete(oldest.value);
      }
    }
    this.localDomainCache.set(cacheKey, { value, expiresAt: now + LOCAL_DOMAIN_TTL_MS });
    return value;
  }

  /**
   * 수신 도메인 MTA-STS 정책 조회(TTL 캐시). mtaSts 미설정 시 호출되지 않음.
   *
   * ★두 가지가 뚫려 있었다(감사 5차 M-1·M-2):
   *
   * **M-1 fail-open.** 정책 페치·파싱 실패가 "정책 없음"과 동일 취급돼 `mxTls`가
   * `opportunistic`으로 남았다 — 즉 **공격자가 정책 조회를 방해하기만 하면 평문·미검증 배달로
   * 떨어졌다.** RFC 8461 §5는 정확히 이 상황을 위해 **캐시된 정책을 계속 쓰라**고 요구하는데
   * 그 로직이 없었다. 그래서 마지막으로 본문까지 성공한 정책을 따로 보관하고(`policy` 필드),
   * 새 조회가 실패하면 그것이 만료되기 전까지 계속 강제한다.
   *
   * **M-2 `max_age` 미소비 + 실패의 장기 캐시.** `max_age`는 파싱만 되고 소비 지점이 0건이라
   * TTL이 고정 1시간이었고, **실패한 조회도 똑같이 1시간 캐시**됐다. 그 결과 공격자가
   * **시간당 한 번만** 개입하면 enforce를 영구히 다운그레이드할 수 있었다. 이제 성공은
   * 정책의 `max_age`를 따르고, 실패는 훨씬 짧게(NEGATIVE) 캐시해 재조회가 금방 돌아온다.
   */
  private async mtaStsLookup(domain: string): Promise<MtaStsLookup> {
    const now = Date.now();
    const cached = this.mtaStsCache.get(domain);
    if (cached && cached.expiresAt > now) return cached.lookup;

    let lookup: MtaStsLookup;
    try {
      lookup = await fetchMtaStsPolicy(domain, this.mtaSts!);
    } catch (err) {
      // 조회 자체가 던진 경우도 "정책 없음"이 아니라 **판정 불가**다 — 아래 보존 규칙을 탄다.
      this.logger.warn("mta-sts fetch failed", { domain, error: errMsg(err) });
      lookup = { found: false };
    }

    // 마지막으로 본문까지 성공한 정책 — 실패 시 이걸로 버틴다(RFC 8461 §5).
    let retained = cached?.policy;
    let ttl: number;
    if (lookup.policy) {
      // max_age는 초 단위. RFC 8461 §3.2의 상한(1년)으로 자르고, 하한도 둬서 과도한 재조회를 막는다.
      const maxAgeMs = Math.min(Math.max(lookup.policy.maxAge, MIN_STS_MAX_AGE_S), MAX_STS_MAX_AGE_S) * 1000;
      ttl = this.mtaSts!.cacheTtlMs ?? maxAgeMs;
      retained = { lookup, expiresAt: now + maxAgeMs };
    } else if (retained && retained.expiresAt > now) {
      /**
       * 조회가 정책을 못 가져왔지만 **아직 유효한 캐시 정책이 있다** — 강제를 유지한다.
       * 여기서 `opportunistic`으로 떨어지면 정책을 한 번 본 도메인이 방해 한 번에 평문이 된다.
       */
      this.logger.info("mta-sts 정책 재조회 실패 — 캐시된 정책 유지", { domain });
      this.mtaStsCache.set(domain, { lookup: retained.lookup, expiresAt: now + STS_NEGATIVE_TTL_MS, policy: retained });
      return retained.lookup;
    } else {
      ttl = STS_NEGATIVE_TTL_MS; // 실패·정책 없음은 짧게만 캐시한다(M-2).
    }
    this.mtaStsCache.set(domain, { lookup, expiresAt: now + ttl, ...(retained ? { policy: retained } : {}) });
    // 축출이 없으면 도메인마다 한 엔트리가 영구히 쌓인다 — 발송 대상 도메인 수는 무제한이다.
    // 만료분을 먼저 쓸고, 그래도 넘치면 가장 먼저 넣은 것부터 버린다(Map은 삽입 순서 보존).
    if (this.mtaStsCache.size > MAX_STS_CACHE_ENTRIES) {
      for (const [k, v] of this.mtaStsCache) if (v.expiresAt <= now) this.mtaStsCache.delete(k);
      while (this.mtaStsCache.size > MAX_STS_CACHE_ENTRIES) {
        const oldest = this.mtaStsCache.keys().next().value;
        if (oldest === undefined) break;
        this.mtaStsCache.delete(oldest);
      }
    }
    return lookup;
  }

  /** 관측 훅 호출 — 던져도 워커 진행을 막지 않는다. */
  private emitResult(outcome: DeliveryOutcome): void {
    if (!this.onResult) return;
    try {
      this.onResult(outcome);
    } catch {
      /* 관측 실패는 삼킴 */
    }
  }

  start(): void {
    if (!this.timer) {
      this.timer = setInterval(() => void this.tick(), this.intervalMs);
      this.timer.unref?.();
    }
    if (this.abuseOptions && !this.abuseTimer) {
      this.abuseTimer = setInterval(() => void this.sweepAbuse(), this.abuseSweepIntervalMs);
      this.abuseTimer.unref?.();
    }
  }

  async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.abuseTimer) {
      clearInterval(this.abuseTimer);
      this.abuseTimer = null;
    }
    while (this.running) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    while (this.abuseSweepRunning) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  /** 한 사이클 처리(테스트용 수동 구동) — 이번 사이클에 실제로 리스를 획득해 처리한 행 수. */
  async tick(): Promise<number> {
    if (this.running) return 0;
    this.running = true;
    try {
      return await this.runTick();
    } finally {
      this.running = false;
    }
  }

  /**
   * Abuse 스윕 한 사이클(테스트·수동 구동용, tick()과 동일 패턴) — 비활성(abuse 옵션
   * 미지정)이면 즉시 {checked:0, suspended:0}. 정상 발송 tick() 루프와는 별도 재진입
   * 가드(abuseSweepRunning)를 쓰므로 서로 블로킹하지 않는다.
   */
  async sweepAbuse(): Promise<{ checked: number; suspended: number }> {
    if (!this.abuseOptions || this.abuseSweepRunning) return { checked: 0, suspended: 0 };
    this.abuseSweepRunning = true;
    try {
      return await this.runAbuseSweep(this.abuseOptions);
    } finally {
      this.abuseSweepRunning = false;
    }
  }

  private async runAbuseSweep(opts: AbuseOptions): Promise<{ checked: number; suspended: number }> {
    const now = opts.now ?? Date.now();
    const windowMs = opts.windowMs ?? DEFAULT_ABUSE_WINDOW_MS;
    const windowStart = now - windowMs;

    // "최근 발송 있는 계정" = 창 안에 mta_queue 행이 하나라도 있는 계정(상태 무관).
    const { rows } = await this.db.query({
      // account_id IS NOT NULL — 시스템 발송(포워딩·바운스)은 귀속 계정이 없어 NULL이다.
      // 빼지 않으면 String(null)="null"로 계정 하나를 헛조회한다.
      sql: "SELECT DISTINCT account_id FROM mta_queue WHERE created_at > ? AND account_id IS NOT NULL",
      params: [windowStart],
    });

    let checked = 0;
    let suspended = 0;
    for (const row of rows) {
      const accountId = String(row.account_id);
      checked++;
      const verdict = await checkAccountAbuse(this.db, accountId, opts);
      if (verdict.action !== "suspend") continue;
      await suspendAccount(this.db, accountId);
      suspended++;
      this.emitResult("suspended");
      this.logger.info("account-suspended", { accountId, rate: verdict.rate, sent: verdict.sent, bounced: verdict.bounced });
    }
    return { checked, suspended };
  }

  private async runTick(): Promise<number> {
    const now = Date.now();
    // 크래시 복구 포함: status=1(in-flight)인데 lease_until이 지났으면 다시 due로 취급.
    // ★LIMIT — 없으면 큐가 10만 건일 때 한 tick이 10만 행을 전부 메모리에 올리고 행마다
    // 리스 UPDATE를 날린다(왕복 10만 번). 한 사이클을 짧게 유지해야 리스 만료·재기동에도
    // 진행이 남는다. 남은 행은 다음 tick이 가져간다(ORDER BY next_attempt이라 순서는 유지).
    const { rows } = await this.db.query({
      sql: `SELECT id, tenant_id, account_id, submission_id, blob_id, env_from, rcpt, rcpt_domain, attempts
            FROM mta_queue
            WHERE (status IN (${STATUS.queued}, ${STATUS.deferred}) AND next_attempt <= ?)
               OR (status = ${STATUS.inFlight} AND lease_until < ?)
            ORDER BY next_attempt ASC
            LIMIT ${this.batchSize}`,
      params: [now, now],
    });
    if (rows.length === 0) return 0;

    const leaseUntil = now + LEASE_MS;
    const leased: QueueRow[] = [];
    for (const row of rows) {
      const id = String(row.id);
      // §9-4 리스 획득: 단일 조건부 UPDATE, 획득 판정은 영향 행 수 === 1.
      const result = await this.db.batch([
        {
          sql: `UPDATE mta_queue SET status = ${STATUS.inFlight}, lease_until = ?
                WHERE id = ?
                  AND ((status IN (${STATUS.queued}, ${STATUS.deferred}) AND next_attempt <= ?)
                       OR (status = ${STATUS.inFlight} AND lease_until < ?))`,
          params: [leaseUntil, id, now, now],
        },
      ]);
      if (result[0]?.changes !== 1) continue; // 경합 패자 — 다른 워커가 선점
      leased.push({
        id,
        tenantId: String(row.tenant_id),
        rcpt: String(row.rcpt),
        rcptDomain: String(row.rcpt_domain),
        envFrom: String(row.env_from),
        blobId: String(row.blob_id),
        attempts: Number(row.attempts),
      });
    }
    if (leased.length === 0) return 0;

    // (rcpt_domain, env_from, blob_id) 그룹 — 연결당 rcpt 배칭
    const groups = new Map<string, QueueRow[]>();
    for (const row of leased) {
      const key = groupKey(row);
      const arr = groups.get(key);
      if (arr) arr.push(row);
      else groups.set(key, [row]);
    }

    for (const groupRows of groups.values()) {
      await this.processGroup(groupRows);
    }

    return leased.length;
  }

  private async processGroup(rows: QueueRow[]): Promise<void> {
    const first = rows[0];
    if (!first) return;
    const domain = first.rcptDomain;
    const envFrom = first.envFrom;
    const blobId = first.blobId;
    const senderDomain = envFrom.slice(envFrom.lastIndexOf("@") + 1).toLowerCase();

    /**
     * 릴레이 해석: 발신 도메인 → 테넌트 기본(해석기가 담당) → 전역 env → MX 직송.
     *
     * ★조회 실패는 MX 직송으로 폴백하지 **않는다**. "설정이 없다"(null)와 "설정을 못 읽었다"는
     * 다르다. 후자를 폴백으로 처리하면 DB가 잠깐 흔들릴 때 릴레이 전용으로 구성한 테넌트의
     * 메일이 인증 없이 25번 포트로 새 나간다 — 제공자 밖 발송이라 SPF·평판이 함께 깨지고,
     * 애초에 아웃바운드 25가 막힌 환경이면 그냥 전량 실패한다. 지연시키고 다시 시도한다.
     */
    let smarthost = this.smarthost;
    /**
     * 수신 도메인이 **우리가 호스팅하는 도메인**이면 릴레이를 태우지 않는다.
     *
     * 태우면 우리 → 릴레이 제공자 → (제공자가 MX 조회) → 우리로 한 바퀴 돌아온다. 그 대가가
     * 셋이다: ① 제공자의 발송 쿼터를 내부 메일이 쓴다 ② 사내 메일 본문이 제3자를 통과한다
     * (내부 전용으로 운영하는 배포에선 이게 제일 걸린다) ③ 제공자가 봉투 발신자를 자기
     * 바운스 주소로 재작성해 우리가 배달 결과를 못 본다.
     *
     * MX 직송이면 우리 자신의 MX로 접속한다(자기 공인 IP — hairpin). 스마트호스트가 생기기
     * 전부터 내부 메일이 그렇게 돌고 있었으므로 새 경로가 아니다(STATUS §8-4).
     * ⚠ 전제: 자기 MX로의 25번 접속이 가능해야 한다. 안 되면 연결 실패로 **지연**될 뿐
     *   메일이 사라지지는 않는다(deferAll).
     */
    if (await this.isLocalDomain(domain, first.tenantId)) {
      smarthost = undefined;
    } else if (this.smarthostResolver) {
      try {
        smarthost = (await this.smarthostResolver.resolve(first.tenantId, senderDomain)) ?? this.smarthost;
      } catch (err) {
        await this.deferAll(rows, { tenant: "relay configuration unavailable", detail: `smarthost resolve failed: ${errMsg(err)}` });
        return;
      }
    }

    let targets: MxRecord[];
    if (smarthost) {
      // 스마트호스트 릴레이 — MX 조회 생략, 전 도메인을 릴레이로
      targets = [{ exchange: smarthost.host, priority: 0 }];
    } else {
      let mxList: MxRecord[];
      try {
        mxList = await this.resolveMxFn(domain);
      } catch (err) {
        await this.deferAll(rows, { tenant: "recipient domain MX lookup failed", detail: `MX resolve failed: ${errMsg(err)}` });
        return;
      }
      // 우선순위 낮은 값 먼저. MX 레코드 없음 → RFC 5321 §5.1 폴백: 도메인 자체를 A로 시도.
      targets = mxList.length > 0 ? [...mxList].sort((a, b) => a.priority - b.priority) : [{ exchange: domain, priority: 0 }];
    }

    // MTA-STS 발신측 강제(opt-in, 스마트호스트 제외) — enforce면 TLS 필수 + MX 일치 강제
    let mxTls: TlsMode = "opportunistic";
    if (this.mtaSts && !smarthost) {
      try {
        const lookup = await this.mtaStsLookup(domain);
        const enforcement = stsEnforcement(lookup);
        if (enforcement.action === "require-tls" && lookup.policy) {
          const matched = targets.filter((t) => mxMatchesPolicy(t.exchange, lookup.policy!.mx));
          if (matched.length === 0) {
            await this.deferAll(rows, { tenant: "recipient MTA-STS policy mismatch", detail: `MTA-STS(enforce): MX가 정책 mx와 불일치 (${domain})` });
            return;
          }
          targets = matched;
          mxTls = "required"; // STARTTLS 실패 시 발송 실패(다운그레이드 배달 금지)
          this.logger.info("mta-sts enforce", { domain, mx: matched.map((m) => m.exchange) });
        } else if (enforcement.action === "report-only") {
          this.logger.info("mta-sts testing", { domain });
        }
      } catch (err) {
        // 정책 조회 실패는 발송을 막지 않음(정책 부재와 동일 취급)
        this.logger.warn("mta-sts lookup error", { domain, error: errMsg(err) });
      }
    }

    // 세대는 blobs 원장이 정본이다(@ionosphere/db lookupBlob). 0을 가정하면 GC가 doomed로 찍었다가
    // 재수신으로 부활한 블롭(generation+1 경로)을 못 읽고 큐 전체가 지연된다 — SCHEMA.md §9-5.
    let generation = 0;
    try {
      generation = (await lookupBlob(this.db, blobId))?.generation ?? 0;
    } catch (err) {
      await this.deferAll(rows, { tenant: "temporary internal error", detail: `blob lookup failed: ${errMsg(err)}` });
      return;
    }
    let raw: Uint8Array;
    try {
      raw = await this.blobs.get(blobId, generation);
    } catch (err) {
      await this.deferAll(rows, { tenant: "temporary internal error", detail: `blob load failed: ${errMsg(err)}` });
      return;
    }

    /**
     * FBL 상관관계 헤더 — ARF 리포트가 원문을 동봉하므로, 이 값으로 "어느 발송이 신고당했나"를
     * 되찾는다(`arf.ts`). **DKIM 서명보다 먼저** 붙여야 서명 범위에 들어가고, 그래야 중간에
     * 누가 바꿔치기할 수 없다.
     *
     * ★값은 큐 행 id다. 계정·테넌트를 직접 싣지 않는 이유: 이 헤더는 **수신자에게 그대로
     * 전달**된다. 내부 식별자 하나만 노출하고 나머지는 우리 DB에서 조인한다.
     *
     * ★한 발송이 수신자별로 행이 여러 개일 수 있다(§7-9). 그때는 첫 행의 id를 쓴다 —
     * 신고는 "이 메시지가 신고당했다"이지 "이 수신자에게 간 사본이"가 아니고, 자동 정지는
     * 계정 단위 집계라 어느 행에 표시되든 같은 결과가 나온다.
     */
    const feedbackId = rows[0]?.id;
    if (typeof feedbackId === "string" && feedbackId.length > 0) {
      raw = prependHeader(raw, `${FEEDBACK_ID_HEADER}: ${feedbackId}`);
    }

    if (this.dkim) {
      const fromDomain = senderDomain;
      try {
        /**
         * 활성 키 **전부**로 서명한다(이중 서명). Ed25519 단독이면 그것을 검증하지 않는 수신자에게는
         * 우리 서명이 없는 것과 같다 — Gmail이 `dkim=neutral (no key)`를 냈다(2026-08-01 실측).
         * 근거는 `DkimHook.selectorFor` 주석에 있다.
         *
         * 순서: RFC 6376 §3.7은 여러 DKIM-Signature의 순서를 규정하지 않는다. 각 서명은
         * **자기 자신만** h=에 넣고 다른 DKIM-Signature는 서명 범위에서 제외하므로(canon 규칙),
         * prepend 순서가 검증에 영향을 주지 않는다 — 나중에 붙는 것이 위로 간다.
         */
        for (const key of await this.dkim.selectorFor(fromDomain)) {
          /**
           * 릴레이 경유면 `message-id`를 서명 범위에서 뺀다 — 릴레이가 그 헤더를 재작성해
           * 우리 서명이 목적지에서 **항상** 깨지기 때문이다(2026-07-31 Google DMARC 리포트로
           * `s=ed1 → fail` 확인, 같은 리포트의 `bh=` 일치로 본문은 무사함을 확인).
           * 근거와 잔여 위험은 `RELAY_SAFE_SIGNED_HEADERS` 주석에 있다.
           *
           * ★이 판단이 여기 있는 이유: 서명 시점에 릴레이 경유 여부를 알아야 하는데, 그 값
           * (`smarthost`)이 이 함수 안에서 이미 결정돼 있다. 직접 발송은 재작성이 없으므로
           * 기본 목록을 그대로 쓴다 — 릴레이의 제약을 전 경로에 퍼뜨리지 않는다.
           */
          const header = dkimSign(raw, {
            domain: fromDomain,
            selector: key.selector,
            privateKey: key.privateKey,
            algorithm: key.algorithm,
            ...(smarthost ? { signedHeaders: [...RELAY_SAFE_SIGNED_HEADERS] } : {}),
          });
          raw = prependHeader(raw, header);
        }
      } catch (err) {
        this.logger.warn("dkim sign failed — sending unsigned", { domain: fromDomain, error: errMsg(err) });
      }
    }

    /**
     * 세션당 RCPT 상한으로 쪼갠다. 릴레이 제공자가 정하는 값이고(Cloudflare Email Service는 50),
     * 넘겨 보내면 초과분이 거절된다. 여기서 나누지 않으면 대량 발송에서 **수신자 일부만 조용히
     * 빠진 채** 나머지가 성공으로 기록된다. 상한이 없으면(직송 포함) 한 덩어리 그대로다.
     *
     * 청크마다 연결을 새로 여는 비용은 감수한다 — DKIM 서명과 블롭 로드는 이미 끝난 뒤라
     * 재사용되고, 상한을 넘기는 그룹 자체가 드물다.
     */
    const cap = Math.max(1, smarthost?.maxRcptsPerSession ?? rows.length);
    for (let i = 0; i < rows.length; i += cap) {
      const chunk = rows.slice(i, i + cap);
      const rcpts = chunk.map((r) => r.rcpt);
      let result: SmtpClientResult | null = null;
      let usedMx: MxRecord | null = null;
      let lastErr = "no MX targets";

      for (const mx of targets) {
        const mxPort = smarthost ? (smarthost.port ?? 587) : this.port;
        /**
         * DANE는 **MX 호스트마다** 다르다(TLSA는 `_25._tcp.<mx>`에 붙는다). 도메인 단위로
         * 한 번 조회해 재사용하면 두 번째 MX에 첫 MX의 고정을 들이대게 된다.
         * 스마트호스트 경유는 제외한다 — 릴레이는 우리가 고른 상대고 이미 required+PKIX다.
         */
        const tlsa: TlsaLookup = smarthost ? { kind: "none" } : await this.lookupTlsa(mx.exchange, mxPort);
        if (tlsa.kind === "bogus") {
          // 이 MX는 건너뛴다(다음 MX 시도). 전부 이러면 아래에서 지연 처리된다 — 조작이
          // 의심되는 상대에게 평문/미검증으로 보내는 것보다 늦게 가는 편이 낫다.
          this.logger.warn("tlsa bogus — 이 MX는 건너뛴다", { mx: mx.exchange, reason: tlsa.reason });
          lastErr = `TLSA 검증 실패(${mx.exchange}): ${tlsa.reason}`;
          continue;
        }
        const dane = tlsa.kind === "tlsa" ? tlsa.set : null;
        const attempt = await sendSmtp({
          host: mx.exchange,
          port: mxPort,
          ehloName: this.ehloName,
          mailFrom: envFrom,
          rcptTo: rcpts,
          raw,
          // 릴레이는 자격증명 보호로 STARTTLS 강제, MX 직송은 opportunistic(단 MTA-STS enforce면 required)
          tls: smarthost ? (smarthost.tls ?? "required") : mxTls,
          ...(smarthost?.auth ? { auth: smarthost.auth } : {}),
          ...(dane ? { dane } : {}),
        });
        if (attempt.dane === "mismatch") {
          // 중간자 신호다. 로그에 남겨야 "왜 이 도메인만 안 나가나"를 추적할 수 있다.
          this.logger.warn("dane mismatch — 배달 중단", { mx: mx.exchange, message: attempt.message });
        }
        if (attempt.code !== 0) {
          // 최소 한 개의 SMTP 응답을 받았음 — 이 MX의 판정을 최종으로 채택(다음 MX로 넘어가지 않음)
          result = attempt;
          usedMx = mx;
          break;
        }
        lastErr = attempt.message; // 연결 자체 실패 — 다음 MX 시도
      }

      // 청크 단위로 판정한다. 한 청크가 실패해도 이미 성공한 청크의 결과를 되돌리지 않는다.
      if (!result || !usedMx) await this.deferAll(chunk, { tenant: lastErr, detail: lastErr });
      else await this.applyOutcome(chunk, result, usedMx, domain, smarthost !== undefined);
    }
  }

  /**
   * @param viaSmarthost 스마트호스트 릴레이 경유인가 — **억제(suppression) 판정이 갈린다.**
   *   릴레이는 우리 submission을 심사하는 중간자이므로, 그가 낸 5xx는 "수신자가 거절했다"는
   *   뜻이 아니다(아래 `permanent` 분기 주석 참조).
   */
  private async applyOutcome(
    rows: QueueRow[],
    result: SmtpClientResult,
    mx: MxRecord,
    domain: string,
    viaSmarthost: boolean,
  ): Promise<void> {
    const now = Date.now();
    const stmts: Statement[] = [];
    const suppressRows: unknown[][] = [];

    for (const row of rows) {
      const rc = result.rcptResults.get(row.rcpt);
      const rcptAccepted = rc !== undefined && rc.code >= 200 && rc.code < 300;
      /**
       * ★어느 단계의 코드를 기록하는가 — RCPT가 아니라 **실패한 단계**의 코드여야 한다.
       *
       * 예전엔 `rc ? rc.code : result.code`였다. RCPT가 250으로 수락됐는데 DATA 이후 최종
       * 응답이 실패면, 그 250이 `last_error`와 로그에 들어가 **실제 실패 코드를 가렸다.**
       * 2026-08-03 라이브에서 포워딩이 계속 deferred로 도는데 `last_error="250"`이라
       * 원인을 알 수 없었다 — 250은 성공 코드다. `GET /v1/queue`로 이 값을 보는 테넌트도
       * 같은 것을 본다.
       *
       * 그래서 RCPT가 수락된 경우에는 세션 최종 코드(`result.code`)를 쓴다 — 그때 실패의
       * 원인은 RCPT가 아니라 그 뒤 단계이기 때문이다. RCPT가 거절된 경우에만 `rc.code`가
       * 실패 코드다. `permanent`도 같은 단계를 따라가야 판정과 기록이 어긋나지 않는다.
       */
      const code = rcptAccepted ? result.code : rc ? rc.code : result.code;
      const permanent = rcptAccepted ? result.permanent : rc ? rc.permanent : result.permanent;

      if (result.ok && rcptAccepted) {
        stmts.push({ sql: `UPDATE mta_queue SET status = ${STATUS.done}, last_error = NULL WHERE id = ?`, params: [row.id] });
        this.logger.info("sent", { rcpt: row.rcpt, domain, mx: mx.exchange, code: result.code });
        this.emitResult("sent");
        continue;
      }

      if (permanent) {
        stmts.push({
          sql: `UPDATE mta_queue SET status = ${STATUS.bounced}, last_error = ? WHERE id = ?`,
          params: [rejectionText(code, result.message), row.id],
        });
        /**
         * ★수신자를 억제할지는 **누가 거절했는가**에 달렸다 — 5xx라는 사실만으로는 부족하다.
         *
         * 수신 MX가 5xx를 주면 "그 주소는 없다/받지 않는다"는 뜻이므로 억제가 맞다. 그런데
         * **스마트호스트 릴레이**는 수신자가 아니라 우리 submission을 심사하는 중간자다. 그가
         * 내는 5xx는 우리 쪽 사정이다 — 정책 위반·인증 문제·도메인 미승인 등. 수신자는 그
         * 메일을 본 적조차 없다.
         *
         * 2026-08-03 라이브에서 이것이 실제로 틀렸다: Cloudflare 릴레이가
         * `550 5.6.0 From: header does not match mail from`을 냈는데(SRS 포워딩에서는 From:과
         * envelope MAIL FROM이 구조적으로 어긋난다), 우리는 그것을 하드바운스로 읽고 **무고한
         * Gmail 주소를 영구 차단**했다. 그 주소는 Gmail이 거절한 적이 없다.
         *
         * 억제는 되돌리기 어려운 쪽이다(hardBounce는 만료가 없다). 그래서 릴레이 경유 5xx는
         * 억제하지 않고 큐만 닫는다 — 운영자가 원인을 고치면 다시 보낼 수 있어야 한다.
         * fail closed의 방향이 여기서는 "억제하지 않는 쪽"이다: 잘못 억제하면 정상 수신자에게
         * 영구히 못 보내고, 억제하지 않으면 같은 설정 오류로 한 번 더 실패할 뿐이다.
         */
        if (viaSmarthost) {
          this.logger.warn("relay rejected — 수신자 억제 없음(릴레이가 낸 5xx는 수신자 판정이 아니다)", {
            rcpt: row.rcpt,
            domain,
            code,
            stage: rcptAccepted ? "data" : "rcpt",
            detail: result.message,
          });
        } else {
          // 수신 MX가 영구 거절했다 — 다시 보내도 같은 답이므로 차단이 맞다.
          suppressRows.push([row.tenantId, row.rcpt, SUPPRESSION_REASON.hardBounce, "mta-bounce", now, suppressionExpiresAt(SUPPRESSION_REASON.hardBounce, now)]);
        }
        this.logger.info("bounced", {
          rcpt: row.rcpt,
          domain,
          code,
          stage: rcptAccepted ? "data" : "rcpt",
          via: viaSmarthost ? "smarthost" : "mx",
          suppressed: !viaSmarthost,
        });
        this.emitResult("bounced");
        continue;
      }

      // 4xx/전송 실패 — 재시도 대상
      const attempts = row.attempts + 1;
      if (attempts >= this.maxAttempts) {
        stmts.push({
          sql: `UPDATE mta_queue SET status = ${STATUS.bounced}, attempts = ?, last_error = ? WHERE id = ?`,
          // 마지막 시도의 거절 문구까지 남긴다 — 8회를 소모한 이유가 코드 하나로는 드러나지 않는다.
          params: [attempts, `max attempts exhausted: ${rejectionText(code, result.message)}`, row.id],
        });
        // 여기까지 온 건 **상대가 계속 4xx를 준** 경우다(연결 자체가 안 되는 경우는 deferAll로 빠진다).
        // 영구 거절이 아니라 우리가 포기한 것이므로 사유를 갈라 둔다 — 운영자가 해제할 수 있어야 한다.
        // 릴레이 경유는 위와 같은 이유로 억제하지 않는다: 우리 submission이 계속 거절된 것이지
        // 수신자가 받지 못한 것이 아니다. `exhausted`는 만료가 있지만, 그래도 무고한 주소를
        // 그 기간 동안 막는다.
        if (!viaSmarthost) {
          suppressRows.push([row.tenantId, row.rcpt, SUPPRESSION_REASON.exhausted, "mta-max-attempts", now, suppressionExpiresAt(SUPPRESSION_REASON.exhausted, now)]);
        }
        this.logger.info("bounced", {
          rcpt: row.rcpt,
          domain,
          attempts,
          reason: "max-attempts",
          via: viaSmarthost ? "smarthost" : "mx",
          suppressed: !viaSmarthost,
        });
        this.emitResult("bounced");
      } else {
        const next = now + backoffMs(attempts);
        stmts.push({
          sql: `UPDATE mta_queue SET status = ${STATUS.deferred}, attempts = ?, next_attempt = ?, lease_until = NULL, last_error = ? WHERE id = ?`,
          // 4xx도 사유를 남긴다 — 재시도 중인 건이 "왜" 밀리는지 알아야 개입 시점을 판단할 수 있다
          // (상대 큐 과부하면 기다리면 되고, 정책 거절이면 기다려도 안 된다).
          params: [attempts, next, rejectionText(code, result.message), row.id],
        });
        // ★코드와 실패 단계를 로그에 남긴다. 예전엔 attempts·next만 찍어서, 재시도가 도는데
        // 왜 도는지 로그만으로는 알 수 없었다(2026-08-03 포워딩 사고). `stage`가 있으면
        // "RCPT는 통과했는데 DATA 뒤에서 막혔다"가 한 줄로 드러난다.
        this.logger.info("deferred", {
          rcpt: row.rcpt,
          domain,
          attempts,
          next,
          code,
          stage: rcptAccepted ? "data" : "rcpt",
        });
        this.emitResult("deferred");
      }
    }

    this.appendSuppressions(stmts, suppressRows);
    await this.db.batch(stmts);
  }

  /**
   * 수신자와 **한 마디도 못 나눈** 실패(MX 조회 실패·연결 실패·블롭 로드 실패)의 처분.
   *
   * ★여기서는 suppression을 만들지 않는다. 이 경로의 원인은 대개 **우리 쪽**이다 —
   * 자체 DNS나 네트워크가 몇 시간 죽으면 그동안 큐에 있던 정상 수신자가 전부 상한을 소진하고,
   * 예전 구현은 그들을 전부 하드바운스로 기록해 **영구 차단 목록에 넣었다.** 수신자에 대해
   * 알아낸 것이 아무것도 없는데 수신자를 벌하는 셈이라, 큐 행만 bounced로 닫고 끝낸다.
   */
  /**
   * TLSA 조회 — 실패는 **DANE 미적용**으로 삼킨다.
   *
   * 여기서 던지면 상대 DNS 사정으로 우리 큐가 멈춘다. DANE는 있으면 강화되는 것이지
   * 없으면 배달을 막는 것이 아니다(있는데 안 맞는 경우만 막는다).
   */
  private async lookupTlsa(mxHost: string, port: number): Promise<TlsaLookup> {
    if (!this.resolveTlsaFn) return { kind: "none" };
    try {
      return await this.resolveTlsaFn(mxHost, port);
    } catch (err) {
      this.logger.warn("tlsa lookup failed — DANE 미적용", { mx: mxHost, error: errMsg(err) });
      return { kind: "none" };
    }
  }

  private async deferAll(rows: QueueRow[], failure: QueueFailure): Promise<void> {
    const now = Date.now();
    const stmts: Statement[] = [];
    // 저장되는 값은 테넌트 노출용뿐이다 — 운영자용 상세는 로그로만 나간다(M-11).
    const stored = redactForTenant(failure.tenant);

    for (const row of rows) {
      const attempts = row.attempts + 1;
      if (attempts >= this.maxAttempts) {
        stmts.push({
          sql: `UPDATE mta_queue SET status = ${STATUS.bounced}, attempts = ?, last_error = ? WHERE id = ?`,
          params: [attempts, stored, row.id],
        });
        this.logger.info("bounced", { rcpt: row.rcpt, attempts, reason: "max-attempts", suppressed: false, error: failure.detail });
        this.emitResult("bounced");
      } else {
        const next = now + backoffMs(attempts);
        stmts.push({
          sql: `UPDATE mta_queue SET status = ${STATUS.deferred}, attempts = ?, next_attempt = ?, lease_until = NULL, last_error = ? WHERE id = ?`,
          params: [attempts, next, stored, row.id],
        });
        this.logger.info("deferred", { rcpt: row.rcpt, attempts, next, error: failure.detail });
        this.emitResult("deferred");
      }
    }

    await this.db.batch(stmts);
  }

  private appendSuppressions(stmts: Statement[], suppressRows: readonly unknown[][]): void {
    if (suppressRows.length === 0) return;
    const sql = this.db.insertIgnore("suppressions", ["tenant_id", "email", "reason", "source", "created_at", "expires_at"]);
    for (const r of suppressRows) stmts.push({ sql, params: r });
  }
}
