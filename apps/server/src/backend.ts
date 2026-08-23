/**
 * 프로토콜 백엔드 ↔ 스토어 접착층.
 * SMTP 수신 → mime 파싱 → 블롭 저장 → appendMessage(INBOX),
 * POP3 → authenticate/maildrop/RETR/QUIT 커밋 (SCHEMA.md §7-5).
 *
 * Phase 0 라우팅: rcpt 주소 = 계정 대표 주소(accounts.email) 직매치.
 * addresses 테이블 라우팅(알리아스·캐치올)은 Phase 2.
 */
import {
  buildReceivedHeader,
  MAX_RECEIVED_HOPS,
  MAX_RELAY_TARGETS,
  noopLogger,
  open,
  ulid,
  type Logger,
  type MaildropLock,
  type ReceivedTransport,
  type ScramStoredKeys,
} from "@ionosphere/core";
import { createHmac, timingSafeEqual } from "node:crypto";
import { parseMessage, type ParsedAddress, type ParsedMessage } from "@ionosphere/mime";
import { isLocallyRoutableDomain, type DbDriver } from "@ionosphere/db";
import { arcSeal, parseCidrList, type CidrMatcher, type DkimAlgorithm, type DnsResolver } from "@ionosphere/mail-auth";
import { prependAuthResults, runInboundAuth, stripForgedAuthResults, stripForgedReceivedSpf } from "./inbound-auth.ts";
import { DEFAULT_RATE_LIMIT, DEFAULT_RELAY_PER_HOUR, enqueueMessage, OutboundRejectedError, type OutboundPolicy } from "@ionosphere/mta";
import type { DkimHook, DkimKeyLookup } from "@ionosphere/mta";
import {
  checkDnsbl,
  checkGreylist,
  evaluateRules,
  scanForVirus,
  scoreSpam,
  SPAM_ACTION,
  type AuthSummary,
  type DnsblZone,
  type GreylistOptions,
  type SpamScore,
  type SpamScoreOptions,
  type VirusScanOptions,
  type VirusScanner,
} from "@ionosphere/spam";
import { runSieve, type SieveEnv } from "@ionosphere/sieve";
import { isSrsAddress, srsForward, srsReverse } from "@ionosphere/srs";
import {
  authenticate,
  putBlob,
  Store,
  StoreQuotaError,
  type AppendAddress,
  type BlobStore,
  scramKeysFor,
  scramAuthorize,
} from "@ionosphere/store";
import type { SmtpAuthResult, SmtpBackend } from "@ionosphere/proto-smtp";
import type { LmtpBackend, LmtpDelivery, LmtpDeliverEnv } from "@ionosphere/proto-lmtp";
import {
  InProcessMaildropLock,
  type Pop3Backend,
  type Pop3MaildropMessage,
} from "@ionosphere/proto-pop3";
import { toAppendAddresses } from "./addresses.ts";

/** ParsedMessage + 봉투 → Sieve 실행 환경(헤더 소문자 키). */
function buildSieveEnv(parsed: ParsedMessage, env: { mailFrom: string; rcptTo: readonly string[] }, size: number): SieveEnv {
  return {
    headers: parsed.headers,
    envelopeFrom: env.mailFrom,
    envelopeTo: [...env.rcptTo],
    size,
  };
}

/** MailboxRow 목록 → "A/B" 경로 → id 맵(계층은 parentId, 루트 parentId=''). */
function buildMailboxPathMap(rows: readonly { id: string; parentId: string; name: string }[]): Map<string, string> {
  const byId = new Map(rows.map((r) => [r.id, r]));
  const path = (r: { id: string; parentId: string; name: string }): string => {
    const segs = [r.name];
    let cur = r;
    for (let d = 0; d < 100 && cur.parentId !== ""; d++) {
      const p = byId.get(cur.parentId);
      if (!p) break;
      segs.unshift(p.name);
      cur = p;
    }
    return segs.join("/");
  };
  return new Map(rows.map((r) => [path(r), r.id]));
}

/** Sieve imap4flags(IMAP 표기) → 스토어 키워드(소문자 $). */
function sieveFlagToKeyword(flag: string): string {
  const sys: Record<string, string> = { "\\seen": "$seen", "\\answered": "$answered", "\\flagged": "$flagged", "\\draft": "$draft", "\\deleted": "$deleted" };
  return sys[flag.toLowerCase()] ?? flag.toLowerCase();
}

/**
 * relay 대상 상한은 `@ionosphere/core`가 소유한다 — 배달 경로(여기)와 생성 경로(REST·CLI)가
 * **같은 값을 봐야** 한다. 예전엔 여기에만 있어서 생성 시에는 통과하고 배달에서만 막혀,
 * 설정은 받아들여졌는데 그 주소로 온 메일이 영구 451 루프에 빠졌다.
 *
 * 초과 시 처분은 fail closed다 — 부분 릴레이가 아니라 **아무것도 릴레이하지 않는다**
 * (Sieve 쪽 기존 정책과 동일).
 */

/**
 * 트레이스 홉 수 = Received 헤더 개수(RFC 5321 §6.3 루프 차단).
 *
 * countForwardHops와 세는 대상이 다르다: 저건 **우리 자신의** 포워딩만 세고, 이건 경로 위의
 * 모든 MTA를 센다. 우리를 경유해 도는 제3자 루프는 X-Ionosphere-Forwarded를 만들지 않으므로
 * 저 카운터엔 잡히지 않는다.
 */
function countReceivedHops(parsed: ParsedMessage): number {
  return parsed.headers.get("received")?.length ?? 0;
}

/**
 * 우리가 붙이는 포워딩 표식 — `<도메인>; s=<HMAC>`.
 *
 * ★왜 서명하나(감사 5차 M-15): 예전엔 값이 도메인 문자열뿐이었고 `countForwardHops`가
 * **헤더 발생 횟수만** 셌다. 이 헤더는 어떤 제거기에도 걸리지 않으므로, 미인증 원격 발신자가
 * `X-Ionosphere-Forwarded: x` 10줄을 넣어 보내면 `hops >= forwardMaxHops`가 즉시 참이 되어
 * **피해자의 `forward_to` 알리아스와 Sieve redirect가 통째로 무력화**됐다(미인증 원격 DoS).
 *
 * 도메인만 검사하는 것으로는 부족하다 — 공격자는 피해자에게 메일을 보내는 쪽이라 **피해자의
 * 도메인 이름을 이미 알고 있다.** 그래서 우리 시크릿으로 봉인한다.
 *
 * Message-ID를 서명 범위에 넣는 이유: 도메인만 서명하면 한 번 포워딩된 메일에서 표식을 오려내
 * **다른 메일에 10번 붙여넣는 재사용**이 가능하다. 메시지에 묶으면 그 재사용이 끊긴다.
 */
function forwardMarker(domain: string, parsed: ParsedMessage, secret: string): string {
  const seal = createHmac("sha256", secret)
    .update(`${domain}\n${messageIdOf(parsed)}`)
    .digest("base64url")
    .slice(0, 16);
  return `${domain}; s=${seal}`;
}

/** 서명 범위에 쓸 Message-ID. 없으면 빈 문자열 — 생성·검증이 같은 값을 쓰므로 일관된다. */
function messageIdOf(parsed: ParsedMessage): string {
  return (parsed.headers.get("message-id")?.[0] ?? "").trim();
}

/**
 * 포워딩 홉 수 = **우리가 봉인한** X-Ionosphere-Forwarded 표식의 개수(루프 방지).
 *
 * 봉인이 없거나 맞지 않는 값은 세지 않는다 — 위조로 루프가드를 발동시켜 피해자의 포워딩을
 * 끄는 것을 막기 위해서다. 세지 않을 뿐 제거하지는 않는다(원본 보존).
 *
 * ★개명(mailer → ionosphere) 전 이름도 함께 센다. 롤링 배포 중에는 구 노드가 붙인
 * `X-Mailer-Forwarded`와 새 노드가 붙인 이름이 한 메시지에 섞인다. 한쪽만 세면 홉 수가
 * 실제보다 적게 나와 **루프가드가 조용히 느슨해진다** — 메일 루프는 증폭되는 사고라
 * 세는 쪽으로(= 더 안전한 쪽으로) 틀린다. 봉인 HMAC은 헤더 이름을 포함하지 않으므로
 * 같은 검증식이 두 이름 모두에 그대로 성립한다.
 */
function countForwardHops(parsed: ParsedMessage, secret: string): number {
  const values = [
    ...(parsed.headers.get("x-ionosphere-forwarded") ?? []),
    ...(parsed.headers.get("x-mailer-forwarded") ?? []),
  ];
  let hops = 0;
  for (const raw of values) {
    const semi = raw.indexOf(";");
    if (semi === -1) continue;
    const domain = raw.slice(0, semi).trim();
    if (!domain) continue;
    const expected = forwardMarker(domain, parsed, secret);
    // 길이가 같은 상수시간 비교 — 표식은 비밀이 아니지만 비교 방식을 갈래마다 다르게 두지 않는다.
    const actual = raw.trim();
    if (actual.length === expected.length && timingSafeEqual(Buffer.from(actual), Buffer.from(expected))) hops += 1;
  }
  return hops;
}

/** raw 앞에 헤더 한 줄(+CRLF)을 붙인다(inbound-auth prependAuthResults와 동형). */
function prependHeaderBytes(raw: Uint8Array, headerLine: string): Uint8Array {
  const head = new TextEncoder().encode(headerLine + "\r\n");
  const out = new Uint8Array(head.length + raw.length);
  out.set(head, 0);
  out.set(raw, head.length);
  return out;
}

/** 수신(비인증) 경로 봉투 — SMTP 25와 LMTP가 공유. */
interface InboundEnv {
  mailFrom: string;
  heloName: string;
  clientIp: string;
  rcptTo: string[];
  raw: Uint8Array;
  authenticatedAs: string | null;
  /** Received의 `with` 키워드 — SMTP 25는 esmtp, LMTP는 lmtp(RFC 3848). */
  transport: ReceivedTransport;
  /** TLS 세션 정보(어댑터가 소켓에서 채움). 평문이면 undefined. */
  tls?: { protocol?: string | undefined; cipher?: string | undefined } | undefined;
}

/** 메시지 단위 준비가 끝난 상태 — 수신자별 배달의 입력. */
interface PreparedInbound {
  kind: "ok";
  parsed: ParsedMessage;
  /**
   * 저장·릴레이용 바이트 — 위조 헤더를 제거하고 **우리 Received(+Received-SPF)를 붙인** 결과.
   *
   * ★왜 원본(`env.raw`)이 아니라 이걸 릴레이해야 하나(감사 5차 H-6): `relayCopy`/`relayBounce`가
   * 원본을 그대로 릴레이해서 **우리를 경유한 메일의 Received 개수가 우리 홉에서 증가하지 않았다.**
   * 그래서 `MAX_RECEIVED_HOPS`가 수신 저장 경로에만 걸리고 배달(릴레이) 경로가 비어 있었다 —
   * 생성 경로와 배달 경로가 같은 값을 봐야 한다는 소유권 규약이 깨진 자리다.
   * `limits.ts`가 `MAX_RECEIVED_HOPS`의 존재 이유로 적어 둔 "우리를 경유해 도는 제3자 루프"를
   * 잡는 카운터가 정확히 그 경로에서 증가하지 않았다. RFC 5321 §4.4는 Received 추가를 MUST로 요구한다.
   */
  stored: Uint8Array;
  blobId: string;
  /** putBlob()이 기록한 세대 — appendMessage로 그대로 넘겨 blobs 행을 같은 세대로 맞춘다. */
  blobGeneration: number;
  size: number;
  receivedAt: number;
  /**
   * 스팸 점수가 junk로 판정했는가. **거부가 아니라 배치 힌트**다 —
   * 배달은 하되 Junk 메일함(있으면)과 `$Junk` 키워드로 보낸다.
   */
  junk?: boolean;
  /** SCHEMA §9-3 코드. `spf: null`은 "검사 안 함"(신뢰 릴레이)이고 `0`(none)과 다르다. */
  authCodes: { spf: number | null; dkim: number; dmarc: number } | null;
  authResultsValue: string;
}

/**
 * 수신자 1명의 최종 처분. SMTP는 이걸 집계해 단일 응답을 내고, LMTP는 수신자별로 그대로 답한다.
 * (예전엔 deliver() 안의 delivered/accepted/quotaFailed 카운터 3개로만 존재해서
 *  LMTP가 수신자별 상태를 표현할 자리조차 없었다.)
 */
type RecipientOutcome =
  | { status: "delivered" }
  | { status: "accepted"; via: "forward" | "bounce-relay" | "sieve-discard" | "sieve-redirect" }
  | { status: "quota" }
  /**
   * 일시 실패 — 재시도하면 될 수도 있는 것(스토어 오류·DB 순단 등).
   *
   * `unknown`과 갈라야 하는 이유: LMTP는 `unknown`을 550(수신자 없음)으로 답한다. 일시 오류를
   * 거기 섞으면 **상류 MTA가 영구 실패로 보고 메일을 버린다.** SMTP 집계에서도 둘 다 4xx로
   * 수렴하긴 하지만, 의미가 다른 값을 같은 칸에 넣으면 LMTP처럼 코드가 갈리는 자리에서 새어나간다.
   */
  | { status: "tempfail" }
  | { status: "unknown" };

/**
 * 팬아웃 처분 합성 — 수신자 1명이 계정 N개로 퍼졌을 때 SMTP/LMTP에 돌려줄 **단일** 처분.
 *
 * 성공이 하나라도 있으면 성공으로 답한다. 4xx로 답하면 발신측이 메시지 전체를 재시도하는데,
 * 그러면 **이미 성공한 계정에 중복 배달**이 재시도마다 쌓인다(쿼터가 풀릴 때까지 며칠). 부분
 * 실패는 재시도로 고쳐지지 않는 종류라, 중복 폭주를 만드는 대신 로그로 드러내고 나머지를 살린다.
 * 전원 실패일 때만 4xx/5xx가 나가므로 "아무 데도 안 들어갔는데 250" 같은 유실은 없다.
 */
function combineFanoutOutcomes(outcomes: readonly RecipientOutcome[], forwarded: boolean): RecipientOutcome {
  if (outcomes.some((o) => o.status === "delivered")) return { status: "delivered" };
  const accepted = outcomes.find((o) => o.status === "accepted");
  if (accepted) return accepted;
  if (forwarded) return { status: "accepted", via: "forward" };
  // 전원 실패 — 재시도 가능한 사유를 우선한다. 하나라도 4xx면 5xx(unknown)로 굳히지 않는다.
  // quota를 tempfail보다 앞에 두는 건 기존 SMTP 집계와 같은 순서라서다(452가 더 구체적이다).
  if (outcomes.some((o) => o.status === "quota")) return { status: "quota" };
  if (outcomes.some((o) => o.status === "tempfail")) return { status: "tempfail" };
  return { status: "unknown" };
}

/** 수신 파이프라인 결과 — 메시지 단위 거부 또는 수신자별 처분 맵(키는 소문자 주소). */
type InboundResult =
  | { kind: "reject"; code: number; enhanced: string; message: string }
  | { kind: "perRecipient"; outcomes: Map<string, RecipientOutcome> };

export interface IonosphereSmtpBackendOptions {
  /** 수신 인증(SPF/DKIM/DMARC)용 — relay 경로에서 사용. 미지정 시 인증 파이프라인 생략. */
  resolver?: DnsResolver;
  /**
   * Authentication-Results authserv-id (우리 호스트명).
   * Received의 `by` 절도 이 값을 쓴다 — 둘 다 "이 서버의 이름"이라 정본이 하나여야 한다.
   * ⚠ 미지정 시 "localhost"로 떨어진다. 제출 백엔드에 넘기는 걸 빠뜨려 라이브 메일에
   *   `by localhost`가 찍힌 적이 있다(received-wiring 테스트가 이제 이걸 잡는다).
   */
  authservId?: string;
  /**
   * submission 프로파일 인증 함수. 있으면 이 백엔드는 발송(submission) 백엔드.
   * 반환은 `SmtpAuthResult` — 어댑터가 감사 로그를 찍으려면 `credKind`·`throttled`가 필요하다.
   */
  authFn?: (user: string, pass: string) => Promise<SmtpAuthResult>;
  /**
   * SCRAM-SHA-256 배선 — **두 함수를 함께** 넘겨야 광고된다(하나만 있으면 교환을 끝낼 수 없다).
   *
   * ★왜 `authFn`처럼 옵션으로 받는가(클래스 메서드로 두지 않는 이유):
   * ① `SmtpServer`가 백엔드 메서드 **유무**로 `scramOffered`를 판정한다(proto-smtp/src/server.ts).
   *    클래스에 그냥 두면 25번 relay 백엔드도 SCRAM을 갖게 되어, 인증을 광고하지 않아야 하는
   *    표면이 SCRAM을 광고한다.
   * ② 계정 축 스로틀이 조립층(`app.ts`)에 있다. 백엔드가 직접 store를 부르면 그 스로틀을
   *    **우회**한다 — SCRAM은 scrypt를 돌지 않지만 계정 단위 분산 대입 방어는 그대로 필요하다.
   *
   * ⚠ 이 옵션이 없어서 라이브 submission(587·465)이 SCRAM을 광고하지 않았다. 엔진·어댑터는
   *   배선돼 있었고 IMAP·POP3 백엔드에도 있었는데 SMTP 백엔드만 빠져 있었다(465 실측:
   *   `250 AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER`). 조립층 누락은 타입으로 드러나지 않는다.
   */
  scramFns?: {
    keys: (user: string) => Promise<ScramStoredKeys | null>;
    authorize: (user: string) => Promise<SmtpAuthResult>;
  };
  /** greylisting 활성화 (기본 off — 첫 발신자 지연). SPF-pass는 면제. */
  greylist?: GreylistOptions | boolean;
  /** DNSBL 존 목록 (opt-in). ⚠ 자체 재귀 리졸버 필요 — 퍼블릭 리졸버는 Spamhaus가 차단. */
  dnsblZones?: DnsblZone[];
  /**
   * 신뢰 릴레이 CIDR 목록(기본 **빈 목록** = 아무도 신뢰 안 함) — 우리가 운영하는 MTA의 접속 대역.
   *
   * 여기 드는 접속에는 **IP 출처를 근거로 삼는 게이트 셋만** 건너뛴다:
   *   ① SPF ② DNSBL ③ greylisting.
   * 셋 다 "이 IP가 낯선 인터넷 피어인가"를 묻는 검사인데, 우리 MSA는 그 질문의 대상이 아니다.
   * 특히 SPF는 사설망 홉에서 **필연적으로 fail**이라 신호가 아니라 잡음이다(inbound-auth.ts
   * `trustedRelay` 주석에 경위가 있다).
   *
   * ⚠ **끄지 않는 것**: DKIM·DMARC·홉 상한·스팸 룰·바이러스 검사·수신자 라우팅·용량 제한.
   * 과거에 `internal: true` 불리언 하나가 게이트 다섯 개를 한꺼번에 꺼서 미인증 오픈 릴레이가
   * 된 적이 있다(감사 C-1). 그래서 이 옵션의 범위를 여기 못박아 둔다 — 늘리려면 이 목록을
   * 고치고 왜 그 게이트가 IP 출처 질문인지 적을 것.
   *
   * ⚠ 신뢰 근거가 **접속 IP뿐**이다(내부 홉은 AUTH 없는 ESMTPS다). 사설망에 아무나 패킷을
   * 넣을 수 없다는 전제 위에 서 있으므로, 공인 대역이나 넓은 프리픽스를 넣지 말 것.
   */
  trustedRelays?: readonly string[];
  /**
   * 바이러스 검사 플러그인(기본 없음 = 비활성). 스캐너 구현은 이 저장소에 없다 —
   * 시그니처 DB 생태계는 복제할 수 없으므로 **끼워 넣을 자리**만 제공한다(PLAN.md).
   */
  virusScanner?: VirusScanner;
  /** 스캔 타임아웃·판정 불가 시 처리(기본 10초 / `defer`). `@ionosphere/spam` virus.ts 참조. */
  virusScanOptions?: VirusScanOptions;
  /**
   * 스팸 점수 판정(기본 없음 = 비활성). 켜면 DNSBL·인증·휴리스틱 룰을 합산해
   * accept/junk/reject를 정한다. 임계값은 `@ionosphere/spam` score.ts 기본값.
   */
  spamScore?: SpamScoreOptions | boolean;
  /** 관측 훅(Phase 5) — 수신 배달 성공 시 반영된 메일함 수만큼 호출. 던져도 무시. */
  onDelivered?: (count: number) => void;
  /**
   * SRS 비밀키(Phase 5 포워딩) — 지정 시 forward_to 알리아스 포워딩 + SRS 바운스 reverse
   * 활성. 미지정 시 포워딩 비활성(forward_to 알리아스는 로컬 계정 있을 때만 배달).
   */
  srsSecret?: string;
  /** 포워딩 루프 방지 최대 홉 수(X-Ionosphere-Forwarded 헤더 카운트). 기본 10. */
  forwardMaxHops?: number;
  /**
   * 발송 정책 — **통째로 받아 통째로 넘긴다.**
   *
   * 예전엔 rateLimit·localOnly·relayPerHour를 각각 필드로 받아 enqueueMessage 호출부에서
   * 손으로 재조립했다. 그래서 `requireSenderOwnership: false`는 app.ts가 넘겨줘도 **여기서
   * 조용히 버려졌다** — SMTP 제출에서는 해제가 아예 동작하지 않았다(JMAP은 정책 객체를
   * 그대로 받아 정상 동작). 갈래마다 옵션을 재작성하면 한쪽만 빠진다는 것이 이 저장소의
   * 반복된 사고라(과거엔 JMAP만 레이트리밋을 우회했다), 필드가 늘어도 새는 곳이 없도록
   * 객체 하나로 받아 그대로 전달한다.
   */
  outbound?: OutboundPolicy;
  /**
   * 릴레이가 **하나라도** 설정돼 있는가 — RCPT 시점의 조기 거절을 억제할지 판단한다.
   *
   * 정확한 판정(`OutboundPolicy.hasRelayFor`)은 발신 도메인을 알아야 하는데, RCPT 시점에는
   * 엔진이 수신자 주소만 넘겨줘 알 수 없다. 확실하지 않을 때 거절하면 릴레이를 붙여 둔
   * 도메인의 정상 발송까지 막으므로, 여기서는 "릴레이가 아예 없을 때"만 조기 거절한다.
   */
  relayConfigured?: () => Promise<boolean>;
  /**
   * DKIM 키 훅(Phase 5) — 지정 시 포워딩할 때 ARC(RFC 8617) 봉인으로 인증 결과를 보존한다.
   * 키가 없는 도메인은 ARC 없이 포워딩(그래도 SRS로 SPF는 통과).
   */
  dkimHook?: DkimHook;
}

export class IonosphereSmtpBackend implements SmtpBackend {
  private readonly db: DbDriver;
  private readonly store: Store;
  private readonly blobs: BlobStore;
  private readonly log: Logger;
  private readonly resolver?: DnsResolver;
  private readonly authservId: string;
  private readonly greylist?: GreylistOptions;
  private readonly dnsblZones: DnsblZone[];
  /** 신뢰 릴레이 매처. 미설정이면 size=0이라 항상 false — 기본은 아무도 신뢰하지 않는다. */
  private readonly trustedRelays: CidrMatcher;
  private readonly virusScanner?: VirusScanner;
  private readonly virusScanOptions?: VirusScanOptions;
  private readonly spamScore?: SpamScoreOptions;
  /** submission 프로파일에서만 존재 — SmtpServer가 이 유무로 authOffered를 판정. relay(25)면 미정의. */
  readonly authenticate?: (user: string, pass: string) => Promise<SmtpAuthResult>;
  /**
   * SCRAM — `authenticate`와 같은 규율으로 **submission에서만 존재**한다.
   * `SmtpServer`가 이 둘의 유무로 `scramOffered`를 판정하므로, relay(25)에 붙으면
   * 인증을 광고하지 않아야 할 표면이 SCRAM을 광고한다.
   */
  readonly scramKeys?: (user: string) => Promise<ScramStoredKeys | null>;
  readonly scramAuthorize?: (user: string) => Promise<SmtpAuthResult>;
  private readonly outbound: OutboundPolicy;
  private readonly onDelivered?: (count: number) => void;
  private readonly srsSecret?: string;
  private readonly forwardMaxHops: number;
  /** 시스템 relay 시간당 상한 — 조립층 정책(outbound.relayPerHour)의 확정값. */
  private readonly relayPerHour: number;
  private readonly relayConfigured: (() => Promise<boolean>) | undefined;
  private readonly localOnly: boolean;
  private readonly dkimHook?: DkimHook;

  constructor(
    db: DbDriver,
    store: Store,
    blobs: BlobStore,
    logger: Logger = noopLogger,
    options: IonosphereSmtpBackendOptions = {},
  ) {
    this.db = db;
    this.store = store;
    this.blobs = blobs;
    this.log = logger.child({ component: "smtp" });
    if (options.resolver) this.resolver = options.resolver;
    this.authservId = options.authservId ?? "localhost";
    if (options.authFn) this.authenticate = options.authFn;
    // 둘을 **함께** 대입한다 — 하나만 붙으면 광고는 안 되지만 계약이 반쪽이 되어 읽기 어렵다.
    if (options.scramFns) {
      this.scramKeys = options.scramFns.keys;
      this.scramAuthorize = options.scramFns.authorize;
    }
    if (options.greylist) this.greylist = options.greylist === true ? {} : options.greylist;
    this.dnsblZones = options.dnsblZones ?? [];
    // 잘못된 CIDR은 여기서 throw한다(부팅 실패) — 조용히 빈 목록이 되면 "켠 줄 알았는데 아닌" 상태가 된다.
    this.trustedRelays = parseCidrList(options.trustedRelays ?? []);
    if (options.virusScanner) this.virusScanner = options.virusScanner;
    if (options.virusScanOptions) this.virusScanOptions = options.virusScanOptions;
    if (options.spamScore) this.spamScore = options.spamScore === true ? {} : options.spamScore;
    this.outbound = options.outbound ?? {};
    if (options.onDelivered) this.onDelivered = options.onDelivered;
    if (options.srsSecret) this.srsSecret = options.srsSecret;
    this.forwardMaxHops = options.forwardMaxHops ?? 10;
    // 미지정이면 무제한이 아니라 기본 상한 — 설정을 안 건드린 배포가 곧 무제한 증폭 채널이었다(C-1).
    this.relayPerHour = this.outbound.relayPerHour ?? DEFAULT_RELAY_PER_HOUR;
    this.relayConfigured = options.relayConfigured;
    this.localOnly = this.outbound.localOnly ?? false;
    if (options.dkimHook) this.dkimHook = options.dkimHook;
  }

  /**
   * 주소의 `@` 오른쪽이 **우리가 호스팅하는 도메인**인가.
   *
   * SRS 분기 전용 판정이다 — SRS HMAC은 포워더 도메인을 서명하지 않으므로(C-1) 토큰이
   * 유효해도 도메인이 우리 것이 아니면 우리를 거칠 이유가 없다. 판정 정본은 @ionosphere/db가 소유한다.
   */
  private async isOurDomain(address: string): Promise<boolean> {
    const at = address.lastIndexOf("@");
    if (at <= 0) return false;
    return isLocallyRoutableDomain(this.db, address.slice(at + 1));
  }

  async verifyRecipient(address: string) {
    // submission(authenticate 존재)에서는 임의 외부 수신자 허용 → 발송 큐로. 검증은 relay만.
    if (this.authenticate) {
      // 내부 전용 모드: 나갈 수 없는 주소는 지금 거절한다. 받아두고 몇 시간 뒤 바운스하면
      // 사용자는 그동안 "보냈다"고 믿는다 — 조용한 실패보다 즉시 실패가 낫다.
      if (this.localOnly && !(await this.isLocalDestination(address))) {
        /**
         * 조기 거절은 **릴레이가 하나도 없을 때만** 한다. 여기서는 발신자를 모르므로
         * (엔진이 RCPT에 수신자만 넘긴다) 발신 도메인별 판정을 할 수 없고, 모르는 채로
         * 거절하면 릴레이를 붙여 둔 도메인의 정상 발송까지 막는다. 정확한 판정은
         * enqueueMessage(hasRelayFor)가 하고, 그때 550이 나가도 사용자는 즉시 알게 된다.
         */
        if (!(await this.relayConfigured?.())) {
          this.log.info("submit rcpt rejected: external delivery disabled", { rcpt: address });
          return { ok: false as const, code: 550, enhanced: "5.7.1", message: "external delivery is not configured" };
        }
      }
      return { ok: true as const };
    }
    /**
     * SRS 바운스 반송처(우리가 만든 SRS 주소로 되돌아온 바운스)는 reverse 가능하면 수락.
     *
     * ★`@` 오른쪽이 **우리 도메인인지** 반드시 함께 본다(감사 5차 C-1). HMAC 페이로드는
     * `tt=원발신도메인=로컬`이라 **포워더 도메인이 서명 범위 밖**이다. 그래서 유효한 토큰
     * 하나를 임의 도메인에 붙이면 이 분기가 통과했고, `deliverToRecipient`도 우리 도메인
     * 판정(`resolveRoute`)보다 **먼저** 이 분기를 타서 미인증 오픈 릴레이가 됐다.
     */
    if (this.srsSecret && isSrsAddress(address) && (await this.isOurDomain(address)) && srsReverse(address, { secret: this.srsSecret }).ok) {
      return { ok: true as const };
    }
    const route = await this.resolveRoute(address);
    // 로컬 계정 or 포워딩(forward_to) 중 하나라도 있으면 수락. 포워딩은 SRS 활성 시에만 유효.
    const forwardable = route.forwardTo.length > 0 && this.srsSecret !== undefined;
    if (route.accountIds.length === 0 && !forwardable) {
      this.log.info("rcpt rejected", { rcpt: address, reason: "no-such-user" });
      return { ok: false as const, code: 550, enhanced: "5.1.1", message: "no such user" };
    }
    return { ok: true as const };
  }

  /**
   * 수신 주소 → 계정 id 해석 (SCHEMA §4 addresses 라우팅):
   *   1) alias 정확 매치 (domain + localpart) 계정
   *   2) 캐치올 (localpart '*') 계정
   *   3) 직접 accounts.email 매치
   * subaddress(localpart+tag)는 tag 제거 후 매칭. forward_to 전용 알리아스는 Phase 5(포워딩) —
   * 지금은 로컬 계정(account_id) 알리아스만 배달 가능.
   */
  /**
   * 수신 계정의 활성 Sieve 스크립트를 실행해 배달 대상을 결정(Phase 4).
   * 스크립트 없음/파싱·실행 오류 → 기본 INBOX(폴백, throw 금지). fileinto 대상 메일함이
   * 없으면 INBOX로 폴백.
   *
   * ★redirect는 여기서 **결정만** 하고 실제 릴레이는 호출부가 한다 — 이 함수는 "어디로 배달할지"를
   * 답하는 자리이고, 외부 발송이라는 부수효과를 이름에 드러나지 않게 숨기지 않기 위해서다.
   */
  private async runSieveRoute(
    accountId: string,
    inboxId: string,
    parsed: ParsedMessage,
    env: { mailFrom: string; rcptTo: readonly string[] },
    size: number,
  ): Promise<{ mailboxIds: string[]; keywords: string[]; redirect: string[]; discard: boolean; fileintoUsed: boolean }> {
    const fallback = { mailboxIds: [inboxId], keywords: [] as string[], redirect: [] as string[], discard: false, fileintoUsed: false };
    const script = await this.store.getActiveSieveScript(accountId);
    if (!script) return fallback;

    let result;
    try {
      result = runSieve(script, buildSieveEnv(parsed, env, size));
    } catch (err) {
      this.log.warn("sieve error — INBOX fallback", { accountId, error: err instanceof Error ? err.message : String(err) });
      return fallback;
    }
    if (result.redirect.length > MAX_RELAY_TARGETS) {
      // RFC 5228 §2.10.3 초과 = 스크립트 오류 → 오류 정책(INBOX 폴백)과 동일하게 처리.
      this.log.warn("sieve redirect 한도 초과 — 릴레이 없이 INBOX 폴백", { accountId, count: result.redirect.length, max: MAX_RELAY_TARGETS });
      return fallback;
    }
    if (result.redirect.length > 0 && !this.srsSecret) {
      // SRS 없이 릴레이하면 원 발신 도메인의 SPF로 우리가 발송하게 되어 수신측에서 거부된다.
      // 이때는 **redirect가 없던 것처럼** 처리한다 — 암묵적 keep을 살려 로컬에 남기지 않으면
      // 메일이 어디에도 없이 사라진다(유실 > 지연).
      this.log.warn("sieve redirect 무시 — SRS 미설정(IONOSPHERE_SRS_SECRET), 로컬 보관으로 대체", {
        accountId,
        count: result.redirect.length,
      });
      result.redirect = [];
    }
    if (result.discarded) return { mailboxIds: [], keywords: [], redirect: [], discard: true, fileintoUsed: false };

    // fileinto 대상(경로)을 mailboxId로 — 없으면 INBOX 폴백
    const mailboxIds = new Set<string>();
    if (result.keep) mailboxIds.add(inboxId);
    if (result.fileinto.length > 0) {
      const rows = await this.store.listMailboxes(accountId);
      const pathToId = buildMailboxPathMap(rows);
      for (const name of result.fileinto) {
        mailboxIds.add(pathToId.get(name) ?? inboxId);
      }
    }
    // 안전망은 **redirect가 없을 때만**. redirect는 암묵적 keep을 취소하므로(RFC 5228 §4.2),
    // `redirect "x@y";`만 있는 스크립트까지 INBOX에 남기면 "전달만" 규칙이 사본을 남기는 셈이 된다.
    if (mailboxIds.size === 0 && result.redirect.length === 0) mailboxIds.add(inboxId);
    return {
      mailboxIds: [...mailboxIds],
      keywords: result.flags.map(sieveFlagToKeyword),
      redirect: result.redirect,
      discard: false,
      // 사용자가 fileinto로 자리를 명시했는가 — junk 재배치가 이걸 존중한다.
      fileintoUsed: result.fileinto.length > 0,
    };
  }

  /** 이 서버가 배달할 수 있는 주소인가(로컬 계정·알리아스·캐치올). 내부 전용 모드 판정에 쓴다. */
  private async isLocalDestination(address: string): Promise<boolean> {
    const route = await this.resolveRoute(address);
    return route.accountIds.length > 0;
  }

  /**
   * 수신 주소 → 배달 라우트(로컬 계정 **목록** + 포워딩 대상 + 테넌트).
   * 알리아스(정확→캐치올)를 먼저 보고, 없으면 직접 accounts.email 매치. forward_to는
   * 콤마/공백 구분 다중 주소를 허용한다. domain은 포워더 도메인(SRS 재작성용)으로도 쓰인다.
   *
   * accountIds가 배열인 이유: 한 알리아스가 로컬 계정 여러 개로 팬아웃될 수 있다(006).
   * 예전엔 목적지가 하나뿐이라, `sales@`를 두 사람에게 보내려면 forward_to로 외부 SMTP를
   * 한 바퀴 돌아야 했다.
   */
  private async resolveRoute(
    address: string,
  ): Promise<{ accountIds: string[]; forwardTo: string[]; tenantId: string | null; domain: string }> {
    const addr = address.toLowerCase();
    const at = addr.lastIndexOf("@");
    if (at <= 0) return { accountIds: [], forwardTo: [], tenantId: null, domain: "" };
    let localpart = addr.slice(0, at);
    const domain = addr.slice(at + 1);
    const plus = localpart.indexOf("+");
    if (plus > 0) localpart = localpart.slice(0, plus);

    // ★d.status = 1(검증됨)이 **인가 조건**이다. 이게 없으면 아무 테넌트나 남의 도메인 이름으로
    // domains 행을 만들고 캐치올 알리아스(`*`)를 걸어 **그 도메인의 수신을 가져갈 수 있다**
    // (정확 매치가 없는 주소는 캐치올이 이긴다 — 아래 ORDER BY). 발송 게이트(enqueue.ts)는
    // status=1을 검사하는데 수신 경로만 빠져 있었다.
    // status=1은 이름당 하나뿐임이 보장된다 — domain_name_claims.name이 PK라 두 번째 테넌트의
    // 검증은 409로 막힌다. 따라서 이 조건 하나로 갈래가 유일해진다.
    const { rows } = await this.db.query({
      sql: `SELECT ad.id, ad.forward_to, d.tenant_id FROM addresses ad JOIN domains d ON d.id = ad.domain_id
            WHERE d.name = ? AND d.status = 1 AND ad.localpart IN (?, '*')
            ORDER BY CASE ad.localpart WHEN ? THEN 0 ELSE 1 END LIMIT 1`,
      params: [domain, localpart, localpart],
    });
    const row = rows[0];
    if (row) {
      const forwardTo =
        row.forward_to == null
          ? []
          : String(row.forward_to)
              .split(/[,\s]+/)
              .map((s) => s.trim())
              .filter((s) => s.length > 0);
      // 이긴 주소 행(정확 매치 > 캐치올)이 정해진 다음에 그 행의 목적지를 편다.
      // 조인으로 한 번에 가져오면 팬아웃 행 수만큼 중복돼 LIMIT 1의 우선순위가 깨진다.
      // ORDER BY는 결정성용 — 배달 순서가 테스트마다 흔들리지 않게 한다.
      // ★a.status = 1 — **비활성 계정은 목적지가 아니다.**
      // 없으면 배달 단계에서 스토어가 "account not active"로 던지고, 그 예외가 팬아웃 합성기를
      // 건너뛰어 트랜잭션 전체가 451이 된다 → 발신측 재시도마다 **살아 있는 계정에 중복이 쌓인다**
      // (재현 확인). 여기서 걸러야 RCPT 단계에서 "수신자 없음"이 정직하게 나온다.
      const { rows: targets } = await this.db.query({
        sql: `SELECT t.account_id FROM address_targets t
              JOIN accounts a ON a.id = t.account_id AND a.status = 1
              WHERE t.address_id = ? ORDER BY t.account_id`,
        params: [String(row.id)],
      });
      return {
        accountIds: targets.map((t) => String(t.account_id)),
        forwardTo,
        tenantId: row.tenant_id == null ? null : String(row.tenant_id),
        domain,
      };
    }

    // 폴백(addresses 행 없이 accounts.email로 직접 라우팅)에도 **위와 같은 도메인 게이트**를
    // 건다. accounts.email은 전역 UNIQUE일 뿐 도메인 소유와 무관하게 채워질 수 있어서, 게이트가
    // 없으면 남의 검증된 도메인 이름으로 계정만 만들어 둔 테넌트에게 수신이 넘어갔다.
    // addresses 경로만 막아 두었던 과거 사고(domain-verification-routing.test.ts)의 폴백판이다.
    // ⚠ 게이트를 REST 계정 생성(@ionosphere/api requireOwnedVerifiedDomain)에만 두면 부족하다 —
    //   도메인 소유권은 나중에 이전될 수 있고(해제 후 타 테넌트 재검증), 그때 남는 옛 계정이
    //   새 소유자의 수신을 가로챈다. 라우팅 시점에도 확인해야 fail closed다.
    // a.status = 1은 팬아웃 목적지와 같은 이유다(위 주석) — 비활성 계정으로 라우팅하면
    // 배달 단계 예외가 되어 451 루프가 된다. 폴백에도 같은 조건을 건다.
    const { rows: fallback } = await this.db.query({
      sql: `SELECT a.id, a.tenant_id FROM accounts a
            JOIN domains d ON d.tenant_id = a.tenant_id AND d.name = ? AND d.status = 1
            WHERE a.email = ? AND a.status = 1 LIMIT 1`,
      params: [domain, `${localpart}@${domain}`],
    });
    const account = fallback[0];
    return account
      ? { accountIds: [String(account.id)], forwardTo: [], tenantId: String(account.tenant_id), domain }
      : { accountIds: [], forwardTo: [], tenantId: null, domain };
  }

  async deliver(env: {
    mailFrom: string;
    heloName: string;
    clientIp: string;
    rcptTo: string[];
    raw: Uint8Array;
    authenticatedAs: string | null;
  }) {
    // 인증된 제출(submission) → 아웃바운드 발송 큐 (SCHEMA §9-1, MTA 워커가 배달)
    if (env.authenticatedAs) {
      return this.submitOutbound(env);
    }
    const result = await this.runInboundPipeline({ ...env, transport: "esmtp" });
    if (result.kind === "reject") {
      return { ok: false as const, code: result.code, enhanced: result.enhanced, message: result.message };
    }
    // SMTP는 트랜잭션 단위 **단일** 응답 — 수신자별 처분을 여기서 집계한다(LMTP는 그대로 노출).
    const outcomes = [...result.outcomes.values()];
    const delivered = outcomes.filter((o) => o.status === "delivered").length;
    const accepted = outcomes.filter((o) => o.status === "delivered" || o.status === "accepted").length;
    const quotaFailed = outcomes.filter((o) => o.status === "quota").length;
    if (accepted === 0) {
      return quotaFailed > 0
        ? { ok: false as const, code: 452, enhanced: "4.2.2", message: "mailbox full" }
        : { ok: false as const, code: 451, enhanced: "4.3.0", message: "delivery failed" };
    }
    this.reportDelivered(delivered);
    return { ok: true as const };
  }

  /**
   * LMTP 경로 — **수신자별 독립 응답**(RFC 2033의 존재 이유).
   *
   * 이전엔 어댑터가 deliver()의 단일 결과를 모든 수신자에게 복사했다. 그래서 수신자 3명 중
   * 1명이 쿼터 초과여도 3명 전부 성공이거나 전부 실패로 보고됐고, 상류 MTA는 실패한 1명 때문에
   * 성공한 2명에게도 재전송해 **중복 배달**을 만들 수 있었다. 이제 파이프라인이 만든 수신자별
   * 처분을 그대로 매핑한다. 메시지 단위 거부(DNSBL·그레이리스팅)는 전원 동일 코드가 맞다.
   */
  async deliverPerRecipient(env: {
    mailFrom: string;
    heloName: string;
    clientIp: string;
    rcptTo: string[];
    raw: Uint8Array;
  }): Promise<LmtpDelivery[]> {
    const result = await this.runInboundPipeline({ ...env, authenticatedAs: null, transport: "lmtp" });
    if (result.kind === "reject") {
      // 메시지 단위 거부 — 모든 수신자에게 같은 코드(LMTP도 이 경우는 전원 동일).
      return env.rcptTo.map((rcpt) => ({
        rcpt,
        ok: false as const,
        code: result.code,
        enhanced: result.enhanced,
        message: result.message,
      }));
    }
    this.reportDelivered([...result.outcomes.values()].filter((o) => o.status === "delivered").length);
    // 원본 RCPT 순서·중복을 그대로 유지해 응답한다(엔진이 RCPT 순서대로 1줄씩 낸다).
    return env.rcptTo.map((rcpt) => {
      const outcome = result.outcomes.get(rcpt.toLowerCase()) ?? { status: "unknown" as const };
      switch (outcome.status) {
        case "delivered":
        case "accepted":
          return { rcpt, ok: true as const, code: 250, enhanced: "2.1.5", message: "delivered" };
        case "quota":
          return { rcpt, ok: false as const, code: 452, enhanced: "4.2.2", message: "mailbox full" };
        case "tempfail":
          // 4xx로 답해야 상류 MTA가 재시도한다. 550으로 뭉개면 일시 오류에 메일을 버린다.
          return { rcpt, ok: false as const, code: 451, enhanced: "4.3.0", message: "temporary failure" };
        default:
          return { rcpt, ok: false as const, code: 550, enhanced: "5.1.1", message: "no such user" };
      }
    });
  }

  /** onDelivered 관측 훅 — 실패는 삼킨다(관측이 배달을 막으면 안 됨). */
  private reportDelivered(count: number): void {
    if (!this.onDelivered || count <= 0) return;
    try {
      this.onDelivered(count);
    } catch {
      /* 관측 실패는 삼킴 */
    }
  }

  /**
   * 수신 파이프라인 — 준비(파싱·DNSBL·인증·그레이리스팅·블롭 저장) 후 수신자별로 배달한다.
   * SMTP(집계)와 LMTP(수신자별) **양쪽이 공유하는 단일 구현**.
   */
  private async runInboundPipeline(env: InboundEnv): Promise<InboundResult> {
    const prep = await this.prepareInbound(env);
    if (prep.kind === "reject") return prep;

    const outcomes = new Map<string, RecipientOutcome>();
    for (const rcpt of new Set(env.rcptTo.map((r) => r.toLowerCase()))) {
      outcomes.set(rcpt, await this.deliverToRecipient(rcpt, prep, env));
    }
    return { kind: "perRecipient", outcomes };
  }

  /**
   * 메시지 단위 준비 — 여기서 거부되면 모든 수신자가 같은 처분을 받는다.
   * (DNSBL 등재, 그레이리스팅 defer는 메시지 단위가 맞다.)
   */
  private async prepareInbound(env: InboundEnv): Promise<{ kind: "reject"; code: number; enhanced: string; message: string } | PreparedInbound> {
    const parsed = parseMessage(env.raw);

    /**
     * 루프 차단(RFC 5321 §6.3) — Received가 임계를 넘으면 메일이 돌고 있다는 뜻이다.
     * DNSBL·인증보다 **먼저** 본다: 판정에 DNS 왕복이 필요 없고, 루프 도는 메시지에
     * 조회 비용을 들일 이유가 없다.
     */
    const hops = countReceivedHops(parsed);
    if (hops >= MAX_RECEIVED_HOPS) {
      this.log.warn("received hop limit — 루프로 판단해 거부", { hops, from: env.mailFrom, ip: env.clientIp });
      return { kind: "reject", code: 554, enhanced: "5.4.6", message: "too many hops (mail loop)" };
    }

    /**
     * 신뢰 릴레이 판정 — 아래 IP 출처 게이트 셋(SPF·DNSBL·greylist)이 **같은 답**을 쓰게 한다.
     * 한 번만 계산해 넘기는 이유가 이것이다: 게이트마다 따로 판정하면 한쪽만 고쳐져 갈라진다.
     */
    const trustedRelay = this.trustedRelays.matches(env.clientIp);

    // DNSBL (opt-in): 등재 IP는 즉시 거부 (554). ⚠ 자체 재귀 리졸버 전제
    // 신뢰 릴레이는 조회하지 않는다 — 우리 호스트를 등재로 읽고 554를 내면 내부 메일이 통째로 막힌다.
    if (this.resolver && this.dnsblZones.length > 0 && !trustedRelay) {
      try {
        const bl = await checkDnsbl(env.clientIp, this.dnsblZones, this.resolver);
        if (bl.listed && bl.score > 0) {
          this.log.warn("dnsbl reject", { ip: env.clientIp, score: bl.score, zones: bl.hits.map((h) => h.zone) });
          return { kind: "reject", code: 554, enhanced: "5.7.1", message: "rejected by DNSBL" };
        }
      } catch (err) {
        this.log.warn("dnsbl check error", { error: String(err) });
      }
    }

    /**
     * 수신 인증 (Phase 2): SPF/DKIM/DMARC → AR 헤더 접두 + message_auth 저장.
     *
     * 먼저 **우리 authserv-id를 사칭한 A-R을 제거한다**(RFC 8601 §5 MUST). 검증 여부와 무관하게
     * 지운다 — 리졸버가 없어 검증을 건너뛰는 구성에서도 위조본이 남으면 안 된다.
     * 순서가 중요하다: DKIM 검증은 아래에서 **원본 env.raw**로 하므로 이 제거의 영향을 받지 않는다.
     */
    let stored = stripForgedReceivedSpf(stripForgedAuthResults(env.raw, this.authservId), this.authservId);
    let authCodes: { spf: number | null; dkim: number; dmarc: number } | null = null;
    let spfPass = false;
    let authResultsValue = `${this.authservId}; none`; // ARC AAR용 — 검증 실행 시 갱신
    // RFC 7208 §9.1 Received-SPF. 검증을 돌린 경우에만 만든다 — 확인하지 않은 결과를 적을 수 없다.
    let receivedSpf: string | undefined;
    // 점수 엔진 입력. 검증을 안 돌린 구성에서는 undefined로 남아 인증 신호가 0이 된다
    // (없는 결과를 `none`으로 적어 신호처럼 쓰면 안 된다).
    let authSummary: AuthSummary | undefined;
    if (this.resolver) {
      try {
        const auth = await runInboundAuth(
          {
            raw: env.raw,
            parsed,
            clientIp: env.clientIp,
            heloName: env.heloName,
            mailFrom: env.mailFrom,
            authservId: this.authservId,
            ...(trustedRelay ? { trustedRelay: true } : {}),
          },
          this.resolver,
        );
        stored = prependAuthResults(auth.authResults, stored);
        authCodes = auth.codes;
        spfPass = auth.summary.spf === "pass";
        authResultsValue = auth.authResults;
        receivedSpf = auth.receivedSpf;
        authSummary = auth.summary as AuthSummary;
        this.log.info("auth", { from: env.mailFrom, ip: env.clientIp, ...auth.summary });
      } catch (err) {
        // 검증 자체가 실패해도 배달은 계속 (인증 결과 없이 저장)
        this.log.warn("auth pipeline error", { error: String(err) });
      }
    }

    /**
     * greylisting (opt-in): SPF-pass 면제. 새 트리플이면 전체 메시지 defer(451) — 재시도 시 통과.
     *
     * 신뢰 릴레이는 아예 건너뛴다. `spfPass=true`로 위장해 면제시키지 않는 이유는, 우리가
     * SPF를 **돌리지도 않았기** 때문이다 — 안 한 검사의 결과를 지어내 다른 게이트에 넘기면
     * 그 게이트의 로그와 통계가 거짓말을 한다.
     */
    if (this.greylist && !trustedRelay) {
      for (const rcpt of new Set(env.rcptTo.map((r) => r.toLowerCase()))) {
        const gl = await checkGreylist(
          this.db,
          { ip: env.clientIp, mailFrom: env.mailFrom, rcpt, spfPass },
          this.greylist,
        );
        if (gl.action === "defer") {
          this.log.info("greylist defer", { ip: env.clientIp, rcpt, retryAfterMs: gl.retryAfterMs });
          return { kind: "reject", code: 451, enhanced: "4.7.1", message: "greylisted, retry later" };
        }
      }
    }

    /**
     * 스팸 점수(opt-in). 신호를 합산해 accept / junk / reject를 정한다.
     *
     * ★DNSBL·greylist가 각자 즉시 판정하던 구조와 다르다 — 여기서는 신호가 **모여서** 결정한다.
     * 단독으로는 거부에 못 미치는 것들이 겹칠 때 잡히고, 강한 신호 하나의 오탐으로 메일이
     * 사라지지 않는다. 확신이 낮은 구간은 junk로 흘린다(유실 없음).
     */
    let junkVerdict: SpamScore | null = null;
    if (this.spamScore) {
      const verdict = scoreSpam(
        {
          ...(authSummary ? { auth: authSummary } : {}),
          rules: evaluateRules({
            parsed,
            mailFrom: env.mailFrom,
            ...(env.heloName ? { heloName: env.heloName } : {}),
            clientIp: env.clientIp,
          }),
        },
        this.spamScore,
      );
      if (verdict.action === SPAM_ACTION.reject) {
        this.log.warn("spam score reject", {
          score: verdict.score,
          from: env.mailFrom,
          ip: env.clientIp,
          reasons: verdict.reasons.map((r) => r.signal).join(","),
        });
        return { kind: "reject", code: 554, enhanced: "5.7.1", message: "message rejected by content-independent policy" };
      }
      // junk는 **거부가 아니다** — 배달은 하되 아래에서 Junk 메일함/키워드로 보낸다.
      if (verdict.action === SPAM_ACTION.junk) junkVerdict = verdict;
    }

    /**
     * 바이러스 검사(opt-in 플러그인). **가장 마지막 게이트다.**
     *
     * ★순서가 의도적이다: 홉 수·DNSBL·greylist는 DNS 왕복이나 조회 한 번이면 끝나는데,
     * 스캔은 본문 전체를 읽는다. 싼 판정으로 걸러낼 수 있는 메일에 그 비용을 들이지 않는다.
     * (greylist가 defer한 메일은 어차피 재시도 때 다시 온다 — 그때 스캔하면 된다.)
     */
    if (this.virusScanner) {
      const v = await scanForVirus(this.virusScanner, env.raw, this.virusScanOptions ?? {});
      if (v.action !== "accept") {
        this.log.warn("virus scan gate", {
          action: v.action,
          from: env.mailFrom,
          ip: env.clientIp,
          // 시그니처 이름은 message에 이미 들어 있다. 본문은 어떤 형태로도 남기지 않는다.
          reason: v.message,
        });
        return { kind: "reject", code: v.code, enhanced: v.enhanced, message: v.message };
      }
    }

    /**
     * 트레이스 헤더(RFC 5321 §4.4). **가장 마지막에 붙여 최상단에 오게 한다** —
     * 이 홉이 만든 Authentication-Results 바로 위가 Received여야 순서가 맞다.
     * for 절은 수신자가 정확히 1명일 때만 넣는다(§4.4 MUST, §7.6 BCC 노출 방지).
     */
    const traceId = ulid();
    const rcptSet = new Set(env.rcptTo.map((r) => r.toLowerCase()));
    const only = rcptSet.size === 1 ? [...rcptSet][0] : undefined;
    stored = prependHeaderBytes(
      stored,
      buildReceivedHeader({
        transport: env.transport,
        heloName: env.heloName,
        clientIp: env.clientIp,
        by: this.authservId,
        id: traceId,
        ...(only ? { forRecipient: only } : {}),
        ...(env.tls ? { tls: env.tls } : {}),
        authenticated: false,
        date: new Date(),
      }),
    );

    /**
     * Received-SPF는 **Received보다 위**에 온다 — RFC 7208 §9.1이 "SHOULD be prepended to the
     * existing header, above the Received: field that is generated by the SMTP receiver"라고
     * 위치를 지정한다. 그래서 Received를 붙인 **뒤에** 붙인다.
     */
    if (receivedSpf) stored = prependHeaderBytes(stored, receivedSpf);

    /**
     * 스팸 판정을 **헤더로 남긴다**(junk일 때만).
     *
     * ★왜 헤더인가: 판정을 메일함 배치로만 표현하면 사용자가 "왜 여기 있는지" 알 수 없고,
     * 운영자도 임계값을 조정할 근거를 못 본다. 신호 이름만 싣고 **본문 조각은 넣지 않는다**
     * (룰이 헤더·봉투만 보는 것과 같은 이유).
     * 값은 헤더 한 줄에 들어가도록 좁힌다 — 신호 이름은 우리가 정하는 식별자라 안전하지만,
     * 길이는 제한한다.
     */
    if (junkVerdict) {
      const signals = junkVerdict.reasons.map((r) => r.signal).join(",").slice(0, 200);
      stored = prependHeaderBytes(stored, `X-Spam-Status: Yes, score=${junkVerdict.score} signals=${signals}`);
    }

    const { blobId, size, generation } = await putBlob(this.db, this.blobs, stored);
    return {
      kind: "ok",
      parsed,
      stored,
      blobId,
      blobGeneration: generation,
      size,
      receivedAt: Date.now(),
      authCodes,
      authResultsValue,
      ...(junkVerdict ? { junk: true } : {}),
    };
  }

  /**
   * 수신자 1명 배달 — 포워딩·SRS 바운스 relay를 처리하고, 로컬 목적지 계정마다
   * deliverToAccount를 돌린 뒤 **하나의 처분값**으로 합성한다.
   *
   * 한 주소가 계정 여러 개로 퍼질 수 있으므로(006 팬아웃) 계정 단위 배달은 별도 함수다.
   * 이 함수는 "주소를 어디로 보낼지", deliverToAccount는 "한 계정 안에서 어떻게 놓을지"를 맡는다.
   */
  private async deliverToRecipient(rcpt: string, prep: PreparedInbound, env: InboundEnv): Promise<RecipientOutcome> {
    const { parsed, authResultsValue } = prep;

    // SRS 바운스 반송처(우리가 만든 SRS 주소로 돌아온 바운스) → 원 발신자로 relay
    if (this.srsSecret && isSrsAddress(rcpt) && (await this.isOurDomain(rcpt))) {
      return (await this.relayBounce(rcpt, env, prep.stored))
        ? { status: "accepted", via: "bounce-relay" }
        : { status: "unknown" };
    }

    const dest = await this.resolveRoute(rcpt); // 로컬 계정 목록 + forward_to
    // 포워딩(forward_to) — SRS 활성 시. 로컬 계정 배달과 병행 가능(사본 포워딩).
    let forwarded = false;
    if (dest.forwardTo.length > 0 && this.srsSecret) {
      forwarded = await this.relayCopy({
        rcpt,
        targets: dest.forwardTo,
        tenantId: dest.tenantId,
        domain: dest.domain,
        reason: "forward",
        env,
        stored: prep.stored,
        parsed,
        authResults: authResultsValue,
      });
    }
    if (dest.accountIds.length === 0) {
      return forwarded ? { status: "accepted", via: "forward" } : { status: "unknown" };
    }

    // 팬아웃 — 계정마다 독립 배달(각자의 Sieve 스크립트·메일함·쿼터). 하나가 실패해도 나머지는
    // 계속 간다. 순차 실행인 이유: appendMessage가 계정별 낙관적 락(modseq_claims)을 잡으므로
    // 동시에 돌려도 경합만 늘 뿐 이득이 없다.
    const outcomes: RecipientOutcome[] = [];
    for (const accountId of dest.accountIds) {
      outcomes.push(await this.deliverToAccount(accountId, rcpt, prep, env, dest.tenantId, dest.domain));
    }
    const failed = outcomes.filter((o) => o.status === "quota" || o.status === "unknown").length;
    if (failed > 0 && failed < outcomes.length) {
      // 부분 실패는 재시도로 못 고친다(성공한 계정에 중복만 쌓인다) — 로그로 드러낸다.
      this.log.warn("팬아웃 부분 실패 — 성공한 계정만 배달됨", { rcpt, total: outcomes.length, failed });
    }
    return combineFanoutOutcomes(outcomes, forwarded);
  }

  /**
   * 계정 1개 배달 — Sieve 라우팅(폐기·fileinto·redirect) 후 메일함에 append.
   * 팬아웃의 한 갈래이므로 forward_to 성패는 모르고, 자기 계정의 처분만 돌려준다.
   */
  private async deliverToAccount(
    accountId: string,
    rcpt: string,
    prep: PreparedInbound,
    env: InboundEnv,
    tenantId: string | null,
    domain: string,
  ): Promise<RecipientOutcome> {
    const { parsed, blobId, blobGeneration, size, receivedAt, authCodes, authResultsValue } = prep;
    const inbox = await this.store.getMailboxByRole(accountId, "inbox");
    if (!inbox) return { status: "unknown" };

    // Sieve 필터(Phase 4) — 활성 스크립트로 배달 대상/플래그/폐기 결정. 오류·미설정 시 INBOX.
    const route = await this.runSieveRoute(accountId, inbox.id, parsed, env, size);
    if (route.discard) {
      this.log.info("sieve discard", { rcpt });
      return { status: "accepted", via: "sieve-discard" }; // 수신은 수락됨(사용자 규칙에 의한 폐기)
    }

    // Sieve redirect(RFC 5228 §4.2) — forward_to와 같은 릴레이 경로를 쓴다(SRS 재작성·ARC 봉인·루프가드).
    // 로컬 append 앞에 두는 이유: forward_to와 순서를 맞춰 "릴레이는 로컬 저장 성패와 무관"이라는
    // 동작을 하나로 통일하기 위함. 대가는 append가 4xx(쿼터)로 실패해 발신측이 재시도하면 릴레이가
    // 중복될 수 있다는 것 — forward_to가 이미 갖고 있던 성질이라 갈래를 늘리지 않는 쪽을 택했다.
    let redirected = false;
    if (route.redirect.length > 0) {
      redirected = await this.relayCopy({
        rcpt,
        targets: route.redirect,
        tenantId,
        domain,
        reason: "sieve-redirect",
        env,
        stored: prep.stored,
        parsed,
        authResults: authResultsValue,
      });
    }
    // redirect가 암묵적 keep을 취소한 경우(`redirect`만 있는 스크립트) — 로컬 저장 없이 끝낸다.
    // 단 릴레이가 실패했다면(루프가드·적재 실패) 사본이 아무 데도 없어 메일이 사라지므로 INBOX에 보존한다.
    let targetMailboxes = route.mailboxIds;
    if (targetMailboxes.length === 0) {
      if (redirected) return { status: "accepted", via: "sieve-redirect" };
      this.log.warn("sieve redirect 릴레이 실패 — 유실 방지로 INBOX 보존", { rcpt });
      targetMailboxes = [inbox.id];
    }

    /**
     * junk 판정 반영 — **배달은 반드시 한다.** 옮기는 것이지 버리는 것이 아니다.
     *
     * ★Sieve가 이미 자리를 정했으면 건드리지 않는다. 사용자가 명시한 규칙이 서버 추정보다
     * 우선이다 — 그러지 않으면 "규칙을 만들었는데 왜 Junk로 가지" 가 된다.
     * ★Junk 메일함은 계정 생성 시 만들어지지 않는다(INBOX만 role='inbox'로 생긴다).
     * 없으면 INBOX에 두고 **키워드만** 단다 — 없는 메일함을 만들어 배달 경로에서
     * 스키마를 건드리기보다, 클라이언트가 걸러낼 수 있는 표식을 남기는 쪽이 안전하다.
     */
    let junkKeywords = route.keywords;
    if (prep.junk && !route.fileintoUsed) {
      const junkBox = (await this.store.listMailboxes(accountId)).find(
        (m) => String(m.name ?? "").toLowerCase() === "junk",
      );
      if (junkBox) targetMailboxes = [String(junkBox.id)];
      if (!junkKeywords.includes("$Junk")) junkKeywords = [...junkKeywords, "$Junk"];
    }

    try {
      const result = await this.store.appendMessage({
        accountId,
        mailboxIds: targetMailboxes,
        blobId,
        blobGeneration,
        sizeBytes: size,
        receivedAt,
        envelope: {
          subject: parsed.subject,
          subjectBase: parsed.subjectBase,
          msgidHash: parsed.msgidHash,
          sentAt: parsed.sentAt,
          preview: parsed.preview,
          hasAttachment: parsed.hasAttachment,
          addresses: toAppendAddresses(parsed),
          threadRefHashes: parsed.threadRefHashes,
        },
        keywords: junkKeywords,
        // FTS 인덱싱용 텍스트 (Phase 2) — 수신 시 subject/body/from/to를 색인
        searchText: {
          ...(parsed.subject ? { subject: parsed.subject } : {}),
          ...(parsed.textBody ? { body: parsed.textBody } : {}),
          ...(parsed.from[0] ? { from: `${parsed.from[0].name ?? ""} ${parsed.from[0].email}` } : {}),
          ...(parsed.to.length > 0 ? { to: parsed.to.map((a) => a.email).join(" ") } : {}),
        },
      });
      // message_auth 저장 (검증 성공 시) — 원본 재파싱 없이 조회 가능 (SCHEMA §9-3)
      if (authCodes) {
        await this.db.batch([
          {
            sql: `INSERT INTO message_auth (message_id, spf, dkim, dmarc) VALUES (?, ?, ?, ?)`,
            params: [result.messageId, authCodes.spf, authCodes.dkim, authCodes.dmarc],
          },
        ]);
      }
      this.log.info("delivered", { rcpt, from: env.mailFrom, messageId: result.messageId, size });
      await this.enqueueInboundWebhook(accountId, rcpt, result.messageId, targetMailboxes, parsed, receivedAt, size);
      return { status: "delivered" };
    } catch (err) {
      if (err instanceof StoreQuotaError) {
        this.log.warn("delivery rejected: quota", { rcpt, size });
        return { status: "quota" };
      }
      /**
       * ★던지지 않는다. 이 함수는 팬아웃의 **한 갈래**이므로 예외로 빠져나가면 이미 성공한
       * 다른 계정의 배달까지 트랜잭션 단위로 무효가 되고, 발신측 재시도마다 그 계정에 중복이
       * 쌓인다(재현 확인). 합성기(combineFanoutOutcomes)가 부분 실패를 다루도록 만들어져
       * 있으니 처분값으로 돌려주는 것이 맞다.
       *
       * 정상 경로에서는 비활성 계정이 resolveRoute에서 이미 걸러진다 — 여기 오는 건 그 사이에
       * 계정이 정지된 레이스나 스토어 장애다. 둘 다 재시도 여지가 있으므로 tempfail이다.
       */
      this.log.error("delivery failed — 이 계정만 건너뛴다", { rcpt, accountId, error: String(err) });
      return { status: "tempfail" };
    }
  }

  /** 수신 웹훅(Phase 4) 적재 — 실패해도 메일 배달은 성공 처리(웹훅은 부가 기능). */
  private async enqueueInboundWebhook(
    accountId: string,
    rcpt: string,
    messageId: string,
    mailboxIds: readonly string[],
    parsed: ParsedMessage,
    receivedAt: number,
    size: number,
  ): Promise<void> {
    try {
      const payload = JSON.stringify({
        event: "inbound",
        messageId,
        mailbox: mailboxIds,
        from: parsed.from.map((a) => ({ name: a.name, email: a.email })),
        to: parsed.to.map((a) => a.email),
        subject: parsed.subject,
        receivedAt: new Date(receivedAt).toISOString(),
        size,
        preview: parsed.preview,
      });
      await this.store.enqueueWebhookDeliveries(accountId, payload);
    } catch (err) {
      this.log.warn("webhook enqueue failed", { rcpt, error: err instanceof Error ? err.message : String(err) });
    }
  }

  /**
   * 수신 메시지 사본을 외부로 릴레이 — **forward_to 알리아스와 Sieve redirect의 공통 경로**.
   *
   * 두 기능은 "받은 메일을 그대로 다른 주소로 보낸다"는 같은 일이라 같은 규칙이 전부 필요하다:
   * SRS envelope-from 재작성(원 도메인 SPF로 발송해 거부당하지 않게), ARC 봉인(RFC 8617,
   * 인증 결과 보존), X-Ionosphere-Forwarded 홉 카운트 루프가드, 시스템 발송(internal) 게이트 우회.
   * 한쪽만 고치면 조용히 갈라지는 자리라 하나로 합쳤다 — 과거 JMAP만 레이트리밋을 우회했던 것과 같은 종류의 사고.
   *
   * null 발신자(<>, 바운스)는 SRS 재작성 없이 유지. 1건 이상 적재되면 true. SRS 미설정 시 호출 금지.
   */
  private async relayCopy(input: {
    rcpt: string;
    targets: readonly string[];
    tenantId: string | null;
    /** SRS 재작성·ARC 봉인에 쓸 우리 도메인(수신 주소의 도메인). */
    domain: string;
    reason: "forward" | "sieve-redirect";
    env: { mailFrom: string; raw: Uint8Array };
    /** 릴레이할 바이트 — **우리 Received가 붙은** prepareInbound의 결과(H-6). */
    stored: Uint8Array;
    parsed: ParsedMessage;
    authResults: string;
  }): Promise<boolean> {
    const { rcpt, targets, domain, reason, env, parsed } = input;
    const secret = this.srsSecret!;
    const hops = countForwardHops(parsed, secret);
    if (hops >= this.forwardMaxHops) {
      this.log.warn("relay loop guard — dropped", { rcpt, reason, hops });
      return false;
    }
    // 분기 수 상한(MAX_RELAY_TARGETS 주석) — 홉 상한만으로는 N^hops 증폭을 막지 못한다.
    if (targets.length > MAX_RELAY_TARGETS) {
      this.log.warn("relay 대상 수 한도 초과 — 릴레이 없이 로컬 보관", { rcpt, reason, count: targets.length, max: MAX_RELAY_TARGETS });
      return false;
    }
    /**
     * ARC 봉인(RFC 8617) — 인증 결과를 체인으로 보존(dkimHook 있을 때). 그다음 루프 헤더 추가.
     *
     * ★원본(`env.raw`)이 아니라 `stored`에서 시작한다(H-6): 우리 Received가 이미 최상단에
     * 붙어 있는 바이트다. 순서도 이래야 맞다 — Received가 먼저, 그 위에 ARC가 얹힌다.
     */
    let outgoing = input.stored;
    if (this.dkimHook) {
      try {
        /**
         * ARC는 DKIM과 달리 **이중 봉인을 할 수 없다** — RFC 8617 §5.1은 홉당 ARC 세트 하나
         * (`i=N`)를 규정하고, 같은 인스턴스 번호로 두 세트를 붙이면 체인이 깨진다.
         *
         * 그래서 하나를 골라야 하는데 **RSA를 우선한다**: ARC의 목적은 *다음 홉*이 우리 체인을
         * 검증하는 것이고, Ed25519(RFC 8463)는 SHOULD라 검증 지원이 고르지 않다 — Gmail은 우리
         * Ed25519 DKIM 서명에 `dkim=neutral (no key)`를 냈다(2026-08-01 실측, 우리 키·DNS·서명은
         * 전부 정상이었다). 검증되지 않는 봉인은 체인 보존에 아무 값을 주지 못한다.
         * DKIM 쪽은 여러 서명이 허용되므로 이중 서명으로 해결했다(`worker.ts`).
         */
        const keys = await this.dkimHook.selectorFor(domain);
        const key = keys.find((k) => k.algorithm === "rsa-sha256") ?? keys[0];
        if (key) {
          const arc = arcSeal(outgoing, {
            domain,
            selector: key.selector,
            privateKey: key.privateKey,
            algorithm: key.algorithm,
            authResults: input.authResults,
          });
          outgoing = prependHeaderBytes(outgoing, arc); // arc는 CRLF로 연결된 3개 헤더
        }
      } catch (err) {
        this.log.warn("arc seal failed — relaying without ARC", { rcpt, reason, error: err instanceof Error ? err.message : String(err) });
      }
    }
    // 루프 카운트 헤더 추가 후 새 블롭으로 저장(모든 대상 공유). 값은 봉인한다(M-15 — forwardMarker 주석).
    const forwardedRaw = prependHeaderBytes(outgoing, `X-Ionosphere-Forwarded: ${forwardMarker(domain, parsed, secret)}`);
    const { blobId, size, generation } = await putBlob(this.db, this.blobs, forwardedRaw);
    // null 발신자(<>)는 SRS 재작성 없이 유지(RFC — 바운스). 그 외에는 SRS0/1로 재작성.
    const envFrom = env.mailFrom ? srsForward(env.mailFrom, domain, { secret }) : "";
    try {
      const result = await enqueueMessage(
        this.db,
        {
          tenantId: input.tenantId ?? "",
          blobId,
          sizeBytes: size,
          blobGeneration: generation,
          envFrom,
          rcpts: targets,
          // 시스템 relay — §8 발송 게이트 우회. 게이트를 끄는 대신 **상한과 봉투발신자 규율을
          // 함께 선언한다**(enqueue.ts SystemRelay 주석). 미지정이면 무제한이 아니라 기본 상한.
          system: { relayPerHour: this.relayPerHour, envFrom: "srs" },
        },
      );
      this.log.info("relayed", { rcpt, reason, targets: targets.length, queued: result.queuedIds.length, from: envFrom });
      return result.queuedIds.length > 0;
    } catch (err) {
      this.log.error("relay enqueue failed", { rcpt, reason, error: err instanceof Error ? err.message : String(err) });
      return false;
    }
  }

  /**
   * SRS 바운스 반송처 relay — 우리가 만든 SRS 주소로 되돌아온 바운스를 원 발신자에게 전달.
   * reverse 실패(변조·만료)는 드롭.
   *
   * ★이 함수가 감사 5차 C-1(미인증 오픈 릴레이 + 임의 도메인 DKIM 서명 탈취)의 진원지였다.
   * 세 가지가 겹쳤다:
   *   ① `enqueueMessage`에 옵션을 **아예 넘기지 않아** relay 상한이 사라졌다
   *      (`relayCopy`는 넘기고 여기만 안 넘긴 비대칭이 결함의 핵심이었다).
   *   ② `envFrom`으로 **공격자가 정한 MAIL FROM**을 그대로 넘겨, 워커가 봉투발신자 도메인으로
   *      서명 키를 고르는 성질을 타고 **임의 호스팅 도메인의 DKIM 키로 서명된 사칭 메일**이 나갔다.
   *   ③ 진짜 바운스인지 확인하지 않아 **본문·발신자를 공격자가 정한 일반 메일**도 반송 취급됐다.
   * ①②는 `SystemRelay` 선언이 타입으로 강제해 닫고, ③은 아래 null 발신자 검사로 닫는다.
   */
  private async relayBounce(rcpt: string, env: { mailFrom: string; raw: Uint8Array }, stored: Uint8Array): Promise<boolean> {
    /**
     * 반송할 것은 **바운스뿐이다.** RFC 5321 §4.5.5는 DSN의 reverse-path를 null(`<>`)로 요구하므로
     * 봉투발신자가 비어 있지 않으면 바운스가 아니다 — 그런 메일을 SRS 주소로 보내는 것은
     * 우리를 릴레이로 쓰려는 시도다. 이 한 검사가 C-1의 공격 시나리오
     * (`MAIL FROM:<ceo@호스팅중인고객도메인.com>` + 유효 SRS 토큰)를 입구에서 끊는다.
     */
    if (env.mailFrom !== "") {
      this.log.warn("srs 주소로 온 비-바운스 메일 — 릴레이 거부", { rcpt, from: env.mailFrom });
      return false;
    }
    const rev = srsReverse(rcpt, { secret: this.srsSecret! });
    if (!rev.ok) {
      this.log.warn("srs bounce reverse failed — dropped", { rcpt, reason: rev.reason });
      return false;
    }
    // 원본이 아니라 우리 Received가 붙은 바이트를 반송한다 — 루프 카운터가 우리 홉에서
    // 증가해야 우리를 경유해 도는 루프가 MAX_RECEIVED_HOPS에 걸린다(H-6).
    const { blobId, size, generation } = await putBlob(this.db, this.blobs, stored);
    try {
      const result = await enqueueMessage(this.db, {
        tenantId: "",
        blobId,
        sizeBytes: size,
        blobGeneration: generation,
        // 값은 넘기지만 강제는 게이트가 한다 — "null-sender" 선언이 무엇을 넘기든 <>로 덮어쓴다.
        envFrom: "",
        rcpts: [rev.address],
        system: { relayPerHour: this.relayPerHour, envFrom: "null-sender" },
      });
      this.log.info("srs bounce relayed", { srs: rcpt, to: rev.address, queued: result.queuedIds.length });
      return result.queuedIds.length > 0;
    } catch (err) {
      this.log.error("srs bounce relay failed", { rcpt, error: err instanceof Error ? err.message : String(err) });
      return false;
    }
  }

  /** 인증 제출 → mta_queue 적재 (실제 배달은 MtaWorker). */
  private async submitOutbound(env: {
    mailFrom: string;
    rcptTo: string[];
    raw: Uint8Array;
    authenticatedAs: string | null;
    /** 트레이스 헤더용 — 호출자(deliver)는 원래 넘기고 있었는데 타입이 받지 않았다. */
    heloName?: string | undefined;
    clientIp?: string | undefined;
    tls?: { protocol?: string | undefined; cipher?: string | undefined } | undefined;
  }) {
    const account = await this.store.getAccountByEmail((env.authenticatedAs ?? "").toLowerCase());
    if (!account) {
      return { ok: false as const, code: 550, enhanced: "5.7.1", message: "unknown submitter" };
    }
    // 정지 계정 차단 (§8 ④). 1차 방어는 AUTH(authenticate가 status=1 요구)지만,
    // AUTH 성공 후 세션 중 abuse 스윕이 정지시키는 레이스를 여기서 잡는다.
    if (account.status !== 1) {
      this.log.warn("submit rejected: account suspended", { submitter: env.authenticatedAs });
      return { ok: false as const, code: 550, enhanced: "5.7.1", message: "account suspended" };
    }
    /**
     * 제출 경로 트레이스(RFC 5321 §4.4 — MSA에도 그대로 적용된다. RFC 6409는 trace 헤더를
     * [SMTP-MTA] 동작으로 넘길 뿐 별도 예외를 두지 않는다).
     *
     * 사용자 IP를 **넣는다**: §4.4가 "SHOULD contain both (1) EHLO 이름 (2) TCP 연결에서 얻은
     * IP"라고 못 박는다. §7.6이 노출 우려를 인정하지만 생략을 권하지는 않는다.
     * 인증된 세션이므로 with 절은 ESMTPA/ESMTPSA가 된다(RFC 3848).
     */
    const submitTrace = buildReceivedHeader({
      transport: "esmtp",
      ...(env.heloName ? { heloName: env.heloName } : {}),
      ...(env.clientIp ? { clientIp: env.clientIp } : {}),
      by: this.authservId,
      id: ulid(),
      ...(env.rcptTo.length === 1 ? { forRecipient: env.rcptTo[0] } : {}),
      ...(env.tls ? { tls: env.tls } : {}),
      authenticated: true,
      date: new Date(),
    });
    const outgoing = prependHeaderBytes(env.raw, submitTrace);

    const { blobId, size, generation } = await putBlob(this.db, this.blobs, outgoing);
    let result;
    try {
      result = await enqueueMessage(
        this.db,
        {
          tenantId: account.tenantId,
          accountId: account.id,
          blobId,
          sizeBytes: size,
          blobGeneration: generation,
          envFrom: env.mailFrom,
          rcpts: env.rcptTo,
        },
        {
          // 정책은 통째로 전달한다 — 필드를 골라 담으면 새 필드가 늘 때 여기만 빠진다.
          ...this.outbound,
          rateLimit: { ...DEFAULT_RATE_LIMIT, ...this.outbound.rateLimit },
        },
      );
    } catch (err) {
      // 발송 게이트/레이트리밋 (§8 ②③) → SMTP 코드 매핑
      if (err instanceof OutboundRejectedError) {
        if (err.reason === "domain-unverified") {
          this.log.warn("submit rejected: domain unverified", { submitter: env.authenticatedAs, from: env.mailFrom });
          return { ok: false as const, code: 553, enhanced: "5.7.1", message: "sender domain not verified" };
        }
        if (err.reason === "external-disabled") {
          this.log.warn("submit rejected: external delivery disabled", { submitter: env.authenticatedAs });
          return { ok: false as const, code: 550, enhanced: "5.7.1", message: "external delivery is not configured" };
        }
        if (err.reason === "sender-not-owned") {
          // 정책상 영구 실패 — 같은 자격증명으로 재시도해도 같다.
          this.log.warn("submit rejected: sender not owned", { submitter: env.authenticatedAs, from: env.mailFrom });
          return { ok: false as const, code: 550, enhanced: "5.7.1", message: "sender address not owned by this account" };
        }
        if (err.reason === "invalid-address") {
          // 주소 자체가 SMTP 명령 줄에 실을 수 없는 형태다 — 재시도해도 같으므로 영구 실패.
          this.log.warn("submit rejected: unsafe envelope address", { submitter: env.authenticatedAs, error: err.message });
          return { ok: false as const, code: 550, enhanced: "5.1.7", message: "invalid envelope address" };
        }
        // rate-limited → 일시 실패(4xx), 클라이언트 재시도
        this.log.warn("submit rejected: rate limit", { submitter: env.authenticatedAs });
        return { ok: false as const, code: 452, enhanced: "4.3.2", message: "sending rate limit exceeded, retry later" };
      }
      throw err;
    }
    this.log.info("submitted", {
      submitter: env.authenticatedAs,
      queued: result.queuedIds.length,
      skipped: result.skipped.length,
    });
    if (result.queuedIds.length === 0) {
      return { ok: false as const, code: 550, enhanced: "5.7.1", message: "all recipients suppressed" };
    }
    return { ok: true as const };
  }
}

/** dkim_keys 조회 + secretbox 복호 → MtaWorker DkimHook (SCHEMA §9-2). */
export class StoreDkimHook implements DkimHook {
  private readonly db: DbDriver;
  private readonly masterKey: string | undefined;

  constructor(db: DbDriver, masterKey: string | undefined) {
    this.db = db;
    this.masterKey = masterKey;
  }

  async selectorFor(domain: string): Promise<readonly DkimKeyLookup[]> {
    /**
     * 도메인의 활성 키 **전부**를 돌려준다 — 호출자가 모두로 서명한다(이중 서명).
     *
     * ★예전에는 `LIMIT 1`로 Ed25519 하나만 골랐다. 그 결과 Ed25519 단독 서명이 나갔고,
     * 그것을 검증하지 않는 수신자에게는 우리 서명이 **아예 없는 것과 같았다** —
     * Gmail 실측 `dkim=neutral (no key) header.s=ed1`(우리 서명·키·DNS는 전부 정상이었다.
     * `fail`이 아니라 `neutral`인 것이 신호다: 검증을 시도하지 않았다는 뜻이다).
     * `docs/PROTOCOLS.md`가 이미 "RSA2048 + Ed25519 이중 서명 권장(Ed25519 단독 금지)"라고
     * 적어 둔 이유가 이것이고, RFC 8463 §5도 같은 취지다.
     *
     * ★`d.status = 1`이 없어서 뚫렸다(감사 5차 H-4 ③, C-1 증폭). `domains.name`에 UNIQUE 제약이
     * 없으므로 공격 테넌트가 `victim.com` **미검증 행 + DKIM 키**를 하나 더 만들 수 있었고,
     * 그러면 활성 키가 2세트가 되어 `algo` 동률에서 **어느 행이 뽑히는지 비결정적**이었다 —
     * 정당 테넌트의 메일이 DNS에 없는 키로 서명돼 수신측에서 `dkim=fail`이 된다.
     * 검증된 도메인만 서명할 수 있어야 한다: 검증되지 않은 도메인은 DNS에 우리 셀렉터를 올릴
     * 방법 자체가 없으므로 서명해도 무의미하고, 남의 도메인을 사칭할 통로만 된다.
     *
     * `ORDER BY`를 유지하는 이유: 이제 전부 서명하므로 어느 키가 뽑히는지의 문제는 사라졌지만,
     * **헤더가 붙는 순서**가 요청마다 달라지면 진단이 어렵다. 결정적 순서는 진단 가능성의 문제다.
     */
    const { rows } = await this.db.query({
      sql: `SELECT k.selector, k.algo, k.private_key
            FROM dkim_keys k JOIN domains d ON d.id = k.domain_id
            WHERE d.name = ? AND k.active = 1 AND d.status = 1
            ORDER BY k.algo DESC, k.selector ASC`,
      params: [domain.toLowerCase()],
    });
    return rows.map((row) => ({
      selector: String(row.selector),
      privateKey: open(String(row.private_key), this.masterKey),
      algorithm: Number(row.algo) === 1 ? ("ed25519-sha256" satisfies DkimAlgorithm) : "rsa-sha256",
    }));
  }
}

interface Pop3Ref {
  uid: number;
  messageId: string;
}

/** 락을 잡은 maildrop 세션 — owner와 리스 갱신 타이머를 함께 들고 있어야 해제가 완전해진다. */
interface Pop3Session {
  owner: string;
  heartbeat: ReturnType<typeof setInterval> | null;
}

export class IonospherePop3Backend implements Pop3Backend {
  private readonly db: DbDriver;
  private readonly store: Store;
  private readonly blobs: BlobStore;
  private readonly log: Logger;
  /**
   * maildrop 배타 잠금. 기본값은 인프로세스 락 — DB 없는 구성·기존 배선과 하위호환.
   * MRA를 2대 이상 띄우거나 110/995 백엔드를 따로 만드는 배포에서는 반드시
   * DbMaildropLock(@ionosphere/store)을 주입해야 RFC 1939 §3 배타성이 성립한다.
   */
  private readonly lock: MaildropLock;
  /** accountId → INBOX mailboxId (세션 간 캐시 아님 — commit 시 재사용 위해 세션 수명만). */
  private readonly inboxByAccount = new Map<string, string>();
  /** accountId → 이 프로세스가 잡은 락 세션. 없으면 락을 안 잡은 것 = 풀 것도 없다. */
  private readonly sessions = new Map<string, Pop3Session>();

  constructor(
    db: DbDriver,
    store: Store,
    blobs: BlobStore,
    logger: Logger = noopLogger,
    lock: MaildropLock = new InProcessMaildropLock(),
  ) {
    this.db = db;
    this.store = store;
    this.blobs = blobs;
    this.log = logger.child({ component: "pop3" });
    this.lock = lock;
  }

  async authenticate(user: string, pass: string) {
    const result = await authenticate(this.db, user, pass);
    if (!result) {
      this.log.warn("auth failed", { user });
      return null;
    }
    this.log.info("auth ok", { user, accountId: result.accountId });
    // `credKind`를 어댑터로 올린다 — 감사 로그가 기본 비번/앱 비번/OAuth를 구분해야 한다.
    // 여기서 기록하지 않는 이유: 이 클래스에는 IP가 없다(어댑터만 소켓을 본다).
    return { accountId: result.accountId, credKind: result.credKind };
  }


  /**
   * SCRAM 저장 키 조회 — 없으면 null. **없다고 즉시 실패시키지 않는다**(엔진이 가짜 salt로
   * 교환을 끝까지 진행해 계정 열거를 막는다). 그래서 여기서 로그도 남기지 않는다 —
   * "그 사용자는 조회가 실패했다"가 로그로 새면 방어가 반쪽이 된다.
   */
  async scramKeys(user: string) {
    return await scramKeysFor(this.db, user);
  }

  /**
   * SCRAM 증명 통과 뒤의 최종 승인. **비밀번호를 증명한 것과 들어와도 되는 것은 다르다** —
   * 정지된 계정도 비밀번호는 맞을 수 있다. PLAIN 경로는 `authenticate`가 status=1을 함께
   * 보지만 SCRAM은 검증을 엔진이 하므로 이 확인이 따로 있어야 한다.
   */
  async scramAuthorize(user: string) {
    const ok = await scramAuthorize(this.db, user);
    if (!ok) {
      this.log.warn("scram authorize 실패 — 계정 없음/정지", { user });
      return null;
    }
    this.log.info("auth ok (scram)", { user, accountId: ok.accountId });
    return { accountId: ok.accountId, credKind: "password" as const };
  }

  async openMaildrop(accountId: string) {
    // owner는 세션마다 새로 만든다 — 해제·갱신을 "내 락"으로 한정하는 근거가 이 값이다.
    const owner = ulid();
    if (!(await this.lock.acquire(accountId, owner))) {
      return { ok: false as const, inUse: true };
    }
    this.sessions.set(accountId, { owner, heartbeat: null });
    const inbox = await this.store.getMailboxByRole(accountId, "inbox");
    if (!inbox) {
      await this.releaseSession(accountId);
      return { ok: false as const, inUse: false };
    }
    // 리스 갱신은 락을 실제로 들고 있는 동안만 — 시작 지점을 open 성공 이후로 둔 이유다.
    this.startHeartbeat(accountId, owner);
    this.inboxByAccount.set(accountId, inbox.id);
    const items = await this.store.listMessages(inbox.id);
    const messages: Pop3MaildropMessage[] = items
      .filter((m) => !m.deleted)
      .map((m) => ({
        uidl: m.messageId, // 영속 UIDL = 불변 message id (SCHEMA.md §10)
        sizeBytes: m.sizeBytes,
        ref: { uid: m.uid, messageId: m.messageId } satisfies Pop3Ref,
      }));
    return { ok: true as const, messages };
  }

  async retrieve(_accountId: string, msg: Pop3MaildropMessage) {
    const ref = msg.ref as Pop3Ref;
    const blob = await this.store.getMessageBlob(ref.messageId);
    if (!blob) throw new Error("message vanished"); // 동시 EXPUNGE — [SYS/TEMP]로 표면화됨
    return this.blobs.get(blob.blobId, blob.generation);
  }

  /**
   * QUIT 시 삭제 커밋(UPDATE 상태). **락을 아직 쥐고 있을 때만** 실행한다.
   *
   * 왜 여기서 다시 확인하는가: 리스는 잃을 수 있다(DB 장애로 갱신이 3주기 연속 실패하면
   * TTL이 지나 다른 MRA가 탈취한다). 그 상태에서 expunge를 강행하면 **락이 지키려던 바로 그
   * 사고**가 난다 — 새 소유자가 서빙 중인 메시지를 이 세션이 지워 상대에게 "message vanished"가
   * 발생한다. 배타성이 깨진 걸 안 순간에는 쓰지 않는 쪽이 안전하다(fail closed).
   *
   * 커밋을 건너뛴 대가는 사용자가 다음 접속에서 같은 메일을 다시 받는 것이다 — 되돌릴 수 있다.
   * 반대로 잘못 지운 메일은 되돌릴 수 없다.
   */
  async commitDeletions(accountId: string, msgs: Pop3MaildropMessage[]) {
    if (msgs.length === 0) return;
    const mailboxId = this.inboxByAccount.get(accountId);
    if (!mailboxId) return;
    const session = this.sessions.get(accountId);
    if (session && this.lock.refreshIntervalMs > 0 && !(await this.lock.refresh(accountId, session.owner))) {
      this.log.error("maildrop 리스를 잃어 삭제를 취소한다 — 다른 인스턴스가 소유 중", {
        accountId,
        pending: msgs.length,
      });
      return;
    }
    await this.store.setDeleted({
      accountId,
      mailboxId,
      uids: msgs.map((m) => (m.ref as Pop3Ref).uid),
      deleted: true,
    });
    await this.store.expunge({ accountId, mailboxId });
    this.log.info("deletions committed", { accountId, count: msgs.length });
  }

  async releaseMaildrop(accountId: string) {
    this.inboxByAccount.delete(accountId);
    await this.releaseSession(accountId);
  }

  /**
   * 락 세션 종료 — 타이머를 먼저 끄고 자기 owner로만 해제한다.
   * 락을 못 잡은 세션(= sessions에 없음)은 아무것도 하지 않는다. POP3 어댑터는 인증 후
   * 연결이 끊기면 무조건 releaseMaildrop을 부르므로, 이 가드가 없으면 **[IN-USE]를 받은
   * 두 번째 세션이 끊기면서 첫 세션의 락을 푼다.**
   */
  private async releaseSession(accountId: string): Promise<void> {
    const session = this.sessions.get(accountId);
    if (!session) return;
    this.sessions.delete(accountId);
    if (session.heartbeat) clearInterval(session.heartbeat);
    await this.lock.release(accountId, session.owner);
  }

  /**
   * 리스 갱신 타이머. STAT/LIST/UIDL은 엔진이 세션 캐시로 답해 백엔드를 전혀 호출하지 않으므로
   * "백엔드 호출 시 연장" 방식으로는 오래 붙어 있는 세션의 리스가 만료된다.
   * refreshIntervalMs가 0인 락(인프로세스)은 만료가 없어 타이머를 걸지 않는다.
   */
  private startHeartbeat(accountId: string, owner: string): void {
    const every = this.lock.refreshIntervalMs;
    if (every <= 0) return;
    const timer = setInterval(() => {
      void this.lock
        .refresh(accountId, owner)
        .then((held) => {
          if (held) return;
          // 이미 뺏겼다 — 갱신을 계속해봐야 남의 락을 건드릴 뿐이라 타이머를 멈추고 알린다.
          this.log.warn("maildrop lease lost", { accountId });
          const session = this.sessions.get(accountId);
          if (session?.owner === owner && session.heartbeat) {
            clearInterval(session.heartbeat);
            session.heartbeat = null;
          }
        })
        .catch((err: unknown) => {
          // 일시적 DB 오류로 세션을 죽이지 않는다 — 다음 주기에 다시 시도(TTL은 3주기분).
          this.log.warn("maildrop lease refresh failed", { accountId, error: String(err) });
        });
    }, every);
    // 타이머 하나가 프로세스 종료를 붙잡지 않도록(세션 락은 프로세스 수명을 늘릴 이유가 없다).
    timer.unref?.();
    const session = this.sessions.get(accountId);
    if (session) session.heartbeat = timer;
    else clearInterval(timer); // 방어적 — open 도중 해제된 경우 타이머만 남지 않게
  }
}

/**
 * LMTP 로컬 배달 백엔드(Phase 5) — 기존 수신 배달 파이프라인(IonosphereSmtpBackend.deliver: 인증결과·
 * Sieve·포워딩·웹훅)을 그대로 재사용한다. LMTP는 DATA 후 수신자별 응답이 필수라 집계 결과를
 * 각 수신자에 매핑한다(원자 배달이므로 상태 공유 — 프로토콜 포맷은 준수). authenticatedAs=null(신뢰 로컬).
 */
export class IonosphereLmtpBackend implements LmtpBackend {
  private readonly smtp: IonosphereSmtpBackend;
  constructor(smtp: IonosphereSmtpBackend) {
    this.smtp = smtp;
  }
  verifyRecipient(address: string): Promise<{ ok: true } | { ok: false; code: number; enhanced: string; message: string }> {
    return this.smtp.verifyRecipient(address);
  }
  async deliverLmtp(env: LmtpDeliverEnv): Promise<LmtpDelivery[]> {
    // 수신자별 처분을 그대로 받는다 — 단일 결과를 복사하던 예전 구현과 달리
    // 한 명이 쿼터 초과여도 나머지는 정상 250을 받는다(RFC 2033의 요점).
    return this.smtp.deliverPerRecipient({
      mailFrom: env.mailFrom,
      heloName: env.lhloName,
      clientIp: env.clientIp,
      rcptTo: env.rcptTo,
      raw: env.raw,
    });
  }
}
