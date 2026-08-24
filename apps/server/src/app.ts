/** 올인원 서버 조립 — DB/블롭/스토어/프로토콜 리스너를 한 프로세스로 (PLAN.md §4). */
import { AuthFailureThrottle, MAX_MESSAGE_BYTES, noopAuditSink, noopLogger, ulid, type AuditSink, type Logger } from "@ionosphere/core";
import { allMigrations, describeDbSpec, migrate, MTA_QUEUE_STATUS, openDatabase, type DbDriver } from "@ionosphere/db";
import {
  authenticate,
  createCredential,
  DbMaildropLock,
  FsBlobStore,
  LayeredBlobStore,
  putBlob,
  scramAuthorize,
  scramKeysFor,
  Store,
  type BlobGcMode,
  type BlobStore,
} from "@ionosphere/store";
import { DEFAULT_RELAY_PER_HOUR, enqueueMessage, type OutboundPolicy } from "@ionosphere/mta";
import { SmtpServer } from "@ionosphere/proto-smtp";
import { Pop3Server } from "@ionosphere/proto-pop3";
import { ImapServer } from "@ionosphere/proto-imap";
import { IonosphereImapBackend } from "./imap-backend.ts";
import { JmapServer } from "./jmap-server.ts";
import { HttpsFrontServer, ROUTE_EXPOSURE, type HttpsFrontRoute } from "./https-front.ts";
import { HttpRedirectServer } from "./http-redirect.ts";
import { ManageSieveServer } from "@ionosphere/proto-managesieve";
import { IonosphereManageSieveBackend } from "./managesieve-backend.ts";
import { MtaWorker, type MxRecord, type RateLimitConfig, type SmarthostOptions } from "@ionosphere/mta";
import { WebhookWorker } from "@ionosphere/webhook";
import { parseCidrList, type DnsResolver } from "@ionosphere/mail-auth";
import type { DnsblZone, GreylistOptions, SpamScoreOptions, VirusScanner, VirusScanOptions } from "@ionosphere/spam";
import { AdminApiServer, type TlsAdmin } from "@ionosphere/api";
import { AutoconfigServer } from "@ionosphere/autoconfig";
import { createIonosphereMetrics, MetricsServer, type IonosphereMetrics } from "@ionosphere/metrics";
import { IonosphereLmtpBackend, IonospherePop3Backend, IonosphereSmtpBackend, StoreDkimHook, type IonosphereSmtpBackendOptions } from "./backend.ts";
import { StoreSmarthostResolver } from "./smarthost.ts";
import { resolveListener, type ListenerName, type ListenerOverrides, type ResolvedListener } from "./listeners.ts";
import { LmtpServer } from "@ionosphere/proto-lmtp";
import type { CertSource, SealedCertSource, TlsMaterial } from "@ionosphere/tls";
import { MailboxReaper } from "./reaper.ts";
import { BlobGcWorker } from "./blob-gc.ts";
import { AuditFileSink } from "./audit-sink.ts";
import { AuditShipper, type AuditS3Target } from "./audit-shipper.ts";
import { NodeDnsResolver } from "./dns-resolver.ts";
import { createTlsaLookup } from "./dane-lookup.ts";
import { startTlsSupport } from "./starttls-support.ts";

/** RFC 8314 권장 암시적 TLS 포트 — autoconfig가 클라이언트에 광고하는 기본값. */
const IMAPS_PORT = 993;
const SMTPS_PORT = 465;
const POP3S_PORT = 995;

/**
 * TLS를 제공하는 리스너 이름 — 리스너별 인증서 소스(`certSources`)의 키다.
 *
 * ★`as const` 배열을 정본으로 두고 타입을 파생시킨다(enum 금지 — erasableSyntaxOnly).
 * 이 목록이 곧 "인증서를 제시하는 포트 전부"이므로, 새 TLS 리스너를 추가하면서 여기 넣지 않으면
 * 리스너별 소스도 갱신 재적재도 그 포트를 건너뛴다. 실제로 143·110 STARTTLS를 추가할 때
 * `reloadAllTls`에서 빠져 **갱신 후 그 두 포트만 만료 인증서를 제시**하는 상태가 있었다
 * (4190에서 같은 함정을 겪고 주석까지 남겼는데 반복됐다 — 그래서 목록을 타입으로 고정한다).
 */
const TLS_LISTENER_NAMES = [
  "smtp", // 25 STARTTLS
  "submission", // 587 STARTTLS
  "smtps", // 465 암시적
  "imap", // 143 STARTTLS
  "imaps", // 993 암시적
  "pop3", // 110 STLS
  "pop3s", // 995 암시적
  "manageSieve", // 4190 STARTTLS
  "httpsFront", // 443 종단
  // ★리스너가 아니라 **인증서 소스 이름**이다(443의 `admin.` vhost가 SNI로 제시할 자료).
  //   8443 전용 종단을 걷어낸 뒤에도 이름을 남긴 이유는 `IONOSPHERE_TLS_ADMIN_TLS_*` env가
  //   그대로 쓰이기 때문이다 — 이름을 바꾸면 3대의 env를 동시에 고쳐야 하고, 그 사이
  //   자료 적재가 실패하면 admin vhost가 통째로 내려간다.
  "adminTls",
] as const;

export type TlsListenerName = (typeof TLS_LISTENER_NAMES)[number];

/** MTA-STS 정책 페치 타임아웃(발신측 강제 경로). */
const MTA_STS_FETCH_TIMEOUT_MS = 10_000;

/**
 * MTA-STS 정책 본문 상한.
 *
 * 정책 파일은 `version`·`mode`·`max_age`와 MX 몇 줄이 전부라 실제로는 수백 바이트다.
 * 상한이 없으면 상대 도메인이 응답으로 얼마든지 큰 본문을 흘려보낼 수 있고, 그 페치는
 * **큐 워커 안에서** 일어나므로 배달 전체가 그 메모리·시간을 함께 문다. 64KiB는 정상 정책의
 * 100배 이상이라 오탐이 없다.
 */
const MTA_STS_MAX_POLICY_BYTES = 64 * 1024;

/** 443 프론트에서 autoconfig upstream으로 보낼 Host 접두사. */
/**
 * HTTP 서비스별 Host 화이트리스트의 정본 — 기본 이름과 env 접미사를 **한 곳**에서 짝짓는다.
 *
 * ★기본이 `{서비스}.localhost`인 이유: 아무 것도 지정하지 않은 배포에서 **우리 이름이 아닌
 * 요청은 전부 404**가 된다(fail closed). 실서비스 이름은 반드시 명시해야 하고, 그 명시가
 * 곧 "우리가 서빙하기로 한 이름 목록"이 된다.
 *
 * ⚠ **배포 순서가 중요하다.** 코드가 먼저 올라가고 env가 비어 있으면 `mta-sts.<도메인>`이
 * 404가 되어, MTA-STS enforce 상태에서는 **수신이 통째로 막힌다**. env를 먼저 넣고 배포할 것.
 */
export const HTTP_SERVICES = {
  mtaSts: { defaultHost: "mta-sts.localhost", env: "MTA_STS" },
  autoconfig: { defaultHost: "autoconfig.localhost", env: "AUTOCONFIG" },
  autodiscover: { defaultHost: "autodiscover.localhost", env: "AUTODISCOVER" },
  admin: { defaultHost: "admin.localhost", env: "ADMIN" },
  jmap: { defaultHost: "jmap.localhost", env: "JMAP" },
  metrics: { defaultHost: "metrics.localhost", env: "METRICS" },
} as const;

export type HttpServiceName = keyof typeof HTTP_SERVICES;

/** 서비스별 허용 Host 목록. 미지정 서비스는 `HTTP_SERVICES`의 기본값 하나만 받는다. */
export type ServiceHosts = Partial<Record<HttpServiceName, readonly string[]>>;

/** 그 서비스가 받을 이름들 — 지정이 없으면 `{서비스}.localhost` 하나. */
export function hostsFor(serviceHosts: ServiceHosts | undefined, name: HttpServiceName): string[] {
  const given = serviceHosts?.[name];
  return given && given.length > 0 ? [...given] : [HTTP_SERVICES[name].defaultHost];
}

/**
 * 평문 HTTP 표면을 묶을 루프백 주소.
 *
 * 왜 필요한가: `listen(port)`에 host를 안 주면 **0.0.0.0(모든 인터페이스)** 이다. 그래서
 * metrics는 주석에 "내부망 전용, 외부 노출 금지"라 적혀 있는데도 코드가 그걸 지키지 않았고,
 * TLS 프론트를 세운 구성에서도 그 뒤에 있어야 할 평문 upstream이 함께 공개됐다.
 *
 * 지금은 평문 표면의 기본값이 **항상** 이 주소다(`plaintextHost` 주석 참조). 예전엔 앞단이
 * 없으면 전 인터페이스로 열었는데, 그건 설정 누락이 곧 전면 공개가 되는 fail open이었다.
 */
const LOOPBACK = "127.0.0.1";


/**
 * start()의 각 단계가 공유하는 값 — 필드에 숨기지 않고 인자로 명시해 데이터 흐름을 드러낸다.
 */
interface StartContext {
  log: Logger;
  /** 수신 인증(SPF/DKIM/DMARC)·도메인 검증·MTA-STS 조회에 공용. */
  resolver: DnsResolver;
  /**
   * 암시적 TLS(993/465/443) 자료 — **기본 소스**의 것. null이면 해당 리스너 비활성.
   *
   * 리스너별 소스를 준 리스너는 이 값이 아니라 `tlsFor(name)`을 봐야 한다. 이 필드를 직접 쓰는
   * 곳이 남아 있으면 그 리스너만 기본 인증서를 제시한다.
   */
  implicitTls: TlsMaterial | null;
  /**
   * 리스너 → 그 리스너가 제시할 자료. 리스너별 소스가 없으면 기본 소스의 자료가 들어간다.
   * 값이 없는(=null) 리스너는 TLS를 켜지 않는다.
   */
  tlsFor: (name: TlsListenerName) => TlsMaterial | null;
  /**
   * STARTTLS 업그레이드용 자료 — `tlsFor`와 같지만 **런타임이 서버측 업그레이드를 지원하지
   * 않으면 undefined**다. 암시적 TLS(993/465/443)와 업그레이드(25/587/143/110/4190)를 구분해야
   * 하는 이유: 광고만 하고 업그레이드를 못 하면 상대가 핸드셰이크에서 멈춘다.
   */
  upgradeTls: (name: TlsListenerName) => TlsMaterial | undefined;
  /** TLS를 의도했는가(평문 AUTH 차단 판정) — 자료 유무와 별개. */
  tlsConfigured: boolean;
  /** 25/587 STARTTLS에 쓸 인증서. 비활성(옵션 off·자료 없음·런타임 미지원) 시 undefined. */
  starttls: TlsMaterial | undefined;
  /**
   * 4190 ManageSieve STARTTLS에 쓸 인증서. 자료가 있고 런타임이 지원하면 켜진다 —
   * **`smtpStartTls` 옵트인과 분리한다.**
   *
   * 왜 분리인가: 25/587이 옵트인인 이유는 잘못 광고하면 **발신 MTA가 핸드셰이크에서 멈춰
   * 수신이 조용히 깨지기** 때문이다(메일 유실 위험). 4190은 반대 방향의 위험이 크다 — 없으면
   * 평문 AUTH가 fail closed로 막혀 **Sieve 관리가 아예 불가능**하다(감사 L-5). 게다가 상대는
   * 사람이 쓰는 대화형 클라이언트라 실패가 즉시 드러나고 메일이 사라지지 않는다.
   * 라이브 env에 IONOSPHERE_SMTP_STARTTLS가 없어도 4190 인증이 살아 있어야 한다.
   */
  accessStartTls: TlsMaterial | undefined;
}

/**
 * 접근 감사 로그 구성.
 *
 * ⚠ 볼륨: 범위가 "모든 작업"(조회 포함)이라 IMAP FETCH마다 한 줄이다. 줄당 ~200바이트면
 * 초당 100 FETCH = 약 17MB/일·인스턴스. gzip이 JSONL에서 보통 10:1이라 이관 후 부피는 1/10.
 * 디스크가 차기 시작하면 `shipIntervalMs`를 줄이거나 `localRetainDays`를 낮춘다.
 */
export interface AppAuditOptions {
  /** 로그 디렉터리(예: `/var/lib/ionosphere/audit`). 없으면 만든다(0o700). */
  dir: string;
  /** 버퍼 flush 간격(ms). 기본 1초 — SIGKILL 시 최대 이만큼 유실된다. */
  flushIntervalMs?: number;
  /** 이관 tick 간격(ms). 기본 1시간. */
  shipIntervalMs?: number;
  /** 업로드 실패로 남은 파일을 며칠 뒤 버릴지. 기본 7일. */
  localRetainDays?: number;
  /**
   * 오브젝트 스토리지 대상. **미지정 시 로컬 전용** — 파일은 쌓이고 보존기간이 지나면 버려진다.
   * 그 구성은 기동 시 경고한다(장기 보존이 안 되는 것을 조용히 두지 않는다).
   */
  s3?: AuditS3Target;
  /**
   * 이관 키에 들어갈 인스턴스 이름. 미지정 시 `hostname`.
   *
   * ★세 인스턴스(MX·MRA·MSA)가 같은 버킷에 쓰므로 이 값이 서로 달라야 한다 —
   * 같으면 같은 날짜 파일이 서로를 덮어써 한쪽 기록이 조용히 사라진다.
   */
  shipHost?: string;
}

export interface IonosphereAppOptions {
  hostname: string;
  dbPath: string;       // ":memory:" 허용 (테스트)
  blobRoot: string;
  /**
   * 25 릴레이(수신). `0`은 임시 포트(테스트), **생략하면 리스너를 아예 띄우지 않는다**.
   *
   * 왜 선택 옵션인가: 역할별로 서버를 나누면 MRA 서버는 25를 열 이유가 없다. 예전엔 필수라
   * 모든 인스턴스가 25를 열었고, MX가 아닌 서버까지 스팸·오배달 표면이 늘었다.
   */
  smtpPort?: number;
  /** POP3(평문 110). 생략하면 리스너를 띄우지 않는다 — 릴레이 서버에는 필요 없다. */
  pop3Port?: number;
  /** POP3S(암시적 TLS, 관례 995). 미지정 시 비활성 — 지정하려면 인증서(certSource/tls)가 필요하다. */
  pop3sPort?: number;
  /**
   * DB 연결 문자열(`postgres://…` / `mysql://…` / 파일 경로). 지정 시 `dbPath`보다 우선한다.
   * **여러 서버가 상태를 공유하려면 SQLite가 아니라 여기를 써야 한다** — SQLite는 로컬 파일이고,
   * 멀티프로세스에서 `SQLITE_BUSY`가 스토어의 재시도 루프에 걸리지 않는다(packages/db/src/open.ts 주석).
   */
  dbUrl?: string;
  /** 이미 열린 드라이버 주입(테스트·특수 어댑터용). 지정 시 dbUrl/dbPath를 무시한다. */
  db?: DbDriver;
  /**
   * 블롭 저장소 주입. 미지정 시 로컬 FS(`blobRoot`).
   * **서버를 분리하면 공유 저장소가 필수**다 — 로컬 FS면 A 서버가 쓴 본문을 B 서버가 못 읽는다.
   */
  blobs?: BlobStore;
  /**
   * 전환기용 읽기 폴백 백엔드(예: 기존 로컬 FS). 지정하면 `blobs`를 primary로 하는 계층형
   * 저장소로 감싼다 — 옛 블롭이 계속 읽히고 GC는 양쪽에서 회수한다.
   * `ionosphere_blob_fallback_reads_total`이 0으로 수렴하면 이 옵션을 빼면 된다.
   */
  blobsFallback?: BlobStore;
  /** IMAP(143). 미지정 시 리슨 안 함. imapsPort는 TLS(imapsTls 또는 tls) 필요. */
  imapPort?: number;
  imapsPort?: number;
  /** LMTP(RFC 2033) 로컬 배달 포트. 미지정 시 리슨 안 함. 신뢰된 로컬/프록시 전제(AUTH·TLS 없음). */
  lmtpPort?: number;
  /**
   * 993 전용 인증서 — 전역 tls와 분리. 전역 tls는 SMTP STARTTLS 광고까지 켜는데,
   * Bun 런타임의 서버측 TLS 업그레이드 버그(oven-sh/bun#25044)로 라이브 수신이 멈출
   * 수 있어 IMAPS(암시적 TLS — 업그레이드 아님)만 독립적으로 켤 수 있게 한다.
   */
  imapsTls?: { key: string | Buffer; cert: string | Buffer };
  /**
   * 암시적 TLS(993/465) 인증서 소스(Phase 5) — none/file/selfsigned/url/acme. 지정 시 imapsTls 대신
   * 이 소스가 자료를 제공하고, 갱신 시 setSecureContext로 무중단 교체(node) 시도한다.
   *
   * 리스너별 소스(`certSources`)를 주지 않은 리스너는 **전부 이 소스를 공유한다.**
   */
  certSource?: CertSource;
  /**
   * 리스너별 인증서 소스 — 지정한 리스너만 `certSource` 대신 이것을 쓴다.
   *
   * ★왜 필요한가: 한 인스턴스가 **서로 다른 이름으로 TLS를 제공**하는 경우가 있다. MX 역할은
   * 25번에서 `mx.example.com`을 제시해야 하고(발신 MTA가 MTA-STS의 `mx:`와 대조한다) 443에서는
   * `mta-sts.example.com`·`autoconfig.example.com`을 제시해야 한다(브라우저·발신자가 SNI로
   * 검증). 와일드카드 인증서 한 장으로 덮으면 가려지지만, 그때도 **개인키 하나가 모든 이름을
   * 대표**한다 — 한 포트의 침해가 전체 이름 공간으로 번진다.
   *
   * 이름은 리스너 식별자와 같다(`smtp`=25, `submission`=587, `smtps`=465, `imap`=143,
   * `imaps`=993, `pop3`=110, `pop3s`=995, `manageSieve`=4190, `httpsFront`=443).
   * `adminTls`만 예외로 **리스너가 없는 소스 이름**이다 — 443의 `admin.` vhost가 쓴다.
   *
   * 갱신 감시(`watch`)는 **소스마다 따로** 걸리고, 각 소스는 자기를 쓰는 리스너만 재적재한다 —
   * 한 소스가 갱신될 때 다른 소스를 쓰는 리스너의 컨텍스트를 덮어쓰면 그 포트가 엉뚱한 인증서를
   * 제시한다.
   */
  certSources?: Partial<Record<TlsListenerName, CertSource>>;
  submissionPort?: number;  // 587 submission(발송). 미지정 시 리슨 안 함
  /**
   * 465 암시적 TLS submission — STARTTLS 업그레이드가 아니라 Bun에서도 안전.
   * 인증서는 imapsTls(공유 암시적 TLS 인증서) 또는 전역 tls. iOS Mail 발신 검증 경로.
   */
  smtpsPort?: number;
  maxSizeBytes?: number;
  tls?: { key: string | Buffer; cert: string | Buffer };
  logger?: Logger;      // 기본 noop — 테스트 조용
  masterKey?: string;   // DKIM 개인키 복호 (IONOSPHERE_MASTER_KEY)
  /** MX 리졸버 주입 — 미지정 시 node:dns. 로컬 페더레이션 테스트에서 오버라이드. */
  resolveMx?: (domain: string) => Promise<MxRecord[]>;
  /** MTA 아웃바운드 포트(기본 25) + 워커 자동 기동 여부(기본 submissionPort 설정 시 true). */
  outboundPort?: number;
  /**
   * DANE(RFC 7672) 발신측 — IONOSPHERE_DANE=1.
   *
   * 켜면 MX마다 TLSA를 **DNSSEC 검증**해 조회하고, 있으면 TLS를 강제하고 인증서를 고정한다.
   * 기본 꺼짐인 이유: 루트부터 걷는 검증 질의가 MX마다 추가되고(지연), 상대 존이 DNSSEC를
   * 잘못 운영하면 우리 배달이 늦어진다. 켜는 것은 운영 판단이다.
   */
  dane?: boolean;
  /**
   * 전역 스마트호스트(IONOSPHERE_SMARTHOST) — 테넌트/도메인별 지정(마이그레이션 007)이 없을 때의 폴백.
   * 지정 시 MX 직접 발송 대신 릴레이로 나간다.
   */
  smarthost?: SmarthostOptions;
  /** 계정별 발송 레이트리밋 오버라이드(§8 ③) — IONOSPHERE_RATE_PER_MINUTE/HOUR/DAY. */
  rateLimit?: RateLimitConfig;
  runMtaWorker?: boolean;
  /** MTA 워커 tick 간격(ms). 기본 30s. 테스트는 짧게. */
  mtaIntervalMs?: number;
  /** 수신 인증용 DNS 리졸버 주입 — 미지정 시 NodeDnsResolver(OS 리졸버). 테스트에서 오버라이드. */
  resolver?: DnsResolver;
  /** greylisting (기본 off). SPF-pass 면제. */
  greylist?: GreylistOptions | boolean;
  /** DNSBL 존 (opt-in, ⚠ 자체 재귀 리졸버 필요). */
  dnsblZones?: DnsblZone[];
  /**
   * 신뢰 릴레이 CIDR(IONOSPHERE_TRUSTED_RELAYS) — 우리가 운영하는 MTA의 접속 대역.
   * 여기 드는 접속은 SPF·DNSBL·greylist를 건너뛴다(그 셋만). 상세와 경위는
   * `IonosphereSmtpBackendOptions.trustedRelays` 주석. 기본은 빈 목록 = 아무도 신뢰 안 함.
   */
  trustedRelays?: readonly string[];
  /**
   * 바이러스 검사 플러그인(기본 없음 = 비활성) — PLAN.md의 "옵셔널 훅만 제공".
   *
   * ★env로 켤 수 없는 것이 의도다. 스캐너는 코드로 주입한다 — 시그니처 DB를 다루는 물건을
   * 문자열 설정으로 붙이면 "켰다고 생각했는데 안 돌던" 상태가 생기고, 그건 검사 없이
   * 배달하는 것보다 나쁘다(검사한다고 믿기 때문).
   */
  virusScanner?: VirusScanner;
  virusScanOptions?: VirusScanOptions;
  /**
   * 스팸 점수 판정(기본 없음 = 비활성). DNSBL·인증·헤더 룰을 합산해 accept/junk/reject.
   * `true`면 기본 임계값(junk 5 / reject 10). 세부 조정은 `SpamScoreOptions`.
   */
  spamScore?: SpamScoreOptions | boolean;
  /** 수신 웹훅 워커 기동 여부(기본 true) + 폴링 주기(ms). */
  runWebhookWorker?: boolean;
  webhookIntervalMs?: number;
  /** 메일함 삭제 2단계 리퍼(§7-7) 기동 여부. 기본 true(툼스톤 없으면 무해). */
  runReaper?: boolean;
  /** 리퍼 폴링 주기(ms). 기본 5분. 테스트는 짧게. */
  reaperIntervalMs?: number;
  /**
   * 블롭 GC 수위 — "off" | "mark"(기본, 파일 삭제 없음) | "sweep"(파일 삭제).
   * 삭제는 되돌릴 수 없으므로 기본은 관측만 한다. 상세는 @ionosphere/store BlobGcMode 주석.
   */
  blobGcMode?: BlobGcMode;
  /** 블롭 GC 폴링 주기(ms). 기본 1시간. */
  blobGcIntervalMs?: number;
  /** doomed → 파일 삭제까지의 유예(ms). 기본 24시간. */
  blobGcGraceMs?: number;
  /** 메시지로 승격되지 않은 JMAP 업로드의 수명(ms). 기본 24시간. */
  blobUploadTtlMs?: number;
  /**
   * 접근 감사 로그 — 지정 시 모든 표면(IMAP·POP3·ManageSieve·SMTP·JMAP·관리 API)이 기록한다.
   * 미지정 시 완전 비활성(기존 동작). 상세는 `audit-sink.ts`·`audit-shipper.ts`.
   */
  audit?: AppAuditOptions;
  /** ManageSieve 포트(4190, Phase 4). 미지정 시 리슨 안 함. */
  manageSievePort?: number;
  /** JMAP HTTP 포트(Phase 4). 미지정 시 리슨 안 함. */
  jmapPort?: number;
  /** JMAP Session/URL 생성용 외부 베이스 URL(예: https://mx.ionosphere.test). */
  jmapBaseUrl?: string;
  /** 관리 REST API 포트. 미지정 시 리슨 안 함. */
  adminPort?: number;
  /**
   * HTTP 서비스별 **Host 화이트리스트**. 미지정 서비스는 `{서비스}.localhost` 하나만 받는다.
   *
   * 목록에 없는 Host로 오면 404다 — 기본 upstream으로 흘려보내지 않는다. "우리가 서빙하기로
   * 한 이름"이 코드/설정에 명시적으로 존재하게 만드는 것이 이 옵션의 목적이다.
   *
   * ⚠ **멀티테넌트에서는 도메인마다 이름이 늘어난다.** `mta-sts.<도메인>`은 호스팅하는 모든
   * 도메인에 대해 열려야 하고, 빠진 테넌트는 정책을 못 받는다(enforce면 그 테넌트 수신 장애).
   * ⚠ **배포 순서**: 코드가 먼저 올라가고 env가 비어 있으면 실서비스 이름이 전부 404가 된다.
   * env를 먼저 넣고 배포할 것.
   */
  serviceHosts?: ServiceHosts;
  /**
   * 내부 전용 모드 — 이 서버가 호스팅하지 않는 도메인으로의 발송을 즉시 거절한다.
   * 아웃바운드 25가 막혔고 스마트호스트도 없을 때 켠다(안 켜면 몇 시간 뒤 바운스되는 조용한 실패).
   */
  localOnly?: boolean;
  /** 관리 API 부트스트랩 토큰(최초 테넌트/키 생성용). IONOSPHERE_ADMIN_TOKEN. */
  adminRootToken?: string;
  /**
   * 클라이언트 자동설정 HTTP 포트(Thunderbird/Outlook/Apple). 미지정 시 리슨 안 함.
   * ⚠ 평문 HTTP — 실운영은 TLS 종단 프록시 뒤에 두고 autoconfig./autodiscover. 호스트로 라우팅.
   * 광고 IMAPS/SMTPS 포트는 imapsPort/smtpsPort(기본 993/465).
   */
  autoconfigPort?: number;
  /** 자동설정 문서의 브랜드 이름(기본 hostname). */
  autoconfigBrand?: string;
  /**
   * 클라이언트에 광고할 IMAP 호스트(예: `imap.example.com`). 기본 hostname.
   * DNS 별칭만 먼저 나눠두면 나중에 실제 서버를 옮길 때 **클라이언트 재설정이 필요 없다**.
   */
  imapHost?: string;
  /** 클라이언트에 광고할 제출(SMTP) 호스트(예: `smtp.example.com`). 기본 hostname. */
  submissionHost?: string;
  /**
   * 클라이언트에 광고할 POP3 호스트(예: `pop3.example.com`) — **지정하면 자동설정에 POP3가 실린다.**
   *
   * 기본값이 없는 이유(opt-in): 포트를 여는 것과 **광고하는 것**은 다른 결정이다. POP3는
   * 보통 서버에서 메일을 내려받아 지우므로 다기기 사용자에게는 IMAP이 맞고, 자동설정에 둘 다
   * 있으면 클라이언트가 POP3를 고를 수 있다. `hostname`으로 폴백시키면 995를 연 모든 배치에서
   * 광고가 켜지므로 폴백하지 않는다.
   *
   * ⚠ 지정하기 전에 그 이름이 **DNS에 있고 인증서가 커버하는지** 확인할 것 — 광고된 이름으로
   * 붙지 못하면 클라이언트는 "설정은 받았는데 연결이 안 되는" 상태가 된다.
   */
  pop3Host?: string;
  /**
   * MTA-STS 정책의 `mx:`에 넣을 호스트 = **MX 레코드가 실제로 가리키는 이름**. 기본 hostname.
   * imapHost/submissionHost와 절대 같이 움직이면 안 된다(enforce 상태에서 수신 장애 직결).
   */
  mxHost?: string;
  /**
   * SMTP STARTTLS(25/587) 활성화 — certSource/imapsTls 인증서로 업그레이드를 제공한다.
   * **MTA-STS enforce의 전제**(발신자가 우리 MX에 TLS를 요구하므로).
   * ⚠ 런타임이 서버측 TLS 업그레이드를 지원할 때만 실제로 켜진다(startTlsSupport) —
   * 미지원 런타임에서 광고만 하면 발신자가 핸드셰이크에서 멈춰 수신이 깨지기 때문.
   */
  smtpStartTls?: boolean;
  /**
   * HTTPS 프론트 포트(443, TLS 종단). 지정 시 certSource/tls 자료로 TLS를 종단하고 Host로 골라
   * localhost의 JMAP·autoconfig upstream으로 리버스 프록시한다. certSource(또는 tls) + jmapPort/
   * autoconfigPort 중 하나 이상 필요. mta-sts./autoconfig./autodiscover. → autoconfig, 그 외 → JMAP.
   */
  httpsFrontPort?: number;
  /**
   * 80 → 443 리다이렉트 포트(보통 80). 미지정 시 80을 열지 않는다.
   *
   * 443 프론트가 있을 때만 의미가 있다 — 리다이렉트 대상이 없으면 얹지 않는다.
   * ⚠ ACME http-01(`IONOSPHERE_TLS_ACME_CHALLENGE=http-01`)과 **같은 포트를 다툰다**.
   * 공존 금지는 `main.ts`가 기동 시점에 막는다(갱신 실패는 90일 뒤에 드러난다).
   */
  httpRedirectPort?: number;
  /**
   * MTA-STS 정책 서빙 모드(RFC 8461) — 지정 시 autoconfig 서버가 /.well-known/mta-sts.txt
   * 응답(mx=hostname). IONOSPHERE_MTA_STS_MODE. autoconfigPort 필요. 미지정 시 비활성.
   */
  mtaStsMode?: "enforce" | "testing" | "none";
  /** MTA-STS 발신측 강제(RFC 8461) — 수신 도메인 정책 enforce 시 TLS·MX 일치 강제. IONOSPHERE_MTA_STS_ENFORCE. */
  mtaStsEnforce?: boolean;
  /**
   * Prometheus 메트릭 노출 HTTP 포트(GET /metrics). 미지정 시 계측·리슨 안 함.
   * ⚠ 평문 — 내부망/프록시 뒤 스크레이프 전용, 외부 노출 금지.
   */
  metricsPort?: number;
  /**
   * 메트릭 바인딩 주소. **기본 127.0.0.1** — 이 표면은 인증이 없어 공개되면 큐 깊이·계정
   * 정지 수 같은 운영 정보가 그대로 새어나간다. 원격 스크레이프가 필요하면 명시 지정한다
   * (IONOSPHERE_METRICS_HOST). 기본을 전 인터페이스로 두면 "내부 전용"이라는 선언이 무의미하다.
   */
  metricsHost?: string;
  /**
   * 서비스별 리스너 오버라이드 — 바인딩 주소·포트·기동 여부를 명시 지정한다
   * (`IONOSPHERE_LISTEN_<SERVICE>`, 예: `IONOSPHERE_LISTEN_ADMIN=0.0.0.0:8080`).
   *
   * **지정하지 않은 서비스는 종전 동작 그대로다.** 특히 루프백으로 묶여 있던 표면
   * (metrics·TLS 프론트 뒤의 admin/jmap/autoconfig)이 이 옵션이 생겼다는 이유로 열리지 않는다 —
   * 여는 것은 눈에 보이는 선택이어야 한다. 상세는 listeners.ts.
   */
  listeners?: ListenerOverrides;
  /**
   * SRS 비밀키(Phase 5) — 지정 시 forward_to 알리아스 포워딩 + SRS 바운스 reverse 활성.
   * IONOSPHERE_SRS_SECRET. 미지정 시 포워딩 비활성. 회전 시 과거 SRS 주소는 만료.
   */
  srsSecret?: string;
  /**
   * 시스템 relay(포워딩·Sieve redirect·바운스)의 테넌트별 시간당 상한. 기본 1000.
   *
   * 이 갈래는 귀속 계정이 없어 계정별 레이트리밋(rateLimit)이 걸리지 않는다 —
   * 무인증 발신자가 알리아스로 밀어넣는 만큼 그대로 외부로 재발송되던 증폭 채널이라
   * 총량 상한이 하나 필요하다. IONOSPHERE_RELAY_PER_HOUR로 조정.
   */
  relayPerHour?: number;
  /**
   * 발신자 소유 검증 — envFrom이 **인증 계정에 할당된 주소**(자기 email 또는 그 계정을 가리키는
   * 알리아스)여야 한다. **기본 on.** 끄려면 `IONOSPHERE_REQUIRE_SENDER_OWNERSHIP=0`.
   *
   * 끄면 같은 테넌트 안에서 계정끼리 사칭이 가능해진다 — 공유 사서함·대리 발송을 알리아스가
   * 아닌 방식으로 구현한 배포에서만 필요하다. 상세는 @ionosphere/mta OutboundPolicy 주석.
   */
  requireSenderOwnership?: boolean;
}

/**
 * relay 총량 기본 상한은 **@ionosphere/mta가 소유한다**(`enqueue.ts DEFAULT_RELAY_PER_HOUR`).
 * 여기 같은 값(1000)이 따로 선언돼 있었는데, 그러면 소유자 쪽을 조정해도 조립층이 옛 값을
 * 계속 쓴다 — "같은 상수가 두 곳에 복제되면 소유자를 정해 올린다"(CLAUDE.md 응집도).
 */

export class IonosphereApp {
  readonly opts: IonosphereAppOptions;
  /**
   * 인증 실패 스로틀 — **리스너들이 나눠 쓰는 한 인스턴스**.
   *
   * 리스너마다 따로 만들면 587·465·993·995·JMAP·admin이 각각 한도를 갖게 되어 "IP당 분당 10회"
   * 정책이 리스너 수만큼 곱해진다(레이트리밋을 갈래마다 재작성해 JMAP만 우회했던 것과 같은 종류의
   * 사고다). 공통 값은 여기서 한 번 만들어 주입한다.
   */
  readonly authThrottle: AuthFailureThrottle;
  db!: DbDriver;
  store!: Store;
  blobs!: BlobStore;
  smtp?: SmtpServer;
  pop3?: Pop3Server;
  submission?: SmtpServer;
  smtps?: SmtpServer;
  imap?: ImapServer;
  imaps?: ImapServer;
  lmtp?: LmtpServer;
  lmtpPort = 0;
  private certWatchUnsub?: () => void;
  /**
   * 스마트호스트 해석기 — MTA 워커(배달)와 발송 게이트(localOnly 예외)가 **같은 인스턴스**를 쓴다.
   * 따로 만들면 TTL 캐시가 둘로 갈려 "게이트는 통과시켰는데 워커는 릴레이를 못 찾는" 창이 생긴다.
   */
  private smarthosts?: StoreSmarthostResolver;
  jmap?: JmapServer;
  managesieve?: ManageSieveServer;
  mta?: MtaWorker;
  webhookWorker?: WebhookWorker;
  reaper?: MailboxReaper;
  blobGc?: BlobGcWorker;
  /**
   * 접근 감사 싱크 — **리스너보다 먼저 만들어져야 한다**(생성 시 주입하므로).
   * 그래서 `startWorkers`가 아니라 `start()` 맨 앞에서 만든다.
   */
  auditSink?: AuditFileSink;
  auditShipper?: AuditShipper;
  /**
   * 모든 리스너에 넘기는 값 — 감사가 꺼져 있으면 `noopAuditSink`다.
   *
   * ★`| undefined`로 두지 않는 이유: 리스너 조립 시 조건부 스프레드를 쓰면 갈래마다 손으로
   * 써야 하고, 그러다 한쪽이 빠지는 것이 이 저장소의 반복 사고다(과거 JMAP만 레이트리밋 우회).
   * 항상 하나를 넘기고 꺼짐은 no-op으로 표현한다.
   */
  private audit: AuditSink = noopAuditSink;
  /** 관리 콘솔 전용 TLS 종단(443과 분리 — 방화벽으로 막을 수 있게). */
  admin?: AdminApiServer;
  adminPort = 0;
  /** 관리 API upstream의 실제 바인딩 주소 — autoconfigHost와 같은 이유(위 주석). */
  adminHost?: string;
  autoconfig?: AutoconfigServer;
  autoconfigPort = 0;
  /**
   * upstream이 **실제로 바인딩된 주소**. 443 프론트가 여기로 연결한다.
   *
   * ★왜 포트만으로 부족한가: 프론트는 upstream을 `127.0.0.1`로 가정했는데,
   * `IONOSPHERE_LISTEN_AUTOCONFIG=10.0.101.12:`처럼 주소를 지정하면 그 주소에**만** 붙는다.
   * 두 값이 어긋나면 프론트가 아무도 없는 루프백에 연결해 **502**가 된다 —
   * 라이브에서 실제로 그랬고, autoconfig·autodiscover·MTA-STS 정책이 전부 502였다.
   * DNS는 `_mta-sts`로 정책이 있다고 광고하는 중이라 발신 MTA만 조용히 실패한다.
   * 바인딩 주소를 버리지 않고 넘겨 두 곳이 같은 값을 보게 한다.
   */
  autoconfigHost?: string;
  httpsFront?: HttpsFrontServer;
  httpRedirect?: HttpRedirectServer;
  httpRedirectPort = 0;
  httpsFrontPort = 0;
  metrics?: IonosphereMetrics;
  metricsServer?: MetricsServer;
  metricsPort = 0;
  smtpPort = 0;
  pop3Port = 0;
  pop3s?: Pop3Server;
  maildropLock!: DbMaildropLock;
  pop3sPort = 0;
  imapPort = 0;
  imapsPort = 0;
  submissionPort = 0;
  smtpsPort = 0;
  jmapPort = 0;
  /** JMAP upstream의 실제 바인딩 주소 — autoconfigHost와 같은 이유(위 주석). */
  jmapHost?: string;
  manageSievePort = 0;

  constructor(opts: IonosphereAppOptions) {
    /**
     * 신뢰 릴레이 CIDR을 **여기서 한 번 검증한다**(결과는 버리고 백엔드가 다시 만든다).
     *
     * 실제 매처는 수신 백엔드가 갖는데 그건 `start()` 안에서 만들어진다. 그때까지 미루면
     * 오타 하나가 리스너를 절반쯤 띄운 뒤에 터진다 — 이 저장소의 규율은 **설정 실수는 기동
     * 시점에 드러나야 한다**이고(80 포트 충돌 가드와 같은 이유), 신뢰 목록은 보안 판정이라
     * 특히 그렇다. 목록이 짧아 두 번 파싱하는 비용은 없다시피 하다.
     */
    parseCidrList(opts.trustedRelays ?? []);
    this.opts = opts;
    this.authThrottle = new AuthFailureThrottle({ ...(opts.logger ? { logger: opts.logger } : {}) });
  }

  /**
   * submission(587/465) 인증. 반환에 `credKind`를 실어 올리는 이유는 어댑터가 감사 로그를
   * 찍기 때문이다 — **IP는 어댑터에만 있다**. 여기서 찍는 로그는 "누가"만 알고 "어디서"를 모른다.
   */
  private authFn(): (user: string, pass: string) => Promise<{ ok: boolean; credKind?: string | undefined }> {
    // 성패를 로깅(운영 진단용) — 감사 로그와 별개로 journald에서 즉시 보이는 값이 있다.
    const log = (this.opts.logger ?? noopLogger).child({ component: "submission" });
    return async (user, pass) => {
      /**
       * 계정 축 스로틀. IP 축은 리스너가 소켓 주소로 걸지만, 봇넷이나 IPv6 프리픽스 전환으로
       * 출처가 흩어지면 **한 계정에 대한 분산 대입**은 IP 축에 걸리지 않는다.
       * 차단 중이면 `authenticate`를 아예 부르지 않는 것이 핵심이다 — 실패마다 scrypt가 도는
       * 것이 이 스로틀이 생긴 이유(브루트포스 = CPU 소모 공격)라, 검증을 돌린 뒤 막으면 늦다.
       */
      if (this.authThrottle.blocked({ account: user })) {
        log.warn("auth throttled", { user });
        // `throttled`를 실어 올린다 — 어댑터가 감사 로그에서 "거부됨"과 "비밀번호 틀림"을 가른다.
        return { ok: false, throttled: true };
      }
      const result = await authenticate(this.db, user, pass);
      if (result) {
        log.info("auth ok", { user });
        this.authThrottle.clear({ account: user });
        return { ok: true, credKind: result.credKind };
      }
      log.warn("auth failed", { user });
      this.authThrottle.recordFailure({ account: user });
      return { ok: false };
    };
  }

  /**
   * submission SCRAM-SHA-256. **`authFn`과 같은 자리에서 만드는 이유**가 계정 축 스로틀이다 —
   * 백엔드가 store를 직접 부르면 그 스로틀을 우회한다(IP 축은 어댑터가 걸지만, 봇넷이나 IPv6
   * 프리픽스 전환으로 출처가 흩어지면 한 계정에 대한 분산 대입은 IP 축에 걸리지 않는다).
   *
   * ⚠ 라이브 587·465가 SCRAM을 광고하지 않던 원인이 이 배선의 **부재**였다. 엔진·어댑터는
   *   완성돼 있었고 IMAP·POP3 백엔드에도 있었는데 SMTP 백엔드만 빠졌다. 조립 누락은 타입으로
   *   드러나지 않으므로 `scram-submission.test.ts`가 실제 세션으로 고정한다.
   */
  private scramFns(): NonNullable<IonosphereSmtpBackendOptions["scramFns"]> {
    const log = (this.opts.logger ?? noopLogger).child({ component: "submission" });
    return {
      /**
       * 저장 키 조회. **차단 중이어도 null을 돌려주고 교환은 계속된다** — 여기서 갈래를 나누면
       * "그 사용자는 조회가 막혔다"가 응답 형태로 새어 계정 열거가 열린다. 차단 판정은
       * `authorize`에서 한다(그 시점에는 이미 증명이 끝나 응답 형태가 갈리지 않는다).
       */
      keys: async (user) => await scramKeysFor(this.db, user),
      authorize: async (user) => {
        // 계정 축 차단 — SCRAM은 scrypt를 돌지 않지만 분산 대입 방어는 그대로 필요하다.
        if (this.authThrottle.blocked({ account: user })) {
          log.warn("auth throttled (scram)", { user });
          return { ok: false, throttled: true };
        }
        const ok = await scramAuthorize(this.db, user);
        if (!ok) {
          log.warn("scram authorize 실패 — 계정 없음/정지", { user });
          this.authThrottle.recordFailure({ account: user });
          return { ok: false };
        }
        log.info("auth ok (scram)", { user });
        this.authThrottle.clear({ account: user });
        return { ok: true, credKind: "password" };
      },
    };
  }

  /**
   * 기동 — 아래 단계 목록이 곧 이 서버의 구성이다. 각 단계의 조립 상세는 전용 메서드에 있고
   * 여기서는 **순서만** 읽힌다(이전엔 한 메서드에 300줄·16개 하위시스템이 뒤섞여 있었다).
   *
   * 순서 제약: 저장소 → (계측) → TLS 자료 → 리스너들 → 관리(HTTPS 프론트는 jmap/autoconfig
   * 포트가 정해진 뒤) → 인증서 감시(교체 대상 리스너가 준비된 뒤).
   */
  async start(): Promise<void> {
    const log = this.opts.logger ?? noopLogger;
    await this.openStorage();
    this.setupMetrics();
    // 감사 싱크는 **리스너보다 먼저**(생성 시 주입) — setupMetrics 뒤여야 onRecord로 계측이 붙는다.
    this.startAudit(log);
    const ctx = await this.resolveTls(log);

    await this.startInbound(ctx);      // 25 릴레이 · POP3 · LMTP
    await this.startAccess(ctx);       // IMAP 143/993 · JMAP · ManageSieve
    await this.startSubmission(ctx);   // 587 · 465 · MTA 워커
    this.startWorkers(log);            // 웹훅 · 메일함 리퍼
    await this.startManagement(ctx);   // 관리 API · autoconfig · 메트릭 · 443 프론트
    this.watchCertRenewal(log);        // 인증서 갱신 → 무중단 교체

    log.info("listening", {
      component: "app",
      smtp: this.smtpPort || undefined,
      pop3: this.pop3Port || undefined,
      pop3s: this.pop3sPort || undefined,
      imap: this.imapPort || undefined,
      imaps: this.imapsPort || undefined,
      submission: this.submissionPort || undefined,
      smtps: this.smtpsPort || undefined,
      jmap: this.jmapPort || undefined,
      managesieve: this.manageSievePort || undefined,
      admin: this.adminPort || undefined,
      autoconfig: this.autoconfigPort || undefined,
      httpsFront: this.httpsFrontPort || undefined,
      metrics: this.metricsPort || undefined,
      mta: this.mta ? "on" : "off",
      /**
       * ★**실제로 연 것**을 찍는다(`dbUrl ?? dbPath` — openStorage와 같은 식).
       *
       * 예전엔 `dbPath`만 찍어서, PostgreSQL로 운영하는데도 로그에는
       * `db:"/var/lib/ionosphere/ionosphere.db"`가 나왔다. 운영자가 "어느 DB를 보는가"를 판단하는
       * 유일한 줄인데 실제와 달랐고, 실제로 이 줄을 보고 "DB 이관이 되돌아갔다"고 오진했다.
       * 자격증명은 `describeDbSpec`이 지운다(마스킹 정본은 @ionosphere/db가 소유).
       */
      db: describeDbSpec(this.opts.dbUrl ?? this.opts.dbPath),
      runtime: `node ${process.versions.node}`,
    });

    await this.warnIfForwardingDisabled(log);
  }

  /**
   * `forward_to` 알리아스가 있는데 SRS 비밀키가 없으면 경고한다 — **조용한 상태를 시끄럽게 만든다.**
   *
   * 왜 필요한가(2026-08-03 라이브 사고): `/etc/ionosphere.env`에 `IONOSPHERE_SRS_SECRET=`이 **값 없이**
   * 키만 있었다. 빈 문자열은 `main.ts`의 truthy 검사에서 falsy라 `srsSecret`이 전달되지 않고,
   * `IonosphereSmtpBackend`의 `forwardable`이 항상 거짓이 되어 포워딩 주소가 `550 no such user`로
   * 거절됐다. 그런데 **어디에도 그 사실이 드러나지 않았다** — `grep -c`로는 줄이 1개라
   * "설정됨"으로 보이고, 기동 로그도 조용했다. 별칭은 DB에 멀쩡히 있으니 DB를 봐도 정상이다.
   * 증상은 "포워딩이 안 된다"인데 원인은 세 겹 아래에 있었다.
   *
   * 왜 기동을 막지 않는가: 포워딩을 쓰지 않는 배치에서 `forward_to` 행이 하나 남아 있다는 이유로
   * 메일 서버 전체가 뜨지 않으면 그 피해가 더 크다. 이건 **일부 기능의 비활성**이지 설정 오류가
   * 아니다 — 그래서 경고로 둔다(잘못된 값은 기동을 막는 `IONOSPHERE_BLOB_GC`와 성격이 다르다).
   *
   * 조회 실패로 기동을 깨지 않는다: 이 함수의 목적은 진단이고, 진단이 서비스를 멈추면 안 된다.
   */
  private async warnIfForwardingDisabled(log: Logger): Promise<void> {
    if (this.opts.srsSecret !== undefined) return;
    try {
      const { rows } = await this.db.query({
        sql: `SELECT COUNT(*) AS n FROM addresses WHERE forward_to IS NOT NULL AND forward_to <> ''`,
      });
      // PG는 COUNT를 문자열로 준다 — Number()로 좁힌다(다이얼렉트 차이).
      const n = Number(rows[0]?.n ?? 0);
      if (n > 0) {
        log.warn(
          "포워딩 알리아스가 있으나 SRS 비밀키가 없어 **비활성**이다 — 해당 주소 수신은 550 no such user로 거절된다",
          { component: "app", forwardAliases: n, fix: "IONOSPHERE_SRS_SECRET 설정 후 재시작 (openssl rand -base64 32)" },
        );
      }
    } catch (err) {
      log.warn("포워딩 설정 점검 실패(진단 전용 — 서비스에는 영향 없음)", {
        component: "app",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * DB 열기 + 마이그레이션 + 스토어/블롭 준비.
   *
   * DB와 블롭은 **주입 가능**하다. 예전엔 `openSqlite`/`FsBlobStore`를 여기서 직결해서,
   * 여러 서버가 하나의 상태를 공유하는 구성(역할별 서버 분리)으로 갈 배선 자체가 없었다.
   * 조립층은 여전히 `dialect`를 모른다 — 선택은 `openDatabase`(스킴 분기)가 한다.
   */
  private async openStorage(): Promise<void> {
    this.db = this.opts.db ?? (await openDatabase(this.opts.dbUrl ?? this.opts.dbPath));
    // 마이그레이션은 배타 락 아래에서 돈다 — 여러 인스턴스가 동시에 부팅해도 안전하다.
    await migrate(this.db, allMigrations);
    /**
     * 마스터 키를 스토어에도 넘긴다 — **웹훅 엔드포인트 시크릿 봉인에 필요하다**.
     *
     * 이 한 줄이 없으면 `packages/store`의 봉인 코드가 있어도 `plain$` 평문으로 저장된다.
     * DKIM 키(`StoreDkimHook`)·스마트호스트 비밀번호(`StoreSmarthostResolver`)는 조립층이
     * 직접 복호해 스토어를 경유하지 않는데, 웹훅 시크릿은 **스토어가 읽고 쓰는 유일한 비밀**이라
     * 스토어가 키를 들어야 한다. 조건부 스프레드는 `exactOptionalPropertyTypes` 때문이다.
     */
    this.store = new Store(this.db, {
      ...(this.opts.masterKey ? { masterKey: this.opts.masterKey } : {}),
    });
    // POP3 배타 락은 DB 기반 — 인프로세스 Set이면 ① MRA를 2대 띄웠을 때 서로를 못 보고
    // ② 같은 프로세스 안에서도 110·995 백엔드가 각자 락을 갖게 된다.
    // **같은 인스턴스를 두 리스너가 공유**해야 하므로 여기서 한 번만 만든다.
    this.maildropLock = new DbMaildropLock(this.db);
    this.smarthosts = new StoreSmarthostResolver(this.db, this.opts.masterKey);
    const primaryBlobs = this.opts.blobs ?? new FsBlobStore(this.opts.blobRoot);
    // 전환기(FS→공유 스토리지): 읽기는 옛 백엔드로 폴백하고 삭제는 양쪽에서 한다.
    // 폴백 적중을 지표로 세는 건 여기여야 한다 — 레지스트리가 이 클래스 안에 있고,
    // 훅을 지연 평가(this.metrics)해야 setupMetrics 이후에도 붙는다.
    this.blobs = this.opts.blobsFallback
      ? new LayeredBlobStore({
          primary: primaryBlobs,
          fallback: this.opts.blobsFallback,
          onFallbackHit: () => this.metrics?.blobFallbackReads.inc(),
        })
      : primaryBlobs;
  }

  /** 관측성(Phase 5) — 메트릭 포트 지정 시에만 계측. 큐 깊이는 렌더 직전 수집기로 갱신. */
  private setupMetrics(): void {
    if (this.opts.metricsPort === undefined) return;
    this.metrics = createIonosphereMetrics();
    const db = this.db;
    const queueDepth = this.metrics.queueDepth;
    this.metrics.registry.onCollect(async () => {
      const { rows } = await db.query({ sql: `SELECT COUNT(*) AS n FROM mta_queue WHERE status = ${MTA_QUEUE_STATUS.queued}` });
      queueDepth.set(Number(rows[0]?.n ?? 0));
    });
  }

  /**
   * 암시적 TLS(993/465/443) 자료 해석 — certSource(신규) 우선, 없으면 imapsTls/tls(하위호환).
   *
   * ⚠ certSource.resolve()는 타입이 `| null`이지만 구현에 따라 **throw한다**(url=원격+캐시 모두
   * 실패, acme=발급 실패). 잡지 않으면 부팅 자체가 죽어 25번 수신까지 멈춘다. 여기서 잡고
   * 수신은 계속하되, tlsConfigured로 **평문 AUTH는 열지 않는다**(fail closed).
   */
  private async resolveTls(log: Logger): Promise<StartContext> {
    /** 소스 하나를 해석한다 — 실패는 잡아서 null로. 던지면 부팅이 죽어 25번 수신까지 멈춘다. */
    const resolveOne = async (src: CertSource, which: string): Promise<TlsMaterial | null> => {
      try {
        return await src.resolve();
      } catch (err) {
        log.error("TLS 인증서 확보 실패 — 해당 리스너는 TLS 없이 남는다(평문 AUTH는 계속 차단)", {
          component: "app",
          listener: which,
          mode: src.mode,
          error: err instanceof Error ? err.message : String(err),
        });
        return null;
      }
    };

    let implicitTls: TlsMaterial | null = null;
    if (this.opts.certSource) {
      implicitTls = await resolveOne(this.opts.certSource, "default");
    } else {
      implicitTls = this.opts.imapsTls ?? this.opts.tls ?? null;
    }

    /**
     * 리스너별 소스 해석 — **한 소스를 여러 리스너가 지정해도 한 번만 해석한다.**
     * url 소스는 resolve()마다 원격 페치이므로, 리스너 수만큼 부르면 기동 시 같은 요청이
     * 10번 나가고 cert-api 레이트리밋에 걸릴 수 있다.
     */
    const perListener = new Map<TlsListenerName, TlsMaterial | null>();
    if (this.opts.certSources) {
      const bySource = new Map<CertSource, TlsMaterial | null>();
      for (const name of TLS_LISTENER_NAMES) {
        const src = this.opts.certSources[name];
        if (!src) continue;
        if (!bySource.has(src)) bySource.set(src, await resolveOne(src, name));
        perListener.set(name, bySource.get(src) ?? null);
      }
    }

    /**
     * 리스너가 제시할 자료 — 전용 소스가 있으면 그것, 없으면 기본.
     * ★`?? implicitTls`가 아니라 `has()`로 갈라야 한다. 전용 소스를 줬는데 그 확보가 **실패한**
     * 리스너는 null이어야 하고, 기본 인증서로 조용히 폴백하면 안 된다 — 운영자가 이름을 나눈
     * 의도를 뒤집고, 그 포트가 엉뚱한 이름의 인증서를 제시하게 된다.
     */
    const tlsFor = (name: TlsListenerName): TlsMaterial | null =>
      perListener.has(name) ? (perListener.get(name) ?? null) : implicitTls;

    /**
     * "TLS를 **의도**했는가" — 평문 AUTH 허용 판정용. 실제 자료 유무와 구분해야 인증서 확보
     * 실패가 평문 AUTH 개방으로 이어지지 않는다. mode="none"은 명시적 비활성이라 제외.
     * 리스너별 소스만 준 구성(기본 소스 없음)도 "의도했다"로 본다 — 아니면 그 배치에서
     * 평문 AUTH가 열린다.
     */
    const anyListenerSource = Object.values(this.opts.certSources ?? {}).some((s) => s !== undefined && s.mode !== "none");
    const tlsConfigured =
      (this.opts.certSource !== undefined && this.opts.certSource.mode !== "none") ||
      anyListenerSource ||
      this.opts.imapsTls !== undefined ||
      this.opts.tls !== undefined;
    /**
     * STARTTLS 업그레이드 자료 — **런타임 지원이 전제**다. 자료가 있어도 런타임이 서버측
     * 업그레이드를 못 하면 광고만 하고 핸드셰이크에서 멈추므로, 지원 판정을 한 곳에서 한다
     * (25/587과 143/110/4190이 같은 함수를 봐야 한쪽만 낡지 않는다).
     *
     * 리스너별 자료를 쓰므로 `tlsFor(name)`을 통과시킨다 — 전용 소스를 준 포트는 그 인증서로
     * 업그레이드해야 한다.
     */
    const support = startTlsSupport();
    const upgradeTls = (name: TlsListenerName): TlsMaterial | undefined => {
      if (!support.supported) return undefined;
      return tlsFor(name) ?? undefined;
    };

    // 25/587은 **옵트인**이다(smtpStartTls) — 잘못 광고하면 발신 MTA가 멈춰 수신이 조용히 깨진다.
    let starttls: TlsMaterial | undefined;
    if (this.opts.smtpStartTls) {
      if (!support.supported) {
        log.error("STARTTLS 요청됐으나 런타임 미지원 — 비활성(수신 보호)", { component: "app", reason: support.reason });
      } else if (!tlsFor("smtp")) {
        log.warn("STARTTLS 요청됐으나 인증서 없음 — 비활성", { component: "app" });
      } else {
        starttls = upgradeTls("smtp");
        log.info("SMTP STARTTLS 활성", { component: "app", reason: support.reason });
      }
    }
    /**
     * 접근 프로토콜(143 IMAP · 110 POP3 · 4190 ManageSieve)은 옵트인 없이 "자료 + 런타임 지원"만
     * 보면 켠다 — 없으면 평문 AUTH가 fail closed로 막혀 그 포트로는 **로그인이 아예 불가능**하다
     * (감사 L-5). 상대가 대화형 클라이언트라 실패가 즉시 드러나고 메일이 사라지지 않는다.
     */
    let accessStartTls: TlsMaterial | undefined;
    if (!support.supported) {
      if (tlsFor("imap") ?? tlsFor("pop3") ?? tlsFor("manageSieve")) {
        log.warn("접근 프로토콜 STARTTLS 비활성(런타임 미지원) — 143·110·4190은 인증 불가 상태로 남는다", { component: "app", reason: support.reason });
      }
    } else {
      accessStartTls = upgradeTls("imap");
    }
    return {
      log,
      resolver: this.opts.resolver ?? new NodeDnsResolver(),
      implicitTls,
      tlsFor,
      upgradeTls,
      tlsConfigured,
      starttls,
      accessStartTls,
    };
  }

  /**
   * 수신 파이프라인(25 릴레이 · LMTP) 공통 백엔드 옵션 — **한 곳에서만 만든다**.
   * 이전엔 이 6줄이 SMTP용과 LMTP용으로 복제돼 있어, 수신 훅을 하나 추가하면 한쪽만
   * 고쳐서 "25로 들어온 메일엔 적용되는데 LMTP엔 안 되는" 차이가 생기기 쉬웠다.
   */
  private inboundBackendOptions(ctx: StartContext): IonosphereSmtpBackendOptions {
    return {
      resolver: ctx.resolver,
      authservId: this.opts.hostname,
      ...(this.opts.greylist !== undefined ? { greylist: this.opts.greylist } : {}),
      ...(this.opts.dnsblZones !== undefined ? { dnsblZones: this.opts.dnsblZones } : {}),
      ...(this.opts.trustedRelays !== undefined ? { trustedRelays: this.opts.trustedRelays } : {}),
      ...(this.opts.virusScanner ? { virusScanner: this.opts.virusScanner } : {}),
      ...(this.opts.virusScanOptions ? { virusScanOptions: this.opts.virusScanOptions } : {}),
      ...(this.opts.spamScore !== undefined ? { spamScore: this.opts.spamScore } : {}),
      ...(this.metrics ? { onDelivered: (n: number) => this.metrics!.received.inc({}, n) } : {}),
      ...(this.opts.srsSecret
        ? {
            srsSecret: this.opts.srsSecret,
            dkimHook: new StoreDkimHook(this.db, this.opts.masterKey),
            outbound: { relayPerHour: this.opts.relayPerHour ?? DEFAULT_RELAY_PER_HOUR },
          }
        : {}),
    };
  }

  /** 발송 경로(587 · 465) 공통 백엔드 옵션 — 마찬가지로 한 곳에서(레이트리밋 누락 방지). */
  private submissionBackendOptions(): IonosphereSmtpBackendOptions {
    return {
      authFn: this.authFn(),
      // SCRAM도 여기서 넘긴다 — 빠뜨리면 587·465가 SCRAM을 **광고하지 않는다**(라이브에서 그랬다).
      scramFns: this.scramFns(),
      // Received의 `by` 절이 이 값을 쓴다. 넘기지 않으면 기본값 "localhost"가 그대로 헤더로
      // 나가 트레이스가 쓸모없어진다 — 실제로 라이브 메일에 `by localhost`로 찍혔다.
      authservId: this.opts.hostname,
      outbound: this.outboundPolicy(),
      relayConfigured: () => this.anyRelayConfigured(),
    };
  }

  /**
   * 발송 정책(레이트리밋·내부 전용) — **SMTP submission과 JMAP이 같은 값을 써야 한다.**
   * 갈래마다 손으로 재작성하면 한쪽만 빠진다(과거 JMAP만 레이트리밋을 우회했던 원인).
   */
  private outboundPolicy(): OutboundPolicy {
    return {
      ...(this.opts.rateLimit ? { rateLimit: this.opts.rateLimit } : {}),
      ...(this.opts.localOnly ? { localOnly: true } : {}),
      // 기본값은 게이트(@ionosphere/mta)가 갖는다 — 여기서는 **명시적 해제만** 전달한다.
      ...(this.opts.requireSenderOwnership === false ? { requireSenderOwnership: false } : {}),
      /**
       * localOnly의 예외 — 이 발신 도메인으로 나갈 릴레이가 실제로 있으면 외부 발송을 연다.
       * localOnly를 켠 이유가 "정책"이 아니라 "나갈 길이 없음"이었으므로, 길이 생기면
       * 설정을 두 군데 고치지 않아도 열려야 한다.
       */
      hasRelayFor: (tenantId, senderDomain) => this.hasRelayFor(tenantId, senderDomain),
    };
  }

  /** 이 발신자로 나갈 릴레이가 있는가 — 전역 스마트호스트(env)도 능력으로 친다. */
  private async hasRelayFor(tenantId: string, senderDomain: string): Promise<boolean> {
    if (this.opts.smarthost) return true;
    return (await this.smarthosts?.resolve(tenantId, senderDomain)) != null;
  }

  /**
   * 릴레이가 하나라도 있는가(RCPT 조기 거절 억제용).
   * 발신자를 모르는 자리라 정확도를 포기하고 **거절을 덜 하는 쪽**으로 답한다.
   */
  private async anyRelayConfigured(): Promise<boolean> {
    if (this.opts.smarthost) return true;
    const { rows } = await this.db.query({ sql: "SELECT 1 AS x FROM smarthosts LIMIT 1" });
    return rows.length > 0;
  }

  /** 수신: 25 릴레이(AUTH 없음, rcpt 검증 엄격) · POP3 · LMTP(신뢰 로컬 배달). */
  private async startInbound(ctx: StartContext): Promise<void> {
    const maxSizeBytes = this.opts.maxSizeBytes ?? MAX_MESSAGE_BYTES;
    const smtpListener = this.listener("smtp", this.opts.smtpPort);
    if (smtpListener) {
      this.smtp = new SmtpServer({
        authThrottle: this.authThrottle,
        audit: this.audit,
        hostname: this.opts.hostname,
        maxSizeBytes,
        backend: new IonosphereSmtpBackend(this.db, this.store, this.blobs, ctx.log, this.inboundBackendOptions(ctx)),
        // STARTTLS 우선(25 전용 소스 → 기본 소스), 없으면 레거시 전역 tls.
        ...(ctx.starttls ? { tls: ctx.starttls } : this.opts.tls ? { tls: this.opts.tls } : {}),
      });
      this.smtpPort = await this.smtp.listen(smtpListener.port, smtpListener.host);
    }

    // 110 평문 — TLS를 확보했다면 평문 인증을 차단한다(143/587과 같은 정책, RFC 8314 §4.1).
    // POP3는 비밀번호를 그대로 실어 보내므로 TLS 없는 인증은 경로상 노출이다.
    const pop3Listener = this.listener("pop3", this.opts.pop3Port);
    const pop3Stls = ctx.upgradeTls("pop3");
    if (pop3Listener) {
      this.pop3 = new Pop3Server({
        authThrottle: this.authThrottle,
        audit: this.audit,
        hostname: this.opts.hostname,
        backend: new IonospherePop3Backend(this.db, this.store, this.blobs, ctx.log, this.maildropLock),
        allowInsecureAuth: !ctx.tlsConfigured,
        /**
         * ★110에 인증서를 넘기는 것은 암시적 TLS가 아니라 **STLS 업그레이드용**이다(RFC 2595).
         * 없으면 110은 "연결은 되는데 로그인은 영원히 불가능한" 포트가 된다.
         */
        ...(pop3Stls ? { starttls: pop3Stls } : {}),
      });
      this.pop3Port = await this.pop3.listen(pop3Listener.port, pop3Listener.host);
    }

    // 995 암시적 TLS(POP3S) — 995 전용 소스가 있으면 그것, 없으면 기본. 이게 있어야 110 평문 차단이
    // "POP3를 못 쓰게 만드는 것"이 아니라 "안전한 경로로 옮기는 것"이 된다.
    const pop3sListener = this.listener("pop3s", this.opts.pop3sPort);
    const pop3sTls = ctx.tlsFor("pop3s");
    if (pop3sListener && pop3sTls) {
      this.pop3s = new Pop3Server({
        authThrottle: this.authThrottle,
        audit: this.audit,
        hostname: this.opts.hostname,
        backend: new IonospherePop3Backend(this.db, this.store, this.blobs, ctx.log, this.maildropLock),
        tls: pop3sTls,
      });
      this.pop3sPort = await this.pop3s.listen(pop3sListener.port, pop3sListener.host);
    }

    // LMTP — 25 relay와 동일 수신 파이프라인 재사용, 수신자별 응답. 신뢰 로컬 전제.
    const lmtpListener = this.listener("lmtp", this.opts.lmtpPort);
    if (lmtpListener) {
      const delivery = new IonosphereSmtpBackend(this.db, this.store, this.blobs, ctx.log, this.inboundBackendOptions(ctx));
      this.lmtp = new LmtpServer({
        audit: this.audit,
        hostname: this.opts.hostname,
        backend: new IonosphereLmtpBackend(delivery),
        maxSizeBytes,
      });
      this.lmtpPort = await this.lmtp.listen(lmtpListener.port, lmtpListener.host);
    }
  }

  /** 접근(조회): IMAP 143/993 · JMAP · ManageSieve. */
  private async startAccess(ctx: StartContext): Promise<void> {
    const imapListener = this.listener("imap", this.opts.imapPort);
    if (imapListener) {
      const imapBackend = new IonosphereImapBackend(this.db, this.store, this.blobs, ctx.log);
      this.imap = new ImapServer({
        authThrottle: this.authThrottle,
        audit: this.audit,
        hostname: this.opts.hostname,
        backend: imapBackend,
        // 143 평문 AUTH: TLS를 **구성했으면** 차단(LOGINDISABLED 광고 + NO [PRIVACYREQUIRED]).
        // 인증서 확보 실패 시에도 열지 않는다. TLS를 아예 구성하지 않은 dev/테스트만 허용.
        allowInsecureAuth: !ctx.tlsConfigured,
        /**
         * ★143에 인증서를 넘기는 것은 암시적 TLS가 아니라 **STARTTLS 업그레이드용**이다.
         * 이게 없으면 어댑터의 currentTls가 비어 STARTTLS를 광고하지 못하고, 143은
         * "연결은 되는데 로그인은 영원히 불가능한" 포트가 된다(2026-08-02 실측).
         * 런타임이 서버측 업그레이드를 지원할 때만 넘긴다 — 광고해 놓고 실패하는 것이 더 나쁘다.
         */
        ...(ctx.upgradeTls("imap") ? { starttls: ctx.upgradeTls("imap")! } : {}),
      });
      this.imapPort = await this.imap.listen(imapListener.port, imapListener.host);
      const imapsListener = this.listener("imaps", this.opts.imapsPort);
      const imapsTls = ctx.tlsFor("imaps");
      if (imapsListener && imapsTls) {
        this.imaps = new ImapServer({
          authThrottle: this.authThrottle,
          audit: this.audit,
          hostname: this.opts.hostname,
          backend: imapBackend,
          tls: imapsTls,
        });
        this.imapsPort = await this.imaps.listen(imapsListener.port, imapsListener.host);
      }
    }

    // JMAP HTTP (Phase 4) — Session + /jmap/api, Basic 인증
    const jmapListener = this.listener("jmap", this.opts.jmapPort, () =>
      this.plaintextHost(this.opts.httpsFrontPort !== undefined, "jmap", ctx.log),
    );
    if (jmapListener) {
      this.jmap = new JmapServer({
        db: this.db,
        store: this.store,
        blobs: this.blobs,
        hostname: this.opts.hostname,
        logger: ctx.log,
        // 587/465와 **동일한 발송 정책**을 넘긴다 — 손으로 재작성하면 JMAP만 한도를 우회한다.
        outbound: this.outboundPolicy(),
        // 인증 실패 스로틀도 같은 이유로 **공유 인스턴스**를 넘긴다(리스너별 한도 곱하기 방지).
        authThrottle: this.authThrottle,
        audit: this.audit,
        ...(this.opts.jmapBaseUrl ? { externalBaseUrl: this.opts.jmapBaseUrl } : {}),
      });
      // 443 프론트가 있으면 JMAP 평문 포트는 그 upstream이다.
      this.jmapPort = await this.jmap.listen(jmapListener.port, jmapListener.host);
      if (jmapListener.host !== undefined) this.jmapHost = jmapListener.host;
    }

    /**
     * ManageSieve (4190) — Sieve 스크립트 관리. **STARTTLS로 인증 경로를 제공한다**(감사 L-5).
     *
     * L-5의 원래 결함은 "광고와 구현 불일치"였고, 광고만 지웠더니 **인증 경로가 아예 없어졌다** —
     * 평문 AUTH는 fail closed로 막혀 있고 TLS로 갈 방법이 없어 라이브에서 Sieve 관리가 불가능했다.
     * 해법은 광고를 지우는 게 아니라 **구현을 붙이는 것**이다.
     *
     * 왜 993/995/465식 암시적 TLS 포트가 아닌가: RFC 5804는 4190(평문+STARTTLS)만 등록했고
     * ManageSieve의 implicit TLS 포트를 **표준화하지 않았다**. 비표준 포트를 쓰면 Roundcube·
     * Thunderbird 등 기존 클라이언트에 전부 수동 설정을 요구하게 되므로, 표준 경로를 택한다.
     *
     * 런타임 판정은 25/587과 **같은 함수(startTlsSupport)** 를 쓴다 — 갈래마다 손으로 재작성하면
     * 한쪽만 낡는다(과거 JMAP만 레이트리밋을 우회한 것과 같은 종류의 사고). bun ≤1.3.14는
     * 서버측 업그레이드가 완료되지 않으므로(oven-sh/bun#25044) 인증서를 넘기지 않고, 그러면
     * 엔진이 광고도 수락도 하지 않아 4190은 "인증 불가"로 남는다 = fail closed.
     */
    const manageSieveListener = this.listener("manageSieve", this.opts.manageSievePort);
    if (manageSieveListener) {
      this.managesieve = new ManageSieveServer({
        authThrottle: this.authThrottle,
        audit: this.audit,
        hostname: this.opts.hostname,
        backend: new IonosphereManageSieveBackend(this.db, this.store),
        ...(ctx.upgradeTls("manageSieve") ? { tls: ctx.upgradeTls("manageSieve")! } : {}),
        // 143/110/587과 **같은 판정**을 써야 한다. 예전엔 여기만 `!this.opts.tls`라,
        // 운영 표준 경로(IONOSPHERE_TLS_MODE=acme|file|url → certSource만 채우고 opts.tls는 빔)에서
        // 다른 리스너가 전부 평문 AUTH를 막는 동안 4190만 AUTHENTICATE PLAIN을 열어 뒀다.
        // ManageSieve는 TLS 리스너도 STARTTLS도 없어서 그대로 비밀번호가 평문으로 흐른다.
        allowInsecureAuth: !ctx.tlsConfigured,
      });
      this.manageSievePort = await this.managesieve.listen(manageSieveListener.port, manageSieveListener.host);
    }
  }

  /** 발송: 587 submission · 465 암시적 TLS submission · MTA 아웃바운드 워커. */
  private async startSubmission(ctx: StartContext): Promise<void> {
    const maxSizeBytes = this.opts.maxSizeBytes ?? MAX_MESSAGE_BYTES;

    const submissionListener = this.listener("submission", this.opts.submissionPort);
    // 587은 25와 같은 옵트인(smtpStartTls) 아래 있다 — 자료만 587 전용 소스를 먼저 본다.
    const submissionStarttls = this.opts.smtpStartTls ? ctx.upgradeTls("submission") : undefined;
    if (submissionListener) {
      this.submission = new SmtpServer({
        authThrottle: this.authThrottle,
        audit: this.audit,
        hostname: this.opts.hostname,
        maxSizeBytes,
        profile: "submission",
        // 587 평문 AUTH: 143과 동일 정책 — TLS를 구성했으면 차단(인증서 확보 실패 시에도 유지).
        allowInsecureAuth: !ctx.tlsConfigured,
        backend: new IonosphereSmtpBackend(this.db, this.store, this.blobs, ctx.log, this.submissionBackendOptions()),
        // 587도 STARTTLS다 — 25와 같은 옵트인 판정을 쓰되 자료는 587 전용 소스를 먼저 본다.
        ...(submissionStarttls ? { tls: submissionStarttls } : this.opts.tls ? { tls: this.opts.tls } : {}),
      });
      this.submissionPort = await this.submission.listen(submissionListener.port, submissionListener.host);
    }

    // 465: 암시적 TLS submission — iOS/모던 클라이언트 발신(RFC 8314 선호 포트)
    const smtpsListener = this.listener("smtps", this.opts.smtpsPort);
    const smtpsTls = ctx.tlsFor("smtps");
    if (smtpsListener && smtpsTls) {
      this.smtps = new SmtpServer({
        authThrottle: this.authThrottle,
        audit: this.audit,
        hostname: this.opts.hostname,
        maxSizeBytes,
        profile: "submission",
        backend: new IonosphereSmtpBackend(this.db, this.store, this.blobs, ctx.log, this.submissionBackendOptions()),
        tls: smtpsTls,
        implicitTls: true,
      });
      this.smtpsPort = await this.smtps.listen(smtpsListener.port, smtpsListener.host);
    }

    // MTA 워커: submission을 열었거나 명시 요청 시 기동
    if (this.opts.runMtaWorker ?? this.opts.submissionPort !== undefined) {
      this.mta = new MtaWorker({
        db: this.db,
        blobs: this.blobs,
        resolveMx: this.opts.resolveMx ?? defaultResolveMx,
        dkim: new StoreDkimHook(this.db, this.opts.masterKey),
        logger: ctx.log,
        ehloName: this.opts.hostname,
        /**
         * DSN 발송 — 워커가 "무엇을 보낼지"를 정하고 여기서 저장·적재만 한다
         * (`DsnHook` 주석: @ionosphere/mta가 store에 의존하면 의존 방향이 뒤집힌다).
         *
         * ★`system` 선언이 필수 필드로 대체 방어를 요구한다(enqueue.ts SystemRelay):
         *  · `envFrom: "null-sender"` — DSN의 reverse-path는 `<>`여야 한다(RFC 5321 §4.5.5).
         *    이 한 줄이 **이중 바운스를 구조적으로 끊는다** — 이 DSN이 실패해도 그 실패에는
         *    또 DSN이 만들어지지 않는다(워커가 빈 envFrom을 걸러 낸다).
         *  · `relayPerHour` — 귀속 계정이 없는 갈래라 이것이 유일한 상한이다.
         */
        dsn: {
          send: async ({ tenantId, to, message }) => {
            const { blobId, size, generation } = await putBlob(this.db, this.blobs, message);
            await enqueueMessage(this.db, {
              tenantId,
              blobId,
              sizeBytes: size,
              blobGeneration: generation,
              envFrom: "",
              rcpts: [to],
              system: { relayPerHour: this.opts.relayPerHour ?? DEFAULT_RELAY_PER_HOUR, envFrom: "null-sender" },
            });
          },
        },
        ...(this.opts.outboundPort !== undefined ? { port: this.opts.outboundPort } : {}),
        ...(this.opts.smarthost !== undefined ? { smarthost: this.opts.smarthost } : {}),
        // DANE(opt-in) — TLSA를 DNSSEC 검증해 조회한다. 검증 실패는 미적용, 조작 신호는 지연.
        ...(this.opts.dane ? { resolveTlsa: createTlsaLookup({ logger: ctx.log }) } : {}),
        // 테넌트/발신 도메인별 릴레이 — 전역 설정보다 우선(해석 실패는 폴백이 아니라 지연이다)
        smarthostResolver: this.smarthosts!,

        ...(this.opts.mtaIntervalMs !== undefined ? { intervalMs: this.opts.mtaIntervalMs } : {}),
        // abuse 자동 정지 (§8 ④) — 바운스율 임계 초과 시 계정 발송 정지
        abuse: { enabled: true },
        // MTA-STS 발신측 강제(opt-in) — 수신 도메인 정책 enforce 시 TLS·MX 일치 강제
        ...(this.opts.mtaStsEnforce
          ? {
              mtaSts: {
                resolveTxt: (name: string) => ctx.resolver.txt(name),
                httpsGet: fetchMtaStsPolicy,
              },
            }
          : {}),
        ...(this.metrics
          ? {
              onResult: (outcome) => {
                if (outcome === "suspended") this.metrics!.suspended.inc();
                else this.metrics!.delivery.inc({ result: outcome });
              },
            }
          : {}),
      });
      this.mta.start();
    }
  }

  /**
   * 접근 감사 로그 기동 — 싱크(파일 append) + 이관 워커(오브젝트 스토리지).
   *
   * ★`start()`의 **맨 앞**에서 불린다(다른 워커와 달리 `startWorkers`가 아니다). 리스너는 생성
   * 시점에 싱크를 받으므로, 리스너가 만들어진 뒤에 싱크를 만들면 전부 no-op으로 굳는다.
   */
  private startAudit(log: Logger): void {
    const cfg = this.opts.audit;
    if (!cfg) return; // 미설정 = 완전 비활성(this.audit은 noopAuditSink로 남는다)

    this.auditSink = new AuditFileSink({
      dir: cfg.dir,
      logger: log,
      ...(cfg.flushIntervalMs !== undefined ? { flushIntervalMs: cfg.flushIntervalMs } : {}),
      // 표면·결과별 카운터. `onRecord` 훅으로 받는 이유는 blobGc의 `onSweep`과 같다 —
      // 싱크가 @ionosphere/metrics를 알지 않아도 계측이 붙는다(의존성 역전).
      ...(this.metrics
        ? { onRecord: (e) => this.metrics!.auditEvents.inc({ surface: e.surface, outcome: e.outcome }) }
        : {}),
    });
    this.auditSink.start();
    this.audit = this.auditSink;

    this.auditShipper = new AuditShipper({
      dir: cfg.dir,
      // 키 충돌 방지의 근거 값 — 세 인스턴스가 같은 버킷에 쓴다(AppAuditOptions.shipHost 주석).
      host: cfg.shipHost ?? this.opts.hostname,
      logger: log,
      ...(cfg.s3 ? { target: cfg.s3 } : {}),
      ...(cfg.shipIntervalMs !== undefined ? { intervalMs: cfg.shipIntervalMs } : {}),
      ...(cfg.localRetainDays !== undefined ? { localRetainDays: cfg.localRetainDays } : {}),
      ...(this.metrics ? { onShipFailure: () => this.metrics!.auditShipFailures.inc({}) } : {}),
    });
    this.auditShipper.start();

    if (!cfg.s3) {
      // 조용히 두지 않는다 — 이 구성은 보존기간이 지나면 기록을 **버린다**(장기 보존 없음).
      log.warn("접근 감사 로그가 로컬 전용이다 — 보존기간이 지난 파일은 이관 없이 버려진다", {
        component: "audit",
        dir: cfg.dir,
        localRetainDays: cfg.localRetainDays ?? 7,
      });
    }
    log.info("audit log on", { component: "audit", dir: cfg.dir, ship: cfg.s3 ? "s3" : "local-only" });
  }

  /**
   * 배경 워커: 수신 웹훅 배달 · 메일함 삭제 2단계 리퍼 · 블롭 GC.
   * 빈 큐 폴링이 무해해 셋 다 기본 기동한다 — 단 블롭 GC는 기본 수위가 "mark"라
   * 파일을 지우지 않는다(BlobGcMode 주석: 삭제는 되돌릴 수 없어 단계적으로 올린다).
   */
  private startWorkers(log: Logger): void {
    if (this.opts.runWebhookWorker ?? true) {
      this.webhookWorker = new WebhookWorker({
        db: this.db,
        logger: log,
        ...(this.opts.webhookIntervalMs !== undefined ? { intervalMs: this.opts.webhookIntervalMs } : {}),
      });
      this.webhookWorker.start();
    }
    if (this.opts.runReaper ?? true) {
      this.reaper = new MailboxReaper({
        store: this.store,
        logger: log,
        // 폐기된 계정의 maildrop 락 행이 영원히 남지 않게 함께 정리한다.
        maildropLock: this.maildropLock,
        ...(this.opts.reaperIntervalMs !== undefined ? { intervalMs: this.opts.reaperIntervalMs } : {}),
      });
      this.reaper.start();
    }
    const gcMode = this.opts.blobGcMode ?? "mark";
    if (gcMode !== "off") {
      this.blobGc = new BlobGcWorker({
        db: this.db,
        blobs: this.blobs,
        mode: gcMode,
        logger: log,
        ...(this.opts.blobGcIntervalMs !== undefined ? { intervalMs: this.opts.blobGcIntervalMs } : {}),
        ...(this.opts.blobGcGraceMs !== undefined ? { graceMs: this.opts.blobGcGraceMs } : {}),
        ...(this.opts.blobUploadTtlMs !== undefined ? { uploadTtlMs: this.opts.blobUploadTtlMs } : {}),
        ...(this.metrics
          ? {
              onSweep: (r) => {
                this.metrics!.blobsDoomed.inc({}, r.doomed);
                this.metrics!.blobsSwept.inc({}, r.swept);
                this.metrics!.blobBytesFreed.inc({}, r.bytesFreed);
              },
            }
          : {}),
      });
      this.blobGc.start();
    }
  }

  /**
   * 리스너 이름 → 그 리스너 객체. **TLS 재적재의 정본 맵**이다.
   *
   * ★왜 맵으로 두는가: 예전엔 `reloadAllTls`가 리스너를 손으로 나열했고, 새 TLS 리스너를
   * 추가할 때마다 그 목록을 같이 고쳐야 했다. 실제로 **143·110이 빠져 있었다** — 두 서버 모두
   * `reloadTls`를 갖고 있는데 호출되지 않아, 갱신 후 그 두 포트만 만료 인증서를 제시하는
   * 상태였다. 같은 함정을 4190에서 겪고 주석까지 남겼는데 STARTTLS를 143·110에 추가하면서
   * 반복됐다. 이제 `TLS_LISTENER_NAMES`가 정본이고, 이 맵이 그 이름 전부를 요구하므로
   * (`Record<TlsListenerName, …>`) 새 리스너를 넣지 않으면 **컴파일이 실패한다.**
   */
  private tlsListeners(): Record<TlsListenerName, { reloadTls(m: TlsMaterial): Promise<void> } | undefined> {
    return {
      smtp: this.smtp,
      submission: this.submission,
      smtps: this.smtps,
      imap: this.imap,
      imaps: this.imaps,
      pop3: this.pop3,
      pop3s: this.pop3s,
      manageSieve: this.managesieve,
      httpsFront: this.httpsFront,
      // 8443 종단을 걷어내 리스너가 없다. 이름은 인증서 소스로만 남아 있고,
      // 그 자료의 실제 반영은 아래 reloadTlsFor의 443 라우트 갱신이 담당한다.
      adminTls: undefined,
    };
  }

  /**
   * 한 소스의 갱신을 **그 소스를 쓰는 리스너에만** 반영한다.
   *
   * ★전부에 뿌리면 안 된다: 리스너별 인증서를 쓰는 배치에서 한 소스가 갱신될 때 다른 소스를
   * 쓰는 리스너의 컨텍스트를 덮어쓰면, 그 포트가 **엉뚱한 이름의 인증서**를 제시한다. 증상은
   * 갱신 시점에야 나타나고 그때 원인이 갱신이라는 것도 드러나지 않는다.
   *
   * `source`가 undefined면 기본 소스의 갱신이므로 **전용 소스가 없는 리스너 전부**가 대상이다.
   *
   * ★public인 이유: 갱신은 90일에 한 번 일어나 실서비스에서 회귀가 드러나기까지 90일이 걸린다.
   * 테스트가 이 경로를 **그대로** 구동할 수 있어야 "갱신 때만 깨지는" 결함을 앞당겨 잡는다.
   */
  async reloadTlsFor(m: TlsMaterial, source?: CertSource): Promise<void> {
    const listeners = this.tlsListeners();
    for (const name of TLS_LISTENER_NAMES) {
      const own = this.opts.certSources?.[name];
      const mine = source === undefined ? own === undefined : own === source;
      if (!mine) continue;
      // TLS 미구성 리스너에서는 reloadTls가 no-op이라 그냥 불러도 안전하다.
      await listeners[name]?.reloadTls(m);
      /**
       * ★adminTls는 **리스너가 없는 소스**다. 위의 `reloadTls`는 아무것도 하지 않으므로
       * (맵의 값이 undefined) 443 SNI 라우트의 사본을 여기서 갱신하지 않으면 `admin.` 이름만
       * 만료 인증서를 계속 제시한다 — 143·110이 재적재 목록에서 빠져 그 두 포트만 만료
       * 인증서를 제시했던 사고와 같은 부류라 한 자리에 붙여 둔다.
       * (8443 종단이 있던 시절에는 "두 곳에 쓰인다"가 이유였고, 지금은 "유일한 곳"이 여기다.)
       */
      if (name === "adminTls" && this.httpsFront) {
        // admin 이름이 여럿일 수 있다(멀티테넌트·별칭). 전부 갈아끼운다 — 하나라도 빠지면
        // 그 이름만 만료 인증서를 제시한다.
        for (const h of hostsFor(this.opts.serviceHosts, "admin")) this.httpsFront.reloadRouteTls(h, m);
      }
    }
  }

  /**
   * 모든 리스너의 TLS 자료를 한 번에 교체 — 관리 API의 수동 refresh·업로드 경로가 쓴다.
   *
   * ⚠ 리스너별 소스를 쓰는 배치에서 이걸 부르면 전용 인증서가 기본 인증서로 덮인다. 그래서
   * 관리 API 경로도 **기본 소스에 대해서만** 부르고(아래 tlsAdmin), 갱신 감시는 소스별로
   * `reloadTlsFor`를 쓴다.
   */
  private async reloadAllTls(m: TlsMaterial): Promise<void> {
    const listeners = this.tlsListeners();
    for (const name of TLS_LISTENER_NAMES) await listeners[name]?.reloadTls(m);
  }

  /** 관리 REST API용 TLS 어댑터. certSource가 없으면 undefined(→ /v1/tls는 501). */
  private buildTlsAdmin(): TlsAdmin | undefined {
    const certSource = this.opts.certSource;
    if (!certSource) return undefined;
    return {
      status: () => certSource.status(),
      refresh: async () => {
        const m = certSource.refresh ? await certSource.refresh() : await certSource.resolve();
        if (m) await this.reloadAllTls(m);
        return certSource.status();
      },
      // sealed 소스만 write 보유 → 업로드 지원(개인키 masterKey 봉인)
      ...("write" in certSource
        ? {
            upload: async (cert: string, key: string) => {
              const m = await (certSource as SealedCertSource).write(cert, key);
              await this.reloadAllTls(m);
              return certSource.status();
            },
          }
        : {}),
    };
  }

  /**
   * 리스너 하나의 최종 결정(기동 여부·포트·바인딩 주소).
   *
   * 기본 주소를 **함수로** 받는 이유: admin·jmap·autoconfig의 기본값은 "TLS 프론트가 있으면
   * 루프백"이라는 판정이고, 그 판정이 경고 로그를 남긴다. 오버라이드로 주소를 명시한 경우에는
   * 그 판정을 아예 돌리지 않아야 "프론트가 없다"는 경고가 잘못 뜨지 않는다.
   */
  private listener(name: ListenerName, legacyPort: number | undefined, defaultHost?: () => string | undefined): ResolvedListener | undefined {
    const override = this.opts.listeners?.[name];
    const port = override?.port ?? legacyPort;
    if (port === undefined || override?.enabled === false) return undefined;
    if (override?.host !== undefined) return { enabled: true, port, host: override.host };
    return resolveListener(override, port, defaultHost?.());
  }

  /**
   * 평문 HTTP 표면(admin·jmap·autoconfig)의 **기본** 바인딩 주소 — 항상 루프백이다.
   *
   * 앞단(TLS 프론트)이 있으면 그 포트는 정의상 내부 upstream이라 루프백이 맞다.
   * 문제는 **앞단이 없을 때**였다. 예전엔 경고만 남기고 `undefined`(=0.0.0.0, 전 인터페이스)를
   * 돌려줬다. 즉 평문 관리 API·JMAP이 인증서 설정 하나 빠뜨렸다는 이유로 전 세계에 열렸고,
   * 라이브가 안전했던 건 코드가 아니라 `live-activate.sh`가 심는 `IONOSPHERE_LISTEN_*` env 한 줄
   * 덕분이었다. **보안은 fail closed** 규약대로, 판정을 못 하는 쪽이 아니라 안전한 쪽으로 간다.
   *
   * 전면 공개가 필요한 배포는 `IONOSPHERE_LISTEN_ADMIN=0.0.0.0:8080`처럼 **명시**해야 한다.
   * 명시가 있으면 이 함수는 아예 호출되지 않는다(`listener()`가 오버라이드 host를 먼저 본다) —
   * 여는 것은 눈에 보이는 선택이어야 한다는 listeners.ts의 규율과 같은 방향이다.
   *
   * 경고는 남긴다. 기본값이 바뀌었으므로 "열려 있어야 할 표면이 안 열렸다"는 오해가 생길 수
   * 있는데, 그 경우 로그가 원인과 해법을 바로 가리켜야 한다.
   */
  private plaintextHost(frontConfigured: boolean, surface: string, log: Logger): string {
    if (frontConfigured) return LOOPBACK;
    log.warn("앞단(TLS 프론트)이 없어 평문 표면을 루프백에만 연다 — 외부에 열려면 IONOSPHERE_LISTEN_*로 주소를 명시할 것", {
      component: "app",
      surface,
    });
    return LOOPBACK;
  }

  /** 관리·부가 표면: 관리 REST API · 클라이언트 자동설정 · 메트릭 노출 · 443 HTTPS 프론트. */
  private async startManagement(ctx: StartContext): Promise<void> {
    const adminListener = this.listener("admin", this.opts.adminPort, () =>
      // 평문 admin은 **항상** 443 프론트의 upstream이다(admin vhost는 늘 얹힌다).
      this.plaintextHost(this.opts.httpsFrontPort !== undefined, "admin", ctx.log),
    );
    if (adminListener) {
      const tlsAdmin = this.buildTlsAdmin();
      this.admin = new AdminApiServer({
        db: this.db,
        store: this.store,
        resolveTxt: (name) => ctx.resolver.txt(name),
        resolveMx: (name) => ctx.resolver.mx(name),
        logger: ctx.log,
        // JMAP·submission과 **같은 스로틀 인스턴스** — 리스너마다 한도를 따로 갖지 않게.
        authThrottle: this.authThrottle,
        audit: this.audit,
        ...(this.opts.adminRootToken ? { rootToken: this.opts.adminRootToken } : {}),
        ...(this.opts.masterKey ? { masterKey: this.opts.masterKey } : {}),
        ...(tlsAdmin ? { tls: tlsAdmin } : {}),
      });
      // 평문 포트는 443 프론트의 upstream이다 — 공개할 이유가 없어 항상 루프백이다.
      // (토큰 스로틀이 x-forwarded-for를 루프백 상대에게만 신뢰하는 것과도 짝이 맞는다.)
      this.adminPort = await this.admin.listen(adminListener.port, adminListener.host);
      if (adminListener.host !== undefined) this.adminHost = adminListener.host;
    }

    // 클라이언트 자동설정 — 광고 포트는 공개 TLS 포트(993/465 기본)
    const autoconfigListener = this.listener("autoconfig", this.opts.autoconfigPort, () =>
      this.plaintextHost(this.opts.httpsFrontPort !== undefined, "autoconfig", ctx.log),
    );
    if (autoconfigListener) {
      this.autoconfig = new AutoconfigServer({
        settings: {
          mailHost: this.opts.hostname,
          // 역할별 호스트(미지정 시 hostname). 클라이언트에게만 광고되는 값이라 MX와 무관하다.
          ...(this.opts.imapHost ? { imapHost: this.opts.imapHost } : {}),
          ...(this.opts.submissionHost ? { submissionHost: this.opts.submissionHost } : {}),
          // POP3는 호스트를 명시한 경우에만 광고한다(opt-in) — 포트를 연 것과 광고는 다른 결정이다.
          ...(this.opts.pop3Host ? { pop3Host: this.opts.pop3Host, pop3Port: this.opts.pop3sPort ?? POP3S_PORT } : {}),
          imapPort: this.opts.imapsPort ?? IMAPS_PORT,
          submissionPort: this.opts.smtpsPort ?? SMTPS_PORT,
          brandShort: this.opts.autoconfigBrand ?? this.opts.hostname,
          // ★MTA-STS의 mx는 **MX 레코드가 가리키는 호스트**다. imapHost/submissionHost를 나눠도
          // 여기는 따라가면 안 된다 — 틀리면 enforce에서 인바운드가 전부 거부된다.
          ...(this.opts.mtaStsMode
            ? { mtaSts: { mode: this.opts.mtaStsMode, mx: [this.opts.mxHost ?? this.opts.hostname] } }
            : {}),
        },
        logger: ctx.log,
      });
      this.autoconfigPort = await this.autoconfig.listen(autoconfigListener.port, autoconfigListener.host);
      if (autoconfigListener.host !== undefined) this.autoconfigHost = autoconfigListener.host;
    }

    const metricsListener = this.listener("metrics", this.opts.metricsPort, () => this.opts.metricsHost ?? LOOPBACK);
    if (metricsListener && this.metrics) {
      /**
       * ★metrics만 "지정했을 때만 검사"다. 이 포트는 이름이 아니라 **주소로** 긁히기 때문에
       * (`http://10.0.101.12:9090/metrics` → `Host: 10.0.101.12:9090`), 기본값으로
       * 이름 화이트리스트를 강제하면 기존 스크레이프가 조용히 404가 된다. 지표가 끊긴 것을
       * 아무도 모르는 상태가 이 표면의 최악이라, 켜는 쪽이 명시한다(`IONOSPHERE_HOST_METRICS`).
       */
      const metricsHosts = this.opts.serviceHosts?.metrics;
      this.metricsServer = new MetricsServer({
        registry: this.metrics.registry,
        ...(metricsHosts && metricsHosts.length > 0 ? { allowedHosts: metricsHosts } : {}),
        logger: ctx.log,
      });
      // ★metrics는 앞단 유무와 무관하게 항상 루프백이다. 주석이 "내부망/프록시 뒤 스크레이프
      // 전용, 외부 노출 금지"라고 선언해 왔는데 코드가 지키지 않았다 — 선언을 코드로 옮긴다.
      // 원격 스크레이프가 필요하면 IONOSPHERE_METRICS_HOST로 명시 지정한다(눈에 보이는 선택).
      this.metricsPort = await this.metricsServer.listen(metricsListener.port, metricsListener.host);
    }

    // HTTPS 프론트(443 종단) — JMAP/autoconfig 앞단 TLS 종단 + Host 라우팅.
    // 위에서 autoconfig/jmap 포트가 정해진 뒤여야 한다.
    const httpsFrontListener = this.listener("httpsFront", this.opts.httpsFrontPort);
    const httpsFrontTls = ctx.tlsFor("httpsFront");
    if (httpsFrontListener && httpsFrontTls) {
      const routes: HttpsFrontRoute[] = [];
      if (this.autoconfigPort) {
        // ★upstream이 실제로 바인딩된 주소를 함께 넘긴다. 포트만 넘기면 프론트가 127.0.0.1을
        // 가정하는데, IONOSPHERE_LISTEN_AUTOCONFIG로 다른 주소를 지정하면 거기엔 아무도 없어 502다.
        routes.push({
          // 세 서비스가 같은 upstream을 쓴다 — 이름만 다르다(mta-sts./autoconfig./autodiscover.).
          hosts: [
            ...hostsFor(this.opts.serviceHosts, "mtaSts"),
            ...hostsFor(this.opts.serviceHosts, "autoconfig"),
            ...hostsFor(this.opts.serviceHosts, "autodiscover"),
          ],
          port: this.autoconfigPort,
          ...(this.autoconfigHost ? { host: this.autoconfigHost } : {}),
          /**
           * ★반드시 public이다. `mta-sts.`가 여기 들어 있고, MTA-STS 정책은 **발신 MTA가
           * 인터넷에서** 가져간다(RFC 8461 — URL에 포트를 적을 자리도 없다). 내부 전용으로
           * 잘못 두면 정책을 못 받고, `enforce` 상태에서는 **인바운드가 전부 거부**된다.
           * autoconfig·autodiscover도 클라이언트가 밖에서 받아가는 이름이다.
           */
          exposure: ROUTE_EXPOSURE.public,
        });
      }
      /**
       * 관리 콘솔을 443에도 얹는다 — `admin.` 이름으로 오면 관리 upstream(8080)으로 보낸다.
       *
       * ★인증서를 라우트에 **함께** 넘기는 이유: 443의 기본 인증서는 mx/mta-sts/autoconfig가
       * 들어간 것이고 admin은 별개 발급물(cert-api `mailer-admin`, CN=admin.ionosphere.test)이라
       * 한 장으로 둘 다 만족시킬 수 없다. SNI로 갈라야 하고, 이름과 인증서는 반드시 같이
       * 바뀌므로 한 객체에 둔다(HttpsFrontRoute.tls 주석).
       *
       * ⚠ 443 자체는 MTA-STS 정책 배포 때문에 방화벽으로 막을 수 없는 공개 표면이다.
       * 그래서 이 라우트는 `exposure: "internal"`로 **착지한 인터페이스**를 보고 가른다 —
       * 공개 쪽으로 들어온 요청은 프록시 앞에서 404다. 그 위에 토큰 인증이 한 겹 더 있다.
       *
       * `adminPort`가 없으면 라우트를 넣지 않는다. 넣으면 upstream이 없어 502가 되는데,
       * 그건 "관리 콘솔이 켜졌는데 고장난 상태"로 보여 원인 추적을 어렵게 만든다.
       */
      const adminFrontTls = ctx.tlsFor("adminTls");
      const adminHosts = hostsFor(this.opts.serviceHosts, "admin");
      if (this.adminPort && adminFrontTls) {
        routes.push({
          hosts: adminHosts,
          port: this.adminPort,
          ...(this.adminHost ? { host: this.adminHost } : {}),
          tls: adminFrontTls,
          /**
           * ★내부 인터페이스로 들어온 연결만 받는다. 443은 MTA-STS 때문에 방화벽으로 막을 수
           * 없지만, **착지한 로컬 주소**로는 가를 수 있다(https-front.ts).
           *
           * 이름을 내부 IP로만 게시하는 것으로는 부족하다 — 공격자는 공인 IP에 `Host:`를 직접
           * 실어 보내면 그만이다. DNS는 접근 통제가 아니다.
           */
          exposure: ROUTE_EXPOSURE.internal,
        });
        ctx.log.info("관리 콘솔을 443에 얹음 — 내부 인터페이스 전용 + 토큰 인증", {
          hosts: adminHosts.join(","),
        });
      }
      /**
       * JMAP도 **이름을 명시한 라우트**다 — 예전에는 "어디에도 안 걸린 것"이 전부 JMAP으로
       * 흘렀다(기본 upstream). 그래서 아무 Host나 붙여도 응답했고, 우리가 서빙하는 이름
       * 목록이 코드 어디에도 없었다. 지금은 목록에 없으면 404다.
       */
      if (this.jmapPort) {
        routes.push({
          hosts: hostsFor(this.opts.serviceHosts, "jmap"),
          port: this.jmapPort,
          ...(this.jmapHost ? { host: this.jmapHost } : {}),
          // 클라이언트가 인터넷에서 세션을 받아간다(RFC 8620).
          exposure: ROUTE_EXPOSURE.public,
        });
      }
      if (routes.length) {
        this.httpsFront = new HttpsFrontServer({
          tls: httpsFrontTls,
          routes,
          logger: ctx.log,
        });
        this.httpsFrontPort = await this.httpsFront.listen(httpsFrontListener.port, httpsFrontListener.host);

        /**
         * 80 → 443 리다이렉트. **443 프론트가 실제로 뜬 뒤에만** 얹는다 — 보낼 곳이 없는
         * 리다이렉트는 사용자를 연결 거부로 안내하는 것과 같다.
         *
         * ★`routes` 배열을 **그대로** 넘긴다(사본이 아니다). 이름·노출 정책이 한쪽에서만
         * 바뀌면 80이 리다이렉트하는 이름과 443이 받는 이름이 갈리고, 그때 리다이렉트 응답
         * 자체가 "그 이름이 존재한다"를 공개 쪽에 흘린다.
         */
        const redirectListener = this.listener("httpRedirect", this.opts.httpRedirectPort);
        if (redirectListener) {
          this.httpRedirect = new HttpRedirectServer({
            routes,
            logger: ctx.log,
          });
          this.httpRedirectPort = await this.httpRedirect.listen(redirectListener.port, redirectListener.host);
          ctx.log.info("80 → 443 리다이렉트 활성", { port: this.httpRedirectPort });
        }
      }
    }

    /**
     * ★관리 콘솔 전용 TLS 포트(8443)는 **걷어냈다**(2026-08-06).
     *
     * 그 포트의 존재 이유는 하나였다: 443은 MTA-STS 정책 서빙 때문에 방화벽으로 막을 수 없으니,
     * 대역 제한이 가능한 별도 포트가 필요하다는 것. 그 전제가 `exposure`로 사라졌다 —
     * 이제 443에서도 **착지한 인터페이스**로 이름별 통제가 되므로(https-front.ts) 같은 통제를
     * 포트 하나로 얻는다. TLS 종단·인증서 재적재 경로·방화벽 규칙이 각각 둘에서 하나로 줄었다.
     *
     * 실측이 그 전제를 확인해 줬다: 8443은 라이브 3대 중 **node-01에서만 닿았고**(나머지 둘은
     * 중앙 방화벽 허용 목록에 없었다) 리스너만 떠 있는 상태였다. 반면 443 admin vhost는
     * 세 대 전부에서 200이다. 포트를 늘리는 것이 통제를 늘리지 않는다는 증거다.
     */
  }

  /** 인증서 갱신 감시 — 새 자료를 받으면 993/465/443을 무중단 교체(bun은 리스너 재생성). */
  private watchCertRenewal(log: Logger): void {
    /**
     * ★감시는 **소스마다** 걸고, 각 소스의 갱신은 **그 소스를 쓰는 리스너에만** 반영한다.
     *
     * 기본 소스만 감시하면 리스너별 소스는 갱신이 반영되지 않아 그 포트가 만료 인증서를
     * 제시한다(증상이 갱신 90일 뒤에 나타나는 종류다). 반대로 아무 소스의 갱신이든 전부에
     * 뿌리면 다른 소스를 쓰는 포트가 엉뚱한 이름의 인증서를 제시한다. 둘 다 갱신 시점에야
     * 드러나므로 여기서 범위를 정확히 맞춘다.
     *
     * 같은 소스를 여러 리스너가 공유해도 감시는 **한 번만** 건다(중복 재적재 방지).
     */
    const unsubs: Array<() => void> = [];
    const arm = (src: CertSource, label: string, scoped?: CertSource): void => {
      if (!src.watch) return;
      unsubs.push(
        src.watch((m) => {
          void this.reloadTlsFor(m, scoped)
            .then(() => log.info("tls cert reloaded", { source: label }))
            .catch((e) => log.warn("tls reload failed", { source: label, error: e instanceof Error ? e.message : String(e) }));
        }),
      );
    };

    if (this.opts.certSource) arm(this.opts.certSource, "default");
    const armed = new Set<CertSource>();
    for (const name of TLS_LISTENER_NAMES) {
      const src = this.opts.certSources?.[name];
      if (!src || armed.has(src)) continue;
      armed.add(src);
      arm(src, name, src);
    }
    if (unsubs.length) this.certWatchUnsub = () => unsubs.forEach((u) => u());
  }

  async stop(): Promise<void> {
    if (this.mta) await this.mta.stop();
    if (this.webhookWorker) await this.webhookWorker.stop();
    if (this.certWatchUnsub) this.certWatchUnsub();
    this.opts.certSource?.close?.();
    // 리스너별 소스도 닫는다 — url 소스는 6시간 재페치 타이머를 들고 있어, 안 닫으면 프로세스가
    // 종료되지 않는다(테스트가 매달리고, 재시작이 SIGKILL로 끝난다). 같은 소스를 공유하는
    // 리스너가 여럿이면 close가 여러 번 불릴 수 있으므로 한 번만 부른다.
    const closed = new Set<CertSource>();
    for (const name of TLS_LISTENER_NAMES) {
      const src = this.opts.certSources?.[name];
      if (!src || closed.has(src)) continue;
      closed.add(src);
      src.close?.();
    }
    if (this.reaper) await this.reaper.stop();
    if (this.blobGc) await this.blobGc.stop();
    if (this.lmtp) await this.lmtp.close();
    if (this.httpRedirect) await this.httpRedirect.close();
    if (this.httpsFront) await this.httpsFront.close();
    if (this.metricsServer) await this.metricsServer.close();
    if (this.autoconfig) await this.autoconfig.close();
    if (this.admin) await this.admin.close();
    if (this.jmap) await this.jmap.close();
    if (this.managesieve) await this.managesieve.close();
    if (this.smtps) await this.smtps.close();
    if (this.submission) await this.submission.close();
    if (this.imaps) await this.imaps.close();
    if (this.imap) await this.imap.close();
    if (this.smtp) await this.smtp.close();
    if (this.pop3s) await this.pop3s.close();
    if (this.pop3) await this.pop3.close();
    /**
     * ★감사 싱크는 **리스너를 모두 닫은 뒤에** 멈춘다. 순서가 뒤집히면 아직 살아 있는 세션이
     * 마지막 flush 이후에 `record()`를 불러 그 이벤트가 그대로 사라진다 — 종료 직전은 배포
     * 재시작 구간이라 하루에 여러 번 지나가는 자리다. `stop()`이 남은 버퍼를 flush한다.
     */
    if (this.auditShipper) await this.auditShipper.stop();
    if (this.auditSink) await this.auditSink.stop();
    await this.db.close();
    (this.opts.logger ?? noopLogger).info("stopped", { component: "app" });
  }

  /**
   * dev/테스트 부트스트랩: 검증된 소유 도메인 + 계정 + 비밀번호 생성 (계정은 신규 전용).
   *
   * 도메인까지 만드는 이유: 수신 라우팅은 **검증된 소유 도메인**만 인정하므로(backend.ts
   * resolveRoute의 d.status=1), 계정만 만들면 로그인은 되는데 메일은 안 오는 반쪽 상태가 된다.
   * 같은 도메인의 두 번째 사용자는 **같은 테넌트**에 붙는다 — 테넌트가 도메인을 소유하는
   * 계층(서비스 → 테넌트 → 도메인 → 주소)이라 사용자마다 테넌트가 갈리면 안 된다.
   */
  async createUser(email: string, password: string): Promise<{ accountId: string }> {
    const normalized = email.toLowerCase();
    const tenantId = await this.ensureVerifiedDomain(normalized.slice(normalized.lastIndexOf("@") + 1));
    const { accountId } = await this.store.createAccount({ tenantId, email: normalized });
    await createCredential(this.db, { accountId, password });
    return { accountId };
  }

  /**
   * 이름으로 검증된 도메인을 찾고, 없으면 소유 테넌트와 함께 만든다.
   * status=1 + domain_name_claims 앵커를 한 배치로 — CLI add-domain의 preVerified와 같은 형태다
   * (dev/테스트 부트스트랩이라 DNS 검증은 건너뛴다).
   */
  private async ensureVerifiedDomain(name: string): Promise<string> {
    const { rows } = await this.db.query({
      sql: "SELECT tenant_id FROM domains WHERE name = ? AND status = 1",
      params: [name],
    });
    const existing = rows[0];
    if (existing) return String(existing.tenant_id);

    const { tenantId } = await this.store.createTenant("default");
    const domainId = ulid();
    const now = Date.now();
    await this.db.batch([
      {
        sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, ?, 1, ?, ?)",
        params: [domainId, tenantId, name, now, now],
      },
      { sql: "INSERT INTO domain_name_claims (name, domain_id) VALUES (?, ?)", params: [name, domainId] },
    ]);
    return tenantId;
  }
}

/**
 * MTA-STS 정책 페치 (RFC 8461 §3.3) — 발신측 강제 경로가 상대 도메인에서 정책 파일을 받는다.
 *
 * ★**리다이렉트를 따라가지 않는다.** RFC 8461 §3.3이 "HTTP 응답은 리다이렉트여서는 안 되고,
 * 리다이렉트는 따르지 않아야 한다"고 못박은 이유가 그대로 우리 위협 모델이다 — 정책의 신뢰
 * 근거는 "`mta-sts.<도메인>`의 유효한 인증서로 받았다"는 사실 하나뿐인데, 리다이렉트를 따르면
 * 그 근거가 **상대가 지정한 아무 호스트**로 옮겨간다. `http://`로 한 단계만 내려보내면 TLS
 * 검증이 사라지고(다운그레이드), 사설 대역으로 보내면 이 프로세스가 내부망을 대신 두드린다(SSRF).
 * 리다이렉트하는 도메인의 정책은 **못 받은 것으로 친다** — 정책 부재는 fail open이 아니라
 * mta-sts 층에서 "강제 없음"으로 처리되므로 배달은 종전대로 진행된다.
 *
 * 스킴을 다시 확인하는 이유: URL은 호출부(`packages/mta-sts`)가 만들지만, 그쪽이 바뀌어도
 * 평문 페치가 조용히 성립하면 안 된다. 신뢰 근거를 쓰는 자리에서 스스로 확인한다.
 */
export async function fetchMtaStsPolicy(url: string): Promise<string> {
  if (!url.startsWith("https://")) throw new Error(`mta-sts: https가 아닌 URL 거부 — ${url}`);
  const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(MTA_STS_FETCH_TIMEOUT_MS) });
  // `redirect: "manual"`의 표현이 런타임마다 갈린다(3xx 그대로 / status 0의 opaqueredirect).
  // 둘 다 "따라가지 않았다"는 뜻이므로 양쪽을 함께 막는다.
  if (res.type === "opaqueredirect" || res.status === 0 || (res.status >= 300 && res.status < 400)) {
    throw new Error(`mta-sts: 리다이렉트는 따르지 않는다(RFC 8461 §3.3) — ${res.status}`);
  }
  if (!res.ok) throw new Error(`mta-sts fetch ${res.status}`);
  return await readCapped(res, MTA_STS_MAX_POLICY_BYTES);
}

/**
 * 응답 본문을 상한까지만 읽는다. 넘으면 던지고 스트림을 끊는다.
 *
 * `Content-Length`를 보고 판단하지 않는 이유: 헤더는 없을 수도 있고(chunked) 본문과 다를 수도
 * 있다. 상한은 **실제로 흘러들어온 바이트**에 걸어야 의미가 있다.
 */
async function readCapped(res: Response, maxBytes: number): Promise<string> {
  const body = res.body;
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) throw new Error(`응답 본문이 상한(${maxBytes}B)을 넘었다`);
      chunks.push(value);
    }
  } finally {
    // 상한 초과로 빠져나갈 때 남은 바이트를 계속 받지 않도록 반드시 끊는다.
    await reader.cancel().catch(() => {});
  }
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    buf.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(buf);
}

/**
 * 기본 MX 리졸버 (node:dns). Phase 3의 자체 재귀 리졸버로 교체 예정 (PLAN.md).
 * MX 없으면 RFC 5321 §5.1에 따라 도메인 자체를 우선순위 0으로 폴백.
 */
async function defaultResolveMx(domain: string): Promise<MxRecord[]> {
  const { resolveMx } = await import("node:dns/promises");
  try {
    const records = await resolveMx(domain);
    if (records.length > 0) {
      return records.map((r) => ({ exchange: r.exchange, priority: r.priority }));
    }
  } catch (err) {
    /**
     * ★"MX 없음"일 때만 A 폴백이다(RFC 5321 §5.1). 예전엔 **모든 예외**를 폴백으로 삼아,
     * SERVFAIL·타임아웃 같은 **일시 오류에도 도메인 자체 A로 발송을 시도**했다 — 그 A가
     * 웹서버면 메일이 엉뚱한 호스트로 가거나 조용히 사라진다. 일시 오류는 던져서 워커가
     * deferAll로 재시도하게 두는 것이 맞다.
     */
    const code = (err as { code?: string }).code;
    if (code !== "ENOTFOUND" && code !== "ENODATA") throw err;
  }
  return [{ exchange: domain, priority: 0 }];
}
