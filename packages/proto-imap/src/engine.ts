/**
 * IMAP 순수 상태머신 — 소켓 I/O 없음 (PLAN.md §4, proto-pop3/engine.ts와 동일 패턴).
 *
 * 상태: not-authenticated → authenticated → selected → (LOGOUT) 종료.
 * 내부 시맨틱은 IMAP4rev2(RFC 9051)로 짜고 rev1 호환 응답을 방출한다(PROTOCOLS §2 전략).
 * 비동기 백엔드 호출은 액션으로 방출 + `xxxResult()` 재개 — 그동안 도착한 명령은
 * 논리 라인 단위로 버퍼링만 된다(파이프라이닝 안전).
 *
 * 이 증분의 명령 표면: CAPABILITY, NOOP, LOGOUT, LOGIN, AUTHENTICATE PLAIN(SASL-IR/
 * continuation/`*` 취소), ID, ENABLE. 메일함 명령(SELECT/FETCH/...)은 다음 증분.
 */
import {
  MAX_MESSAGE_BYTES,
  MAX_PREAUTH_LITERAL_BYTES,
  MAX_QUEUED_LINE_BYTES,
  decodeSaslBase64,
  parseSaslOAuth,
  parseSaslPlain,
  ScramServerSession,
  type ScramStep,
  type ScramStoredKeys,
} from "@ionosphere/core";
import { ImapLineReader, type LinePart, type ReaderEvent } from "./reader.ts";
import { ImapParseError, parseCommand, valueText, type ImapValue, type ParsedCommand } from "./parser.ts";
import { formatUidSet, matchSequenceSet, parseSequenceSet, type SeqRange } from "./sequence-set.ts";
import { evaluateSearch, parseSearchProgram, searchNeedsRaw } from "./search-criteria.ts";
import { parseFetchItems, type FetchItem } from "./fetch-items.ts";
import { formatSortLine, formatThreadLine, parseSortSpec, type ImapSortKeys, type SortSpec } from "./sort-thread.ts";
import {
  binaryLiteralWire,
  extractBinary,
  extractSection,
  formatBodyStructure,
  formatEnvelope,
  formatInternalDate,
  literalWire,
  parseImapDateTime,
  wireToBytes,
} from "./fetch-format.ts";
import {
  compileListPattern,
  HIERARCHY_DELIMITER,
  joinListPattern,
  normalizeMailboxName,
  quoteMailboxName,
  roleToAttribute,
} from "./list-match.ts";

export type ImapState = "not-authenticated" | "authenticated" | "selected";

/** 백엔드가 돌려주는 메일함 한 개 — name은 구분자 `/`의 전체 경로(UTF-8). */
export interface ImapMailbox {
  name: string;
  role: string | null;
  /** SUBSCRIBE 상태 — LSUB 필터용. 생략 시 구독으로 취급(하위 호환). */
  subscribed?: boolean;
  uidvalidity: number;
  uidnext: number;
  highestmodseq: number;
  totalCount: number;
  unreadCount: number;
  totalBytes: number;
  /**
   * OBJECTID(RFC 8474)의 `MAILBOXID` — 이름·UIDVALIDITY와 무관한 **불변 id**다.
   * 메일함 이름을 바꿔도 같은 값이라, 클라이언트가 "이름이 바뀐 것"과 "지우고 새로 만든 것"을
   * 구분할 수 있다(그 구분이 없으면 캐시를 통째로 버린다).
   */
  mailboxId?: string;
}

/** 엔진 → 어댑터 백엔드 요청. 이름은 정규화(INBOX 케이스) 완료 상태로 전달된다. */
export type ImapBackendRequest =
  | { kind: "listMailboxes" }
  /** QUOTA (RFC 9208) — 계정 단위 사용량·한도. */
  | { kind: "getQuota" }
  | { kind: "createMailbox"; name: string }
  | { kind: "deleteMailbox"; name: string }
  | { kind: "renameMailbox"; from: string; to: string }
  | { kind: "getAcl"; name: string }
  | { kind: "setAcl"; name: string; identifier: string; rights: string }
  | { kind: "deleteAcl"; name: string; identifier: string }
  | { kind: "listRights"; name: string; identifier: string }
  | { kind: "myRights"; name: string }
  /** SUBSCRIBE/UNSUBSCRIBE 영속화 (RFC 9051 §6.3.7/6.3.8). */
  | { kind: "setSubscribed"; name: string; subscribed: boolean }
  | { kind: "selectMailbox"; name: string }
  /** CLOSE — \Deleted 메시지 영구 삭제(응답 불요, ok/no만). */
  | { kind: "expungeMailbox"; name: string }
  /**
   * FETCH — uids의 메시지 데이터. needRaw면 raw 바이트 포함,
   * markSeen이면 백엔드가 \Seen을 먼저 설정한 뒤 갱신된 flags를 돌려준다(계약).
   */
  | { kind: "fetchMessages"; name: string; uids: readonly number[]; needRaw: boolean; markSeen: boolean; needSortKeys?: boolean }
  /**
   * STORE — 플래그 갱신 후 갱신된 flags를 flagsUpdated로 돌려준다(계약).
   * unchangedSince 지정 시 modseq > 값인 메시지는 건너뛰고 failed에 보고(RFC 7162).
   */
  | { kind: "storeFlags"; name: string; uids: readonly number[]; mode: "set" | "add" | "remove"; flags: readonly string[]; unchangedSince?: number }
  /** QRESYNC — sinceModseq 이후 삭제(uid 툼스톤)·변경(flags) 델타. */
  | {
      kind: "syncSince";
      name: string;
      sinceModseq: number;
      /**
       * QRESYNC 세 번째 인자의 known-uids (RFC 7162 §3.2.5). 클라이언트가 "내가 아는 uid는
       * 이것들"이라고 알려 주는 값이다.
       *
       * ★백엔드가 툼스톤 보존창 **밖**의 요청을 받았을 때 이 값이 답을 가능하게 한다:
       * 여기서 현재 존재하는 uid를 빼면 사라진 uid가 정확히 나온다(§3.2.5.2). 없으면
       * 백엔드가 `1:uidnext-1`로 간주한다 — RFC가 정한 기본값이다.
       */
      knownUids?: readonly SeqRange[];
    }
  /** EXPUNGE — \Deleted 영구 삭제. uids 지정 시 그 UID들만(UIDPLUS UID EXPUNGE). */
  | { kind: "expunge"; name: string; uids: readonly number[] | null }
  /** APPEND — internalDateMs null이면 현재 시각(백엔드 결정). */
    /**
   * APPEND. `items`가 있으면 MULTIAPPEND(RFC 3502)이고 **전부 아니면 전무**로 처리해야 한다
   * (§3). 단일 APPEND는 `items` 하나짜리와 같다 — 백엔드가 갈래를 나누지 않게 항상 채운다.
   */
  | {
      kind: "appendMessage";
      name: string;
      flags: readonly string[];
      internalDateMs: number | null;
      raw: Uint8Array;
      items?: readonly { raw: Uint8Array; flags: readonly string[]; internalDateMs?: number }[];
    }
  /**
   * REPLACE (RFC 8508) — 새 메시지를 넣고 **그다음에** 옛 메시지를 지운다.
   *
   * ★순서가 안전성의 전부다. 반대로 하면 넣기가 실패했을 때 **메일이 사라진다**.
   * 이 순서면 최악이 사본 하나가 남는 것이고, 그건 사용자가 지울 수 있다.
   */
  | {
      kind: "replaceMessage";
      /** 옛 메시지가 있는 메일함(선택 중인 것). */
      from: string;
      /** 새 메시지를 넣을 메일함 — 같을 수도 다를 수도 있다. */
      to: string;
      oldUid: number;
      raw: Uint8Array;
      flags: readonly string[];
      internalDateMs: number | null;
    }
  | { kind: "copyMessages"; from: string; to: string; uids: readonly number[] }
  /** MOVE — 원자적 이동(RFC 6851). 응답은 copied 재사용(원본 제거는 엔진이 EXPUNGE 방출). */
  | { kind: "moveMessages"; from: string; to: string; uids: readonly number[] };

/** fetchMessages 응답의 메시지 한 건. */
export type { ImapSortKeys } from "./sort-thread.ts";

export interface ImapFetchData {
  uid: number;
  /**
   * OBJECTID(RFC 8474)의 `EMAILID` — **UID가 아니라** 메시지 자체의 불변 id다.
   * COPY하면 UID는 새로 붙지만 이건 사본의 새 id다(사본은 다른 메시지이므로).
   */
  emailId?: string;
  /** OBJECTID의 `THREADID` — 같은 스레드면 같은 값. 없으면 NIL. */
  threadId?: string;
  flags: readonly string[];
  /**
   * INTERNALDATE — **메시지가 서버에 도착한 시각**이다.
   *
   * ★`SAVEDATE`(이 메일함에 들어온 시각)와 다르다. COPY한 사본은 원본의 INTERNALDATE를
   * 물려받고(RFC 9051 §6.4.7) SAVEDATE만 새로 찍힌다 — 예전엔 둘을 같은 값(savedate)으로
   * 실어 보내서 COPY가 INTERNALDATE를 바꿨다.
   */
  internalDateMs: number;
  /** SAVEDATE (RFC 8514) — 이 메일함에 들어온 시각. */
  saveDateMs?: number;
  size: number;
  /** CONDSTORE — 메시지 최종 modseq(messages.modseq 물질화). */
  modseq: number;
  /** needRaw 요청 시에만. */
  raw?: Uint8Array;
  /**
   * SORT/THREAD(RFC 5256)용 키 — `needSortKeys` 요청 시에만.
   *
   * ★원문을 파싱해서 뽑지 않는다. 스토어가 이미 물질화해 둔 값들이라(`subject_base`·
   * `sent_at`·`thread_id`·`message_addresses`) 정렬 한 번에 메일함 전체 블롭을 메모리에
   * 올릴 이유가 없다 — SEARCH가 예전에 그렇게 해서 5만 통 × 50KB = 2.5GB였다.
   */
  sortKeys?: ImapSortKeys;
}



export type ImapBackendResponse =
  | { kind: "mailboxes"; mailboxes: readonly ImapMailbox[] }
  /**
   * SELECT 스냅샷 — uids는 오름차순(세션 seq번호 = 배열 인덱스+1).
   * keywords: 메일함에 현존하는 비시스템 키워드(IMAP 표기) — `* FLAGS` 공지용(imaptest 요구).
   */
  | { kind: "selected"; mailbox: ImapMailbox; uids: readonly number[]; firstUnseenSeq: number | null; keywords?: readonly string[] }
  | { kind: "messages"; messages: readonly ImapFetchData[] }
  | { kind: "flagsUpdated"; updated: readonly { uid: number; flags: readonly string[]; modseq?: number }[]; failed?: readonly number[] }
  /** syncSince 응답 — QRESYNC SELECT 파라미터 처리용. */
  | { kind: "sync"; vanished: readonly number[]; changed: readonly { uid: number; flags: readonly string[]; modseq: number }[] }
  /** 실제 삭제된 UID 목록(오름차순 무관 — 엔진이 정렬). */
  | { kind: "expunged"; uids: readonly number[] }
  /** APPEND 결과 — APPENDUID 응답 코드용(UIDPLUS). */
  /** APPENDUID — MULTIAPPEND면 `uids`가 전부이고 `uid`는 그 첫 번째다(단일 경로 호환). */
  | { kind: "appended"; uidvalidity: number; uid: number; uids?: readonly number[] }
  /** COPY/MOVE 결과 — COPYUID용. srcUids[i] ↔ dstUids[i] 대응. */
  /** REPLACE 결과 — 새 uid와, 실제로 지워진 옛 uid(못 지웠으면 null). */
  | { kind: "replaced"; uidvalidity: number; uid: number; expungedUid: number | null }
  | { kind: "copied"; uidvalidity: number; srcUids: readonly number[]; dstUids: readonly number[] }
  | { kind: "acl"; mailbox: string; entries: readonly { identifier: string; rights: string }[] }
  | { kind: "rights"; mailbox: string; identifier: string; rights: string }
  /**
   * 쿼터 현황. `limitBytes === 0`이면 무제한 — 그때는 `* QUOTA`에 STORAGE 항목을 싣지 않는다
   * (RFC 9208은 "한도 없음"을 표현하는 값을 정의하지 않는다. 0을 실으면 "0바이트 허용"으로
   * 읽혀 클라이언트가 업로드를 막는다).
   */
  | { kind: "quota"; usedBytes: number; limitBytes: number; messageCount: number }
  | { kind: "ok" }
  /** code는 RFC 5530 응답 코드(ALREADYEXISTS/NONEXISTENT 등). */
  | { kind: "no"; code?: string; message: string };

/** selected 상태의 세션 뷰 — seq↔UID 맵은 세션 로컬(EXPUNGE 반영 전까지 고정). */
interface SelectedView {
  name: string;
  readWrite: boolean;
  uidvalidity: number;
  uids: number[];
  /** `* FLAGS`로 공지된 키워드 집합(시스템 플래그 제외) — 미공지 키워드 사용 전 재공지. */
  announcedKeywords: Set<string>;
  /** NOOP/CHECK 플래그 재동기화 워터마크 — 이 modseq 이후 변경만 델타 방출. */
  lastSyncModseq: number;
}

const SYSTEM_FLAGS = ["\\Answered", "\\Flagged", "\\Deleted", "\\Seen", "\\Draft"] as const;

/**
 * 한 번의 백엔드 왕복에 실을 메시지 수 — **원문(raw)이 필요할 때**.
 *
 * ★왜 필요한가(2026-08-23 검수): `UID FETCH 1:* BODY[]`와 `SEARCH BODY "x"`가 메일함 **전체**
 * uid를 한 요청에 실었고, 백엔드가 그만큼의 블롭을 전부 메모리에 올렸다. 5만 통 × 평균 50KB면
 * 한 배열에 2.5GB다. 전 프로토콜이 단일 프로세스라 그 순간 서비스 전체가 위태로워진다.
 *
 * 32인 이유: 원문 크기 상한이 25MB(`MAX_MESSAGE_BYTES`)라 최악은 여전히 크지만, 실사용
 * 메시지는 수십 KB라 32면 왕복 비용을 흡수하면서 상주 메모리를 수 MB로 묶는다.
 *
 * ⚠ 진짜 경계는 **개수가 아니라 바이트**다. 다만 엔진은 가져오기 전에는 크기를 모르고
 * (`size`는 fetch 결과에 들어 있다), 크기를 먼저 묻는 왕복을 더하면 그것대로 비용이다.
 * 개수 상한은 그 근사이고, 무한(5만)에서 32로 줄이는 것이 이 값의 목적이다.
 */
const FETCH_BATCH_RAW = 32;

/**
 * 원문이 필요 없을 때(FLAGS·UID·INTERNALDATE 등)의 배치 크기.
 *
 * 메타데이터만이라 행당 수십 바이트다. 그래도 상한을 두는 이유는 `IN (?)` 파라미터
 * 한도(`store/chunk.ts`, D1 100개)와 응답 조립 배열 때문이다 — 저장소가 청크로 나눠 돌더라도
 * 결과 배열은 한 번에 다 올라온다.
 */
const FETCH_BATCH_META = 512;

/** 논리 라인 하나가 붙들고 있는 바이트 — 큐 상한 계산용(텍스트는 latin1이라 1문자=1바이트). */
function lineBytes(parts: readonly LinePart[]): number {
  let n = 0;
  for (const p of parts) n += p.kind === "text" ? p.text.length : p.bytes.length;
  return n;
}

function flagsLine(keywords: Iterable<string>): string {
  const kw = [...keywords];
  return `* FLAGS (${[...SYSTEM_FLAGS, ...kw].join(" ")})`;
}

export type ImapAction =
  | { kind: "reply"; text: string }
  /** FETCH 등 리터럴 포함 응답 — CRLF까지 포함된 완성 바이트. */
  | { kind: "replyBinary"; bytes: Uint8Array }
  | { kind: "close" }
  /** 어댑터가 소켓을 TLS로 승격하고 `tlsEstablished()`로 알린다(RFC 3501 §6.2.1). */
  | { kind: "startTls" }
  /**
   * COMPRESS=DEFLATE (RFC 4978) — **이 액션 다음부터** 양방향이 압축된다.
   * 태그 OK는 이 액션 **앞에** 놓여 평문으로 나가야 한다(STARTTLS와 같은 규율).
   */
  | { kind: "startCompress" }
  | { kind: "auth"; user: string; pass: string }
  /** SCRAM 교환 중 — 저장된 키를 찾아 `scramKeysResult()`로 돌려준다. */
  | { kind: "scramKeys"; user: string }
  /** SCRAM 증명 통과 — 어댑터가 계정 상태를 보고 `authResult()`로 재개한다(비밀번호 없음). */
  | { kind: "authVerified"; tag: string; user: string }
  /**
   * SCRAM 교환이 엔진 안에서 실패했다 — **어댑터가 기록해야 한다는 통보**다. 응답은 엔진이
   * 이미 냈으므로 어댑터는 재개하지 않는다(`authResult()`를 부르면 안 된다).
   *
   * ★왜 별도 액션인가: SCRAM 증명 검증은 순수 계산이라 백엔드 왕복이 없다. 그래서 실패가
   * `authVerified`도 `auth`도 거치지 않고 reply만 내고 끝났고, 어댑터의 스로틀·감사가 실행되지
   * 않았다 — SCRAM으로는 무제한 대입이 무기록으로 가능했다. `authVerified`를 재사용하면
   * 실패가 성공 경로를 타므로 절대 안 된다.
   */
  | { kind: "authFailed"; user?: string; mechanism: string }
  | { kind: "backend"; req: ImapBackendRequest };

export type ImapAuthResult = { accountId: string } | null;

export interface ImapEngineOptions {
  hostname: string;
  /**
   * TLS 회선 여부 — 어댑터가 전달. 평문에서는 LOGINDISABLED를 광고하고 LOGIN/AUTH를
   * 거부한다(RFC 9051 §7.2.1). dev/테스트는 allowInsecureAuth로 완화.
   */
  secure?: boolean;
  allowInsecureAuth?: boolean;
  /**
   * STARTTLS를 광고·수락할 수 있는가 — 어댑터가 인증서를 들고 있을 때만 true.
   * 없는 기능을 광고하면 클라이언트는 그것을 시도하고 실패한 뒤 **자격증명이 틀렸다고
   * 오해**한다(ManageSieve에서 겪은 것과 같은 함정).
   */
  tlsAvailable?: boolean;
  /** SCRAM 광고 여부 — 어댑터가 백엔드의 키 조회·승인 존재로 판단해 넘긴다. */
  scramOffered?: boolean;
  /**
   * SCRAM 가짜 salt 유도용 비밀 — **서버 전체가 같은 값**이어야 한다.
   * 연결마다 다르면 같은 사용자명의 가짜 salt가 매번 바뀌어 계정 열거가 다시 열린다.
   */
  scramDecoySecret?: Buffer;
  /** 리더 한도 오버라이드(테스트용). */
  maxLineBytes?: number;
  maxLiteralBytes?: number;
}

/** AUTHENTICATE 진행 상태 — continuation으로 SASL 데이터 라인을 기다리는 중. */
interface SaslPending {
  tag: string;
  mechanism: "PLAIN" | "XOAUTH2" | "OAUTHBEARER" | "SCRAM-SHA-256";
  /** SCRAM 전용 — 교환 상태. 규칙은 `@ionosphere/core/scram-session.ts`가 소유한다. */
  scram?: { session: ScramServerSession; stage: "clientFirst" | "clientFinal" | "serverFinal"; username?: string };
}

/** 지원 SASL 메커니즘(평문 회선에서 authAllowed일 때 광고). */
const SASL_MECHANISMS = ["PLAIN", "XOAUTH2", "OAUTHBEARER"] as const;
/** SCRAM은 백엔드가 키 조회·승인을 둘 다 제공할 때만 광고한다(못 끝낼 교환을 시작하지 않는다). */
import { randomBytes } from "node:crypto";

const SCRAM_MECHANISM = "SCRAM-SHA-256";
/** 프로세스 기본 decoy 비밀 — 모듈 로드 시 한 번 만든다. */
const PROCESS_SCRAM_DECOY = randomBytes(32);

type Pending =
  | { kind: "auth"; tag: string }
  | { kind: "sasl-line"; sasl: SaslPending }
  /** SCRAM 키 조회 대기 — 어댑터가 `scramKeysResult()`로 재개한다. */
  | { kind: "scram-keys"; sasl: SaslPending }
  /** 백엔드 요청 대기 — resume이 응답을 액션으로 변환(명령별 continuation). */
  | { kind: "backend"; resume: (res: ImapBackendResponse) => ImapAction[] };

const BASE_CAPABILITIES = ["IMAP4rev1", "IMAP4rev2", "LITERAL-", "SASL-IR", "ID", "ENABLE", "NAMESPACE", "CHILDREN", "SPECIAL-USE", "UNSELECT", "UIDPLUS", "MOVE", "IDLE", "CONDSTORE", "QRESYNC", "ESEARCH", "SEARCHRES", "BINARY", "SAVEDATE", "MULTIAPPEND", "REPLACE", "OBJECTID", "SORT", "THREAD=ORDEREDSUBJECT", "THREAD=REFERENCES", "LIST-STATUS", "QUOTA", "QUOTA=RES-STORAGE", "QUOTA=RES-MESSAGE"] as const;

/**
 * 쿼터 루트 이름 — 이 저장소의 쿼터는 **계정 단위**라 루트가 하나뿐이다(RFC 9208 §3.1이
 * 허용하는 형태). 빈 문자열이 관례적인 "전체" 루트다.
 */
const QUOTA_ROOT = "";
/**
 * ENABLE로 옵트인 가능한 확장(RFC 5161). QRESYNC는 CONDSTORE를 함의(RFC 7162).
 *
 * ★`IMAP4rev2`도 여기 있다(RFC 9051 §6.3.1). 둘 다 광고하는 서버는 **rev1 모드로 시작**하고
 * 클라이언트가 `ENABLE IMAP4rev2`를 보내야 rev2 시맨틱으로 바뀐다. 이 저장소의 엔진은
 * 내부적으로 이미 rev2로 짜여 있지만(\Recent 없음·UTF-8 메일함 이름), **응답 모양**이
 * 다른 것들 — SEARCH가 ESEARCH로 나가고 SELECT에서 RECENT·UNSEEN이 사라지는 것 —
 * 은 rev1 클라이언트를 깨뜨리므로 ENABLE 전에는 내지 않는다.
 */
const ENABLABLE = ["CONDSTORE", "QRESYNC", "IMAP4rev2"] as const;

export class ImapEngine {
  private readonly hostname: string;
  private readonly scramOffered: boolean;
  private readonly scramDecoySecret: Buffer;
  /** ★readonly가 아니다 — STARTTLS 성공 시 어댑터가 tlsEstablished()로 뒤집는다. */
  private secure: boolean;
  private readonly allowInsecureAuth: boolean;
  private readonly tlsAvailable: boolean;
  /** STARTTLS OK를 보낸 뒤 핸드셰이크를 기다리는 중 — 그 사이 들어온 라인은 버린다. */
  private awaitingTls = false;
  /** COMPRESS=DEFLATE가 이미 켜졌나 — 두 번 켜면 `NO [COMPRESSIONACTIVE]`(RFC 4978 §3). */
  private compressed = false;
  private readonly reader: ImapLineReader;

  private state: ImapState = "not-authenticated";
  private selected: SelectedView | null = null;
  private closed = false;
  private pending: Pending | null = null;
  /** IDLE 진행 중이면 그 tag — pending과 별도 슬롯(IDLE 중 idleTick 백엔드 폴링 공존). */
  private idleTag: string | null = null;
  /** 백엔드 응답 대기 중 도착한 논리 라인 버퍼(파이프라이닝). */
  private readonly queued: LinePart[][] = [];
  /** `queued`가 붙들고 있는 총 바이트 — 상한 없이 두면 리터럴 상한을 지켜도 같은 메모리를 먹는다. */
  private queuedBytes = 0;
  private readonly enabled = new Set<string>();
  /**
   * SEARCHRES(RFC 5182)의 검색 결과 변수 `$` — **UID로** 담는다.
   *
   * ★seq로 담으면 안 된다. EXPUNGE 한 번에 뒤쪽 번호가 전부 밀려 저장된 집합이 조용히
   * 다른 메시지를 가리키게 되고, 그 상태로 `STORE $ +FLAGS \Deleted`가 오면 **엉뚱한 메일을
   * 지운다**. UID는 밀리지 않으므로 사라진 것만 조회 시 빠진다(RFC 5182 §2.1의 요구와 같다).
   *
   * SELECT/EXAMINE 성공 시 비운다(§2.1) — 메일함이 바뀌면 그 번호들은 의미가 없다.
   */
  private savedSearch: number[] = [];
  /** 인증 후 복원할 리터럴 상한(APPEND 기준). 인증 전에는 훨씬 작은 값으로 리더를 조인다. */
  private readonly authedMaxLiteralBytes: number;

  constructor(opts: ImapEngineOptions) {
    this.hostname = opts.hostname;
    this.secure = opts.secure ?? false;
    this.allowInsecureAuth = opts.allowInsecureAuth ?? false;
    this.tlsAvailable = opts.tlsAvailable ?? false;
    this.scramOffered = opts.scramOffered ?? false;
    this.scramDecoySecret = opts.scramDecoySecret ?? PROCESS_SCRAM_DECOY;
    this.authedMaxLiteralBytes = opts.maxLiteralBytes ?? MAX_MESSAGE_BYTES;
    this.reader = new ImapLineReader({
      ...(opts.maxLineBytes !== undefined ? { maxLineBytes: opts.maxLineBytes } : {}),
      // 인증 전 상한. 테스트가 더 작은 값을 주면 그쪽을 존중한다(min).
      maxLiteralBytes: Math.min(this.authedMaxLiteralBytes, MAX_PREAUTH_LITERAL_BYTES),
    });
  }

  /** 연결 수립 직후 어댑터가 한 번 호출 — 인사말(untagged OK + CAPABILITY 코드). */
  greeting(): ImapAction[] {
    return [{ kind: "reply", text: `* OK [CAPABILITY ${this.capabilities().join(" ")}] ${this.hostname} IMAP ready` }];
  }

  feed(chunk: Uint8Array): ImapAction[] {
    if (this.closed) return [];
    /**
     * ★STARTTLS OK를 보낸 뒤 핸드셰이크가 끝나기 전에 도착한 평문 바이트는 **버린다.**
     * 그 구간의 바이트는 TLS 레코드이거나(어댑터가 소켓을 넘겼으므로 여기 오지 않는다)
     * 공격자가 미리 밀어 넣은 명령이다. 후자를 실행하면 업그레이드 후 세션에 평문 구간의
     * 명령이 섞여 들어간다 — RFC 3501 §6.2.1이 캐시를 버리라고 한 것과 같은 이유다.
     */
    if (this.awaitingTls) return [];
    const actions: ImapAction[] = [];
    for (const ev of this.reader.feed(chunk)) {
      actions.push(...this.handleReaderEvent(ev));
      if (this.closed) break;
    }
    return actions;
  }

  /** {kind:"backend"} 액션에 대한 어댑터 응답 — 재개 후 버퍼된 라인 처리. */
  backendResult(res: ImapBackendResponse): ImapAction[] {
    if (!this.pending || this.pending.kind !== "backend") {
      throw new Error("ImapEngine: backendResult()는 backend 액션 이후에만 호출 가능");
    }
    const resume = this.pending.resume;
    this.pending = null;
    return [...resume(res), ...this.drainQueued()];
  }

  /** {kind:"auth"} 액션에 대한 백엔드 응답 — 재개 후 버퍼된 라인 처리. */
  /**
   * SCRAM 실패를 어댑터에 알리는 액션. **거절 응답과 늘 함께 나가야 한다** —
   * 응답만 내고 이걸 빼면 그 갈래가 다시 무기록이 된다(이 액션이 생긴 이유).
   */
  private scramFailedAction(step: ScramStep): ImapAction {
    return {
      kind: "authFailed",
      mechanism: SCRAM_MECHANISM,
      ...(step.need === "failed" && step.username ? { user: step.username } : {}),
    };
  }

  /**
   * SCRAM 저장 키(없으면 null) — **null이어도 교환은 계속된다.**
   * 즉시 실패시키면 "그 계정이 없다"가 응답 형태로 샌다(core/scram-session.ts).
   */
  scramKeysResult(keys: ScramStoredKeys | null): ImapAction[] {
    const p = this.pending;
    if (p?.kind !== "scram-keys") throw new Error("ImapEngine: scramKeysResult()는 scramKeys 액션 이후에만 호출 가능");
    const sc = p.sasl.scram;
    if (!sc) throw new Error("ImapEngine: scram 상태 없음");
    const step = sc.session.provideKeys(keys);
    if (step.need !== "send") {
      this.pending = null;
      return [
        this.scramFailedAction(step),
        { kind: "reply", text: `${p.sasl.tag} NO [AUTHENTICATIONFAILED] authentication failed` },
      ];
    }
    this.pending = { kind: "sasl-line", sasl: p.sasl };
    return [{ kind: "reply", text: `+ ${Buffer.from(step.message).toString("base64")}` }];
  }

  authResult(result: ImapAuthResult): ImapAction[] {
    if (!this.pending || this.pending.kind !== "auth") {
      throw new Error("ImapEngine: authResult()는 auth 액션 이후에만 호출 가능");
    }
    const tag = this.pending.tag;
    this.pending = null;
    const actions: ImapAction[] = [];
    if (result) {
      this.state = "authenticated";
      // 인증됐으므로 APPEND용 원래 리터럴 상한을 돌려준다(그 전까지는 MAX_PREAUTH_LITERAL_BYTES).
      this.reader.setMaxLiteralBytes(this.authedMaxLiteralBytes);
      actions.push({ kind: "reply", text: `${tag} OK [CAPABILITY ${this.capabilities().join(" ")}] authenticated` });
    } else {
      actions.push({ kind: "reply", text: `${tag} NO [AUTHENTICATIONFAILED] authentication failed` });
    }
    actions.push(...this.drainQueued());
    return actions;
  }

  // ── 내부 ──────────────────────────────────────────────────────────────────

  private capabilities(): string[] {
    const caps: string[] = [...BASE_CAPABILITIES];
    /**
     * ★`COMPRESS`는 **인증 후에만** 광고한다. 인증 전에는 받지 않으므로(위 주석) 광고하면
     * 클라이언트가 시도하고 실패한 뒤 자격증명을 의심한다 — 광고 = 구현이라는 규율이다.
     * 이미 켜진 뒤에도 빼야 한다(RFC 4978 §3: 두 번 켤 수 없다).
     */
    if (this.state !== "not-authenticated" && !this.compressed) caps.push("COMPRESS=DEFLATE");
    if (this.state === "not-authenticated") {
      // 평문이고 인증서가 있으면 STARTTLS를 알린다 — 이게 없으면 143은 로그인 불가 포트가 된다.
      if (this.starttlsOffered()) caps.push("STARTTLS");
      if (this.authAllowed()) {
        // ★SCRAM을 **먼저** 광고한다 — 클라이언트가 순서를 선호도로 읽는 경우가 많아,
        //   PLAIN이 앞에 있으면 더 안전한 메커니즘을 두고도 평문을 고른다.
        if (this.scramOffered) caps.push(`AUTH=${SCRAM_MECHANISM}`);
        for (const m of SASL_MECHANISMS) caps.push(`AUTH=${m}`);
      }
      else caps.push("LOGINDISABLED");
    }
    return caps;
  }

  private authAllowed(): boolean {
    return this.secure || this.allowInsecureAuth;
  }

  /** STARTTLS를 광고·수락할 수 있는가 — 인증서가 있고 아직 평문일 때만. */
  private starttlsOffered(): boolean {
    return this.tlsAvailable && !this.secure;
  }

  /**
   * 어댑터가 TLS 핸드셰이크 완료를 통보 — 이후 회선은 secure다.
   *
   * ★RFC 3501 §6.2.1: 업그레이드 후 **협상 이전에 캐시한 서버 정보를 버려야 한다.**
   * 클라이언트가 CAPABILITY를 다시 물으므로 여기서 먼저 보내지 않는다(ManageSieve와 다른 점).
   */
  tlsEstablished(): ImapAction[] {
    this.secure = true;
    this.awaitingTls = false;
    return [];
  }

  private handleReaderEvent(ev: ReaderEvent): ImapAction[] {
    switch (ev.kind) {
      case "continue":
        // sync 리터럴 — 백엔드 대기 중이라도 continuation은 즉시 보내야 교착이 없다
        return [{ kind: "reply", text: "+ OK" }];
      case "error":
        return [{ kind: "reply", text: `* BAD ${ev.message}` }];
      case "line":
        if (this.pending && (this.pending.kind === "auth" || this.pending.kind === "backend")) {
          this.queued.push(ev.parts);
          this.queuedBytes += lineBytes(ev.parts);
          // 리터럴 상한만으로는 부족하다 — 상한 이하의 리터럴을 **여러 개** 보내면 같은 메모리를
          // 먹는다. 여기까지 왔으면 정상 클라이언트의 파이프라이닝이 아니므로 fail closed.
          if (this.queuedBytes > MAX_QUEUED_LINE_BYTES) {
            this.queued.length = 0;
            this.queuedBytes = 0;
            this.closed = true;
            return [
              { kind: "reply", text: "* BYE too much pipelined data" },
              { kind: "close" },
            ];
          }
          return [];
        }
        return this.handleLine(ev.parts);
    }
  }

  private drainQueued(): ImapAction[] {
    const actions: ImapAction[] = [];
    while (this.queued.length > 0 && !this.pending && !this.closed) {
      const parts = this.queued.shift();
      if (parts) {
        this.queuedBytes -= lineBytes(parts);
        actions.push(...this.handleLine(parts));
      }
    }
    if (this.queued.length === 0) this.queuedBytes = 0;
    return actions;
  }

  /** IDLE 진행 중 여부 — 어댑터의 idleTick() 호출 게이트. */
  isIdling(): boolean {
    return this.idleTag !== null;
  }

  /**
   * IDLE 알림 폴링(RFC 2177 — IDLE 중 서버는 untagged 갱신을 보내야 함).
   * 어댑터가 주기 호출: selected면 refresh와 동일한 diff(EXISTS/EXPUNGE/FLAGS 델타)를
   * tagged OK 없이 방출한다. 다른 백엔드 요청이 진행 중이면 이번 틱은 건너뜀.
   */
  idleTick(): ImapAction[] {
    if (this.idleTag === null || this.pending !== null || this.state !== "selected" || this.closed) return [];
    return this.refreshSelected(null);
  }

  private handleLine(parts: LinePart[]): ImapAction[] {
    // IDLE 중 — DONE 라인만 유효(RFC 2177)
    if (this.idleTag !== null) {
      const tag = this.idleTag;
      this.idleTag = null;
      const text = parts.length === 1 && parts[0]?.kind === "text" ? parts[0].text.trim().toUpperCase() : "";
      return [{ kind: "reply", text: text === "DONE" ? `${tag} OK IDLE terminated` : `${tag} BAD expected DONE` }];
    }

    // AUTHENTICATE continuation 대기 중 — 이 라인은 IMAP 명령이 아니라 SASL 데이터
    if (this.pending && this.pending.kind === "sasl-line") {
      const sasl = this.pending.sasl;
      this.pending = null;
      const text = parts.length === 1 && parts[0]?.kind === "text" ? parts[0].text : null;
      return this.handleSaslData(sasl, text);
    }

    let cmd: ParsedCommand;
    try {
      cmd = parseCommand(parts);
    } catch (err) {
      const msg = err instanceof ImapParseError ? err.message : "parse error";
      return [{ kind: "reply", text: `* BAD ${msg}` }];
    }

    switch (cmd.name) {
      case "CAPABILITY":
        return this.cmdCapability(cmd);
      case "NOOP":
      case "CHECK":
        // selected면 다른 세션의 변경(APPEND/EXPUNGE)을 여기서 반영 — RFC가 허용하는 알림 지점
        if (this.state === "selected" && this.selected) {
          return this.refreshSelected(`${cmd.tag} OK ${cmd.name} completed`);
        }
        return [{ kind: "reply", text: `${cmd.tag} OK ${cmd.name} completed` }];
      case "LOGOUT":
        return this.cmdLogout(cmd);
      case "ID":
        return this.cmdId(cmd);
      case "STARTTLS":
        return this.cmdStartTls(cmd);
      case "LOGIN":
        return this.cmdLogin(cmd);
      case "AUTHENTICATE":
        return this.cmdAuthenticate(cmd);
      case "ENABLE":
        return this.cmdEnable(cmd);
      /**
       * COMPRESS (RFC 4978) — 회선 압축.
       *
       * ★TLS 위에서 쓰면 압축 오라클(CRIME 계열)이 성립할 수 있다는 지적이 있지만, IMAP은
       * HTTP와 달리 **공격자가 같은 회선에 자기 데이터를 끼워 넣을 방법이 없다**(요청을
       * 유발할 크로스오리진 개념이 없다). 그래서 광고하되, 인증 **후에만** 받는다 —
       * 인증 전 압축은 자원만 쓰게 하는 무료 증폭 수단이다.
       */
      case "COMPRESS": {
        if (this.state === "not-authenticated") {
          return [{ kind: "reply", text: `${cmd.tag} BAD COMPRESS not allowed before authentication` }];
        }
        const alg = valueText(cmd.args[0] ?? { kind: "atom", value: "" })?.toUpperCase();
        if (alg !== "DEFLATE") {
          return [{ kind: "reply", text: `${cmd.tag} BAD COMPRESS unsupported algorithm` }];
        }
        if (this.compressed) {
          return [{ kind: "reply", text: `${cmd.tag} NO [COMPRESSIONACTIVE] compression already active` }];
        }
        this.compressed = true;
        // OK는 **압축 전에** 나가야 한다 — 순서가 뒤집히면 클라이언트가 그 줄을 못 읽는다.
        return [
          { kind: "reply", text: `${cmd.tag} OK DEFLATE active` },
          { kind: "startCompress" },
        ];
      }
      case "GETQUOTAROOT":
        return this.requireAuth(cmd, () => this.cmdGetQuota(cmd, "GETQUOTAROOT"));
      case "GETQUOTA":
        return this.requireAuth(cmd, () => this.cmdGetQuota(cmd, "GETQUOTA"));
      case "SETQUOTA":
        /**
         * 쿼터는 **운영자가 정한다**(관리 API·CLI). 클라이언트가 자기 한도를 올릴 수 있으면
         * 쿼터가 쿼터가 아니다. RFC 9208 §4.1도 서버가 거부할 수 있다고 명시한다.
         */
        return this.requireAuth(cmd, () => [
          { kind: "reply", text: `${cmd.tag} NO [CANNOT] quota is managed by the administrator` },
        ]);
      case "NAMESPACE":
        return this.requireAuth(cmd, () => [
          { kind: "reply", text: `* NAMESPACE (("" "${HIERARCHY_DELIMITER}")) NIL NIL` },
          { kind: "reply", text: `${cmd.tag} OK NAMESPACE completed` },
        ]);
      case "LIST":
        return this.requireAuth(cmd, () => this.cmdList(cmd, "LIST"));
      case "LSUB":
        // rev1 호환 — 구독 관리 미배선(전 메일함 구독 취급, SCHEMA subscribed 기본 1)
        return this.requireAuth(cmd, () => this.cmdList(cmd, "LSUB"));
      case "SUBSCRIBE":
      case "UNSUBSCRIBE":
        return this.requireAuth(cmd, () => {
          const name = this.mailboxArg(cmd, 0);
          if (name === null || cmd.args.length !== 1) {
            return [{ kind: "reply", text: `${cmd.tag} BAD ${cmd.name} expects mailbox name` }];
          }
          return this.callBackend({ kind: "setSubscribed", name, subscribed: cmd.name === "SUBSCRIBE" }, (res) =>
            res.kind === "ok"
              ? [{ kind: "reply", text: `${cmd.tag} OK ${cmd.name} completed` }]
              : [ImapEngine.noReply(cmd.tag, cmd.name, res.kind === "no" ? res : { message: "failed" })],
          );
        });
      case "CREATE":
        return this.requireAuth(cmd, () => this.cmdCreate(cmd));
      case "DELETE":
        return this.requireAuth(cmd, () => this.cmdDelete(cmd));
      case "RENAME":
        return this.requireAuth(cmd, () => this.cmdRename(cmd));
      case "GETACL":
        return this.requireAuth(cmd, () => this.cmdGetAcl(cmd));
      case "SETACL":
        return this.requireAuth(cmd, () => this.cmdSetAcl(cmd));
      case "DELETEACL":
        return this.requireAuth(cmd, () => this.cmdDeleteAcl(cmd));
      case "LISTRIGHTS":
        return this.requireAuth(cmd, () => this.cmdListRights(cmd));
      case "MYRIGHTS":
        return this.requireAuth(cmd, () => this.cmdMyRights(cmd));
      case "STATUS":
        return this.requireAuth(cmd, () => this.cmdStatus(cmd));
      case "SELECT":
        return this.requireAuth(cmd, () => this.cmdSelect(cmd, true));
      case "EXAMINE":
        return this.requireAuth(cmd, () => this.cmdSelect(cmd, false));
      case "UNSELECT":
        return this.requireSelected(cmd, () => {
          this.leaveSelected();
          return [{ kind: "reply", text: `${cmd.tag} OK UNSELECT completed` }];
        });
      case "CLOSE":
        return this.requireSelected(cmd, () => this.cmdClose(cmd));
      case "FETCH":
        return this.requireSelected(cmd, () => this.cmdFetch(cmd, false));
      case "STORE":
        return this.requireSelected(cmd, () => this.cmdStore(cmd, false));
      case "SEARCH":
        return this.requireSelected(cmd, () => this.cmdSearch(cmd, false));
      case "SORT":
        return this.requireSelected(cmd, () => this.cmdSortThread(cmd, false, "sort"));
      case "THREAD":
        return this.requireSelected(cmd, () => this.cmdSortThread(cmd, false, "thread"));
      case "EXPUNGE":
        return this.requireSelected(cmd, () => this.cmdExpunge(cmd, null));
      case "APPEND":
        return this.requireAuth(cmd, () => this.cmdAppend(cmd));
      case "REPLACE":
        return this.requireSelected(cmd, () => this.cmdReplace(cmd, false));
      case "COPY":
        return this.requireSelected(cmd, () => this.cmdCopyMove(cmd, false, "copy"));
      case "MOVE":
        return this.requireSelected(cmd, () => this.cmdCopyMove(cmd, false, "move"));
      case "IDLE":
        return this.requireAuth(cmd, () => {
          this.idleTag = cmd.tag;
          return [{ kind: "reply", text: "+ idling" }];
        });
      case "UID":
        return this.cmdUid(cmd);
      default:
        return [{ kind: "reply", text: `${cmd.tag} BAD unknown command` }];
    }
  }

  private requireAuth(cmd: ParsedCommand, fn: () => ImapAction[]): ImapAction[] {
    if (this.state === "not-authenticated") {
      return [{ kind: "reply", text: `${cmd.tag} BAD command not allowed before authentication` }];
    }
    return fn();
  }

  private requireSelected(cmd: ParsedCommand, fn: () => ImapAction[]): ImapAction[] {
    if (this.state !== "selected" || !this.selected) {
      return [{ kind: "reply", text: `${cmd.tag} BAD command requires a selected mailbox` }];
    }
    return fn();
  }

  private leaveSelected(): void {
    this.selected = null;
    this.state = "authenticated";
  }

  /** 백엔드 요청 방출 + continuation 등록 — 응답은 backendResult()로 재개된다. */
  private callBackend(req: ImapBackendRequest, resume: (res: ImapBackendResponse) => ImapAction[]): ImapAction[] {
    this.pending = { kind: "backend", resume };
    return [{ kind: "backend", req }];
  }

  /** astring 인자 → 정규화된 메일함 이름. 리스트 값이면 null. */
  private mailboxArg(cmd: ParsedCommand, idx: number): string | null {
    const v = cmd.args[idx];
    if (!v) return null;
    const text = valueText(v);
    if (text === null) return null;
    return normalizeMailboxName(text);
  }

  private static noReply(tag: string, verb: string, res: { code?: string; message: string }): ImapAction {
    const code = res.code ? `[${res.code}] ` : "";
    return { kind: "reply", text: `${tag} NO ${code}${verb} ${res.message}` };
  }

  private identifierArg(cmd: ParsedCommand, idx: number): string | null {
    const value = cmd.args[idx];
    return value ? valueText(value) : null;
  }

  private cmdGetAcl(cmd: ParsedCommand): ImapAction[] {
    const name = this.mailboxArg(cmd, 0);
    if (name === null || cmd.args.length !== 1) return [{ kind: "reply", text: `${cmd.tag} BAD GETACL expects mailbox name` }];
    return this.callBackend({ kind: "getAcl", name }, (res) => {
      if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, "GETACL", res)];
      if (res.kind !== "acl") return [{ kind: "reply", text: `${cmd.tag} NO GETACL failed` }];
      const pairs = res.entries.flatMap((entry) => [entry.identifier, entry.rights]).join(" ");
      return [{ kind: "reply", text: `* ACL ${quoteMailboxName(res.mailbox)} ${pairs}` }, { kind: "reply", text: `${cmd.tag} OK GETACL completed` }];
    });
  }

  private cmdSetAcl(cmd: ParsedCommand): ImapAction[] {
    const name = this.mailboxArg(cmd, 0);
    const identifier = this.identifierArg(cmd, 1);
    const rights = this.identifierArg(cmd, 2);
    if (name === null || identifier === null || rights === null || cmd.args.length !== 3) return [{ kind: "reply", text: `${cmd.tag} BAD SETACL expects mailbox identifier rights` }];
    return this.callBackend({ kind: "setAcl", name, identifier, rights }, (res) =>
      res.kind === "ok" ? [{ kind: "reply", text: `${cmd.tag} OK SETACL completed` }] : [ImapEngine.noReply(cmd.tag, "SETACL", res.kind === "no" ? res : { message: "failed" })],
    );
  }

  private cmdDeleteAcl(cmd: ParsedCommand): ImapAction[] {
    const name = this.mailboxArg(cmd, 0);
    const identifier = this.identifierArg(cmd, 1);
    if (name === null || identifier === null || cmd.args.length !== 2) return [{ kind: "reply", text: `${cmd.tag} BAD DELETEACL expects mailbox identifier` }];
    return this.callBackend({ kind: "deleteAcl", name, identifier }, (res) =>
      res.kind === "ok" ? [{ kind: "reply", text: `${cmd.tag} OK DELETEACL completed` }] : [ImapEngine.noReply(cmd.tag, "DELETEACL", res.kind === "no" ? res : { message: "failed" })],
    );
  }

  private cmdListRights(cmd: ParsedCommand): ImapAction[] {
    const name = this.mailboxArg(cmd, 0);
    const identifier = this.identifierArg(cmd, 1);
    if (name === null || identifier === null || cmd.args.length !== 2) return [{ kind: "reply", text: `${cmd.tag} BAD LISTRIGHTS expects mailbox identifier` }];
    return this.callBackend({ kind: "listRights", name, identifier }, (res) => {
      if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, "LISTRIGHTS", res)];
      if (res.kind !== "rights") return [{ kind: "reply", text: `${cmd.tag} NO LISTRIGHTS failed` }];
      return [{ kind: "reply", text: `* LISTRIGHTS ${quoteMailboxName(res.mailbox)} ${res.identifier} "" ${res.rights}` }, { kind: "reply", text: `${cmd.tag} OK LISTRIGHTS completed` }];
    });
  }

  private cmdMyRights(cmd: ParsedCommand): ImapAction[] {
    const name = this.mailboxArg(cmd, 0);
    if (name === null || cmd.args.length !== 1) return [{ kind: "reply", text: `${cmd.tag} BAD MYRIGHTS expects mailbox name` }];
    return this.callBackend({ kind: "myRights", name }, (res) => {
      if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, "MYRIGHTS", res)];
      if (res.kind !== "rights") return [{ kind: "reply", text: `${cmd.tag} NO MYRIGHTS failed` }];
      return [{ kind: "reply", text: `* MYRIGHTS ${quoteMailboxName(res.mailbox)} ${res.rights}` }, { kind: "reply", text: `${cmd.tag} OK MYRIGHTS completed` }];
    });
  }

  // ── 메일함 명령 ────────────────────────────────────────────────────────────

  private cmdList(cmd: ParsedCommand, verb: "LIST" | "LSUB"): ImapAction[] {
    const ref = cmd.args[0] ? valueText(cmd.args[0]) : null;
    const pattern = cmd.args[1] ? valueText(cmd.args[1]) : null;
    if (ref === null || pattern === null) {
      return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} expects reference and pattern` }];
    }
    // LIST RETURN 옵션(LIST-EXTENDED 부분집합): STATUS(RFC 5819) + SUBSCRIBED
    let statusItems: string[] | null = null;
    let returnSubscribed = false;
    if (cmd.args.length > 2) {
      const kw = valueText(cmd.args[2] ?? { kind: "atom", value: "" })?.toUpperCase();
      const opts = cmd.args[3];
      if (verb !== "LIST" || kw !== "RETURN" || !opts || opts.kind !== "list" || cmd.args.length !== 4) {
        return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} invalid arguments` }];
      }
      for (let i = 0; i < opts.items.length; i++) {
        const opt = valueText(opts.items[i]!)?.toUpperCase();
        if (opt === "SUBSCRIBED") {
          returnSubscribed = true;
        } else if (opt === "STATUS") {
          const list = opts.items[i + 1];
          i += 1;
          if (!list || list.kind !== "list") return [{ kind: "reply", text: `${cmd.tag} BAD STATUS expects item list` }];
          statusItems = [];
          for (const it of list.items) {
            const t = valueText(it)?.toUpperCase();
            if (!t) return [{ kind: "reply", text: `${cmd.tag} BAD invalid STATUS item` }];
            statusItems.push(t);
          }
        } else {
          return [{ kind: "reply", text: `${cmd.tag} BAD unknown RETURN option` }];
        }
      }
    }
    // 빈 패턴 — 계층 구분자 공지(RFC 9051 §6.3.9)
    if (pattern.length === 0) {
      return [
        { kind: "reply", text: `* ${verb} (\\Noselect) "${HIERARCHY_DELIMITER}" ""` },
        { kind: "reply", text: `${cmd.tag} OK ${verb} completed` },
      ];
    }
    const full = normalizeMailboxName(joinListPattern(ref, pattern));
    // 패턴 파싱은 메일함 수와 무관하다 — 루프 밖에서 한 번만 컴파일한다.
    const matches = compileListPattern(full);
    return this.callBackend({ kind: "listMailboxes" }, (res) => {
      if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, verb, res)];
      if (res.kind !== "mailboxes") return [{ kind: "reply", text: `${cmd.tag} NO ${verb} failed` }];
      const actions: ImapAction[] = [];
      /**
       * `\HasChildren` 판정용 **부모 경로 집합**.
       *
       * ★예전엔 메일함마다 `[...names].some((n) => n.startsWith(m.name + "/"))`였다 —
       * Set을 배열로 복사하고 전체를 훑으므로 O(N²)이고, 1000개면 100만 연산 + 배열 1000개다.
       * 각 이름의 조상 경로를 한 번만 모아 두면 판정이 조회 한 번(O(1))이 된다.
       */
      const parents = new Set<string>();
      for (const m of res.mailboxes) {
        const segs = m.name.split(HIERARCHY_DELIMITER);
        for (let i = 1; i < segs.length; i++) parents.add(segs.slice(0, i).join(HIERARCHY_DELIMITER));
      }
      for (const m of res.mailboxes) {
        if (!matches(m.name)) continue;
        if (verb === "LSUB" && m.subscribed === false) continue; // 구독 필터(영속화됨)
        const attrs: string[] = [];
        const special = roleToAttribute(m.role);
        if (special) attrs.push(special);
        const hasChildren = parents.has(m.name);
        attrs.push(hasChildren ? "\\HasChildren" : "\\HasNoChildren");
        if (returnSubscribed && m.subscribed !== false) attrs.push("\\Subscribed");
        actions.push({
          kind: "reply",
          text: `* ${verb} (${attrs.join(" ")}) "${HIERARCHY_DELIMITER}" ${quoteMailboxName(m.name)}`,
        });
        // LIST-STATUS — 각 LIST 라인 뒤에 STATUS 인라인(RFC 5819)
        if (statusItems) {
          const fields = ImapEngine.statusFields(m, statusItems);
          if (fields !== null) {
            actions.push({ kind: "reply", text: `* STATUS ${quoteMailboxName(m.name)} (${fields.join(" ")})` });
          }
        }
      }
      actions.push({ kind: "reply", text: `${cmd.tag} OK ${verb} completed` });
      return actions;
    });
  }

  private cmdCreate(cmd: ParsedCommand): ImapAction[] {
    let name = this.mailboxArg(cmd, 0);
    if (name === null || cmd.args.length !== 1) {
      return [{ kind: "reply", text: `${cmd.tag} BAD CREATE expects mailbox name` }];
    }
    // 끝 구분자는 관례상 무시(RFC 9051 §6.3.4)
    if (name.endsWith(HIERARCHY_DELIMITER)) name = name.slice(0, -1);
    if (name.length === 0 || name === "INBOX") {
      return [{ kind: "reply", text: `${cmd.tag} NO CREATE invalid mailbox name` }];
    }
    return this.callBackend({ kind: "createMailbox", name }, (res) =>
      res.kind === "ok"
        ? [{ kind: "reply", text: `${cmd.tag} OK CREATE completed` }]
        : [ImapEngine.noReply(cmd.tag, "CREATE", res.kind === "no" ? res : { message: "failed" })],
    );
  }

  private cmdDelete(cmd: ParsedCommand): ImapAction[] {
    const name = this.mailboxArg(cmd, 0);
    if (name === null || cmd.args.length !== 1) {
      return [{ kind: "reply", text: `${cmd.tag} BAD DELETE expects mailbox name` }];
    }
    if (name === "INBOX") {
      return [{ kind: "reply", text: `${cmd.tag} NO DELETE INBOX is not allowed` }];
    }
    return this.callBackend({ kind: "deleteMailbox", name }, (res) =>
      res.kind === "ok"
        ? [{ kind: "reply", text: `${cmd.tag} OK DELETE completed` }]
        : [ImapEngine.noReply(cmd.tag, "DELETE", res.kind === "no" ? res : { message: "failed" })],
    );
  }

  private cmdRename(cmd: ParsedCommand): ImapAction[] {
    const from = this.mailboxArg(cmd, 0);
    const to = this.mailboxArg(cmd, 1);
    if (from === null || to === null || cmd.args.length !== 2) {
      return [{ kind: "reply", text: `${cmd.tag} BAD RENAME expects source and destination` }];
    }
    if (to === "INBOX") {
      return [{ kind: "reply", text: `${cmd.tag} NO RENAME destination INBOX is not allowed` }];
    }
    return this.callBackend({ kind: "renameMailbox", from, to }, (res) =>
      res.kind === "ok"
        ? [{ kind: "reply", text: `${cmd.tag} OK RENAME completed` }]
        : [ImapEngine.noReply(cmd.tag, "RENAME", res.kind === "no" ? res : { message: "failed" })],
    );
  }

  /**
   * SELECT/EXAMINE (RFC 9051 §6.3.2/6.3.3) — 성공 시 selected 전이, 실패 시
   * 기존 선택도 해제된다(RFC 명시: SELECT 실패 = unselected 상태).
   */
  private cmdSelect(cmd: ParsedCommand, readWrite: boolean): ImapAction[] {
    const verb = readWrite ? "SELECT" : "EXAMINE";
    const name = this.mailboxArg(cmd, 0);
    if (name === null || cmd.args.length > 2) {
      return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} expects mailbox name` }];
    }
    // SELECT 파라미터(RFC 7162): (CONDSTORE) 또는 (QRESYNC (uv modseq [known-uids]))
    let qresync: { uidvalidity: number; modseq: number; knownUids: SeqRange[] | null } | null = null;
    const params = cmd.args[1];
    if (params !== undefined) {
      if (params.kind !== "list") return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} invalid parameters` }];
      for (let i = 0; i < params.items.length; i++) {
        const p = valueText(params.items[i]!)?.toUpperCase();
        if (p === "CONDSTORE") {
          this.enabled.add("CONDSTORE");
        } else if (p === "QRESYNC") {
          if (!this.enabled.has("QRESYNC")) {
            return [{ kind: "reply", text: `${cmd.tag} BAD QRESYNC not enabled` }];
          }
          const args = params.items[i + 1];
          i += 1;
          if (!args || args.kind !== "list") return [{ kind: "reply", text: `${cmd.tag} BAD invalid QRESYNC parameters` }];
          const uv = valueText(args.items[0] ?? { kind: "atom", value: "" });
          const ms = valueText(args.items[1] ?? { kind: "atom", value: "" });
          if (!uv || !ms || !/^\d+$/.test(uv) || !/^\d+$/.test(ms)) {
            return [{ kind: "reply", text: `${cmd.tag} BAD invalid QRESYNC parameters` }];
          }
          /**
           * ★세 번째 인자 known-uids를 **이제 읽는다**(RFC 7162 §3.2.5). 예전엔 문법으로만
           * 받아 주고 버렸는데, 툼스톤 보존창이 생긴 뒤로는 이 값이 "보존창 밖 요청에도
           * 정확히 답할 수 있는" 유일한 근거다. 못 읽으면 `1:uidnext-1`로 간주된다.
           *
           * 네 번째 인자(seq-match-data)는 아직 쓰지 않는다 — 그건 최적화이고, 없어도
           * 답의 정확성은 known-uids만으로 성립한다.
           */
          const knownText = args.items[2] ? valueText(args.items[2]) : null;
          const knownUids = knownText !== null ? parseSequenceSet(knownText) : null;
          qresync = { uidvalidity: Number(uv), modseq: Number(ms), knownUids };
        } else {
          return [{ kind: "reply", text: `${cmd.tag} BAD unknown ${verb} parameter` }];
        }
      }
    }
    // 재선택 전 기존 선택 해제 — 실패해도 unselected가 되도록 먼저 내린다
    this.leaveSelected();
    return this.callBackend({ kind: "selectMailbox", name }, (res) => {
      if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, verb, res)];
      if (res.kind !== "selected") return [{ kind: "reply", text: `${cmd.tag} NO ${verb} failed` }];
      const m = res.mailbox;
      const keywords = res.keywords ?? [];
      this.selected = {
        name: m.name,
        readWrite,
        uidvalidity: m.uidvalidity,
        uids: [...res.uids],
        announcedKeywords: new Set(keywords),
        lastSyncModseq: m.highestmodseq,
      };
      this.state = "selected";
      this.savedSearch = []; // SEARCHRES 리셋(RFC 5182 §2.1) — 메일함이 바뀌면 `$`는 무의미하다
      const rev2 = this.enabled.has("IMAP4rev2");
      const actions: ImapAction[] = [
        { kind: "reply", text: flagsLine(keywords) },
        { kind: "reply", text: `* ${res.uids.length} EXISTS` },
        /**
         * ★rev1에게는 `RECENT`를 **보내야** 한다 — 옛 클라이언트 중에 SELECT 응답에서 이 줄을
         * 기다리는 것이 있다. 우리는 \Recent를 지원하지 않으므로 값은 늘 0이다.
         * rev2는 이 응답 자체를 없앴으므로(RFC 9051 §7.3) ENABLE한 클라이언트에겐 보내지 않는다.
         */
        ...(rev2 ? [] : [{ kind: "reply" as const, text: "* 0 RECENT" }]),
        { kind: "reply", text: `* OK [UIDVALIDITY ${m.uidvalidity}] UIDs valid` },
        /**
         * OBJECTID(RFC 8474 §5) — 이름·UIDVALIDITY와 무관한 불변 id. 이게 있으면
         * 클라이언트가 "이름이 바뀐 것"과 "지우고 새로 만든 것"을 구분해 캐시를 지킨다.
         */
        ...(m.mailboxId !== undefined ? [{ kind: "reply" as const, text: `* OK [MAILBOXID (${m.mailboxId})] object id` }] : []),
        { kind: "reply", text: `* OK [UIDNEXT ${m.uidnext}] predicted next UID` },
        { kind: "reply", text: `* OK [HIGHESTMODSEQ ${m.highestmodseq}] modseq` },
        {
          kind: "reply",
          // 임의 키워드 허용(\* — SCHEMA 키워드 모델). EXAMINE은 영구 플래그 없음.
          text: readWrite
            ? "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] flags"
            : "* OK [PERMANENTFLAGS ()] read-only",
        },
      ];
      // rev2는 SELECT의 `[UNSEEN]` 응답 코드를 없앴다(RFC 9051 §7.1 — 클라이언트가
      // SEARCH UNSEEN으로 직접 구하라는 취지). rev1에게는 그대로 보낸다.
      if (!rev2 && res.firstUnseenSeq !== null) {
        actions.push({ kind: "reply", text: `* OK [UNSEEN ${res.firstUnseenSeq}] first unseen` });
      }
      const tagged: ImapAction = {
        kind: "reply",
        text: `${cmd.tag} OK [${readWrite ? "READ-WRITE" : "READ-ONLY"}] ${verb} completed`,
      };
      // QRESYNC 재동기화 — uidvalidity 일치 시에만 델타(불일치면 클라이언트가 전체 재동기화)
      if (qresync && qresync.uidvalidity === m.uidvalidity) {
        const since = qresync.modseq;
        return [
          ...actions,
          ...this.callBackend(
            { kind: "syncSince", name: m.name, sinceModseq: since, ...(qresync.knownUids ? { knownUids: qresync.knownUids } : {}) },
            (sync) => {
            if (sync.kind !== "sync") return [tagged];
            const out: ImapAction[] = [];
            if (sync.vanished.length > 0) {
              out.push({ kind: "reply", text: `* VANISHED (EARLIER) ${formatUidSet(sync.vanished)}` });
            }
            const view = this.selected;
            for (const c of sync.changed) {
              const seq = view ? view.uids.indexOf(c.uid) + 1 : 0;
              if (seq > 0) {
                out.push(...this.ensureFlagsAnnounced(c.flags));
                out.push({ kind: "reply", text: `* ${seq} FETCH (UID ${c.uid} FLAGS (${c.flags.join(" ")}) MODSEQ (${c.modseq}))` });
              }
            }
            out.push(tagged);
            return out;
          }),
        ];
      }
      actions.push(tagged);
      return actions;
    });
  }

  /** CLOSE (RFC 9051 §6.4.2) — READ-WRITE면 조용히 expunge 후 해제. untagged 없음. */
  private cmdClose(cmd: ParsedCommand): ImapAction[] {
    const view = this.selected;
    if (!view) return [{ kind: "reply", text: `${cmd.tag} BAD command requires a selected mailbox` }];
    this.leaveSelected();
    if (!view.readWrite) {
      return [{ kind: "reply", text: `${cmd.tag} OK CLOSE completed` }];
    }
    return this.callBackend({ kind: "expungeMailbox", name: view.name }, (res) =>
      res.kind === "ok"
        ? [{ kind: "reply", text: `${cmd.tag} OK CLOSE completed` }]
        : [ImapEngine.noReply(cmd.tag, "CLOSE", res.kind === "no" ? res : { message: "failed" })],
    );
  }

  /** UID 접두 명령(RFC 9051 §6.4.9) — 하위 명령을 uid 모드로 재디스패치. */
  private cmdUid(cmd: ParsedCommand): ImapAction[] {
    const sub = cmd.args[0] ? valueText(cmd.args[0])?.toUpperCase() : null;
    const rest: ParsedCommand = { tag: cmd.tag, name: sub ?? "", args: cmd.args.slice(1) };
    switch (sub) {
      case "FETCH":
        return this.requireSelected(cmd, () => this.cmdFetch(rest, true));
      case "STORE":
        return this.requireSelected(cmd, () => this.cmdStore(rest, true));
      case "SEARCH":
        return this.requireSelected(cmd, () => this.cmdSearch(rest, true));
      case "SORT":
        return this.requireSelected(cmd, () => this.cmdSortThread(rest, true, "sort"));
      case "THREAD":
        return this.requireSelected(cmd, () => this.cmdSortThread(rest, true, "thread"));
      case "COPY":
        return this.requireSelected(cmd, () => this.cmdCopyMove(rest, true, "copy"));
      case "MOVE":
        return this.requireSelected(cmd, () => this.cmdCopyMove(rest, true, "move"));
      case "REPLACE":
        return this.requireSelected(cmd, () => this.cmdReplace(rest, true));
      case "EXPUNGE": {
        // UIDPLUS UID EXPUNGE — uid 집합 내 \Deleted만
        const setText = rest.args[0] ? valueText(rest.args[0]) : null;
        const ranges = setText !== null ? this.resolveSetArg(setText, true) : null;
        if (!ranges) return [{ kind: "reply", text: `${cmd.tag} BAD UID EXPUNGE expects sequence set` }];
        return this.requireSelected(cmd, () => this.cmdExpunge(rest, ranges));
      }
      default:
        return [{ kind: "reply", text: `${cmd.tag} BAD unknown UID command` }];
    }
  }

  /** FETCH / UID FETCH (RFC 9051 §6.4.5). */
  private cmdFetch(cmd: ParsedCommand, uidMode: boolean): ImapAction[] {
    const verb = uidMode ? "UID FETCH" : "FETCH";
    const view = this.selected;
    if (!view) return [{ kind: "reply", text: `${cmd.tag} BAD command requires a selected mailbox` }];
    const setText = cmd.args[0] ? valueText(cmd.args[0]) : null;
    const ranges = setText !== null ? this.resolveSetArg(setText, uidMode) : null;
    // CONDSTORE 수정자(RFC 7162): 마지막 인자가 (CHANGEDSINCE n) 리스트
    let itemArgs = cmd.args.slice(1);
    let changedSince: number | null = null;
    const lastArg = itemArgs[itemArgs.length - 1];
    if (itemArgs.length >= 2 && lastArg?.kind === "list" && valueText(lastArg.items[0] ?? { kind: "atom", value: "" })?.toUpperCase() === "CHANGEDSINCE") {
      const n = valueText(lastArg.items[1] ?? { kind: "atom", value: "" });
      if (!n || !/^\d+$/.test(n) || lastArg.items.length !== 2) {
        return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} invalid CHANGEDSINCE` }];
      }
      changedSince = Number(n);
      this.enabled.add("CONDSTORE"); // 사용 자체가 활성화(RFC 7162)
      itemArgs = itemArgs.slice(0, -1);
    }
    const items = ranges !== null ? parseFetchItems(itemArgs) : null;
    if (!ranges || !items) {
      return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} invalid arguments` }];
    }
    // UID FETCH는 응답에 UID 항목 필수(RFC), CHANGEDSINCE는 MODSEQ 자동 포함
    if (uidMode && !items.some((it) => it.kind === "uid")) items.push({ kind: "uid" });
    if (changedSince !== null && !items.some((it) => it.kind === "modseq")) items.push({ kind: "modseq" });

    const targets = this.resolveTargets(ranges, uidMode);
    if (targets.length === 0) {
      return [{ kind: "reply", text: `${cmd.tag} OK ${verb} completed` }];
    }

    const needRaw = items.some(
      (it) =>
        it.kind === "envelope" ||
        it.kind === "body" ||
        it.kind === "bodystructure" ||
        it.kind === "section" ||
        it.kind === "binary" ||
        it.kind === "binarySize",
    );
    // BINARY도 BODY[]와 같이 \Seen을 세운다(RFC 3516 — .PEEK만 예외).
    const markSeen = view.readWrite && items.some((it) => (it.kind === "section" || it.kind === "binary") && !it.peek);

    /**
     * ★배치로 나눠 가져온다. 예전엔 메일함 **전체** uid를 한 요청에 실어, 백엔드가 그만큼의
     * 블롭을 전부 메모리에 올렸다(5만 통 × 50KB = 2.5GB). 응답은 배치마다 바로 흘려보내므로
     * 상주 메모리가 배치 하나 크기로 묶인다.
     *
     * 배치 사이에 다른 세션이 메시지를 지울 수 있지만, 그건 **원래 있던 성질**이다 —
     * 세션 뷰는 SELECT 시점 스냅샷이고 사라진 uid는 예전부터 조용히 생략됐다(아래 `!data`).
     */
    const batchSize = needRaw ? FETCH_BATCH_RAW : FETCH_BATCH_META;
    /**
     * 배치 하나를 응답 줄로. `unknownCte`가 서면 **명령 전체가 실패**한다 —
     * 풀 수 없는 인코딩은 부분 성공으로 넘길 수 없다(RFC 3516 §4.2가 NO를 요구한다).
     */
    const emit = (
      batch: readonly { seq: number; uid: number }[],
      res: ImapBackendResponse,
    ): { actions: ImapAction[]; unknownCte: boolean } => {
      if (res.kind !== "messages") return { actions: [], unknownCte: false };
      const byUid = new Map(res.messages.map((m) => [m.uid, m]));
      const actions: ImapAction[] = [];
      for (const t of batch) {
        const data = byUid.get(t.uid);
        if (!data) continue; // 스냅샷 이후 사라진 메시지 — 조용히 생략(EXPUNGE는 별도 흐름)
        if (changedSince !== null && data.modseq <= changedSince) continue; // CONDSTORE 필터
        const parts: string[] = [];
        for (const it of items) {
          const wire = this.fetchItemWire(it, t.uid, data);
          if (wire === null) return { actions, unknownCte: true };
          parts.push(wire);
        }
        if (items.some((it) => it.kind === "flags")) actions.push(...this.ensureFlagsAnnounced(data.flags));
        actions.push({ kind: "replyBinary", bytes: wireToBytes(`* ${t.seq} FETCH (${parts.join(" ")})\r\n`) });
      }
      return { actions, unknownCte: false };
    };

    /** 배치 하나를 요청하고, 응답을 흘린 뒤 다음 배치를 이어 건다(꼬리 연쇄). */
    const fetchFrom = (offset: number): ImapAction[] => {
      const batch = targets.slice(offset, offset + batchSize);
      return this.callBackend(
        { kind: "fetchMessages", name: view.name, uids: batch.map((t) => t.uid), needRaw, markSeen },
        (res) => {
          if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, verb, res)];
          if (res.kind !== "messages") return [{ kind: "reply", text: `${cmd.tag} NO ${verb} failed` }];
          const { actions, unknownCte } = emit(batch, res);
          if (unknownCte) {
            actions.push({ kind: "reply", text: `${cmd.tag} NO [UNKNOWN-CTE] ${verb} cannot decode section` });
            return actions;
          }
          const next = offset + batchSize;
          if (next < targets.length) return [...actions, ...fetchFrom(next)];
          actions.push({ kind: "reply", text: `${cmd.tag} OK ${verb} completed` });
          return actions;
        },
      );
    };
    return fetchFrom(0);
  }

  /** APPEND (RFC 9051 §6.3.12) — [flags] [date-time] literal. UIDPLUS APPENDUID 방출. */
  /**
   * APPEND (RFC 9051 §6.3.12) + MULTIAPPEND (RFC 3502).
   *
   * ★MULTIAPPEND는 `[flags] [date] literal`이 **반복**되는 형태다. 반복이라는 것 말고는
   * 단일 APPEND와 같아서, 파싱을 한 루프로 두고 백엔드에는 항상 목록으로 넘긴다 —
   * 갈래를 나누면 한쪽만 고쳐지는 형태가 된다.
   *
   * 원자성은 백엔드 몫이다(§3: 전부 아니면 전무). 여기서는 그 계약을 **한 요청**으로
   * 넘기는 것까지가 할 일이다.
   */
  private cmdAppend(cmd: ParsedCommand): ImapAction[] {
    const name = this.mailboxArg(cmd, 0);
    if (name === null) return [{ kind: "reply", text: `${cmd.tag} BAD APPEND expects mailbox name` }];

    const items: { raw: Uint8Array; flags: string[]; internalDateMs?: number }[] = [];
    let idx = 1;
    while (idx < cmd.args.length) {
      const flags: string[] = [];
      const flagsVal = cmd.args[idx];
      if (flagsVal?.kind === "list") {
        for (const f of flagsVal.items) {
          const t = valueText(f);
          if (t === null) return [{ kind: "reply", text: `${cmd.tag} BAD APPEND invalid flag` }];
          flags.push(t);
        }
        idx += 1;
      }
      let internalDateMs: number | null = null;
      const dateVal = cmd.args[idx];
      if (dateVal && dateVal.kind === "quoted") {
        const ms = parseImapDateTime(dateVal.value);
        if (ms !== null) {
          internalDateMs = ms;
          idx += 1;
        }
      }
      const msgVal = cmd.args[idx];
      let raw: Uint8Array;
      if (msgVal?.kind === "literal") raw = msgVal.bytes;
      else if (msgVal?.kind === "quoted") raw = new TextEncoder().encode(msgVal.value);
      else return [{ kind: "reply", text: `${cmd.tag} BAD APPEND expects message literal` }];
      if (raw.length === 0) return [{ kind: "reply", text: `${cmd.tag} NO APPEND empty message` }];
      items.push({ raw, flags, ...(internalDateMs !== null ? { internalDateMs } : {}) });
      idx += 1;
    }
    if (items.length === 0) return [{ kind: "reply", text: `${cmd.tag} BAD APPEND expects message literal` }];
    const first = items[0]!;

    return this.callBackend(
      {
        kind: "appendMessage",
        name,
        flags: first.flags,
        internalDateMs: first.internalDateMs ?? null,
        raw: first.raw,
        items,
      },
      (res) => {
        if (res.kind === "appended") {
          const actions: ImapAction[] = [];
          const uids = res.uids ?? [res.uid];
          // 선택 중 메일함에 APPEND — 즉시 EXISTS 반영(imaptest own_msgs 추적 요구)
          const view = this.selected;
          if (view && view.name === name) {
            let added = false;
            for (const u of uids) {
              if (view.uids.includes(u)) continue;
              view.uids.push(u);
              added = true;
            }
            if (added) {
              view.uids.sort((a, b) => a - b);
              actions.push({ kind: "reply", text: `* ${view.uids.length} EXISTS` });
            }
          }
          // APPENDUID의 uid-set은 넣은 순서를 뜻한다(RFC 4315 §3 / RFC 3502 §4.3).
          actions.push({
            kind: "reply",
            text: `${cmd.tag} OK [APPENDUID ${res.uidvalidity} ${formatUidSet(uids)}] APPEND completed`,
          });
          return actions;
        }
        return [ImapEngine.noReply(cmd.tag, "APPEND", res.kind === "no" ? res : { message: "failed" })];
      },
    );
  }

  /**
   * REPLACE / UID REPLACE (RFC 8508).
   *
   * ★"드래프트를 고쳤다"를 한 명령으로 표현한다. 클라이언트가 APPEND + STORE \Deleted +
   * EXPUNGE를 손으로 하면 그 사이에 다른 세션이 옛 것을 보거나, 중간에 끊겨 둘 다 남는다.
   *
   * ★**편차(2026-08-24)**: 우리 구현은 append와 expunge가 **한 트랜잭션이 아니다**.
   * 두 배치 빌더를 합치는 것이 위험 대비 이득이 적어, 대신 **순서**로 안전성을 만든다 —
   * 넣기가 성공한 뒤에만 지운다. 그래서 실패 모드가 "메일이 사라진다"가 아니라
   * "사본이 하나 남는다"이고, 후자는 사용자가 지울 수 있다. §3이 요구하는 원자성의
   * 핵심(옛 것을 먼저 지우지 않는다)은 지킨다.
   */
  private cmdReplace(cmd: ParsedCommand, uidMode: boolean): ImapAction[] {
    const verb = uidMode ? "UID REPLACE" : "REPLACE";
    const view = this.selected;
    if (!view) return [{ kind: "reply", text: `${cmd.tag} BAD command requires a selected mailbox` }];
    if (!view.readWrite) return [{ kind: "reply", text: `${cmd.tag} NO [READ-ONLY] mailbox is read-only` }];

    const setText = cmd.args[0] ? valueText(cmd.args[0]) : null;
    const ranges = setText !== null ? this.resolveSetArg(setText, uidMode) : null;
    if (!ranges) return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} expects a message number` }];
    const targets = this.resolveTargets(ranges, uidMode);
    /**
     * ★대상이 **정확히 하나**여야 한다(§3: `REPLACE`는 한 통을 바꾼다). 집합을 허용하면
     * "여러 통을 한 통으로 바꾼다"가 되는데 그건 규격에 없고 사용자 의도일 리도 없다.
     */
    if (targets.length !== 1) return [{ kind: "reply", text: `${cmd.tag} NO ${verb} expects exactly one message` }];
    const oldUid = targets[0]!.uid;

    const dest = this.mailboxArg(cmd, 1);
    if (dest === null) return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} expects mailbox name` }];

    // 나머지는 APPEND와 같은 `[flags] [date] literal`이다.
    let idx = 2;
    const flags: string[] = [];
    const flagsVal = cmd.args[idx];
    if (flagsVal?.kind === "list") {
      for (const f of flagsVal.items) {
        const t = valueText(f);
        if (t === null) return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} invalid flag` }];
        flags.push(t);
      }
      idx += 1;
    }
    let internalDateMs: number | null = null;
    const dateVal = cmd.args[idx];
    if (dateVal?.kind === "quoted") {
      const ms = parseImapDateTime(dateVal.value);
      if (ms !== null) {
        internalDateMs = ms;
        idx += 1;
      }
    }
    const msgVal = cmd.args[idx];
    let raw: Uint8Array;
    if (msgVal?.kind === "literal") raw = msgVal.bytes;
    else if (msgVal?.kind === "quoted") raw = new TextEncoder().encode(msgVal.value);
    else return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} expects message literal` }];
    if (raw.length === 0) return [{ kind: "reply", text: `${cmd.tag} NO ${verb} empty message` }];
    if (idx !== cmd.args.length - 1) return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} invalid arguments` }];

    return this.callBackend(
      { kind: "replaceMessage", from: view.name, to: dest, oldUid, raw, flags, internalDateMs },
      (res) => {
        if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, verb, res)];
        if (res.kind !== "replaced") return [{ kind: "reply", text: `${cmd.tag} NO ${verb} failed` }];
        const actions: ImapAction[] = [];
        // 새 메시지가 선택 중 메일함에 들어갔으면 EXISTS를 먼저 알린다(§5의 예시 순서).
        if (view.name === dest && !view.uids.includes(res.uid)) {
          view.uids.push(res.uid);
          view.uids.sort((a, b) => a - b);
          actions.push({ kind: "reply", text: `* ${view.uids.length} EXISTS` });
        }
        if (res.expungedUid !== null) actions.push(...this.removalActions([res.expungedUid]));
        actions.push({ kind: "reply", text: `${cmd.tag} OK [APPENDUID ${res.uidvalidity} ${res.uid}] ${verb} completed` });
        return actions;
      },
    );
  }

  /** COPY/MOVE + UID 변형 (RFC 9051 §6.4.7, RFC 6851) — COPYUID 방출. */
  private cmdCopyMove(cmd: ParsedCommand, uidMode: boolean, op: "copy" | "move"): ImapAction[] {
    const verb = `${uidMode ? "UID " : ""}${op.toUpperCase()}`;
    const view = this.selected;
    if (!view) return [{ kind: "reply", text: `${cmd.tag} BAD command requires a selected mailbox` }];
    if (op === "move" && !view.readWrite) {
      return [{ kind: "reply", text: `${cmd.tag} NO [READ-ONLY] mailbox is read-only` }];
    }
    const setText = cmd.args[0] ? valueText(cmd.args[0]) : null;
    const ranges = setText !== null ? this.resolveSetArg(setText, uidMode) : null;
    const dest = this.mailboxArg(cmd, 1);
    if (!ranges || dest === null || cmd.args.length !== 2) {
      return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} invalid arguments` }];
    }
    const targets = this.resolveTargets(ranges, uidMode);
    if (targets.length === 0) return [{ kind: "reply", text: `${cmd.tag} OK ${verb} completed` }];
    const uids = targets.map((t) => t.uid);

    const req: ImapBackendRequest =
      op === "copy" ? { kind: "copyMessages", from: view.name, to: dest, uids } : { kind: "moveMessages", from: view.name, to: dest, uids };
    return this.callBackend(req, (res) => {
      if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, verb, res)];
      if (res.kind !== "copied") return [{ kind: "reply", text: `${cmd.tag} NO ${verb} failed` }];
      const copyuid = `COPYUID ${res.uidvalidity} ${formatUidSet(res.srcUids)} ${formatUidSet(res.dstUids)}`;
      if (op === "copy") {
        return [{ kind: "reply", text: `${cmd.tag} OK [${copyuid}] ${verb} completed` }];
      }
      // MOVE — RFC 6851: untagged OK [COPYUID] → EXPUNGE/VANISHED → tagged OK
      return [
        { kind: "reply", text: `* OK [${copyuid}] moved` },
        ...this.removalActions(res.srcUids),
        { kind: "reply", text: `${cmd.tag} OK ${verb} completed` },
      ];
    });
  }

  /** seq/uid 집합을 세션 뷰의 {seq, uid} 대상 목록으로 해석. */
  private resolveTargets(ranges: readonly SeqRange[], uidMode: boolean): Array<{ seq: number; uid: number }> {
    const view = this.selected;
    if (!view) return [];
    const targets: Array<{ seq: number; uid: number }> = [];
    if (uidMode) {
      const maxUid = view.uids.length > 0 ? view.uids[view.uids.length - 1]! : 0;
      view.uids.forEach((uid, i) => {
        if (matchSequenceSet(ranges, uid, maxUid)) targets.push({ seq: i + 1, uid });
      });
    } else {
      const max = view.uids.length;
      for (let s = 1; s <= max; s++) {
        if (matchSequenceSet(ranges, s, max)) targets.push({ seq: s, uid: view.uids[s - 1]! });
      }
    }
    return targets;
  }

  /** STORE / UID STORE (RFC 9051 §6.4.6). */
  private cmdStore(cmd: ParsedCommand, uidMode: boolean): ImapAction[] {
    const verb = uidMode ? "UID STORE" : "STORE";
    const view = this.selected;
    if (!view) return [{ kind: "reply", text: `${cmd.tag} BAD command requires a selected mailbox` }];
    if (!view.readWrite) {
      return [{ kind: "reply", text: `${cmd.tag} NO [READ-ONLY] mailbox is read-only` }];
    }
    const setText = cmd.args[0] ? valueText(cmd.args[0]) : null;
    const ranges = setText !== null ? this.resolveSetArg(setText, uidMode) : null;
    // CONDSTORE 수정자(RFC 7162 §3.1.3): STORE set (UNCHANGEDSINCE n) item flags
    let argIdx = 1;
    let unchangedSince: number | null = null;
    const modArg = cmd.args[1];
    if (modArg?.kind === "list" && valueText(modArg.items[0] ?? { kind: "atom", value: "" })?.toUpperCase() === "UNCHANGEDSINCE") {
      const n = valueText(modArg.items[1] ?? { kind: "atom", value: "" });
      if (!n || !/^\d+$/.test(n) || modArg.items.length !== 2) {
        return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} invalid UNCHANGEDSINCE` }];
      }
      unchangedSince = Number(n);
      this.enabled.add("CONDSTORE");
      argIdx = 2;
    }
    const itemText = cmd.args[argIdx] ? valueText(cmd.args[argIdx]!)?.toUpperCase() : null;
    if (!ranges || !itemText) return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} invalid arguments` }];

    const m = /^([+-]?)FLAGS(\.SILENT)?$/.exec(itemText);
    if (!m) return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} unknown data item` }];
    const mode = m[1] === "+" ? "add" : m[1] === "-" ? "remove" : "set";
    const silent = m[2] !== undefined;

    // 플래그: 리스트 또는 나열된 atom들(RFC는 괄호 생략 허용)
    const flagValues =
      cmd.args.length === argIdx + 2 && cmd.args[argIdx + 1]?.kind === "list"
        ? (cmd.args[argIdx + 1] as Extract<ImapValue, { kind: "list" }>).items
        : cmd.args.slice(argIdx + 1);
    const flags: string[] = [];
    for (const fv of flagValues) {
      const t = valueText(fv);
      if (t === null) return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} invalid flag` }];
      flags.push(t);
    }
    // 빈 flag-list도 유효(ABNF: "(" [flag ...] ")") — +/-FLAGS ()는 no-op, FLAGS ()는 전체 해제

    const targets = this.resolveTargets(ranges, uidMode);
    if (targets.length === 0) return [{ kind: "reply", text: `${cmd.tag} OK ${verb} completed` }];
    const seqByUid = new Map(targets.map((t) => [t.uid, t.seq]));

    const req: ImapBackendRequest = {
      kind: "storeFlags",
      name: view.name,
      uids: targets.map((t) => t.uid),
      mode,
      flags,
      ...(unchangedSince !== null ? { unchangedSince } : {}),
    };
    return this.callBackend(req, (res) => {
      if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, verb, res)];
      if (res.kind !== "flagsUpdated") return [{ kind: "reply", text: `${cmd.tag} NO ${verb} failed` }];
      const condstore = this.enabled.has("CONDSTORE");
      const actions: ImapAction[] = [];
      if (!silent) {
        for (const u of res.updated) {
          const seq = seqByUid.get(u.uid);
          if (seq === undefined) continue;
          actions.push(...this.ensureFlagsAnnounced(u.flags));
          const uidPart = uidMode ? ` UID ${u.uid}` : "";
          const modseqPart = condstore && u.modseq !== undefined ? ` MODSEQ (${u.modseq})` : "";
          actions.push({ kind: "reply", text: `* ${seq} FETCH (FLAGS (${u.flags.join(" ")})${uidPart}${modseqPart})` });
        }
      }
      // UNCHANGEDSINCE 충돌 — MODIFIED 응답 코드(실패 집합, RFC 7162)
      const failed = res.failed ?? [];
      if (failed.length > 0) {
        const failedSet = uidMode
          ? formatUidSet(failed)
          : formatUidSet(failed.map((uid) => seqByUid.get(uid) ?? 0).filter((s) => s > 0));
        actions.push({ kind: "reply", text: `${cmd.tag} OK [MODIFIED ${failedSet}] conditional ${verb} failed for some messages` });
      } else {
        actions.push({ kind: "reply", text: `${cmd.tag} OK ${verb} completed` });
      }
      return actions;
    });
  }

  /** EXPUNGE / UID EXPUNGE(UIDPLUS) — untagged EXPUNGE는 내림차순 seq로 방출. */
  private cmdExpunge(cmd: ParsedCommand, uidRanges: SeqRange[] | null): ImapAction[] {
    const verb = uidRanges ? "UID EXPUNGE" : "EXPUNGE";
    const view = this.selected;
    if (!view) return [{ kind: "reply", text: `${cmd.tag} BAD command requires a selected mailbox` }];
    if (!view.readWrite) {
      return [{ kind: "reply", text: `${cmd.tag} NO [READ-ONLY] mailbox is read-only` }];
    }
    const limitUids = uidRanges ? this.resolveTargets(uidRanges, true).map((t) => t.uid) : null;
    if (limitUids !== null && limitUids.length === 0) {
      return [{ kind: "reply", text: `${cmd.tag} OK ${verb} completed` }];
    }
    return this.callBackend({ kind: "expunge", name: view.name, uids: limitUids }, (res) => {
      if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, verb, res)];
      if (res.kind !== "expunged") return [{ kind: "reply", text: `${cmd.tag} NO ${verb} failed` }];
      return [...this.removalActions(res.uids), { kind: "reply", text: `${cmd.tag} OK ${verb} completed` }];
    });
  }

  /**
   * 응답에 쓰일 플래그 중 미공지 키워드가 있으면 `* FLAGS` 재공지를 선행한다
   * (imaptest: "Keyword used without being in FLAGS" 검사 — RFC 3501 관행).
   */
  private ensureFlagsAnnounced(flags: readonly string[]): ImapAction[] {
    const view = this.selected;
    if (!view) return [];
    const systems = new Set<string>(SYSTEM_FLAGS.map((f) => f.toUpperCase()));
    let changed = false;
    for (const f of flags) {
      if (systems.has(f.toUpperCase())) continue;
      if (!view.announcedKeywords.has(f)) {
        view.announcedKeywords.add(f);
        changed = true;
      }
    }
    return changed ? [{ kind: "reply", text: flagsLine(view.announcedKeywords) }] : [];
  }

  /**
   * NOOP/CHECK 시 재동기화 — 백엔드 스냅샷과 세션 뷰를 diff해 타 세션의
   * EXPUNGE(제거)·APPEND(추가 EXISTS)를 반영한다(멀티 세션 가시성 — imaptest 요구).
   */
  private refreshSelected(taggedOk: string | null): ImapAction[] {
    const view = this.selected;
    if (!view) return taggedOk !== null ? [{ kind: "reply", text: taggedOk }] : [];
    return this.callBackend({ kind: "selectMailbox", name: view.name }, (res) => {
      if (res.kind !== "selected") return taggedOk !== null ? [{ kind: "reply", text: taggedOk }] : [];
      const current = this.selected;
      if (!current) return taggedOk !== null ? [{ kind: "reply", text: taggedOk }] : [];
      const actions: ImapAction[] = [];
      // 키워드 목록의 DB 진실 — 축소 공지는 배치 "끝"에서(EXPUNGE·플래그 델타가
      // 먼저 반영돼야 클라이언트 모델에 참조가 남지 않음 — imaptest keyword refcount)
      const dbKeywords = new Set(res.keywords ?? []);
      const syncKeywordList = (extra: Iterable<string>): ImapAction[] => {
        const v = this.selected;
        if (!v) return [];
        const finalSet = new Set(dbKeywords);
        for (const k of extra) if (!k.startsWith("\\")) finalSet.add(k); // 스냅샷 후 등장분 보존
        const differs = finalSet.size !== v.announcedKeywords.size || [...finalSet].some((k) => !v.announcedKeywords.has(k));
        if (!differs) return [];
        v.announcedKeywords = finalSet;
        return [{ kind: "reply", text: flagsLine(finalSet) }];
      };
      const fresh = new Set(res.uids);
      const removed = current.uids.filter((u) => !fresh.has(u));
      actions.push(...this.removalActions(removed));
      const known = new Set(current.uids);
      const added = res.uids.filter((u) => !known.has(u));
      if (added.length > 0) {
        current.uids.push(...added);
        current.uids.sort((a, b) => a - b);
        actions.push({ kind: "reply", text: `* ${current.uids.length} EXISTS` });
      }
      // 플래그 델타 — 타 세션의 STORE를 untagged FETCH FLAGS로 전파(checkpoint 일관성)
      const since = current.lastSyncModseq;
      const newWatermark = res.mailbox.highestmodseq;
      if (newWatermark <= since) {
        actions.push(...syncKeywordList([]));
        if (taggedOk !== null) actions.push({ kind: "reply", text: taggedOk });
        return actions;
      }
      return [
        ...actions,
        ...this.callBackend({ kind: "syncSince", name: current.name, sinceModseq: since }, (sync) => {
          const out: ImapAction[] = [];
          const deltaKeywords: string[] = [];
          if (sync.kind === "sync") {
            const v = this.selected;
            if (v) {
              v.lastSyncModseq = newWatermark;
              const condstore = this.enabled.has("CONDSTORE");
              for (const c of sync.changed) {
                const seq = v.uids.indexOf(c.uid) + 1;
                if (seq <= 0) continue;
                deltaKeywords.push(...c.flags);
                out.push(...this.ensureFlagsAnnounced(c.flags));
                const modseqPart = condstore ? ` MODSEQ (${c.modseq})` : "";
                out.push({ kind: "reply", text: `* ${seq} FETCH (UID ${c.uid} FLAGS (${c.flags.join(" ")})${modseqPart})` });
              }
            }
          }
          out.push(...syncKeywordList(deltaKeywords));
          if (taggedOk !== null) out.push({ kind: "reply", text: taggedOk });
          return out;
        }),
      ];
    });
  }

  /**
   * 메시지 제거 알림 — QRESYNC 활성 시 `* VANISHED uid-set`, 아니면 내림차순
   * `* n EXPUNGE`(앞선 제거가 뒤 seq를 흔들지 않는 순서). 세션 뷰도 갱신.
   */
  private removalActions(uids: readonly number[]): ImapAction[] {
    const view = this.selected;
    if (!view) return [];
    if (this.enabled.has("QRESYNC")) {
      const present = uids.filter((u) => view.uids.includes(u));
      for (const u of present) view.uids.splice(view.uids.indexOf(u), 1);
      return present.length > 0 ? [{ kind: "reply", text: `* VANISHED ${formatUidSet(present)}` }] : [];
    }
    const actions: ImapAction[] = [];
    const idxs = uids
      .map((uid) => view.uids.indexOf(uid))
      .filter((i) => i !== -1)
      .sort((a, b) => b - a);
    for (const i of idxs) {
      actions.push({ kind: "reply", text: `* ${i + 1} EXPUNGE` });
      view.uids.splice(i, 1);
    }
    return actions;
  }

  /**
   * 시퀀스셋 인자 해석 — `$`(SEARCHRES, RFC 5182)를 저장된 검색 결과로 편다.
   *
   * ★저장은 UID인데 사용처는 seq일 수도 UID일 수도 있다(§2.4: `UID SEARCH`로 저장한 `$`를
   * 비UID `FETCH`에 쓰는 것이 허용된다). 그래서 **쓰는 시점에** 모드에 맞춰 옮긴다 —
   * 저장 시점에 옮겨 두면 그 사이의 EXPUNGE가 번호를 밀어 틀린 집합이 된다.
   *
   * 뷰에 없는 UID(그 사이 사라진 것)는 조용히 빠진다. 그게 §2.1이 요구하는 동작이다.
   */
  private resolveSetArg(text: string, uidMode: boolean): SeqRange[] | null {
    if (text !== "$") return parseSequenceSet(text);
    const view = this.selected;
    if (!view) return null;
    const numbers: number[] = [];
    for (const uid of this.savedSearch) {
      if (uidMode) {
        if (view.uids.includes(uid)) numbers.push(uid);
        continue;
      }
      const i = view.uids.indexOf(uid);
      if (i !== -1) numbers.push(i + 1);
    }
    numbers.sort((a, b) => a - b);
    return numbers.map((n) => ({ from: n, to: n }));
  }

  /** SEARCH / UID SEARCH (RFC 9051 §6.4.4) — rev1 고전 응답(`* SEARCH n...`). */
  private cmdSearch(cmd: ParsedCommand, uidMode: boolean): ImapAction[] {
    const verb = uidMode ? "UID SEARCH" : "SEARCH";
    const view = this.selected;
    if (!view) return [{ kind: "reply", text: `${cmd.tag} BAD command requires a selected mailbox` }];
    // ESEARCH(RFC 4731): SEARCH RETURN (MIN MAX COUNT ALL) <criteria>
    let esearch: Set<string> | null = null;
    let critArgs = cmd.args;
    if (valueText(cmd.args[0] ?? { kind: "atom", value: "" })?.toUpperCase() === "RETURN" && cmd.args[1]?.kind === "list") {
      esearch = new Set();
      for (const o of cmd.args[1].items) {
        const t = valueText(o)?.toUpperCase();
        if (t !== "MIN" && t !== "MAX" && t !== "COUNT" && t !== "ALL" && t !== "SAVE") {
          return [{ kind: "reply", text: `${cmd.tag} BAD unknown RETURN option` }];
        }
        esearch.add(t);
      }
      if (esearch.size === 0) esearch.add("ALL"); // RETURN () == RETURN (ALL) — RFC 4731
      critArgs = cmd.args.slice(2);
    } else if (this.enabled.has("IMAP4rev2")) {
      /**
       * ★rev2에서는 RETURN이 없어도 **ESEARCH로** 답한다(RFC 9051 §6.4.4 — 고전
       * `* SEARCH n n n` 응답이 rev2에서 사라졌다). rev1 클라이언트는 ESEARCH를 못 읽으므로
       * ENABLE 전에는 절대 이 갈래로 오면 안 된다.
       */
      esearch = new Set(["ALL"]);
    }
    const program = parseSearchProgram(critArgs);
    if (!program.ok) {
      return [
        {
          kind: "reply",
          text: program.badCharset
            ? `${cmd.tag} NO [BADCHARSET (UTF-8 US-ASCII)] unsupported charset`
            : `${cmd.tag} BAD ${verb} invalid search criteria`,
        },
      ];
    }
    if (view.uids.length === 0) {
      if (esearch?.has("SAVE")) this.savedSearch = [];
      const line = ImapEngine.searchReply(cmd.tag, uidMode, esearch, []);
      return [
        ...(line === null ? [] : [{ kind: "reply" as const, text: line }]),
        { kind: "reply", text: `${cmd.tag} OK ${verb} completed` },
      ];
    }
    const needRaw = searchNeedsRaw(program.key);
    const maxSeq = view.uids.length;
    const maxUid = view.uids[view.uids.length - 1] ?? 0;
    /**
     * ★SEARCH도 배치로 나눈다. 예전엔 메일함 **전체** uid를 한 요청에 실었고 `needRaw`면
     * 블롭 전부가 메모리에 올라왔다 — `SEARCH BODY "x"` 한 줄이 5만 통 × 50KB = 2.5GB였다.
     *
     * FETCH와 달리 **응답을 배치마다 흘릴 수 없다**: `* SEARCH`는 매칭 전체를 한 줄에 싣고
     * ESEARCH의 MIN/MAX/COUNT도 전량을 봐야 정해진다. 그래서 배치는 원문의 상주 시간을 줄이고
     * (배치가 끝나면 그 raw는 버려진다) 누적하는 것은 **매칭된 번호뿐**이다 — 그건 통당
     * 4바이트라 5만 통이어도 문제가 되지 않는다.
     */
    const batchSize = needRaw ? FETCH_BATCH_RAW : FETCH_BATCH_META;
    const hits: number[] = [];
    /** SAVE용 — `$`는 UID로 담는다(위 `savedSearch` 주석). hits와 같은 순서·같은 길이다. */
    const hitUids: number[] = [];
    const searchFrom = (offset: number): ImapAction[] => {
      const batchUids = view.uids.slice(offset, offset + batchSize);
      return this.callBackend(
        { kind: "fetchMessages", name: view.name, uids: batchUids, needRaw, markSeen: false },
        (res) => {
          if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, verb, res)];
          if (res.kind !== "messages") return [{ kind: "reply", text: `${cmd.tag} NO ${verb} failed` }];
          const byUid = new Map(res.messages.map((m) => [m.uid, m]));
          batchUids.forEach((uid, k) => {
            const data = byUid.get(uid);
            if (!data) return;
            const i = offset + k; // 세션 뷰 인덱스 → seq는 i+1
            const matched = evaluateSearch(
              program.key,
              { seq: i + 1, uid, flags: data.flags, size: data.size, internalDateMs: data.internalDateMs, saveDateMs: data.saveDateMs, modseq: data.modseq, raw: data.raw },
              maxSeq,
              maxUid,
            );
            if (matched) {
              hits.push(uidMode ? uid : i + 1);
              hitUids.push(uid);
            }
          });
          const next = offset + batchSize;
          if (next < view.uids.length) return searchFrom(next);
          if (esearch?.has("SAVE")) this.savedSearch = ImapEngine.savedFor(esearch, hitUids);
          const line = ImapEngine.searchReply(cmd.tag, uidMode, esearch, hits);
          return [
            ...(line === null ? [] : [{ kind: "reply" as const, text: line }]),
            { kind: "reply", text: `${cmd.tag} OK ${verb} completed` },
          ];
        },
      );
    };
    return searchFrom(0);
  }

  /**
   * SORT / THREAD (RFC 5256) — 두 명령이 **같은 뼈대**를 쓴다.
   *
   * 둘 다 "크라이테리어로 고른 뒤 정렬해서 번호를 낸다"이고, 다른 것은 마지막 조립뿐이다
   * (SORT는 평평한 목록, THREAD는 괄호 트리). 나눠 쓰면 배치 순회와 크라이테리어 파싱이
   * 두 벌이 되고, 그러면 한쪽만 고쳐지는 형태로 갈라진다.
   *
   * ★정렬 키는 **스토어가 물질화해 둔 값**으로 만든다(`sortKeys`). 원문을 파싱해 제목·발신자를
   * 뽑으면 정렬 한 번에 메일함 전체 블롭이 메모리에 올라온다 — SEARCH가 예전에 그렇게 해서
   * 5만 통 × 50KB = 2.5GB였다. 크라이테리어가 본문을 볼 때만 원문을 싣는다.
   */
  private cmdSortThread(cmd: ParsedCommand, uidMode: boolean, mode: "sort" | "thread"): ImapAction[] {
    const verb = `${uidMode ? "UID " : ""}${mode.toUpperCase()}`;
    const view = this.selected;
    if (!view) return [{ kind: "reply", text: `${cmd.tag} BAD command requires a selected mailbox` }];

    /**
     * 첫 인자는 SORT면 정렬 기준 리스트, THREAD면 알고리즘 이름. 그다음이 charset,
     * 그다음이 크라이테리어다(RFC 5256 §3·§4 — charset은 **필수 인자**다).
     */
    let sortSpec: SortSpec[] = [];
    let algorithm = "ORDEREDSUBJECT";
    let idx = 0;
    if (mode === "sort") {
      const list = cmd.args[0];
      if (!list || list.kind !== "list") return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} expects a sort criteria list` }];
      const parsed = parseSortSpec(list.items);
      if (parsed === null) return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} invalid sort criteria` }];
      sortSpec = parsed;
      idx = 1;
    } else {
      const alg = valueText(cmd.args[0] ?? { kind: "atom", value: "" })?.toUpperCase();
      if (alg !== "ORDEREDSUBJECT" && alg !== "REFERENCES") {
        return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} unsupported threading algorithm` }];
      }
      algorithm = alg;
      idx = 1;
    }

    // charset — US-ASCII/UTF-8만 받는다(SEARCH의 CHARSET 처리와 같은 규칙).
    const charset = valueText(cmd.args[idx] ?? { kind: "atom", value: "" })?.toUpperCase();
    if (charset === undefined || charset === null) return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} expects a charset` }];
    if (charset !== "UTF-8" && charset !== "US-ASCII") {
      return [{ kind: "reply", text: `${cmd.tag} NO [BADCHARSET (UTF-8 US-ASCII)] unsupported charset` }];
    }
    idx += 1;

    const program = parseSearchProgram(cmd.args.slice(idx));
    if (!program.ok) {
      return [
        {
          kind: "reply",
          text: program.badCharset
            ? `${cmd.tag} NO [BADCHARSET (UTF-8 US-ASCII)] unsupported charset`
            : `${cmd.tag} BAD ${verb} invalid search criteria`,
        },
      ];
    }

    const emptyLine = mode === "sort" ? "* SORT" : "* THREAD";
    if (view.uids.length === 0) {
      return [
        { kind: "reply", text: emptyLine },
        { kind: "reply", text: `${cmd.tag} OK ${verb} completed` },
      ];
    }

    const needRaw = searchNeedsRaw(program.key);
    const maxSeq = view.uids.length;
    const maxUid = view.uids[view.uids.length - 1] ?? 0;
    const batchSize = needRaw ? FETCH_BATCH_RAW : FETCH_BATCH_META;
    /** 매칭된 메시지의 (번호, 정렬키). 원문은 배치가 끝나면 버려진다. */
    const hits: { num: number; seq: number; uid: number; keys: ImapSortKeys }[] = [];
    /** ARRIVAL·SIZE 정렬용 — hits를 넓히지 않고 곁에 둔다. */
    const sortMeta = new Map<number, { internalDateMs: number; size: number }>();

    const step = (offset: number): ImapAction[] => {
      const batchUids = view.uids.slice(offset, offset + batchSize);
      return this.callBackend(
        { kind: "fetchMessages", name: view.name, uids: batchUids, needRaw, markSeen: false, needSortKeys: true },
        (res) => {
          if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, verb, res)];
          if (res.kind !== "messages") return [{ kind: "reply", text: `${cmd.tag} NO ${verb} failed` }];
          const byUid = new Map(res.messages.map((m) => [m.uid, m]));
          batchUids.forEach((uid, k) => {
            const data = byUid.get(uid);
            if (!data) return;
            const i = offset + k;
            const matched = evaluateSearch(
              program.key,
              { seq: i + 1, uid, flags: data.flags, size: data.size, internalDateMs: data.internalDateMs, saveDateMs: data.saveDateMs, modseq: data.modseq, raw: data.raw },
              maxSeq,
              maxUid,
            );
            if (!matched) return;
            hits.push({
              num: uidMode ? uid : i + 1,
              seq: i + 1,
              uid,
              keys: data.sortKeys ?? { subjectBase: "", sentAtMs: 0, threadId: "", from: "", to: "", cc: "" },
            });
            sortMeta.set(uid, { internalDateMs: data.internalDateMs, size: data.size });
          });
          const next = offset + batchSize;
          if (next < view.uids.length) return step(next);

          const line = mode === "sort" ? formatSortLine(hits, sortSpec, sortMeta) : formatThreadLine(hits, algorithm);
          return [
            { kind: "reply", text: line },
            { kind: "reply", text: `${cmd.tag} OK ${verb} completed` },
          ];
        },
      );
    };
    return step(0);
  }

  /**
   * `$`에 담을 UID들 (RFC 5182 §2.1의 표).
   *
   * SAVE가 MIN/MAX와만 함께 오면 **그 한두 통만** 담고, ALL이나 COUNT가 섞이면 전부 담는다.
   * hitUids는 오름차순이라 MIN은 첫 원소, MAX는 마지막 원소다.
   */
  private static savedFor(esearch: Set<string>, hitUids: readonly number[]): number[] {
    if (hitUids.length === 0) return [];
    const minMaxOnly = (esearch.has("MIN") || esearch.has("MAX")) && !esearch.has("ALL") && !esearch.has("COUNT");
    if (!minMaxOnly) return [...hitUids];
    const out = new Set<number>();
    if (esearch.has("MIN")) out.add(hitUids[0]!);
    if (esearch.has("MAX")) out.add(hitUids[hitUids.length - 1]!);
    return [...out].sort((a, b) => a - b);
  }

  /**
   * SEARCH 응답 — 고전(`* SEARCH n...`) 또는 ESEARCH(RFC 4731). hits는 seq/uid(모드별).
   *
   * ★SAVE만 있으면 **아무 응답도 내지 않는다**(RFC 5182 §2.2: "In absence of any other
   * SEARCH result option, the SAVE result option also suppresses any SEARCH response").
   * 그래서 반환형이 `| null`이다.
   */
  private static searchReply(tag: string, uidMode: boolean, esearch: Set<string> | null, hits: readonly number[]): string | null {
    if (esearch === null) return `* SEARCH${hits.length > 0 ? " " + hits.join(" ") : ""}`;
    if (esearch.has("SAVE") && esearch.size === 1) return null;
    const parts = [`(TAG "${tag}")`];
    if (uidMode) parts.push("UID");
    // MIN/MAX/ALL은 매칭 없으면 생략, COUNT는 항상(RFC 4731 §3.1)
    if (hits.length > 0) {
      if (esearch.has("MIN")) parts.push(`MIN ${Math.min(...hits)}`);
      if (esearch.has("MAX")) parts.push(`MAX ${Math.max(...hits)}`);
      if (esearch.has("ALL")) parts.push(`ALL ${formatUidSet(hits)}`);
    }
    if (esearch.has("COUNT")) parts.push(`COUNT ${hits.length}`);
    return `* ESEARCH ${parts.join(" ")}`;
  }

  /** FETCH 항목 하나의 와이어 문자열(latin1) — fetch-format.ts 규약. */
  private fetchItemWire(it: FetchItem, uid: number, data: ImapFetchData): string | null {
    const raw = data.raw ?? new Uint8Array(0);
    switch (it.kind) {
      case "flags":
        return `FLAGS (${data.flags.join(" ")})`;
      case "uid":
        return `UID ${uid}`;
      case "modseq":
        return `MODSEQ (${data.modseq})`;
      case "internaldate":
        return `INTERNALDATE "${formatInternalDate(data.internalDateMs)}"`;
      case "emailid":
        // 없으면 NIL — "id가 없다"와 "빈 id"는 다르다(RFC 8474 §4).
        return `EMAILID ${data.emailId === undefined ? "NIL" : `(${data.emailId})`}`;
      case "threadid":
        return `THREADID ${data.threadId === undefined || data.threadId === "" ? "NIL" : `(${data.threadId})`}`;
      case "savedate":
        // 저장 시각을 모르면 NIL이 규격이다(RFC 8514 §3) — 우리는 항상 아는데 타입이 선택이다.
        return `SAVEDATE ${data.saveDateMs === undefined ? "NIL" : `"${formatInternalDate(data.saveDateMs)}"`}`;
      case "rfc822size":
        return `RFC822.SIZE ${data.size}`;
      case "envelope":
        return `ENVELOPE ${formatEnvelope(raw)}`;
      case "body":
        return `BODY ${formatBodyStructure(raw, false)}`;
      case "bodystructure":
        return `BODYSTRUCTURE ${formatBodyStructure(raw, true)}`;
      case "section": {
        let bytes = extractSection(raw, it.spec);
        if (bytes !== null && it.partial) {
          bytes = bytes.subarray(it.partial.start, it.partial.start + it.partial.count);
        }
        return `${it.label} ${bytes === null ? "NIL" : literalWire(bytes)}`;
      }
      case "binary": {
        const got = extractBinary(raw, it.path);
        if (got === null) return `${it.label} NIL`; // 없는 파트 — 섹션과 같은 규약
        if (got.kind === "unknown-cte") return null; // 호출자가 NO [UNKNOWN-CTE]로 옮긴다
        // ★partial은 **푼 뒤** 기준이다(RFC 3516 §4.2) — 인코딩된 바이트로 자르면 쓰레기가 나온다.
        const bytes = it.partial ? got.bytes.subarray(it.partial.start, it.partial.start + it.partial.count) : got.bytes;
        return `${it.label} ${binaryLiteralWire(bytes)}`;
      }
      case "binarySize": {
        const got = extractBinary(raw, it.path);
        if (got === null) return `${it.label} 0`; // 없는 파트는 0(크기 항목에 NIL은 문법상 못 온다)
        if (got.kind === "unknown-cte") return null;
        return `${it.label} ${got.bytes.length}`;
      }
    }
  }

  /** STATUS (RFC 9051 §6.3.11 + STATUS=SIZE RFC 8438 + HIGHESTMODSEQ RFC 7162). */
  private cmdStatus(cmd: ParsedCommand): ImapAction[] {
    const name = this.mailboxArg(cmd, 0);
    const items = cmd.args[1];
    if (name === null || !items || items.kind !== "list" || cmd.args.length !== 2) {
      return [{ kind: "reply", text: `${cmd.tag} BAD STATUS expects mailbox name and item list` }];
    }
    const wanted: string[] = [];
    for (const it of items.items) {
      const t = valueText(it)?.toUpperCase();
      if (!t) return [{ kind: "reply", text: `${cmd.tag} BAD invalid STATUS item` }];
      wanted.push(t);
    }
    if (wanted.length === 0) {
      return [{ kind: "reply", text: `${cmd.tag} BAD empty STATUS item list` }];
    }
    return this.callBackend({ kind: "listMailboxes" }, (res) => {
      if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, "STATUS", res)];
      if (res.kind !== "mailboxes") return [{ kind: "reply", text: `${cmd.tag} NO STATUS failed` }];
      const m = res.mailboxes.find((x) => x.name === name);
      if (!m) {
        return [{ kind: "reply", text: `${cmd.tag} NO [NONEXISTENT] STATUS no such mailbox` }];
      }
      const fields = ImapEngine.statusFields(m, wanted);
      if (fields === null) return [{ kind: "reply", text: `${cmd.tag} BAD unknown STATUS item` }];
      return [
        { kind: "reply", text: `* STATUS ${quoteMailboxName(m.name)} (${fields.join(" ")})` },
        { kind: "reply", text: `${cmd.tag} OK STATUS completed` },
      ];
    });
  }

  /** STATUS 항목 포매팅 — STATUS 명령과 LIST-STATUS(RFC 5819)가 공유. 미지 항목이면 null. */
  private static statusFields(m: ImapMailbox, wanted: readonly string[]): string[] | null {
    const fields: string[] = [];
    for (const item of wanted) {
      switch (item) {
        case "MESSAGES":
          fields.push(`MESSAGES ${m.totalCount}`);
          break;
        case "RECENT":
          fields.push("RECENT 0"); // rev2 시맨틱 — \Recent 미지원(항상 0)
          break;
        case "MAILBOXID":
          if (m.mailboxId !== undefined) fields.push(`MAILBOXID (${m.mailboxId})`);
          break;
        case "UIDNEXT":
          fields.push(`UIDNEXT ${m.uidnext}`);
          break;
        case "UIDVALIDITY":
          fields.push(`UIDVALIDITY ${m.uidvalidity}`);
          break;
        case "UNSEEN":
          fields.push(`UNSEEN ${m.unreadCount}`);
          break;
        case "SIZE":
          fields.push(`SIZE ${m.totalBytes}`);
          break;
        case "HIGHESTMODSEQ":
          fields.push(`HIGHESTMODSEQ ${m.highestmodseq}`);
          break;
        default:
          return null;
      }
    }
    return fields;
  }

  /**
   * GETQUOTA / GETQUOTAROOT (RFC 9208 §4.2·§4.3).
   *
   * 쿼터가 계정 단위라 루트가 하나뿐이고, 어떤 메일함을 물어도 같은 루트를 답한다.
   * STORAGE 단위는 **KiB**다(§5.2) — 바이트로 답하면 클라이언트가 1024배로 표시한다.
   */
  private cmdGetQuota(cmd: ParsedCommand, verb: "GETQUOTA" | "GETQUOTAROOT"): ImapAction[] {
    const arg = cmd.args[0] ? valueText(cmd.args[0]) : null;
    if (arg === null || cmd.args.length !== 1) {
      return [{ kind: "reply", text: `${cmd.tag} BAD ${verb} expects one argument` }];
    }
    // GETQUOTA는 **루트 이름**을 받는다 — 우리가 광고한 것 말고는 없다.
    if (verb === "GETQUOTA" && normalizeMailboxName(arg) !== QUOTA_ROOT) {
      return [{ kind: "reply", text: `${cmd.tag} NO [NONEXISTENT] no such quota root` }];
    }
    const mailbox = normalizeMailboxName(arg);
    return this.callBackend({ kind: "getQuota" }, (res) => {
      if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, verb, res)];
      if (res.kind !== "quota") return [{ kind: "reply", text: `${cmd.tag} NO ${verb} failed` }];
      const actions: ImapAction[] = [];
      if (verb === "GETQUOTAROOT") {
        actions.push({ kind: "reply", text: `* QUOTAROOT ${quoteMailboxName(mailbox)} ${quoteMailboxName(QUOTA_ROOT)}` });
      }
      actions.push({ kind: "reply", text: `* QUOTA ${quoteMailboxName(QUOTA_ROOT)} (${ImapEngine.quotaResources(res)})` });
      actions.push({ kind: "reply", text: `${cmd.tag} OK ${verb} completed` });
      return actions;
    });
  }

  /**
   * `* QUOTA`의 자원 목록.
   *
   * ★한도가 0(무제한)이면 **STORAGE를 싣지 않는다.** RFC 9208은 "한도 없음"을 표현하는 값을
   * 정의하지 않으므로, 0을 실으면 클라이언트가 "0바이트 허용"으로 읽고 업로드를 막는다 —
   * 없는 제한을 있다고 말하는 셈이다. 자원이 하나도 없으면 빈 목록이 되고, 그건 RFC가
   * 허용하는 "이 루트에 제한이 없다"는 표현이다.
   */
  private static quotaResources(q: Extract<ImapBackendResponse, { kind: "quota" }>): string {
    if (q.limitBytes <= 0) return "";
    // STORAGE 단위는 KiB(§5.2). 올림해야 "한도보다 조금 적게 썼는데 꽉 찼다"가 되지 않는다.
    const usedKib = Math.ceil(q.usedBytes / 1024);
    const limitKib = Math.ceil(q.limitBytes / 1024);
    return `STORAGE ${usedKib} ${limitKib}`;
  }

  private cmdCapability(cmd: ParsedCommand): ImapAction[] {
    return [
      { kind: "reply", text: `* CAPABILITY ${this.capabilities().join(" ")}` },
      { kind: "reply", text: `${cmd.tag} OK CAPABILITY completed` },
    ];
  }

  private cmdLogout(cmd: ParsedCommand): ImapAction[] {
    this.closed = true;
    return [
      { kind: "reply", text: `* BYE ${this.hostname} logging out` },
      { kind: "reply", text: `${cmd.tag} OK LOGOUT completed` },
      { kind: "close" },
    ];
  }

  /** ID (RFC 2971) — 클라이언트 파라미터는 무시 가능. 서버 정보 최소 응답. */
  private cmdId(cmd: ParsedCommand): ImapAction[] {
    return [
      { kind: "reply", text: '* ID ("name" "ionosphere")' },
      { kind: "reply", text: `${cmd.tag} OK ID completed` },
    ];
  }

  /**
   * STARTTLS (RFC 3501 §6.2.1) — OK를 보낸 **직후** 어댑터가 소켓을 승격한다.
   *
   * ★OK 응답 다음 바이트부터 TLS 핸드셰이크다. 그래서 여기서 파이프라인 버퍼를 **버린다** —
   * 평문 구간에 미리 밀어 넣은 명령을 업그레이드 후에 실행하면 그것이 곧 명령 주입이다
   * (RFC 3501이 "버려야 한다"고 못 박은 이유).
   */
  private cmdStartTls(cmd: ParsedCommand): ImapAction[] {
    if (this.secure) return [{ kind: "reply", text: `${cmd.tag} BAD TLS already active` }];
    if (!this.tlsAvailable) return [{ kind: "reply", text: `${cmd.tag} NO STARTTLS not available` }];
    // 대기 중인 백엔드 왕복이 있으면 업그레이드 경계가 흐려진다 — 거절이 안전하다.
    if (this.pending || this.idleTag !== null) return [{ kind: "reply", text: `${cmd.tag} BAD STARTTLS not allowed mid-command` }];
    this.awaitingTls = true;
    this.queued.length = 0;
    this.queuedBytes = 0;
    return [{ kind: "reply", text: `${cmd.tag} OK Begin TLS negotiation now` }, { kind: "startTls" }];
  }

  private cmdLogin(cmd: ParsedCommand): ImapAction[] {
    if (this.state !== "not-authenticated") {
      return [{ kind: "reply", text: `${cmd.tag} BAD LOGIN not allowed in current state` }];
    }
    if (!this.authAllowed()) {
      return [{ kind: "reply", text: `${cmd.tag} NO [PRIVACYREQUIRED] LOGIN disabled on insecure connection` }];
    }
    const user = cmd.args[0] ? valueText(cmd.args[0]) : null;
    const pass = cmd.args[1] ? valueText(cmd.args[1]) : null;
    if (user === null || pass === null || cmd.args.length !== 2) {
      return [{ kind: "reply", text: `${cmd.tag} BAD LOGIN expects username and password` }];
    }
    this.pending = { kind: "auth", tag: cmd.tag };
    return [{ kind: "auth", user, pass }];
  }

  private cmdAuthenticate(cmd: ParsedCommand): ImapAction[] {
    if (this.state !== "not-authenticated") {
      return [{ kind: "reply", text: `${cmd.tag} BAD AUTHENTICATE not allowed in current state` }];
    }
    if (!this.authAllowed()) {
      return [{ kind: "reply", text: `${cmd.tag} NO [PRIVACYREQUIRED] AUTHENTICATE disabled on insecure connection` }];
    }
    const mech = cmd.args[0] ? valueText(cmd.args[0])?.toUpperCase() : null;
    if (mech === SCRAM_MECHANISM && this.scramOffered) {
      const sasl: SaslPending = {
        tag: cmd.tag,
        mechanism: SCRAM_MECHANISM,
        scram: { session: new ScramServerSession(this.scramDecoySecret), stage: "clientFirst" },
      };
      const initialScram = cmd.args[1] ? valueText(cmd.args[1]) : null;
      if (cmd.args.length > 2) return [{ kind: "reply", text: `${cmd.tag} BAD too many arguments` }];
      if (initialScram !== null) return this.handleSaslData(sasl, initialScram);
      this.pending = { kind: "sasl-line", sasl };
      return [{ kind: "reply", text: "+ " }];
    }
    const mechanism = SASL_MECHANISMS.find((m) => m === mech);
    if (!mechanism) {
      return [{ kind: "reply", text: `${cmd.tag} NO [CANNOT] unsupported authentication mechanism` }];
    }
    const initial = cmd.args[1] ? valueText(cmd.args[1]) : null;
    if (cmd.args.length > 2) {
      return [{ kind: "reply", text: `${cmd.tag} BAD too many arguments` }];
    }
    if (initial !== null) {
      // SASL-IR (RFC 4959) — initial response 동봉
      return this.handleSaslData({ tag: cmd.tag, mechanism }, initial);
    }
    this.pending = { kind: "sasl-line", sasl: { tag: cmd.tag, mechanism } };
    return [{ kind: "reply", text: "+ " }];
  }

  private handleSaslData(sasl: SaslPending, data: string | null): ImapAction[] {
    /**
     * ★server-final 다음 줄은 **빈 줄**이다(RFC 4959 흐름). IMAP 리더는 빈 줄을
     * `null`(텍스트 없음)로 준다 — 그걸 "형식 오류"로 다루면 정상 교환이 마지막 한 줄에서
     * 깨진다. 이 단계에서만 빈 줄을 정상 입력으로 받는다.
     */
    if (sasl.mechanism === "SCRAM-SHA-256" && sasl.scram?.stage === "serverFinal" && (data === null || data === "")) {
      this.pending = { kind: "auth", tag: sasl.tag };
      return [{ kind: "authVerified", tag: sasl.tag, user: sasl.scram.username ?? "" }];
    }
    if (data === null) {
      return [{ kind: "reply", text: `${sasl.tag} BAD malformed SASL response` }];
    }
    if (data === "*") {
      // RFC 3501/9051: 클라이언트 취소
      return [{ kind: "reply", text: `${sasl.tag} BAD authentication cancelled` }];
    }
    // "=" 는 빈 initial response(RFC 4959) — PLAIN에서는 유효하지 않음
    const b64 = data === "=" ? "" : data;
    // 디코딩·PLAIN 파싱은 @ionosphere/core 정본(4개 프로토콜 공유) — 예전엔 엔진마다 규칙이 달랐다.
    const bytes = decodeSaslBase64(b64);
    if (bytes === null) {
      return [{ kind: "reply", text: `${sasl.tag} BAD invalid base64` }];
    }
    const s = new TextDecoder().decode(bytes);

    if (sasl.mechanism === "SCRAM-SHA-256" && sasl.scram) {
      const sc = sasl.scram;
      if (sc.stage === "serverFinal") {
        /**
         * server-final(`+ <b64>`)에 대한 클라이언트의 빈 응답. 여기서야 태그 OK를 보낸다.
         * ★왕복을 하나 더 두는 이유: server-final은 클라이언트가 **서버를 검증하는** 값이다.
         * OK에 얹어 한 번에 끝내면 클라이언트는 확인할 기회 없이 성공을 받는다.
         */
        this.pending = { kind: "auth", tag: sasl.tag };
        return [{ kind: "authVerified", tag: sasl.tag, user: sc.username ?? "" }];
      }
      if (sc.stage === "clientFirst") {
        /**
         * ★단계 판정을 `stage`로 한다. 예전에 `start()`의 반환값으로 판정하려 했는데,
         * 이미 시작된 세션에 `start()`를 다시 부르면 **세션이 닫혀** 뒤이은 `final()`이
         * 무조건 실패했다(테스트가 잡았다). 상태를 상태로 판정할 것.
         */
        const step = sc.session.start(s);
        if (step.need !== "lookup") {
          return [
            this.scramFailedAction(step),
            { kind: "reply", text: `${sasl.tag} NO [AUTHENTICATIONFAILED] authentication failed` },
          ];
        }
        this.pending = { kind: "scram-keys", sasl: { ...sasl, scram: { ...sc, stage: "clientFinal" } } };
        return [{ kind: "scramKeys", user: step.username }];
      }
      const fin = sc.session.final(s);
      if (fin.need !== "done") {
        return [
          this.scramFailedAction(fin),
          { kind: "reply", text: `${sasl.tag} NO [AUTHENTICATIONFAILED] authentication failed` },
        ];
      }
      this.pending = {
        kind: "sasl-line",
        sasl: { ...sasl, scram: { session: sc.session, stage: "serverFinal", username: fin.username } },
      };
      return [{ kind: "reply", text: `+ ${Buffer.from(fin.message).toString("base64")}` }];
    }

    // OAuth SASL(XOAUTH2/OAUTHBEARER) — 토큰을 pass로 흘려 kind=2 자격증명으로 검증
    if (sasl.mechanism === "XOAUTH2" || sasl.mechanism === "OAUTHBEARER") {
      const creds = parseSaslOAuth(sasl.mechanism, s);
      if (!creds) {
        return [{ kind: "reply", text: `${sasl.tag} NO [AUTHENTICATIONFAILED] malformed ${sasl.mechanism} response` }];
      }
      this.pending = { kind: "auth", tag: sasl.tag };
      return [{ kind: "auth", user: creds.user, pass: creds.token }];
    }
    // RFC 4616: [authzid] NUL authcid NUL passwd (비밀번호에 NUL 포함 가능 — 정본이 처리)
    const creds = parseSaslPlain(bytes);
    if (!creds) {
      return [{ kind: "reply", text: `${sasl.tag} NO [AUTHENTICATIONFAILED] malformed PLAIN response` }];
    }
    this.pending = { kind: "auth", tag: sasl.tag };
    return [{ kind: "auth", user: creds.user, pass: creds.pass }];
  }

  /** ENABLE (RFC 5161) — 아는 확장만 ENABLED로 응답. */
  private cmdEnable(cmd: ParsedCommand): ImapAction[] {
    if (this.state === "not-authenticated") {
      return [{ kind: "reply", text: `${cmd.tag} BAD ENABLE not allowed before authentication` }];
    }
    /**
     * ★선택 상태에서는 거부한다(RFC 5161 §3.1: "only be used in the authenticated state,
     * before any mailbox is selected"). 예전엔 받아 줬는데, `IMAP4rev2`가 ENABLE 대상이 된
     * 지금은 그게 위험하다 — SELECT 도중에 켜지면 그 세션의 SEARCH 응답 모양이 중간에
     * `* SEARCH`에서 `* ESEARCH`로 바뀐다. 클라이언트는 그 전환을 알 방법이 없다.
     */
    if (this.state === "selected") {
      return [{ kind: "reply", text: `${cmd.tag} BAD ENABLE not allowed with a mailbox selected` }];
    }
    /**
     * ★대소문자 무시로 맞추되 **정본 철자로 되돌린다.** 예전엔 `toUpperCase()` 한 값을 그대로
     * 비교했는데, CONDSTORE·QRESYNC가 전부 대문자라 드러나지 않았다. `IMAP4rev2`를 넣자마자
     * `IMAP4REV2`가 되어 목록에 없는 이름이 됐고, ENABLE이 조용히 아무것도 안 켰다 —
     * 클라이언트는 `* ENABLED`(빈 줄)를 받고 rev1로 계속 간다.
     */
    const accepted: string[] = [];
    for (const arg of cmd.args) {
      const text = valueText(arg);
      if (text === null) continue;
      const name = ENABLABLE.find((n) => n.toUpperCase() === text.toUpperCase());
      if (name && !this.enabled.has(name)) {
        this.enabled.add(name);
        if (name === "QRESYNC") this.enabled.add("CONDSTORE"); // 함의(RFC 7162)
        accepted.push(name);
      }
    }
    return [
      { kind: "reply", text: `* ENABLED${accepted.length > 0 ? " " + accepted.join(" ") : ""}` },
      { kind: "reply", text: `${cmd.tag} OK ENABLE completed` },
    ];
  }
}
