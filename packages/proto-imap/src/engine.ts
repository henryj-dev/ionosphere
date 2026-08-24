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
import {
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
}

/** 엔진 → 어댑터 백엔드 요청. 이름은 정규화(INBOX 케이스) 완료 상태로 전달된다. */
export type ImapBackendRequest =
  | { kind: "listMailboxes" }
  | { kind: "createMailbox"; name: string }
  | { kind: "deleteMailbox"; name: string }
  | { kind: "renameMailbox"; from: string; to: string }
  /** SUBSCRIBE/UNSUBSCRIBE 영속화 (RFC 9051 §6.3.7/6.3.8). */
  | { kind: "setSubscribed"; name: string; subscribed: boolean }
  | { kind: "selectMailbox"; name: string }
  /** CLOSE — \Deleted 메시지 영구 삭제(응답 불요, ok/no만). */
  | { kind: "expungeMailbox"; name: string }
  /**
   * FETCH — uids의 메시지 데이터. needRaw면 raw 바이트 포함,
   * markSeen이면 백엔드가 \Seen을 먼저 설정한 뒤 갱신된 flags를 돌려준다(계약).
   */
  | { kind: "fetchMessages"; name: string; uids: readonly number[]; needRaw: boolean; markSeen: boolean }
  /**
   * STORE — 플래그 갱신 후 갱신된 flags를 flagsUpdated로 돌려준다(계약).
   * unchangedSince 지정 시 modseq > 값인 메시지는 건너뛰고 failed에 보고(RFC 7162).
   */
  | { kind: "storeFlags"; name: string; uids: readonly number[]; mode: "set" | "add" | "remove"; flags: readonly string[]; unchangedSince?: number }
  /** QRESYNC — sinceModseq 이후 삭제(uid 툼스톤)·변경(flags) 델타. */
  | { kind: "syncSince"; name: string; sinceModseq: number }
  /** EXPUNGE — \Deleted 영구 삭제. uids 지정 시 그 UID들만(UIDPLUS UID EXPUNGE). */
  | { kind: "expunge"; name: string; uids: readonly number[] | null }
  /** APPEND — internalDateMs null이면 현재 시각(백엔드 결정). */
  | { kind: "appendMessage"; name: string; flags: readonly string[]; internalDateMs: number | null; raw: Uint8Array }
  | { kind: "copyMessages"; from: string; to: string; uids: readonly number[] }
  /** MOVE — 원자적 이동(RFC 6851). 응답은 copied 재사용(원본 제거는 엔진이 EXPUNGE 방출). */
  | { kind: "moveMessages"; from: string; to: string; uids: readonly number[] };

/** fetchMessages 응답의 메시지 한 건. */
export interface ImapFetchData {
  uid: number;
  flags: readonly string[];
  internalDateMs: number;
  size: number;
  /** CONDSTORE — 메시지 최종 modseq(messages.modseq 물질화). */
  modseq: number;
  /** needRaw 요청 시에만. */
  raw?: Uint8Array;
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
  | { kind: "appended"; uidvalidity: number; uid: number }
  /** COPY/MOVE 결과 — COPYUID용. srcUids[i] ↔ dstUids[i] 대응. */
  | { kind: "copied"; uidvalidity: number; srcUids: readonly number[]; dstUids: readonly number[] }
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

const BASE_CAPABILITIES = ["IMAP4rev1", "LITERAL-", "SASL-IR", "ID", "ENABLE", "NAMESPACE", "CHILDREN", "SPECIAL-USE", "UNSELECT", "UIDPLUS", "MOVE", "IDLE", "CONDSTORE", "QRESYNC", "ESEARCH", "LIST-STATUS"] as const;
/** ENABLE로 옵트인 가능한 확장(RFC 5161). QRESYNC는 CONDSTORE를 함의(RFC 7162). */
const ENABLABLE = ["CONDSTORE", "QRESYNC"] as const;

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
      case "EXPUNGE":
        return this.requireSelected(cmd, () => this.cmdExpunge(cmd, null));
      case "APPEND":
        return this.requireAuth(cmd, () => this.cmdAppend(cmd));
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
    let qresync: { uidvalidity: number; modseq: number } | null = null;
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
          qresync = { uidvalidity: Number(uv), modseq: Number(ms) };
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
      const actions: ImapAction[] = [
        { kind: "reply", text: flagsLine(keywords) },
        { kind: "reply", text: `* ${res.uids.length} EXISTS` },
        { kind: "reply", text: "* 0 RECENT" }, // rev2 시맨틱 — \Recent 미지원
        { kind: "reply", text: `* OK [UIDVALIDITY ${m.uidvalidity}] UIDs valid` },
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
      if (res.firstUnseenSeq !== null) {
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
          ...this.callBackend({ kind: "syncSince", name: m.name, sinceModseq: since }, (sync) => {
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
      case "COPY":
        return this.requireSelected(cmd, () => this.cmdCopyMove(rest, true, "copy"));
      case "MOVE":
        return this.requireSelected(cmd, () => this.cmdCopyMove(rest, true, "move"));
      case "EXPUNGE": {
        // UIDPLUS UID EXPUNGE — uid 집합 내 \Deleted만
        const setText = rest.args[0] ? valueText(rest.args[0]) : null;
        const ranges = setText !== null ? parseSequenceSet(setText) : null;
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
    const ranges = setText !== null ? parseSequenceSet(setText) : null;
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

    const needRaw = items.some((it) => it.kind === "envelope" || it.kind === "body" || it.kind === "bodystructure" || it.kind === "section");
    const markSeen = view.readWrite && items.some((it) => it.kind === "section" && !it.peek);

    /**
     * ★배치로 나눠 가져온다. 예전엔 메일함 **전체** uid를 한 요청에 실어, 백엔드가 그만큼의
     * 블롭을 전부 메모리에 올렸다(5만 통 × 50KB = 2.5GB). 응답은 배치마다 바로 흘려보내므로
     * 상주 메모리가 배치 하나 크기로 묶인다.
     *
     * 배치 사이에 다른 세션이 메시지를 지울 수 있지만, 그건 **원래 있던 성질**이다 —
     * 세션 뷰는 SELECT 시점 스냅샷이고 사라진 uid는 예전부터 조용히 생략됐다(아래 `!data`).
     */
    const batchSize = needRaw ? FETCH_BATCH_RAW : FETCH_BATCH_META;
    const emit = (batch: readonly { seq: number; uid: number }[], res: ImapBackendResponse): ImapAction[] => {
      if (res.kind !== "messages") return [];
      const byUid = new Map(res.messages.map((m) => [m.uid, m]));
      const actions: ImapAction[] = [];
      for (const t of batch) {
        const data = byUid.get(t.uid);
        if (!data) continue; // 스냅샷 이후 사라진 메시지 — 조용히 생략(EXPUNGE는 별도 흐름)
        if (changedSince !== null && data.modseq <= changedSince) continue; // CONDSTORE 필터
        if (items.some((it) => it.kind === "flags")) actions.push(...this.ensureFlagsAnnounced(data.flags));
        const parts = items.map((it) => this.fetchItemWire(it, t.uid, data));
        actions.push({ kind: "replyBinary", bytes: wireToBytes(`* ${t.seq} FETCH (${parts.join(" ")})\r\n`) });
      }
      return actions;
    };

    /** 배치 하나를 요청하고, 응답을 흘린 뒤 다음 배치를 이어 건다(꼬리 연쇄). */
    const fetchFrom = (offset: number): ImapAction[] => {
      const batch = targets.slice(offset, offset + batchSize);
      return this.callBackend(
        { kind: "fetchMessages", name: view.name, uids: batch.map((t) => t.uid), needRaw, markSeen },
        (res) => {
          if (res.kind === "no") return [ImapEngine.noReply(cmd.tag, verb, res)];
          if (res.kind !== "messages") return [{ kind: "reply", text: `${cmd.tag} NO ${verb} failed` }];
          const actions = emit(batch, res);
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
  private cmdAppend(cmd: ParsedCommand): ImapAction[] {
    const name = this.mailboxArg(cmd, 0);
    if (name === null) return [{ kind: "reply", text: `${cmd.tag} BAD APPEND expects mailbox name` }];
    let idx = 1;
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
    if (!msgVal || idx !== cmd.args.length - 1) {
      return [{ kind: "reply", text: `${cmd.tag} BAD APPEND expects message literal` }];
    }
    let raw: Uint8Array;
    if (msgVal.kind === "literal") raw = msgVal.bytes;
    else if (msgVal.kind === "quoted") raw = new TextEncoder().encode(msgVal.value);
    else return [{ kind: "reply", text: `${cmd.tag} BAD APPEND expects message literal` }];
    if (raw.length === 0) return [{ kind: "reply", text: `${cmd.tag} NO APPEND empty message` }];

    return this.callBackend({ kind: "appendMessage", name, flags, internalDateMs, raw }, (res) => {
      if (res.kind === "appended") {
        const actions: ImapAction[] = [];
        // 선택 중 메일함에 APPEND — 즉시 EXISTS 반영(imaptest own_msgs 추적 요구)
        const view = this.selected;
        if (view && view.name === name && !view.uids.includes(res.uid)) {
          view.uids.push(res.uid);
          view.uids.sort((a, b) => a - b);
          actions.push({ kind: "reply", text: `* ${view.uids.length} EXISTS` });
        }
        actions.push({ kind: "reply", text: `${cmd.tag} OK [APPENDUID ${res.uidvalidity} ${res.uid}] APPEND completed` });
        return actions;
      }
      return [ImapEngine.noReply(cmd.tag, "APPEND", res.kind === "no" ? res : { message: "failed" })];
    });
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
    const ranges = setText !== null ? parseSequenceSet(setText) : null;
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
    const ranges = setText !== null ? parseSequenceSet(setText) : null;
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
        if (t !== "MIN" && t !== "MAX" && t !== "COUNT" && t !== "ALL") {
          return [{ kind: "reply", text: `${cmd.tag} BAD unknown RETURN option` }];
        }
        esearch.add(t);
      }
      if (esearch.size === 0) esearch.add("ALL"); // RETURN () == RETURN (ALL) — RFC 4731
      critArgs = cmd.args.slice(2);
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
      return [
        { kind: "reply", text: ImapEngine.searchReply(cmd.tag, uidMode, esearch, []) },
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
              { seq: i + 1, uid, flags: data.flags, size: data.size, internalDateMs: data.internalDateMs, modseq: data.modseq, raw: data.raw },
              maxSeq,
              maxUid,
            );
            if (matched) hits.push(uidMode ? uid : i + 1);
          });
          const next = offset + batchSize;
          if (next < view.uids.length) return searchFrom(next);
          return [
            { kind: "reply", text: ImapEngine.searchReply(cmd.tag, uidMode, esearch, hits) },
            { kind: "reply", text: `${cmd.tag} OK ${verb} completed` },
          ];
        },
      );
    };
    return searchFrom(0);
  }

  /** SEARCH 응답 — 고전(`* SEARCH n...`) 또는 ESEARCH(RFC 4731). hits는 seq/uid(모드별). */
  private static searchReply(tag: string, uidMode: boolean, esearch: Set<string> | null, hits: readonly number[]): string {
    if (esearch === null) return `* SEARCH${hits.length > 0 ? " " + hits.join(" ") : ""}`;
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
  private fetchItemWire(it: FetchItem, uid: number, data: ImapFetchData): string {
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
    const known: readonly string[] = ENABLABLE;
    const accepted: string[] = [];
    for (const arg of cmd.args) {
      const name = valueText(arg)?.toUpperCase();
      if (name && known.includes(name) && !this.enabled.has(name)) {
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
