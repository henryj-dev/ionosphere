/**
 * POP3 순수 상태머신 (RFC 1939) — 소켓 I/O 없음. PLAN.md §4: 프로토콜 패키지는 상태머신만.
 *
 * 상태: AUTHORIZATION → TRANSACTION → (QUIT) UPDATE(즉시 커밋) → 종료.
 * 비동기 백엔드 호출(인증/maildrop 오픈/조회/커밋)은 액션으로 방출하고, 어댑터가
 * 실제 호출을 수행한 뒤 대응하는 `xxxResult()` 메서드로 결과를 돌려준다 — 그동안
 * feed()로 들어온 이후 라인은 버퍼링만 되고 처리되지 않는다(파이프라이닝 안전).
 */
import {
  MAX_COMMAND_LINE,
  MAX_PIPELINE_PENDING_BYTES,
  decodeSaslBase64,
  parseSaslOAuth,
  parseSaslPlain,
  ScramServerSession,
  type ScramStep,
  type ScramStoredKeys,
} from "@ionosphere/core";

const CR = 0x0d;
const LF = 0x0a;
const DOT = 0x2e;
const CRLF = new Uint8Array([CR, LF]);
const TERMINATOR = new Uint8Array([DOT, CR, LF]);

import { randomBytes } from "node:crypto";

/** 프로세스 기본 decoy 비밀 — 모듈 로드 시 한 번. */
const PROCESS_SCRAM_DECOY = randomBytes(32);

export type Pop3State = "AUTHORIZATION" | "TRANSACTION";

/** maildrop 메시지 한 건 — Pop3Backend.openMaildrop()이 돌려주는 형태와 동일 형상. */
export interface Pop3EngineMessage {
  uidl: string;
  sizeBytes: number;
  /** 백엔드 전용 불투명 토큰 — 엔진은 내용을 해석하지 않고 그대로 왕복시킨다. */
  ref: unknown;
}

export type Pop3Action =
  | { kind: "reply"; text: string }
  | { kind: "replyBinary"; bytes: Uint8Array }
  | { kind: "close" }
  /** 어댑터가 소켓을 TLS로 승격하고 `tlsEstablished()`로 알린다(RFC 2595 §4). */
  | { kind: "startTls" }
  | { kind: "auth"; user: string; pass: string }
  /** SCRAM 교환 중 — 저장된 키를 찾아 `scramKeysResult()`로 돌려준다. */
  | { kind: "scramKeys"; user: string }
  /** SCRAM 증명 통과 — 어댑터가 계정 상태를 보고 `authResult()`로 재개한다(비밀번호 없음). */
  | { kind: "authVerified"; user: string }
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
  | { kind: "openMaildrop" }
  | { kind: "retrieve"; msgnum: number }
  | { kind: "commitDeletions"; messages: readonly Pop3EngineMessage[] };

export type Pop3AuthResult = { accountId: string } | null;
export type Pop3OpenMaildropResult =
  | { ok: true; messages: readonly Pop3EngineMessage[] }
  | { ok: false; inUse: boolean };
export type Pop3RetrieveResult = { ok: true; bytes: Uint8Array } | { ok: false };

export interface Pop3EngineOptions {
  hostname: string;
  /**
   * TLS 회선 여부 — 어댑터가 전달. 평문 회선에서는 USER/PASS·SASL을 **거부**하고 CAPA에서도
   * 광고하지 않는다(RFC 8314 §4.1: 평문 인증 금지).
   *
   * 왜 필요한가: POP3는 비밀번호를 그대로 실어 보낸다. TLS가 없으면 경로상 누구나 읽는다.
   * IMAP 143(LOGINDISABLED)·SMTP 587은 이미 같은 정책을 쓰는데 POP3만 빠져 있어,
   * **110이 공인망에 열린 채 평문 비밀번호를 받고 있었다**(2026-07-27 실측 확인).
   */
  secure?: boolean;
  /**
   * STLS를 광고·수락할 수 있는가 — 어댑터가 인증서를 들고 있을 때만 true.
   * 없는 기능을 광고하면 클라이언트가 시도하고 실패한 뒤 자격증명 문제로 오해한다.
   */
  tlsAvailable?: boolean;
  /** SCRAM 광고 여부 — 어댑터가 백엔드의 키 조회·승인 존재로 판단해 넘긴다. */
  scramOffered?: boolean;
  /** SCRAM 가짜 salt 유도용 비밀 — **서버 전체가 같은 값**이어야 계정 열거가 막힌다. */
  scramDecoySecret?: Buffer;
  /** dev/테스트 완화 — 평문에서도 인증 허용. 운영에서 켜면 위 보호가 사라진다. */
  allowInsecureAuth?: boolean;
}

interface SessionMessage extends Pop3EngineMessage {
  msgnum: number;
  deleted: boolean;
}

type Pending =
  | { kind: "auth" }
  | { kind: "scram-keys" }
  | { kind: "openMaildrop" }
  | { kind: "retrieve"; msgnum: number; mode: "retr" }
  | { kind: "retrieve"; msgnum: number; mode: "top"; lines: number }
  | { kind: "commit" };

// ── 바이트 레벨 dot-stuffing 유틸 (RETR/TOP 본문 8비트 안전 통과) ─────────────

function splitLines(bytes: Uint8Array): Uint8Array[] {
  const lines: Uint8Array[] = [];
  let start = 0;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === LF) {
      let end = i;
      if (end > start && bytes[end - 1] === CR) end -= 1;
      lines.push(bytes.subarray(start, end));
      start = i + 1;
    }
  }
  if (start < bytes.length) lines.push(bytes.subarray(start));
  return lines;
}

function stuffLine(line: Uint8Array): Uint8Array {
  if (line.length > 0 && line[0] === DOT) {
    const out = new Uint8Array(line.length + 1);
    out[0] = DOT;
    out.set(line, 1);
    return out;
  }
  return line;
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

function buildMultilineBinary(statusLine: string, bodyLines: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [new TextEncoder().encode(`${statusLine}\r\n`)];
  for (const line of bodyLines) {
    parts.push(stuffLine(line), CRLF);
  }
  parts.push(TERMINATOR);
  return concatBytes(parts);
}

function buildTextMultiline(statusLine: string, lines: string[]): string {
  const stuffed = lines.map((l) => (l.startsWith(".") ? `.${l}` : l));
  // 주의: 끝 CRLF는 붙이지 않는다 — reply 액션은 어댑터 writeText가 CRLF를 추가함.
  // (여기서 붙이면 ".\r\n\r\n" 이중 종결 = RFC 1939 위반 — e2e에서 발견된 결함)
  return [statusLine, ...stuffed, "."].join("\r\n");
}

export class Pop3Engine {
  private readonly hostname: string;
  private state: Pop3State = "AUTHORIZATION";
  /** ★readonly가 아니다 — STLS 성공 시 어댑터가 tlsEstablished()로 뒤집는다. */
  private secure: boolean;
  private readonly allowInsecureAuth: boolean;
  private readonly tlsAvailable: boolean;
  /** STLS +OK를 보낸 뒤 핸드셰이크를 기다리는 중 — 그 사이 들어온 평문 라인은 버린다. */
  private awaitingTls = false;
  private readonly decoder = new TextDecoder();
  private buffer = "";
  private pending: Pending | null = null;
  private closed = false;
  private username: string | null = null;
  private messages: SessionMessage[] = [];
  /** SASL AUTH continuation 대기(클라이언트 데이터 라인). null=명령 모드. */
  private awaitingSasl:
    | { mechanism: "PLAIN" | "XOAUTH2" | "OAUTHBEARER" }
    | {
        mechanism: "SCRAM-SHA-256";
        session: ScramServerSession;
        stage: "clientFirst" | "clientFinal" | "serverFinal";
        username?: string;
      }
    | null = null;
  private readonly scramOffered: boolean;
  private readonly scramDecoySecret: Buffer;

  constructor(opts: Pop3EngineOptions) {
    this.hostname = opts.hostname;
    this.secure = opts.secure ?? false;
    this.allowInsecureAuth = opts.allowInsecureAuth ?? false;
    this.tlsAvailable = opts.tlsAvailable ?? false;
    this.scramOffered = opts.scramOffered ?? false;
    this.scramDecoySecret = opts.scramDecoySecret ?? PROCESS_SCRAM_DECOY;
  }

  /** 인증을 받아도 되는 회선인가 — TLS이거나 명시적으로 완화된 경우만. */
  private authAllowed(): boolean {
    return this.secure || this.allowInsecureAuth;
  }

  /** 평문 회선에서의 인증 시도 거부 응답. 이유를 알려줘야 클라이언트가 995로 갈 수 있다. */
  private insecureAuthRejected(): Pop3Action[] {
    return [{ kind: "reply", text: "-ERR [AUTH] TLS required for authentication (use implicit TLS, port 995)" }];
  }

  /** 연결 수립 직후 어댑터가 한 번 호출 — 인사말 방출. */
  greeting(): Pop3Action[] {
    return [{ kind: "reply", text: `+OK ${this.hostname} POP3 server ready` }];
  }

  /** 소켓에서 읽은 바이트를 투입 — 완결된 명령 라인만큼 액션을 반환한다. */
  feed(chunk: Uint8Array): Pop3Action[] {
    /**
     * ★STLS +OK 뒤 핸드셰이크 전에 도착한 평문 바이트는 버린다. 공격자가 미리 밀어 넣은
     * 명령을 업그레이드 후에 실행하면 그것이 곧 명령 주입이다(RFC 2595 §4의 세션 리셋과 같은 이유).
     */
    if (this.awaitingTls) return [];
    if (this.closed) return [];
    this.buffer += this.decoder.decode(chunk, { stream: true });
    return this.drain();
  }

  /**
   * 누적 버퍼에 상한을 건다 — **라인 루프 바깥에서** 검사하는 것이 요점이다.
   *
   * 예전 코드는 상한이 아예 없었고, `drain()`의 루프는 `\n`을 못 찾으면 `break`만 했다.
   * 그래서 **CRLF를 영영 보내지 않는 스트림**에는 어떤 검사도 도달하지 않았다. 미인증
   * (AUTHORIZATION) 상태에서 TCP 연결 하나로 성립하고, 계속 전송하므로 유휴 타임아웃도
   * 발동하지 않는다 — 300MB 투입 시 방출 액션 0, RSS 90MB → 1836MB(2026-07-30 실측).
   * 전 프로토콜이 단일 프로세스라 메일 서비스 전체가 멈춘다.
   * proto-smtp의 `guardDataBuffer`가 정확히 같은 이유로 존재한다.
   *
   * 상한이 두 갈래인 이유: 루프가 멈춘 뒤 남은 버퍼의 의미가 상태에 따라 다르다.
   *  - `pending === null`: 완결된 라인은 전부 소비됐으므로 남은 것은 **미완결 라인 하나**다.
   *  - `pending !== null`: 백엔드 응답 대기라 루프가 돌지 못했으므로 완결된 라인도 남는다.
   *    미인증 공격자도 `PASS` 한 줄로 이 창을 연다(백엔드가 scrypt를 도는 동안).
   *
   * 초과분을 버리고 재동기할 수는 없다 — 스트림 중간을 버리면 명령 경계가 깨진다. 끊는다.
   */
  private guardBuffer(): Pop3Action[] {
    const limit = this.pending === null ? MAX_COMMAND_LINE : MAX_PIPELINE_PENDING_BYTES;
    if (this.buffer.length <= limit) return [];
    this.buffer = "";
    this.closed = true;
    return [
      { kind: "reply", text: "-ERR line too long, closing connection" },
      { kind: "close" },
    ];
  }

  /**
   * SCRAM 실패를 어댑터에 알리는 액션. **거절 응답과 늘 함께 나가야 한다** —
   * 응답만 내고 이걸 빼면 그 갈래가 다시 무기록이 된다(이 액션이 생긴 이유).
   */
  private scramFailedAction(step: ScramStep): Pop3Action {
    return {
      kind: "authFailed",
      mechanism: "SCRAM-SHA-256",
      ...(step.need === "failed" && step.username ? { user: step.username } : {}),
    };
  }

  /**
   * SCRAM 저장 키(없으면 null) — **null이어도 교환은 계속된다**(계정 열거 방어).
   */
  scramKeysResult(keys: ScramStoredKeys | null): Pop3Action[] {
    if (this.pending?.kind !== "scram-keys") throw new Error("Pop3Engine: scramKeysResult()는 scramKeys 액션 이후에만 호출 가능");
    this.pending = null;
    const sasl = this.awaitingSasl;
    if (!sasl || sasl.mechanism !== "SCRAM-SHA-256") return [];
    const step = sasl.session.provideKeys(keys);
    if (step.need !== "send") {
      this.awaitingSasl = null;
      return [this.scramFailedAction(step), { kind: "reply", text: "-ERR [AUTH] authentication failed" }];
    }
    return [{ kind: "reply", text: `+ ${Buffer.from(step.message).toString("base64")}` }];
  }

  authResult(result: Pop3AuthResult): Pop3Action[] {
    if (!this.pending || this.pending.kind !== "auth") {
      throw new Error("Pop3Engine: authResult()는 auth 액션 이후에만 호출 가능");
    }
    this.pending = null;
    if (!result) {
      this.username = null;
      return [{ kind: "reply", text: "-ERR [AUTH] authentication failed" }, ...this.drain()];
    }
    this.pending = { kind: "openMaildrop" };
    // accountId는 어댑터가 보관 — 엔진은 openMaildrop 호출을 요청만 한다.
    return [{ kind: "openMaildrop" }];
  }

  openMaildropResult(result: Pop3OpenMaildropResult): Pop3Action[] {
    if (!this.pending || this.pending.kind !== "openMaildrop") {
      throw new Error("Pop3Engine: openMaildropResult()는 openMaildrop 액션 이후에만 호출 가능");
    }
    this.pending = null;
    if (!result.ok) {
      this.username = null;
      return [{ kind: "reply", text: "-ERR [IN-USE] maildrop locked" }, ...this.drain()];
    }
    this.messages = result.messages.map((m, i) => ({ ...m, msgnum: i + 1, deleted: false }));
    this.state = "TRANSACTION";
    const total = this.messages.reduce((s, m) => s + m.sizeBytes, 0);
    return [
      { kind: "reply", text: `+OK maildrop has ${this.messages.length} messages (${total} octets)` },
      ...this.drain(),
    ];
  }

  retrieveResult(result: Pop3RetrieveResult): Pop3Action[] {
    if (!this.pending || this.pending.kind !== "retrieve") {
      throw new Error("Pop3Engine: retrieveResult()는 retrieve 액션 이후에만 호출 가능");
    }
    const pending = this.pending;
    this.pending = null;
    if (!result.ok) {
      return [{ kind: "reply", text: "-ERR [SYS/TEMP] failed to retrieve message" }, ...this.drain()];
    }
    const msg = this.messages.find((m) => m.msgnum === pending.msgnum);
    if (!msg) {
      return [{ kind: "reply", text: "-ERR [SYS/TEMP] internal error" }, ...this.drain()];
    }
    const bytes =
      pending.mode === "retr"
        ? buildMultilineBinary(`+OK ${msg.sizeBytes} octets`, splitLines(result.bytes))
        : this.buildTopBytes(result.bytes, pending.lines);
    return [{ kind: "replyBinary", bytes }, ...this.drain()];
  }

  commitDeletionsResult(ok: boolean): Pop3Action[] {
    if (!this.pending || this.pending.kind !== "commit") {
      throw new Error("Pop3Engine: commitDeletionsResult()는 commitDeletions 액션 이후에만 호출 가능");
    }
    this.pending = null;
    this.closed = true;
    if (!ok) {
      return [
        { kind: "reply", text: "-ERR [SYS/TEMP] failed to commit deletions" },
        { kind: "close" },
      ];
    }
    return [
      { kind: "reply", text: `+OK ${this.hostname} POP3 server signing off` },
      { kind: "close" },
    ];
  }

  private buildTopBytes(fullBytes: Uint8Array, bodyLineCount: number): Uint8Array {
    const allLines = splitLines(fullBytes);
    let blankIdx = allLines.findIndex((l) => l.length === 0);
    if (blankIdx === -1) blankIdx = allLines.length;
    const headerLines = allLines.slice(0, blankIdx);
    const outLines = [...headerLines];
    if (blankIdx < allLines.length) {
      outLines.push(new Uint8Array(0));
      outLines.push(...allLines.slice(blankIdx + 1, blankIdx + 1 + bodyLineCount));
    }
    return buildMultilineBinary("+OK top of message follows", outLines);
  }

  private drain(): Pop3Action[] {
    const actions: Pop3Action[] = [];
    while (!this.pending && !this.closed) {
      const idx = this.buffer.indexOf("\n");
      if (idx === -1) break;
      let line = this.buffer.slice(0, idx);
      this.buffer = this.buffer.slice(idx + 1);
      if (line.endsWith("\r")) line = line.slice(0, -1);
      // SASL continuation 대기 중이면 이 라인은 명령이 아니라 SASL 데이터
      actions.push(...(this.awaitingSasl ? this.handleSaslData(line) : this.handleLine(line)));
    }
    // 루프를 빠져나온 지점 = 더 처리할 완결 라인이 없는 지점. 여기서만 버퍼 상한을 판정한다
    // (feed()뿐 아니라 xxxResult() 재개 경로도 이 함수를 거치므로 한 곳으로 충분하다).
    if (!this.closed) actions.push(...this.guardBuffer());
    return actions;
  }

  private handleLine(line: string): Pop3Action[] {
    const trimmed = line.trim();
    if (trimmed.length === 0) return [{ kind: "reply", text: "-ERR unknown command" }];
    const spaceIdx = trimmed.indexOf(" ");
    const verb = (spaceIdx === -1 ? trimmed : trimmed.slice(0, spaceIdx)).toUpperCase();
    const rest = spaceIdx === -1 ? "" : trimmed.slice(spaceIdx + 1).trim();

    switch (verb) {
      case "CAPA":
        return this.cmdCapa();
      case "QUIT":
        return this.cmdQuit();
      case "USER":
        return this.cmdUser(rest);
      case "PASS":
        return this.cmdPass(rest);
      case "STLS":
        return this.cmdStls();
      case "AUTH":
        return this.cmdAuth(rest);
      case "APOP":
        // 구현 금지 정책 — PROTOCOLS.md §3 (MD5 + 평문 동등 비밀 저장 요구).
        return [{ kind: "reply", text: "-ERR APOP not supported" }];
      case "NOOP":
        return this.requireTransaction(() => [{ kind: "reply", text: "+OK" }]);
      case "STAT":
        return this.requireTransaction(() => this.cmdStat());
      case "LIST":
        return this.requireTransaction(() => this.cmdList(rest));
      case "RETR":
        return this.requireTransaction(() => this.cmdRetr(rest));
      case "DELE":
        return this.requireTransaction(() => this.cmdDele(rest));
      case "RSET":
        return this.requireTransaction(() => this.cmdRset());
      case "TOP":
        return this.requireTransaction(() => this.cmdTop(rest));
      case "UIDL":
        return this.requireTransaction(() => this.cmdUidl(rest));
      default:
        return [{ kind: "reply", text: "-ERR unknown command" }];
    }
  }

  private requireTransaction(fn: () => Pop3Action[]): Pop3Action[] {
    if (this.state !== "TRANSACTION") {
      return [{ kind: "reply", text: "-ERR bad sequence of commands" }];
    }
    return fn();
  }

  /** STLS를 광고·수락할 수 있는가 — 인증서가 있고 아직 평문일 때만. */
  private starttlsOffered(): boolean {
    return this.tlsAvailable && !this.secure;
  }

  /**
   * STLS (RFC 2595 §4) — +OK 다음 바이트부터 TLS 핸드셰이크다.
   *
   * ★AUTHORIZATION 상태에서만 받는다. 그리고 성공하면 **세션을 초기 상태로 되돌린다**
   * (§4: "the session is reset"). 평문 구간에서 USER로 흘린 이름이 업그레이드 후 세션에
   * 남으면, 그 이름이 검증 없이 이어지는 셈이 된다.
   */
  private cmdStls(): Pop3Action[] {
    if (this.secure) return [{ kind: "reply", text: "-ERR TLS already active" }];
    if (!this.starttlsOffered()) return [{ kind: "reply", text: "-ERR STLS not available" }];
    if (this.state !== "AUTHORIZATION") return [{ kind: "reply", text: "-ERR bad sequence of commands" }];
    this.awaitingTls = true;
    return [{ kind: "reply", text: "+OK Begin TLS negotiation" }, { kind: "startTls" }];
  }

  /**
   * 어댑터가 TLS 핸드셰이크 완료를 통보 — 이후 회선은 secure다.
   * RFC 2595 §4대로 인증 상태를 버린다(평문 구간의 USER는 무효).
   */
  tlsEstablished(): Pop3Action[] {
    this.secure = true;
    this.awaitingTls = false;
    this.username = null;
    return [];
  }

  private cmdCapa(): Pop3Action[] {
    // 평문 회선에서는 USER/SASL을 광고하지 않는다 — 광고해놓고 거부하면 클라이언트가
    // "비밀번호가 틀렸다"고 오해한다. 능력 목록에서 빼야 다른 경로(995)를 찾는다.
    const caps = [
      // 평문이고 인증서가 있으면 STLS를 알린다 — 이게 없으면 110은 로그인 불가 포트가 된다.
      ...(this.starttlsOffered() ? ["STLS"] : []),
      ...(this.authAllowed() ? ["USER"] : []),
      "TOP",
      "UIDL",
      "RESP-CODES",
      "AUTH-RESP-CODE",
      "PIPELINING",
      ...(this.authAllowed()
        ? [this.scramOffered ? "SASL SCRAM-SHA-256 PLAIN XOAUTH2 OAUTHBEARER" : "SASL PLAIN XOAUTH2 OAUTHBEARER"]
        : []),
      "IMPLEMENTATION ionosphere",
    ];
    return [{ kind: "reply", text: buildTextMultiline("+OK Capability list follows", caps) }];
  }

  /** SASL AUTH (RFC 5034) — 인자 없으면 메커니즘 목록, 아니면 mech[+IR]. XOAUTH2/OAUTHBEARER + PLAIN. */
  private cmdAuth(rest: string): Pop3Action[] {
    if (this.state !== "AUTHORIZATION") return [{ kind: "reply", text: "-ERR bad sequence of commands" }];
    if (!this.authAllowed()) return this.insecureAuthRejected();
    if (rest.length === 0) {
      // ★SCRAM을 **먼저** 나열한다 — 클라이언트가 순서를 선호도로 읽는 경우가 많다.
      const mechs = this.scramOffered ? ["SCRAM-SHA-256", "PLAIN", "XOAUTH2", "OAUTHBEARER"] : ["PLAIN", "XOAUTH2", "OAUTHBEARER"];
      return [{ kind: "reply", text: buildTextMultiline("+OK", mechs) }];
    }
    const sp = rest.indexOf(" ");
    const mech = (sp === -1 ? rest : rest.slice(0, sp)).toUpperCase();
    const ir = sp === -1 ? "" : rest.slice(sp + 1).trim();
    if (mech === "SCRAM-SHA-256") {
      // 광고하지 않은 메커니즘은 받지 않는다 — 백엔드가 못 끝낼 교환을 시작하면 안 된다.
      if (!this.scramOffered) return [{ kind: "reply", text: "-ERR [AUTH] unsupported SASL mechanism" }];
      this.awaitingSasl = {
        mechanism: "SCRAM-SHA-256",
        session: new ScramServerSession(this.scramDecoySecret),
        stage: "clientFirst",
      };
      if (ir.length > 0) return this.handleSaslData(ir);
      return [{ kind: "reply", text: "+ " }];
    }
    if (mech !== "PLAIN" && mech !== "XOAUTH2" && mech !== "OAUTHBEARER") {
      return [{ kind: "reply", text: "-ERR [AUTH] unsupported SASL mechanism" }];
    }
    this.awaitingSasl = { mechanism: mech };
    if (ir.length > 0) return this.handleSaslData(ir); // SASL-IR(초기응답 동봉)
    return [{ kind: "reply", text: "+ " }]; // continuation 요청
  }

  /** SASL 데이터 라인(base64 또는 '*' 취소) → auth 액션 emit 또는 -ERR. */
  private handleSaslData(data: string): Pop3Action[] {
    const sasl = this.awaitingSasl!;
    if (data === "*") {
      this.awaitingSasl = null;
      return [{ kind: "reply", text: "-ERR [AUTH] authentication cancelled" }];
    }

    if (sasl.mechanism === "SCRAM-SHA-256") {
      /**
       * ★단계는 `stage`로 판정한다. `start()` 반환값으로 갈래를 나누면 이미 시작된 세션에
       * `start()`를 다시 불러 **세션이 닫히고** 뒤이은 `final()`이 무조건 실패한다
       * (IMAP 배선에서 실제로 겪었다).
       */
      if (sasl.stage === "serverFinal") {
        // server-final에 대한 클라이언트의 빈 응답 — 여기서야 성공 처리한다.
        this.awaitingSasl = null;
        this.username = sasl.username ?? "";
        this.pending = { kind: "auth" };
        return [{ kind: "authVerified", user: sasl.username ?? "" }];
      }
      const bytes = decodeSaslBase64(data);
      if (bytes === null) {
        this.awaitingSasl = null;
        return [{ kind: "reply", text: "-ERR [AUTH] invalid base64" }];
      }
      const text = new TextDecoder().decode(bytes);
      if (sasl.stage === "clientFirst") {
        const step = sasl.session.start(text);
        if (step.need !== "lookup") {
          this.awaitingSasl = null;
          return [this.scramFailedAction(step), { kind: "reply", text: "-ERR [AUTH] authentication failed" }];
        }
        this.awaitingSasl = { ...sasl, stage: "clientFinal" };
        this.pending = { kind: "scram-keys" };
        return [{ kind: "scramKeys", user: step.username }];
      }
      const fin = sasl.session.final(text);
      if (fin.need !== "done") {
        this.awaitingSasl = null;
        return [this.scramFailedAction(fin), { kind: "reply", text: "-ERR [AUTH] authentication failed" }];
      }
      this.awaitingSasl = { ...sasl, stage: "serverFinal", username: fin.username };
      return [{ kind: "reply", text: `+ ${Buffer.from(fin.message).toString("base64")}` }];
    }

    this.awaitingSasl = null;
    // 디코딩·PLAIN 파싱은 @ionosphere/core 정본 — split 기반이던 예전 구현은 비밀번호에 NUL이
    // 있으면 거부해서 같은 계정이 IMAP은 되고 POP3는 안 되는 갈라짐이 있었다.
    const bytes = decodeSaslBase64(data);
    if (bytes === null) {
      return [{ kind: "reply", text: "-ERR [AUTH] invalid base64" }];
    }
    const s = new TextDecoder().decode(bytes);
    let user: string;
    let pass: string;
    if (sasl.mechanism === "PLAIN") {
      const creds = parseSaslPlain(bytes);
      if (!creds) return [{ kind: "reply", text: "-ERR [AUTH] malformed PLAIN response" }];
      user = creds.user;
      pass = creds.pass;
    } else {
      const creds = parseSaslOAuth(sasl.mechanism, s);
      if (!creds) return [{ kind: "reply", text: `-ERR [AUTH] malformed ${sasl.mechanism} response` }];
      user = creds.user;
      pass = creds.token;
    }
    this.username = user;
    this.pending = { kind: "auth" };
    return [{ kind: "auth", user, pass }];
  }

  private cmdUser(name: string): Pop3Action[] {
    if (this.state !== "AUTHORIZATION") return [{ kind: "reply", text: "-ERR bad sequence of commands" }];
    if (!this.authAllowed()) return this.insecureAuthRejected();
    if (!name) return [{ kind: "reply", text: "-ERR missing username" }];
    this.username = name;
    return [{ kind: "reply", text: "+OK" }];
  }

  private cmdPass(pass: string): Pop3Action[] {
    if (this.state !== "AUTHORIZATION") return [{ kind: "reply", text: "-ERR bad sequence of commands" }];
    if (!this.authAllowed()) return this.insecureAuthRejected();
    if (!this.username) return [{ kind: "reply", text: "-ERR bad sequence of commands" }];
    if (!pass) return [{ kind: "reply", text: "-ERR missing password" }];
    this.pending = { kind: "auth" };
    return [{ kind: "auth", user: this.username, pass }];
  }

  private cmdStat(): Pop3Action[] {
    const active = this.messages.filter((m) => !m.deleted);
    const total = active.reduce((s, m) => s + m.sizeBytes, 0);
    return [{ kind: "reply", text: `+OK ${active.length} ${total}` }];
  }

  private cmdList(arg: string): Pop3Action[] {
    if (arg) {
      const r = this.getActiveMessage(arg);
      if (!r.ok) return [{ kind: "reply", text: r.text }];
      return [{ kind: "reply", text: `+OK ${r.msg.msgnum} ${r.msg.sizeBytes}` }];
    }
    const active = this.messages.filter((m) => !m.deleted);
    const total = active.reduce((s, m) => s + m.sizeBytes, 0);
    const lines = active.map((m) => `${m.msgnum} ${m.sizeBytes}`);
    return [{ kind: "reply", text: buildTextMultiline(`+OK ${active.length} messages (${total} octets)`, lines) }];
  }

  private cmdUidl(arg: string): Pop3Action[] {
    if (arg) {
      const r = this.getActiveMessage(arg);
      if (!r.ok) return [{ kind: "reply", text: r.text }];
      return [{ kind: "reply", text: `+OK ${r.msg.msgnum} ${r.msg.uidl}` }];
    }
    const active = this.messages.filter((m) => !m.deleted);
    const lines = active.map((m) => `${m.msgnum} ${m.uidl}`);
    return [{ kind: "reply", text: buildTextMultiline("+OK", lines) }];
  }

  private cmdRetr(arg: string): Pop3Action[] {
    const r = this.getActiveMessage(arg);
    if (!r.ok) return [{ kind: "reply", text: r.text }];
    this.pending = { kind: "retrieve", msgnum: r.msg.msgnum, mode: "retr" };
    return [{ kind: "retrieve", msgnum: r.msg.msgnum }];
  }

  private cmdDele(arg: string): Pop3Action[] {
    const r = this.getActiveMessage(arg);
    if (!r.ok) return [{ kind: "reply", text: r.text }];
    r.msg.deleted = true;
    return [{ kind: "reply", text: `+OK message ${r.msg.msgnum} deleted` }];
  }

  private cmdRset(): Pop3Action[] {
    for (const m of this.messages) m.deleted = false;
    const total = this.messages.reduce((s, m) => s + m.sizeBytes, 0);
    return [{ kind: "reply", text: `+OK maildrop has ${this.messages.length} messages (${total} octets)` }];
  }

  private cmdTop(rest: string): Pop3Action[] {
    const parts = rest.split(/\s+/).filter((p) => p.length > 0);
    const msgArg = parts[0];
    const linesArg = parts[1];
    if (parts.length !== 2 || msgArg === undefined || linesArg === undefined) {
      return [{ kind: "reply", text: "-ERR invalid arguments" }];
    }
    const r = this.getActiveMessage(msgArg);
    if (!r.ok) return [{ kind: "reply", text: r.text }];
    const lineCount = this.parseNonNegativeInt(linesArg);
    if (lineCount === null) return [{ kind: "reply", text: "-ERR invalid arguments" }];
    this.pending = { kind: "retrieve", msgnum: r.msg.msgnum, mode: "top", lines: lineCount };
    return [{ kind: "retrieve", msgnum: r.msg.msgnum }];
  }

  private cmdQuit(): Pop3Action[] {
    if (this.state === "AUTHORIZATION") {
      this.closed = true;
      return [
        { kind: "reply", text: `+OK ${this.hostname} POP3 server signing off` },
        { kind: "close" },
      ];
    }
    const toDelete = this.messages.filter((m) => m.deleted).map((m) => ({ uidl: m.uidl, sizeBytes: m.sizeBytes, ref: m.ref }));
    this.pending = { kind: "commit" };
    return [{ kind: "commitDeletions", messages: toDelete }];
  }

  private parseNonNegativeInt(s: string): number | null {
    if (!/^\d+$/.test(s)) return null;
    return Number(s);
  }

  private getActiveMessage(arg: string): { ok: true; msg: SessionMessage } | { ok: false; text: string } {
    const n = this.parseNonNegativeInt(arg);
    if (n === null) return { ok: false, text: "-ERR invalid message number" };
    const msg = this.messages.find((m) => m.msgnum === n);
    if (!msg) return { ok: false, text: "-ERR no such message" };
    if (msg.deleted) return { ok: false, text: "-ERR message deleted" };
    return { ok: true, msg };
  }
}
