/**
 * SMTP 수신 엔진 — 순수 바이트 스트림 상태머신 (소켓 I/O 없음, PLAN.md §4 설계원칙 1).
 * 소켓/TLS는 server.ts 어댑터가 담당. 여기는 오직 바이트를 먹고 SmtpAction[]을 뱉는다.
 *
 * 기준: docs/PROTOCOLS.md §1 MUST 티어 + "2026 최소 신뢰 EHLO 세트"
 * (SIZE 8BITMIME PIPELINING ENHANCEDSTATUSCODES STARTTLS SMTPUTF8).
 *
 * 비동기 연속 패턴: RCPT TO와 DATA 종료는 백엔드 확인이 필요한 지점이라 액션만 emit하고
 * pump를 멈춘다 — 어댑터가 rcptResult()/deliveryResult()를 호출하면 재개.
 * 그동안 들어온 파이프라인 바이트는 버퍼에 쌓아두고 재개 시 이어서 처리(PIPELINING).
 */

import {
  MAX_COMMAND_LINE,
  MAX_PIPELINE_PENDING_BYTES,
  MAX_RCPT_PER_SESSION,
  MAX_SMTP_ERRORS_PER_SESSION,
  decodeSaslBase64,
  parseSaslOAuth,
  parseSaslPlain,
  ScramServerSession,
  type ScramStep,
  type ScramStoredKeys,
} from "@ionosphere/core";

import { randomBytes } from "node:crypto";

const CR = 0x0d;
const LF = 0x0a;
const DOT = 0x2e;
const CRLF_BYTES = new Uint8Array([CR, LF]);

/**
 * DATA 본문에서 **CRLF 없이** 한 줄이 커질 수 있는 상한.
 *
 * 왜 필요한가: 크기 초과 판정(dataOverflow)은 **완결된 라인**에서만 돌아간다. 그래서 CRLF를
 * 영영 보내지 않는 스트림에는 maxSizeBytes가 아무 효과가 없었고, 버퍼가 무한히 자랐다
 * (25번 포트에 무인증으로 접속해 개행 없는 바이트만 흘리면 프로세스가 죽는다 — 실측 확인).
 *
 * 부수 효과로 CPU도 묶인다: feed()가 청크마다 버퍼 전체를 복사하므로(concatBytes) 상한이
 * 없으면 O(n²)이 된다. 1MB로 묶으면 복사 총량이 무시할 수준이 된다.
 *
 * 값의 근거: RFC 5321 §4.5.3.1.6의 텍스트 라인 상한은 1000옥텟이지만 줄바꿈을 하지 않는
 * 구현이 실제로 있어 넉넉히 잡았다. 초과분은 552(메시지 크기 초과)로 수렴한다.
 */
const MAX_DATA_LINE = 1024 * 1024;

export interface SmtpEngineOptions {
  /** 배너/EHLO 응답용 호스트명. */
  hostname: string;
  /** SIZE 광고 + MAIL FROM SIZE=/DATA 누적 검증. */
  maxSizeBytes: number;
  /** STARTTLS 광고 여부 — 어댑터가 tls 옵션 보유 여부로 결정해 전달. */
  tlsAvailable: boolean;
  /** 리스너 프로파일. submission(587류)은 MAIL FROM 전에 인증을 강제. 기본 relay(25류). */
  profile?: "relay" | "submission";
  /** AUTH PLAIN/LOGIN 광고 여부 — 어댑터가 backend.authenticate 존재 여부로 결정해 전달. */
  authOffered?: boolean;
  /** dev 전용: TLS 업그레이드 전에도 AUTH 허용. RFC 4954 — 평문에서는 기본 금지. */
  allowInsecureAuth?: boolean;
  /**
   * SCRAM 가짜 salt 유도용 비밀 — **서버 전체가 같은 값을 써야 한다.**
   * 연결마다 다르면 같은 사용자명의 가짜 salt가 매번 바뀌어 계정 열거가 다시 열린다.
   * 안 주면 프로세스 수명 동안 고정된 값을 쓴다(재시작 시 바뀌지만, 열거 방어에는 충분하다 —
   * 한 세션 안에서 재시도로 비교하는 것을 막는 것이 목적이다).
   */
  scramDecoySecret?: Buffer;
  /** SCRAM 광고 여부 — 어댑터가 백엔드의 키 조회·승인 존재로 판단해 넘긴다. */
  scramOffered?: boolean;
}

/** 프로세스 기본 decoy 비밀 — 모듈 로드 시 한 번 만든다. */
const PROCESS_SCRAM_DECOY = randomBytes(32);

export type SmtpAction =
  | { kind: "reply"; text: string }
  | { kind: "startTls" }
  | { kind: "rcpt"; address: string }
  | { kind: "auth"; user: string; pass: string }
  /** SCRAM 교환 중 — 이 사용자의 저장된 키를 찾아 `scramKeysResult()`로 돌려준다. */
  | { kind: "scramKeys"; user: string }
  /**
   * SCRAM 증명이 통과했다 — 어댑터는 세션을 그 계정에 묶고 `authResult()`로 재개한다.
   * ★`{kind:"auth"}`와 달리 **비밀번호를 넘기지 않는다.** SCRAM의 요점이 그것이다:
   * 서버는 평문을 쥐지 않은 채 상대를 검증한다. 여기에 평문을 실으면 그 이득이 사라진다.
   */
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
  | { kind: "deliver"; mailFrom: string; heloName: string; rcptTo: readonly string[]; raw: Uint8Array; authenticatedAs: string | null }
  | { kind: "close" };

export type RcptOutcome = { ok: true } | { ok: false; code: number; enhanced: string; message: string };

export type DeliverOutcome =
  | { ok: true; queuedId?: string }
  | { ok: false; code: number; enhanced: string; message: string };

type ConnState = "init" | "greeted" | "mail" | "rcpt" | "data";
type Awaiting = "rcpt" | "deliver" | "tls" | "auth" | "scramKeys" | null;

/** AUTH 커맨드 진행 중(챌린지/응답 왕복) 상태 — {kind:"auth"} 액션 전 단계. */
type AuthContinuation =
  | { mechanism: "PLAIN" }
  | { mechanism: "LOGIN"; step: "username" }
  | { mechanism: "LOGIN"; step: "password"; user: string }
  | { mechanism: "XOAUTH2" | "OAUTHBEARER" }
  | { mechanism: "SCRAM-SHA-256"; session: ScramServerSession; stage: "keys" | "final" }
  /** server-final을 보내고 클라이언트의 빈 응답을 기다리는 단계 — 사용자명은 이미 증명됐다. */
  | { mechanism: "SCRAM-SHA-256"; session: ScramServerSession; stage: "serverFinal"; username: string };

function reply(code: number, enhanced: string, message: string): SmtpAction {
  return { kind: "reply", text: `${code} ${enhanced} ${message}\r\n` };
}

/** 확장 상태코드 없는 단일행 응답(배너/HELO/354 등). */
function rawReply(line: string): SmtpAction {
  return { kind: "reply", text: `${line}\r\n` };
}

function indexOfCRLF(buf: Uint8Array, from: number = 0): number {
  for (let i = from; i < buf.length - 1; i++) {
    if (buf[i] === CR && buf[i + 1] === LF) return i;
  }
  return -1;
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length === 0) return b;
  if (b.length === 0) return a;
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function concatChunks(chunks: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

const utf8Decoder = new TextDecoder();

function decodeLine(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes);
}

/**
 * base64/PLAIN 파싱은 @ionosphere/core 정본을 쓴다(4개 프로토콜 공유). 이 SMTP 구현이 가장
 * 정확했기에 정본의 기준이 되었고, 별칭만 남긴다.
 */
const decodeBase64Strict = decodeSaslBase64;
const decodePlainAuth = parseSaslPlain;

function splitVerb(line: string): { verb: string; rest: string } {
  const spaceIdx = line.indexOf(" ");
  if (spaceIdx === -1) return { verb: line.toUpperCase(), rest: "" };
  return { verb: line.slice(0, spaceIdx).toUpperCase(), rest: line.slice(spaceIdx + 1).trim() };
}

function splitParam(token: string): [string, string | undefined] {
  const eq = token.indexOf("=");
  if (eq === -1) return [token, undefined];
  return [token.slice(0, eq), token.slice(eq + 1)];
}

type ParamSyntaxError = { ok: false; code: number; enhanced: string; message: string };

interface ParsedMailFrom {
  address: string;
  size?: number;
  body?: "8BITMIME" | "7BIT";
  smtputf8: boolean;
}

/** `FROM:<addr> [SIZE=n] [BODY=8BITMIME|7BIT] [SMTPUTF8]` 파싱 (docs/PROTOCOLS.md §1). */
function parseMailFromArgs(rest: string): { ok: true; value: ParsedMailFrom } | ParamSyntaxError {
  const m = /^from:\s*<([^>]*)>\s*(.*)$/i.exec(rest);
  if (!m) return { ok: false, code: 501, enhanced: "5.5.4", message: "Syntax: MAIL FROM:<address> [params]" };
  const address = m[1] ?? "";
  const paramsPart = (m[2] ?? "").trim();
  const parsed: ParsedMailFrom = { address, smtputf8: false };

  if (paramsPart.length > 0) {
    for (const token of paramsPart.split(/\s+/)) {
      const [rawKey, rawVal] = splitParam(token);
      const key = rawKey.toUpperCase();
      if (key === "SIZE") {
        const n = rawVal === undefined ? Number.NaN : Number(rawVal);
        if (rawVal === undefined || !Number.isInteger(n) || n < 0) {
          return { ok: false, code: 501, enhanced: "5.5.4", message: "Invalid SIZE parameter" };
        }
        parsed.size = n;
      } else if (key === "BODY") {
        const v = (rawVal ?? "").toUpperCase();
        if (v !== "8BITMIME" && v !== "7BIT") {
          return { ok: false, code: 501, enhanced: "5.5.4", message: "Invalid BODY parameter" };
        }
        parsed.body = v;
      } else if (key === "SMTPUTF8") {
        parsed.smtputf8 = true;
      } else {
        return { ok: false, code: 504, enhanced: "5.5.4", message: `Unrecognized MAIL FROM parameter: ${key}` };
      }
    }
  }
  return { ok: true, value: parsed };
}

/** `TO:<addr>` 파싱. 파라미터는 관대하게 무시(RCPT 파라미터는 스코프 밖). */
function parseRcptToArgs(rest: string): { ok: true; value: { address: string } } | ParamSyntaxError {
  const m = /^to:\s*<([^>]*)>\s*(.*)$/i.exec(rest);
  if (!m) return { ok: false, code: 501, enhanced: "5.5.4", message: "Syntax: RCPT TO:<address> [params]" };
  const address = m[1] ?? "";
  if (address.length === 0) return { ok: false, code: 501, enhanced: "5.1.3", message: "Bad recipient address syntax" };
  return { ok: true, value: { address } };
}

export class SmtpEngine {
  private readonly hostname: string;
  private readonly maxSizeBytes: number;
  private readonly tlsAvailableConfigured: boolean;
  private readonly profile: "relay" | "submission";
  private readonly authOfferedConfigured: boolean;
  private readonly allowInsecureAuthConfigured: boolean;

  private buffer: Uint8Array = new Uint8Array(0);
  private state: ConnState = "init";
  private isTls = false;
  private awaiting: Awaiting = null;
  /**
   * SCRAM 가짜 salt 유도용 서버 비밀 — **엔진 인스턴스가 아니라 서버 단위**여야 한다.
   * 연결마다 달라지면 같은 사용자명의 가짜 salt가 매번 바뀌어 계정 열거가 다시 열린다
   * (scram-session.ts fakeKeys 주석). 옵션으로 안 주면 프로세스 수명 동안 고정된 값을 쓴다.
   */
  private readonly scramDecoySecret: Buffer;
  private readonly scramOfferedConfigured: boolean;
  private closed = false;

  private mailFrom: string | null = null;
  private heloName = "";
  private rcptTo: string[] = [];
  /**
   * 세션 누적 카운터 — **트랜잭션 리셋(RSET·MAIL FROM·DATA 종료)에도, STARTTLS 업그레이드에도
   * 초기화하지 않는다.** 어느 하나로든 리셋되면 그 명령 한 줄이 곧 한도 우회다.
   * (RFC 3207이 STARTTLS 후 폐기하라는 것은 협상·트랜잭션 상태이지 남용 카운터가 아니다.)
   */
  private rcptCount = 0;
  private errorCount = 0;
  private pendingRcptAddress: string | null = null;

  private dataChunks: Uint8Array[] = [];
  private dataSize = 0;
  private dataOverflow = false;
  /** awaiting 중 파이프라인 상한을 넘겼다 — 재개 시점에 421로 끊는다. */
  private pendingOverflow = false;

  private authenticatedAs: string | null = null;
  private authContinuation: AuthContinuation | null = null;
  private pendingAuthUser: string | null = null;

  constructor(opts: SmtpEngineOptions) {
    this.hostname = opts.hostname;
    this.maxSizeBytes = opts.maxSizeBytes;
    this.tlsAvailableConfigured = opts.tlsAvailable;
    this.profile = opts.profile ?? "relay";
    this.authOfferedConfigured = opts.authOffered ?? false;
    this.allowInsecureAuthConfigured = opts.allowInsecureAuth ?? false;
    this.scramDecoySecret = opts.scramDecoySecret ?? PROCESS_SCRAM_DECOY;
    this.scramOfferedConfigured = opts.scramOffered ?? false;
  }

  /** 연결 수립 직후 어댑터가 한 번 호출 — 220 배너. */
  greeting(): SmtpAction[] {
    return [rawReply(`220 ${this.hostname} ESMTP ready`)];
  }

  /**
   * 방출 직전에 4xx/5xx를 세고, 세션 오류 상한을 넘으면 421로 끊는다.
   *
   * **엔진의 공개 메서드는 전부 반환 직전에 이 함수를 통과한다.** 세는 지점을 응답 생성부마다
   * 흩어 두면(현재 40곳 남짓) 반드시 새는 갈래가 생기고, 새는 갈래 하나가 곧 무제한 오라클이다.
   * 배열 하나를 정확히 한 번만 통과시키는 것이 이 배치의 요점 — `pump()` 결과는 호출한 공개
   * 메서드의 배열에 합쳐진 뒤 거기서 한 번 세어진다.
   *
   * 왜 상한이 필요한가(감사 H-3): `RCPT TO`는 맞으면 250·틀리면 550으로 답하는 검증 오라클이고,
   * SRS 분기는 DB 조회 없이 HMAC 1회라 비용이 거의 0이다. 세션당 개수·오류 상한이 **둘 다
   * 없어서** 연결 하나로 무제한 대입이 가능했다.
   */
  private guardErrors(actions: SmtpAction[]): SmtpAction[] {
    if (this.closed) return actions;
    for (const a of actions) {
      // 확장 상태코드 유무와 무관하게 응답은 항상 3자리 코드로 시작한다(reply/rawReply 공통).
      if (a.kind === "reply" && (a.text.startsWith("4") || a.text.startsWith("5"))) this.errorCount += 1;
    }
    if (this.errorCount <= MAX_SMTP_ERRORS_PER_SESSION) return actions;
    this.closed = true;
    this.buffer = new Uint8Array(0);
    actions.push(reply(421, "4.7.0", "Too many errors, closing connection"), { kind: "close" });
    return actions;
  }

  /** 소켓에서 읽은 바이트를 먹인다. 파이프라인된 여러 명령을 한 번에 처리할 수 있다. */
  feed(chunk: Uint8Array): SmtpAction[] {
    if (this.closed) return [];
    if (this.awaiting !== null) {
      // 재개 전까지는 pump()가 돌지 않아 어떤 상한도 적용되지 않는다 — 여기서 직접 막는다.
      // 초과분은 버린다(어차피 재개 시 421로 끊는다). 버퍼를 더 키우지 않는 게 요점.
      if (this.buffer.length + chunk.length > MAX_PIPELINE_PENDING_BYTES) {
        this.pendingOverflow = true;
        return [];
      }
      this.buffer = concatBytes(this.buffer, chunk);
      return [];
    }
    this.buffer = concatBytes(this.buffer, chunk);
    return this.guardErrors(this.pump());
  }

  /** RCPT TO 백엔드 검증 결과 — {kind:"rcpt"} 액션에 대한 응답. */
  rcptResult(outcome: RcptOutcome): SmtpAction[] {
    if (this.awaiting !== "rcpt") throw new Error("rcptResult() called without a pending RCPT verification");
    const address = this.pendingRcptAddress ?? "";
    this.pendingRcptAddress = null;
    this.awaiting = null;

    const actions: SmtpAction[] = [];
    if (outcome.ok) {
      this.rcptTo.push(address);
      this.state = "rcpt";
      actions.push(reply(250, "2.1.5", `${address} OK`));
    } else {
      actions.push(reply(outcome.code, outcome.enhanced, outcome.message));
    }
    actions.push(...this.pump());
    return this.guardErrors(actions);
  }

  /** 배달 백엔드 결과 — {kind:"deliver"} 액션(DATA 종료 시점)에 대한 응답. */
  deliveryResult(outcome: DeliverOutcome): SmtpAction[] {
    if (this.awaiting !== "deliver") throw new Error("deliveryResult() called without a pending delivery");
    this.awaiting = null;

    const actions: SmtpAction[] = [];
    if (outcome.ok) {
      const detail = outcome.queuedId !== undefined ? `queued as ${outcome.queuedId}` : "OK";
      actions.push(reply(250, "2.6.0", detail));
    } else {
      actions.push(reply(outcome.code, outcome.enhanced, outcome.message));
    }
    this.resetTransaction();
    actions.push(...this.pump());
    return this.guardErrors(actions);
  }

  /** AUTH 백엔드 검증 결과 — {kind:"auth"} 액션에 대한 응답. */
  authResult(ok: boolean): SmtpAction[] {
    if (this.awaiting !== "auth") throw new Error("authResult() called without a pending AUTH verification");
    // ★SCRAM도 같은 경로를 탄다 — 엔진이 검증을 끝낸 뒤 pendingAuthUser를 채워 두면
    //   여기서 세션이 묶인다. 인증 성공 처리를 메커니즘마다 따로 두지 않는다.
    const user = this.pendingAuthUser;
    this.pendingAuthUser = null;
    this.awaiting = null;

    const actions: SmtpAction[] = [];
    if (ok) {
      this.authenticatedAs = user;
      actions.push(reply(235, "2.7.0", "Authentication successful"));
    } else {
      actions.push(reply(535, "5.7.8", "Authentication credentials invalid"));
    }
    actions.push(...this.pump());
    return this.guardErrors(actions);
  }

  /** 어댑터가 TLS 업그레이드를 완료한 뒤 호출 — RFC 3207: 이전 상태 폐기, 새 EHLO 요구. */
  tlsUpgraded(): void {
    this.isTls = true;
    this.awaiting = null;
    this.state = "init";
    this.mailFrom = null;
    this.rcptTo = [];
    this.pendingRcptAddress = null;
    this.dataChunks = [];
    this.dataSize = 0;
    this.dataOverflow = false;
    this.buffer = new Uint8Array(0);
    // 업그레이드 전 평문 바이트는 어차피 폐기 대상이라(스트리핑 완화) 폭주 표시도 함께 지운다.
    this.pendingOverflow = false;
    // 재TLS 이후 재인증 요구(스펙) — 이전 세션의 인증 상태/진행중 챌린지 폐기.
    this.authenticatedAs = null;
    this.authContinuation = null;
    this.pendingAuthUser = null;
  }

  // ── 내부 파서 루프 ─────────────────────────────────────────────────
  private pump(): SmtpAction[] {
    const actions: SmtpAction[] = [];
    if (this.pendingOverflow) {
      // awaiting 중 상한을 넘겼다 — 스트림이 이미 잘려 나가 프로토콜 동기가 깨졌으므로 끊는다.
      this.pendingOverflow = false;
      this.closed = true;
      this.buffer = new Uint8Array(0);
      return [reply(421, "4.7.0", "Too much pipelined data, closing connection"), { kind: "close" }];
    }
    while (this.awaiting === null && !this.closed) {
      if (this.authContinuation !== null) {
        const crlfIdx = indexOfCRLF(this.buffer);
        if (crlfIdx === -1) {
          if (this.buffer.length > MAX_COMMAND_LINE) {
            this.authContinuation = null;
            actions.push(reply(501, "5.5.2", "Line too long"));
            this.buffer = new Uint8Array(0);
          }
          break;
        }
        const lineBytes = this.buffer.subarray(0, crlfIdx);
        this.buffer = this.buffer.subarray(crlfIdx + 2);
        this.handleAuthContinuationLine(lineBytes, actions);
        continue;
      }

      if (this.state === "data") {
        const advanced = this.pumpDataLine(actions);
        if (!advanced) break;
        continue;
      }

      const crlfIdx = indexOfCRLF(this.buffer);
      if (crlfIdx === -1) {
        if (this.buffer.length > MAX_COMMAND_LINE) {
          actions.push(reply(550, "5.5.2", "Line too long"));
          this.buffer = new Uint8Array(0);
        }
        break;
      }
      const lineBytes = this.buffer.subarray(0, crlfIdx);
      this.buffer = this.buffer.subarray(crlfIdx + 2);
      this.handleCommandLine(lineBytes, actions);
    }
    return actions;
  }

  /**
   * CRLF가 아직 안 온 DATA 바이트에 상한을 건다(MAX_DATA_LINE 주석 참조).
   *
   * 초과 시 dataOverflow로 수렴시키는 이유: 연결을 끊는 대신 **종료 마커를 계속 스캔**하면
   * 세션이 동기를 유지한 채 552로 정상 거절할 수 있다. 대신 누적은 즉시 멈춘다.
   * 버퍼를 비울 때 끝의 CR 한 바이트만 남기는 건, 그 CR이 종료 마커 `CRLF "." CRLF`의
   * 첫 바이트일 수 있어서다 — 통째로 버리면 마커를 놓쳐 세션이 영영 DATA에 갇힌다.
   */
  private guardDataBuffer(): void {
    const tooLong = this.buffer.length > MAX_DATA_LINE;
    const tooBig = this.dataSize + this.buffer.length > this.maxSizeBytes;
    if (!tooLong && !tooBig) return;
    this.dataOverflow = true;
    this.dataChunks = [];
    this.dataSize = 0;
    const last = this.buffer[this.buffer.length - 1];
    this.buffer = last === CR ? this.buffer.subarray(this.buffer.length - 1) : new Uint8Array(0);
  }

  /** DATA 콘텐츠 한 줄 처리. 더 처리할 완결된 줄이 없으면 false(더 필요한 바이트 대기). */
  private pumpDataLine(actions: SmtpAction[]): boolean {
    const crlfIdx = indexOfCRLF(this.buffer);
    if (crlfIdx === -1) {
      this.guardDataBuffer();
      return false;
    }

    const line = this.buffer.subarray(0, crlfIdx); // CRLF 제외
    this.buffer = this.buffer.subarray(crlfIdx + 2);

    if (line.length === 1 && line[0] === DOT) {
      this.finishData(actions);
      return true;
    }

    if (!this.dataOverflow) {
      // dot-stuffing 해제: 라인 선두 dot 하나 제거
      const content = line.length > 0 && line[0] === DOT ? line.subarray(1) : line;
      const lineTotal = content.length + 2;
      if (this.dataSize + lineTotal > this.maxSizeBytes) {
        this.dataOverflow = true;
        this.dataChunks = []; // 더는 축적하지 않음 — 메모리 보호
      } else {
        this.dataChunks.push(content, CRLF_BYTES);
        this.dataSize += lineTotal;
      }
    }
    return true;
  }

  private finishData(actions: SmtpAction[]): void {
    if (this.dataOverflow) {
      actions.push(reply(552, "5.3.4", "Message size exceeds fixed maximum message size"));
      this.resetTransaction();
      return;
    }
    const raw = concatChunks(this.dataChunks);
    this.dataChunks = [];
    this.dataSize = 0;
    const mailFrom = this.mailFrom ?? "";
    const rcptTo = [...this.rcptTo];
    this.awaiting = "deliver";
    actions.push({ kind: "deliver", mailFrom, heloName: this.heloName, rcptTo, raw, authenticatedAs: this.authenticatedAs });
  }

  /** AUTH 챌린지/응답 왕복 중 도착한 한 줄(base64 응답 또는 `*` 취소) 처리. */
  private handleAuthContinuationLine(lineBytes: Uint8Array, actions: SmtpAction[]): void {
    if (lineBytes.length > MAX_COMMAND_LINE) {
      this.authContinuation = null;
      actions.push(reply(501, "5.5.2", "Line too long"));
      return;
    }
    const line = decodeLine(lineBytes).trim();
    if (line === "*") {
      this.authContinuation = null;
      actions.push(reply(501, "5.7.0", "Authentication cancelled"));
      return;
    }

    const cont = this.authContinuation;
    if (cont === null) return; // 도달 불가 — pump()가 이미 null 체크함

    if (cont.mechanism === "PLAIN") {
      this.authContinuation = null;
      this.finishPlainAuth(line, actions);
      return;
    }

    if (cont.mechanism === "XOAUTH2" || cont.mechanism === "OAUTHBEARER") {
      this.authContinuation = null;
      this.finishOAuthAuth(cont.mechanism, line, actions);
      return;
    }

    if (cont.mechanism === "SCRAM-SHA-256") {
      if (cont.stage === "keys") {
        this.beginScram(cont.session, line, actions);
        return;
      }
      if (cont.stage === "serverFinal") {
        /**
         * ★server-final(334)에 대한 클라이언트의 빈 응답. 여기서야 235를 보낸다.
         *
         * 왜 왕복을 하나 더 두는가: server-final은 **클라이언트가 서버를 검증하는 값**이다
         * (상호 인증이 SCRAM의 절반이다). 235에 얹어 한 번에 끝내면 클라이언트는 검증할
         * 기회 없이 성공을 받는다. 334로 먼저 주고 클라이언트가 확인한 뒤 235로 닫는다.
         */
        this.authContinuation = null;
        this.awaiting = "auth";
        this.pendingAuthUser = cont.username;
        actions.push({ kind: "authVerified", user: cont.username });
        return;
      }
      // client-final — 검증은 순수 계산이라 엔진이 직접 한다(백엔드 왕복 없음).
      const decoded = decodeBase64Strict(line);
      if (decoded === null) {
        this.authContinuation = null;
        actions.push(reply(501, "5.5.2", "Invalid base64 encoding"));
        return;
      }
      const step = cont.session.final(utf8Decoder.decode(decoded));
      if (step.need !== "done") {
        this.authContinuation = null;
        actions.push(this.scramFailedAction(step));
        actions.push(reply(535, "5.7.8", "Authentication credentials invalid"));
        return;
      }
      this.authContinuation = { mechanism: "SCRAM-SHA-256", session: cont.session, stage: "serverFinal", username: step.username };
      actions.push(rawReply(`334 ${Buffer.from(step.message).toString("base64")}`));
      return;
    }

    // LOGIN (여기 도달 시 cont는 LOGIN — 명시 가드로 TS 내로잉)
    if (cont.mechanism === "LOGIN") {
      const decoded = decodeBase64Strict(line);
      if (decoded === null) {
        this.authContinuation = null;
        actions.push(reply(501, "5.5.2", "Invalid base64 encoding"));
        return;
      }
      if (cont.step === "username") {
        this.authContinuation = { mechanism: "LOGIN", step: "password", user: utf8Decoder.decode(decoded) };
        actions.push(rawReply("334 UGFzc3dvcmQ6"));
        return;
      }
      const user = cont.user;
      this.authContinuation = null;
      this.pendingAuthUser = user;
      this.awaiting = "auth";
      actions.push({ kind: "auth", user, pass: utf8Decoder.decode(decoded) });
    }
  }

  /** SASL PLAIN 최종 페이로드(초기응답 또는 연속행) 처리 — 파싱 성공 시 auth 액션 emit. */
  private finishPlainAuth(b64: string, actions: SmtpAction[]): void {
    const bytes = decodeBase64Strict(b64);
    if (bytes === null) {
      actions.push(reply(501, "5.5.2", "Invalid base64 encoding"));
      return;
    }
    const creds = decodePlainAuth(bytes);
    if (creds === null) {
      actions.push(reply(501, "5.5.2", "Invalid PLAIN authentication response"));
      return;
    }
    this.pendingAuthUser = creds.user;
    this.awaiting = "auth";
    actions.push({ kind: "auth", user: creds.user, pass: creds.pass });
  }

  /** OAuth SASL(XOAUTH2/OAUTHBEARER) 최종 페이로드 — 토큰을 pass로 흘려 kind=2 자격증명 검증. */
  private finishOAuthAuth(mechanism: "XOAUTH2" | "OAUTHBEARER", b64: string, actions: SmtpAction[]): void {
    const bytes = decodeBase64Strict(b64);
    if (bytes === null) {
      actions.push(reply(501, "5.5.2", "Invalid base64 encoding"));
      return;
    }
    const creds = parseSaslOAuth(mechanism, utf8Decoder.decode(bytes));
    if (creds === null) {
      actions.push(reply(501, "5.5.2", `Invalid ${mechanism} authentication response`));
      return;
    }
    this.pendingAuthUser = creds.user;
    this.awaiting = "auth";
    actions.push({ kind: "auth", user: creds.user, pass: creds.token });
  }

  private handleCommandLine(lineBytes: Uint8Array, actions: SmtpAction[]): void {
    if (lineBytes.length > MAX_COMMAND_LINE) {
      actions.push(reply(550, "5.5.2", "Line too long"));
      return;
    }
    const line = decodeLine(lineBytes);
    if (line.trim().length === 0) {
      actions.push(reply(500, "5.5.1", "Command unrecognized"));
      return;
    }
    const { verb, rest } = splitVerb(line);
    switch (verb) {
      case "EHLO":
        this.handleEhlo(rest, actions);
        return;
      case "HELO":
        this.handleHelo(rest, actions);
        return;
      case "MAIL":
        this.handleMail(rest, actions);
        return;
      case "RCPT":
        this.handleRcpt(rest, actions);
        return;
      case "DATA":
        this.handleData(rest, actions);
        return;
      case "RSET":
        this.resetTransaction();
        actions.push(reply(250, "2.1.5", "OK"));
        return;
      case "NOOP":
        actions.push(reply(250, "2.0.0", "OK"));
        return;
      case "QUIT":
        actions.push(reply(221, "2.0.0", "Bye"));
        actions.push({ kind: "close" });
        this.closed = true;
        return;
      case "VRFY":
        this.handleVrfy(rest, actions);
        return;
      case "EXPN":
        actions.push(reply(502, "5.5.1", "Command not implemented"));
        return;
      case "HELP":
        actions.push(reply(214, "2.0.0", "See RFC 5321"));
        return;
      case "STARTTLS":
        this.handleStartTls(actions);
        return;
      case "AUTH":
        this.handleAuth(rest, actions);
        return;
      default:
        actions.push(reply(500, "5.5.1", "Command unrecognized"));
    }
  }

  private handleEhlo(rest: string, actions: SmtpAction[]): void {
    if (rest.length === 0) {
      actions.push(reply(501, "5.5.4", "Syntax: EHLO hostname"));
      return;
    }
    this.resetTransaction();
    this.state = "greeted";
    this.heloName = rest; // SPF HELO identity (RFC 7208)

    // docs/PROTOCOLS.md §1 "2026 최소 신뢰 EHLO 세트" 순서
    const caps = ["8BITMIME", "PIPELINING", "ENHANCEDSTATUSCODES", "SMTPUTF8"];
    const lines = [`250-${this.hostname} Hello ${rest}`, `250-SIZE ${this.maxSizeBytes}`, ...caps.map((c) => `250-${c}`)];
    if (this.tlsAvailableConfigured && !this.isTls) lines.push("250-STARTTLS");
    // RFC 4954: 평문 회선에는 allowInsecureAuth 없이 광고 금지
        // ★SCRAM을 **앞에** 놓는다. 다수 클라이언트가 광고 순서를 선호도로 읽어서,
    //   PLAIN이 앞에 있으면 더 안전한 메커니즘을 두고도 평문을 고른다.
    if (this.authAllowed()) {
      const mechs = this.scramOfferedConfigured
        ? "SCRAM-SHA-256 PLAIN LOGIN XOAUTH2 OAUTHBEARER"
        : "PLAIN LOGIN XOAUTH2 OAUTHBEARER";
      lines.push(`250-AUTH ${mechs}`);
    }
    // 마지막 줄만 대시 없이
    const last = lines.pop()!;
    lines.push(last.replace("250-", "250 "));
    actions.push({ kind: "reply", text: lines.map((l) => `${l}\r\n`).join("") });
  }

  private handleHelo(rest: string, actions: SmtpAction[]): void {
    if (rest.length === 0) {
      actions.push(reply(501, "5.5.4", "Syntax: HELO hostname"));
      return;
    }
    this.resetTransaction();
    this.state = "greeted";
    this.heloName = rest; // SPF HELO identity (RFC 7208)
    actions.push(rawReply(`250 ${this.hostname} Hello ${rest}`));
  }

  private handleMail(rest: string, actions: SmtpAction[]): void {
    if (this.state === "init") {
      actions.push(reply(503, "5.5.1", "Send HELO/EHLO first"));
      return;
    }
    if (this.profile === "submission" && this.authenticatedAs === null) {
      actions.push(reply(530, "5.7.0", "Authentication required"));
      return;
    }
    if (this.state !== "greeted") {
      actions.push(reply(503, "5.5.1", "Sender already specified"));
      return;
    }
    const parsed = parseMailFromArgs(rest);
    if (!parsed.ok) {
      actions.push(reply(parsed.code, parsed.enhanced, parsed.message));
      return;
    }
    if (parsed.value.size !== undefined && parsed.value.size > this.maxSizeBytes) {
      actions.push(reply(552, "5.3.4", "Message size exceeds fixed maximum message size"));
      return;
    }
    this.mailFrom = parsed.value.address;
    this.rcptTo = [];
    this.state = "mail";
    actions.push(reply(250, "2.1.0", "OK"));
  }

  private handleRcpt(rest: string, actions: SmtpAction[]): void {
    if (this.state !== "mail" && this.state !== "rcpt") {
      actions.push(reply(503, "5.5.1", "Need MAIL before RCPT"));
      return;
    }
    const parsed = parseRcptToArgs(rest);
    if (!parsed.ok) {
      actions.push(reply(parsed.code, parsed.enhanced, parsed.message));
      return;
    }
    // 백엔드 검증에 도달하는 RCPT만 센다 — 오라클의 비용·정보량이 걸린 곳이 여기다.
    // 452(일시)라 상한에 닿아도 정상 발신자의 메일은 재시도로 배달된다(limits.ts 주석 참조).
    if (this.rcptCount >= MAX_RCPT_PER_SESSION) {
      actions.push(reply(452, "4.5.3", "Too many recipients"));
      return;
    }
    this.rcptCount += 1;
    this.pendingRcptAddress = parsed.value.address;
    this.awaiting = "rcpt";
    actions.push({ kind: "rcpt", address: parsed.value.address });
  }

  private handleData(rest: string, actions: SmtpAction[]): void {
    if (rest.length > 0) {
      actions.push(reply(501, "5.5.4", "Syntax: DATA"));
      return;
    }
    if (this.state !== "rcpt") {
      actions.push(reply(503, "5.5.1", "Need RCPT before DATA"));
      return;
    }
    this.state = "data";
    actions.push(rawReply("354 Start mail input; end with <CRLF>.<CRLF>"));
  }

  private handleVrfy(rest: string, actions: SmtpAction[]): void {
    if (rest.trim().length === 0) {
      actions.push(reply(501, "5.5.4", "Syntax: VRFY address"));
      return;
    }
    // RFC 5321 §7.3 — 사용자 열거 방지, 항상 252
    actions.push(reply(252, "2.1.5", "Cannot VRFY user, but will accept message"));
  }

  private handleStartTls(actions: SmtpAction[]): void {
    if (!this.tlsAvailableConfigured) {
      actions.push(reply(502, "5.5.1", "Command not implemented"));
      return;
    }
    if (this.isTls) {
      actions.push(reply(503, "5.5.1", "Already using TLS"));
      return;
    }
    // 업그레이드 전 파이프라인된 잔여 평문 바이트는 폐기(스트리핑 공격 완화)
    this.buffer = new Uint8Array(0);
    actions.push(reply(220, "2.0.0", "Ready to start TLS"));
    actions.push({ kind: "startTls" });
    this.awaiting = "tls";
  }

  /** RFC 4954: AUTH는 authOffered && (TLS 업그레이드됨 || allowInsecureAuth)일 때만 광고/수락. */
  private authAllowed(): boolean {
    return this.authOfferedConfigured && (this.isTls || this.allowInsecureAuthConfigured);
  }

  private handleAuth(rest: string, actions: SmtpAction[]): void {
    if (!this.authAllowed()) {
      actions.push(reply(502, "5.5.1", "Command not implemented"));
      return;
    }
    if (this.authenticatedAs !== null) {
      actions.push(reply(503, "5.5.1", "Already authenticated"));
      return;
    }
    const { verb: mechanism, rest: initialResponse } = splitVerb(rest);
    if (mechanism === "PLAIN") {
      if (initialResponse.length > 0) {
        this.finishPlainAuth(initialResponse, actions);
      } else {
        this.authContinuation = { mechanism: "PLAIN" };
        actions.push(rawReply("334"));
      }
      return;
    }
    if (mechanism === "LOGIN") {
      if (initialResponse.length > 0) {
        const decoded = decodeBase64Strict(initialResponse);
        if (decoded === null) {
          actions.push(reply(501, "5.5.2", "Invalid base64 encoding"));
          return;
        }
        this.authContinuation = { mechanism: "LOGIN", step: "password", user: utf8Decoder.decode(decoded) };
        actions.push(rawReply("334 UGFzc3dvcmQ6"));
      } else {
        this.authContinuation = { mechanism: "LOGIN", step: "username" };
        actions.push(rawReply("334 VXNlcm5hbWU6"));
      }
      return;
    }
    if (mechanism === "SCRAM-SHA-256") {
      // 광고하지 않은 메커니즘은 받지 않는다 — 백엔드가 못 끝낼 교환을 시작하면 안 된다.
      if (!this.scramOfferedConfigured) {
        actions.push(reply(504, "5.5.4", "Unrecognized authentication type"));
        return;
      }
      const session = new ScramServerSession(this.scramDecoySecret);
      if (initialResponse.length > 0) {
        this.beginScram(session, initialResponse, actions);
      } else {
        this.authContinuation = { mechanism: "SCRAM-SHA-256", session, stage: "keys" };
        actions.push(rawReply("334 ")); // 빈 챌린지 — 클라이언트가 client-first를 보낸다
      }
      return;
    }
    if (mechanism === "XOAUTH2" || mechanism === "OAUTHBEARER") {
      if (initialResponse.length > 0) {
        this.finishOAuthAuth(mechanism, initialResponse, actions);
      } else {
        this.authContinuation = { mechanism };
        actions.push(rawReply("334 ")); // 빈 챌린지 — 클라이언트가 초기응답 전송
      }
      return;
    }
    actions.push(reply(504, "5.5.4", "Unrecognized authentication type"));
  }

  /**
   * SCRAM 실패를 어댑터에 알리는 액션. **거절 응답과 늘 함께 나가야 한다** —
   * 응답만 내고 이걸 빼면 그 갈래가 다시 무기록이 된다(이 액션이 생긴 이유).
   */
  private scramFailedAction(step: ScramStep): SmtpAction {
    return {
      kind: "authFailed",
      mechanism: "SCRAM-SHA-256",
      ...(step.need === "failed" && step.username ? { user: step.username } : {}),
    };
  }

  /** client-first를 세션에 넣고 키 조회를 요청한다. */
  private beginScram(session: ScramServerSession, b64: string, actions: SmtpAction[]): void {
    const decoded = decodeBase64Strict(b64);
    if (decoded === null) {
      this.authContinuation = null;
      actions.push(reply(501, "5.5.2", "Invalid base64 encoding"));
      return;
    }
    const step = session.start(utf8Decoder.decode(decoded));
    if (step.need !== "lookup") {
      this.authContinuation = null;
      actions.push(this.scramFailedAction(step));
      actions.push(reply(535, "5.7.8", "Authentication credentials invalid"));
      return;
    }
    this.authContinuation = { mechanism: "SCRAM-SHA-256", session, stage: "keys" };
    this.awaiting = "scramKeys";
    actions.push({ kind: "scramKeys", user: step.username });
  }

  /**
   * 저장된 SCRAM 키(없으면 null) — **null이어도 교환은 계속된다.**
   * 즉시 실패시키면 "그 계정이 없다"가 응답 형태로 샌다(scram-session.ts 주석).
   */
  scramKeysResult(keys: ScramStoredKeys | null): SmtpAction[] {
    if (this.awaiting !== "scramKeys") throw new Error("scramKeysResult() called without a pending SCRAM lookup");
    this.awaiting = null;
    const cont = this.authContinuation;
    if (cont === null || cont.mechanism !== "SCRAM-SHA-256") return [];
    const step = cont.session.provideKeys(keys);
    if (step.need !== "send") {
      this.authContinuation = null;
      return [this.scramFailedAction(step), reply(535, "5.7.8", "Authentication credentials invalid")];
    }
    this.authContinuation = { mechanism: "SCRAM-SHA-256", session: cont.session, stage: "final" };
    return [rawReply(`334 ${Buffer.from(step.message).toString("base64")}`)];
  }

  private resetTransaction(): void {
    this.mailFrom = null;
    this.rcptTo = [];
    this.pendingRcptAddress = null;
    this.dataChunks = [];
    this.dataSize = 0;
    this.dataOverflow = false;
    if (this.state !== "init") this.state = "greeted";
  }
}
