/**
 * 최소 발신(outbound) SMTP 클라이언트 — node:net(+node:tls) 위에 직접 구현한다
 * (docs/PROTOCOLS.md §1 SMTP 클라이언트측 기대치: EHLO 멀티라인, dot-stuffing, STARTTLS
 * opportunistic, 8BITMIME).
 *
 * ★편차 (실행 요약에 기재): STARTTLS는 여기서 **클라이언트측** 업그레이드
 * (`tls.connect({socket, servername})`)만 수행한다. Bun 알려진 버그(oven-sh/bun#25044,
 * proto-smtp/test/starttls.test.ts 참고)는 **서버측** TLSSocket 업그레이드(`new
 * TLSSocket(existingSocket, {isServer:true})`)에 한정된 문제라 이론상 클라이언트측은
 * 영향이 없어야 한다. 하지만 이 패키지의 통합테스트는 상대 서버로 @ionosphere/proto-smtp의
 * SmtpServer(자체가 서버측 업그레이드 버그의 영향을 받음)를 쓰기 때문에, bun test에서
 * STARTTLS를 광고하는 서버를 세우면 서버측이 멈춰 클라이언트측 코드의 정상 여부와
 * 무관하게 테스트가 행행(hang)한다. 그래서 테스트는 TLS 미설정 SmtpServer(STARTTLS
 * 비광고)를 상대로 tls:"never"로 검증한다 — PLAN.md §6 리스크 표의 폴백 지침
 * ("문제 시 해당 컴포넌트만 Node 실행") 그대로. 프로덕션 MTA는 Node로 구동되므로
 * STARTTLS opportunistic 경로 자체는 그대로 구현해 둔다.
 */
import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect, type DetailedPeerCertificate, type TLSSocket } from "node:tls";
import { X509Certificate } from "node:crypto";
import { checkDane, hasUsableTlsa, type DaneTlsaSet } from "@ionosphere/mail-auth";
import { findUnsafeAddress, isSafeEnvelopeAddress } from "./envelope.ts";

/**
 * TLS 모드:
 * - "opportunistic": STARTTLS 광고 시 업그레이드, 실패해도 평문 진행 (MX 직접 발송 기본)
 * - "required": STARTTLS 필수 — 미광고/실패 시 발송 중단(deferred) (587 릴레이 기본)
 * - "implicit": 연결 자체를 TLS로 시작 (465)
 * - "never": 평문 고정 (테스트 전용)
 */
export type TlsMode = "opportunistic" | "required" | "implicit" | "never";

export interface SmtpAuth {
  user: string;
  pass: string;
}

export interface SmtpClientOptions {
  host: string;
  port: number;
  ehloName: string;
  mailFrom: string;
  rcptTo: readonly string[];
  raw: Uint8Array;
  /** 기본 30초. */
  timeoutMs?: number;
  /** 기본 "opportunistic". */
  tls?: TlsMode;
  /**
   * SASL 인증(릴레이/스마트호스트용) — EHLO(TLS 후 재EHLO 포함) 뒤 AUTH PLAIN/LOGIN.
   * 인증 실패는 항상 permanent=false로 돌려준다 — 자격증명·설정 문제로 수신자를
   * 바운스/suppression 처리하면 안 되기 때문(재시도 대상).
   */
  auth?: SmtpAuth;
  /**
   * DANE(RFC 7672) — **DNSSEC로 검증된** TLSA 집합. 조회·검증은 호출부 몫이다
   * (`@ionosphere/dns`의 ValidatingResolver). 여기서는 "검증됐다"는 사실을 받아 쓴다.
   *
   * ★쓸 수 있는 레코드가 있으면 TLS가 **필수**가 되고(opportunistic이어도) 인증서가
   * TLSA와 맞지 않으면 배달을 **중단한다**(재시도 대상). 그것이 DANE의 전부다.
   */
  dane?: DaneTlsaSet;
}

export interface RcptOutcome {
  code: number;
  permanent: boolean;
  /**
   * 그 수신자에 대한 **원격의 문구**.
   *
   * ★왜 필요한가: 전원 거절이면 세션 결과의 `message`가 우리가 합성한
   * `"all recipients rejected"`라 원격이 왜 거절했는지가 사라진다. 그 값이 그대로
   * `mta_queue.last_error`(테넌트가 `GET /v1/queue`로 본다)와 DSN의 `Diagnostic-Code`로
   * 가므로, 사유가 없으면 둘 다 "실패했다"를 두 번 말하는 것에 가깝다 —
   * `rejectionText()` 주석이 2026-08-03 라이브 사고로 적어 둔 것이 정확히 이 문제다.
   */
  message: string;
}

export interface SmtpClientResult {
  ok: boolean;
  code: number;
  message: string;
  /** 5xx=true, 그 외(4xx·네트워크/타임아웃)=false. */
  permanent: boolean;
  /** 수신자별 RCPT 응답 — 일부만 거부돼도 나머지로 진행하기 위한 부분 성공 정보. */
  rcptResults: Map<string, RcptOutcome>;
  /** DANE를 적용했다면 그 판정(운영 로그·메트릭용). 미적용이면 undefined. */
  dane?: "match" | "mismatch";
}

const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * 응답 하나를 읽으며 버퍼링할 최대 바이트.
 *
 * RFC 5321 §4.5.3.1.5의 응답 줄 상한은 512옥텟이고, EHLO 멀티라인을 다 합쳐도 수 KB면 충분하다.
 * 64KB는 넉넉히 잡은 값이다 — 목적은 정상 응답을 자르는 게 아니라 **끝나지 않는 응답**을 막는 것.
 */
const MAX_REPLY_BYTES = 64 * 1024;

interface ParsedReply {
  code: number;
  lines: string[];
}

/** 소켓에서 SMTP 응답 한 개(멀티라인 `250-...\r\n250 ...` 포함)를 읽어 파싱한다. */
class ReplyReader {
  private buf = "";
  private readonly socket: Socket | TLSSocket;

  constructor(socket: Socket | TLSSocket) {
    this.socket = socket;
  }

  read(): Promise<ParsedReply> {
    return new Promise((resolve, reject) => {
      const lines: string[] = [];
      let code = -1;
      let settled = false;

      const cleanup = (): void => {
        this.socket.off("data", onData);
        this.socket.off("error", onError);
        this.socket.off("close", onClose);
      };
      const settleResolve = (result: ParsedReply): void => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(result);
      };
      const settleReject = (err: Error): void => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(err);
      };

      const tryParse = (): void => {
        for (;;) {
          const idx = this.buf.indexOf("\r\n");
          if (idx === -1) return;
          const line = this.buf.slice(0, idx);
          this.buf = this.buf.slice(idx + 2);
          const m = /^(\d{3})([ -])(.*)$/.exec(line);
          if (!m) {
            settleReject(new Error(`malformed SMTP reply line: ${JSON.stringify(line)}`));
            return;
          }
          const lineCode = Number(m[1]);
          const sep = m[2];
          const text = m[3] ?? "";
          if (code === -1) code = lineCode;
          lines.push(text);
          if (sep === " ") {
            settleResolve({ code, lines });
            return;
          }
        }
      };

      const onData = (chunk: Buffer): void => {
        this.buf += chunk.toString("latin1");
        // 상대가 CRLF를 영영 안 보내면 이 버퍼가 무한히 자란다(악의적이거나 고장난 MX).
        // 발송 워커는 한 프로세스라 여기서 죽으면 큐 전체가 멈춘다 — 상한을 넘으면 끊는다.
        if (this.buf.length > MAX_REPLY_BYTES) {
          settleReject(new Error(`SMTP reply too large (> ${MAX_REPLY_BYTES} bytes) — 상대가 응답을 끝내지 않는다`));
          return;
        }
        tryParse();
      };
      const onError = (err: Error): void => settleReject(err);
      const onClose = (): void => settleReject(new Error("connection closed while awaiting SMTP reply"));

      this.socket.on("data", onData);
      this.socket.on("error", onError);
      this.socket.on("close", onClose);
      tryParse(); // 이전 읽기에서 남은 버퍼로 즉시 완결될 수도 있음
    });
  }
}

function isPermanent(code: number): boolean {
  return code >= 500 && code < 600;
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** 연결 실패(코드 없음)를 나타내는 결과 — MX 페일오버 판정에 code===0을 쓴다. */
function connectFailure(err: unknown, rcptResults: Map<string, RcptOutcome>): SmtpClientResult {
  return { ok: false, code: 0, message: errMsg(err), permanent: false, rcptResults };
}

function connectWithTimeout(host: string, port: number, timeoutMs: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`connect timeout to ${host}:${port}`));
    }, timeoutMs);
    socket.once("connect", () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once("error", (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/** 암시적 TLS 연결(465 등) — 소켓 자체를 TLS로 연다. */
function connectImplicitTls(host: string, port: number, timeoutMs: number, verify: boolean): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect({ host, port, servername: host, rejectUnauthorized: verify });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`connect timeout to ${host}:${port}`));
    }, timeoutMs);
    socket.once("secureConnect", () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once("error", (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/**
 * 클라이언트측 STARTTLS 업그레이드 — tls.connect({socket, servername}).
 *
 * `verify`가 신뢰 검증 여부다(아래 verifyPeer 주석 참조). opportunistic에서 false인 이유는
 * 임의 MX의 자체서명 인증서가 흔해서다 — 대부분 MTA의 실무 관행(암호화는 하되 신뢰는 강제 안 함).
 */
function upgradeTls(socket: Socket, servername: string, timeoutMs: number, verify: boolean): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("tls handshake timeout")), timeoutMs);
    const tlsSocket = tlsConnect({ socket, servername, rejectUnauthorized: verify });
    tlsSocket.once("secureConnect", () => {
      clearTimeout(timer);
      resolve(tlsSocket);
    });
    tlsSocket.once("error", (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/**
 * 상대가 제시한 인증서 체인을 DANE 대조용 형태로 뽑는다.
 *
 * ★`peerCert.pubkey`를 쓰지 않는다. TLSA selector 1은 **SubjectPublicKeyInfo**를 가리키는데
 * node의 `pubkey`는 알고리즘에 따라 SPKI가 아닐 수 있다. X509Certificate로 다시 뽑으면
 * 형식이 한 가지로 확정된다 — 여기서 어긋나면 정상 상대가 mismatch로 튄다.
 */
function peerChain(socket: TLSSocket): { raw: Uint8Array; spki: Uint8Array }[] {
  const out: { raw: Uint8Array; spki: Uint8Array }[] = [];
  let cur: DetailedPeerCertificate | undefined = socket.getPeerCertificate(true);
  const seen = new Set<string>();
  while (cur && cur.raw && cur.raw.length > 0) {
    // 루트 인증서는 자기 자신을 issuerCertificate로 가리킨다 — 지문으로 끊지 않으면 무한 루프.
    const fp = cur.fingerprint256 || Buffer.from(cur.raw).toString("base64");
    if (seen.has(fp)) break;
    seen.add(fp);
    try {
      const spki = new X509Certificate(cur.raw).publicKey.export({ format: "der", type: "spki" });
      out.push({ raw: new Uint8Array(cur.raw), spki: new Uint8Array(spki) });
    } catch {
      break; // 파싱 못 하는 인증서 — 대조 대상이 못 된다. 체인이 비면 mismatch로 귀결된다.
    }
    cur = cur.issuerCertificate;
  }
  return out;
}

/**
 * TLS가 선 뒤 DANE 대조 — 맞지 않으면 **배달을 중단할 결과**를 돌려준다(맞으면 null).
 *
 * ★permanent=false다. TLSA 불일치는 중간자 신호이거나 상대의 키 교체 중 과도기다. 어느 쪽이든
 * 바운스로 굳히면 안 된다 — 공격자가 잠깐 끼어드는 것만으로 정상 메일을 영구 실패시킬 수 있다.
 */
function daneFailure(
  socket: TLSSocket,
  tlsa: DaneTlsaSet,
  host: string,
  rcptResults: Map<string, RcptOutcome>,
): SmtpClientResult | null {
  const verdict = checkDane(peerChain(socket), tlsa);
  if (verdict.status === "match") return null;
  if (verdict.status === "not-applicable") {
    // 연결 전 `hasUsableTlsa`가 참이었는데 여기서 not-applicable이면 두 판정이 어긋난 것이다.
    // 조용히 통과시키지 않는다 — 고정한다고 해놓고 안 한 상태가 가장 나쁘다.
    return {
      ok: false,
      code: 0,
      message: `DANE 내부 불일치(${host}): ${verdict.reason}`,
      permanent: false,
      rcptResults,
    };
  }
  return {
    ok: false,
    code: 0,
    message: `DANE mismatch (${host}): ${verdict.reason}`,
    permanent: false,
    rcptResults,
    dane: "mismatch",
  };
}

function parseCaps(ehloLines: readonly string[]): Set<string> {
  const caps = new Set<string>();
  for (const line of ehloLines.slice(1)) {
    const token = line.trim().split(/\s+/, 1)[0];
    if (token) caps.add(token.toUpperCase());
  }
  return caps;
}

/** EHLO 응답에서 AUTH 메커니즘 목록 추출 — `250-AUTH PLAIN LOGIN` 형태. */
function parseAuthMechs(ehloLines: readonly string[]): Set<string> {
  const mechs = new Set<string>();
  for (const line of ehloLines.slice(1)) {
    const tokens = line.trim().split(/\s+/);
    if (tokens[0]?.toUpperCase() === "AUTH") {
      for (const m of tokens.slice(1)) mechs.add(m.toUpperCase());
    }
  }
  return mechs;
}

async function ehloRoundtrip(socket: Socket | TLSSocket, reader: ReplyReader, ehloName: string): Promise<ParsedReply> {
  socket.write(`EHLO ${ehloName}\r\n`);
  return reader.read();
}

async function quit(socket: Socket | TLSSocket, reader: ReplyReader): Promise<void> {
  try {
    socket.write("QUIT\r\n");
    await reader.read();
  } catch {
    // 종료 인사는 베스트에포트 — 실패해도 무시하고 소켓을 닫는다.
  }
}

/**
 * SASL AUTH — PLAIN(initial-response, RFC 4954) 우선, 미광고 시 LOGIN 폴백.
 * 성공이면 code 235 응답을 돌려주고, 그 외 코드는 호출자가 실패 처리한다.
 */
async function doAuth(
  socket: Socket | TLSSocket,
  reader: ReplyReader,
  ehloLines: readonly string[],
  auth: SmtpAuth,
): Promise<ParsedReply> {
  const mechs = parseAuthMechs(ehloLines);
  if (mechs.size === 0) {
    return { code: 0, lines: ["AUTH not advertised by server"] };
  }
  if (mechs.has("PLAIN") || !mechs.has("LOGIN")) {
    // PLAIN 미광고+LOGIN 미광고면 어차피 실패 — PLAIN으로 시도해 서버 응답을 그대로 전달
    const initial = Buffer.from(`\u0000${auth.user}\u0000${auth.pass}`, "utf8").toString("base64");
    socket.write(`AUTH PLAIN ${initial}\r\n`);
    return reader.read();
  }
  // LOGIN: 334 챌린지 두 번(사용자명/비밀번호)
  socket.write("AUTH LOGIN\r\n");
  let reply = await reader.read();
  if (reply.code !== 334) return reply;
  socket.write(`${Buffer.from(auth.user, "utf8").toString("base64")}\r\n`);
  reply = await reader.read();
  if (reply.code !== 334) return reply;
  socket.write(`${Buffer.from(auth.pass, "utf8").toString("base64")}\r\n`);
  return reader.read();
}

/**
 * 라인 선두 '.' 이스케이프(dot-stuffing, RFC 5321 §4.5.2) — 바이트 레벨로 처리(본문 인코딩 불문).
 *
 * **2패스인 이유**: 예전엔 `number[]`에 바이트를 하나씩 push했다. JS 배열 원소는 박싱돼
 * 25MB 메시지가 힙에서 200MB+가 되고(발송 워커 메모리 스파이크·GC 정지), `Uint8Array.from`이
 * 그 위에 사본을 하나 더 만들었다. 먼저 세고 정확한 크기로 한 번만 할당한다.
 *
 * 스터핑할 게 없으면 **원본을 그대로 돌려준다** — 대부분의 메시지가 여기 해당해서 복사가 아예 없다.
 */
function dotStuff(raw: Uint8Array): Uint8Array {
  let extra = 0;
  let atLineStart = true;
  for (const b of raw) {
    if (atLineStart && b === 0x2e) extra++;
    atLineStart = b === 0x0a;
  }
  if (extra === 0) return raw;

  const out = new Uint8Array(raw.length + extra);
  let o = 0;
  atLineStart = true;
  for (const b of raw) {
    if (atLineStart && b === 0x2e) out[o++] = 0x2e;
    out[o++] = b;
    atLineStart = b === 0x0a;
  }
  return out;
}

function endsWithCrlf(bytes: Uint8Array): boolean {
  const n = bytes.length;
  return n >= 2 && bytes[n - 2] === 0x0d && bytes[n - 1] === 0x0a;
}

export async function sendSmtp(opts: SmtpClientOptions): Promise<SmtpClientResult> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const rcptResults = new Map<string, RcptOutcome>();

  /**
   * ★DANE가 적용되면 opportunistic이라도 TLS는 **필수**가 된다(RFC 7672 §2.2).
   * 상대가 TLSA를 게시했다는 것은 "암호화 없이는 받지 않겠다"는 선언이고, 우리가 평문으로
   * 흘리면 다운그레이드 공격이 그대로 성립한다.
   */
  const daneActive = opts.dane !== undefined && hasUsableTlsa(opts.dane);
  const requestedTls = opts.tls ?? "opportunistic";
  // "never"까지 승격 대상에 넣는 이유: 조용한 우회 경로를 남기지 않기 위해서다.
  // implicit은 이미 TLS라 그대로 둔다.
  const tlsMode: TlsMode =
    daneActive && (requestedTls === "opportunistic" || requestedTls === "never") ? "required" : requestedTls;

  /**
   * 전송 직전 마지막 방어선 — 이 값들은 아래에서 `MAIL FROM:<...>` / `RCPT TO:<...>`로
   * **명령 줄에 그대로** 실린다. 적재 시점(enqueue)에도 검사하지만, 이 수정 이전에 이미
   * DB에 들어간 오염된 값이 있을 수 있어 여기서도 막는다. 영구 실패로 굳혀 재시도를 막는다
   * — 주소 자체가 틀린 것이라 몇 번을 보내도 같다.
   */
  const unsafe = isSafeEnvelopeAddress(opts.mailFrom) ? findUnsafeAddress(opts.rcptTo) : opts.mailFrom;
  if (unsafe !== null) {
    return {
      ok: false,
      code: 550,
      message: `unsafe envelope address (CR/LF injection guard): ${JSON.stringify(unsafe)}`,
      permanent: true,
      rcptResults,
    };
  }

  /**
   * ★신뢰 검증 여부. required/implicit은 **"TLS를 썼다"가 아니라 "상대가 맞다"를 요구**한다:
   *  - MTA-STS enforce(RFC 8461 §4.1)는 MX 호스트명에 대한 인증서 검증이 핵심이다. 검증 없이
   *    암호화만 하면 능동적 MITM을 전혀 막지 못해 정책이 사실상 무의미해진다.
   *  - 스마트호스트는 AUTH PLAIN으로 **자격증명을 실어 보낸다.** 검증 없는 TLS면 그대로 가로채인다
   *    (SmarthostOptions.tls 기본값이 required인 이유가 바로 이 보호였는데 검증이 빠져 있었다).
   * opportunistic만 false — 임의 MX의 자체서명이 흔한 현실을 인정하는 자리다.
   * 자체서명 스마트호스트를 쓰는 구성은 IONOSPHERE_SMARTHOST_TLS=opportunistic으로 명시 강등할 수 있다.
   */
  /**
   * ★DANE에서는 PKIX 검증을 **끈다**(RFC 7672 §3.1). TLSA가 신뢰앵커를 대신하므로 공개 CA
   * 사슬도 호스트명 일치도 요구하지 않는다 — DANE를 쓰는 MX 상당수가 자체서명이다.
   * 켜 두면 정상적인 DANE 상대를 우리가 거절한다. 안전은 아래 `enforceDane`이 지킨다:
   * TLSA와 맞지 않으면 배달하지 않는다.
   */
  const verifyPeer = !daneActive && (tlsMode === "required" || tlsMode === "implicit");

  let socket: Socket | TLSSocket;
  try {
    socket =
      tlsMode === "implicit"
        ? await connectImplicitTls(opts.host, opts.port, timeoutMs, verifyPeer)
        : await connectWithTimeout(opts.host, opts.port, timeoutMs);
  } catch (err) {
    return connectFailure(err, rcptResults);
  }
  socket.setTimeout(timeoutMs);
  socket.once("timeout", () => socket.destroy(new Error(`smtp idle timeout (${timeoutMs}ms)`)));

  // implicit은 여기서 이미 TLS다 — 배너를 읽기 전에 상대를 확정한다.
  if (daneActive && tlsMode === "implicit") {
    const fail = daneFailure(socket as TLSSocket, opts.dane!, opts.host, rcptResults);
    if (fail) {
      socket.destroy();
      return fail;
    }
  }

  let reader = new ReplyReader(socket);

  try {
    const banner = await reader.read();
    if (banner.code < 200 || banner.code >= 300) {
      const result: SmtpClientResult = {
        ok: false,
        code: banner.code,
        message: banner.lines.join(" "),
        permanent: isPermanent(banner.code),
        rcptResults,
      };
      socket.destroy();
      return result;
    }

    let ehlo = await ehloRoundtrip(socket, reader, opts.ehloName);
    if (ehlo.code < 200 || ehlo.code >= 300) {
      const result: SmtpClientResult = {
        ok: false,
        code: ehlo.code,
        message: ehlo.lines.join(" "),
        permanent: isPermanent(ehlo.code),
        rcptResults,
      };
      socket.destroy();
      return result;
    }
    let caps = parseCaps(ehlo.lines);

    if ((tlsMode === "opportunistic" || tlsMode === "required") && caps.has("STARTTLS")) {
      socket.write("STARTTLS\r\n");
      const startTlsReply = await reader.read();
      if (startTlsReply.code >= 200 && startTlsReply.code < 300) {
        const tlsSocket = await upgradeTls(socket, opts.host, timeoutMs, verifyPeer);
        if (daneActive) {
          const fail = daneFailure(tlsSocket, opts.dane!, opts.host, rcptResults);
          if (fail) {
            tlsSocket.destroy();
            return fail;
          }
        }
        socket = tlsSocket;
        socket.setTimeout(timeoutMs);
        socket.once("timeout", () => socket.destroy(new Error(`smtp idle timeout (${timeoutMs}ms)`)));
        reader = new ReplyReader(socket);
        // RFC 3207: 업그레이드 후 이전 세션 상태 폐기 — 재EHLO 필수
        ehlo = await ehloRoundtrip(socket, reader, opts.ehloName);
        if (ehlo.code < 200 || ehlo.code >= 300) {
          const result: SmtpClientResult = {
            ok: false,
            code: ehlo.code,
            message: ehlo.lines.join(" "),
            permanent: isPermanent(ehlo.code),
            rcptResults,
          };
          socket.destroy();
          return result;
        }
        caps = parseCaps(ehlo.lines);
      } else if (tlsMode === "required") {
        // required인데 STARTTLS 거부 — 평문 진행 금지, 재시도 대상(deferred)
        const result: SmtpClientResult = {
          ok: false,
          code: startTlsReply.code,
          message: `STARTTLS refused: ${startTlsReply.lines.join(" ")}`,
          permanent: false,
          rcptResults,
        };
        await quit(socket, reader);
        socket.destroy();
        return result;
      }
      // STARTTLS 자체가 거부/실패해도 opportunistic 정의상 평문으로 계속 진행한다.
    } else if (tlsMode === "required" && !caps.has("STARTTLS")) {
      // required인데 서버가 STARTTLS 미광고 — 설정/상대 문제, 재시도 대상(deferred)
      const result: SmtpClientResult = {
        ok: false,
        code: 0,
        message: "STARTTLS required but not advertised",
        permanent: false,
        rcptResults,
      };
      await quit(socket, reader);
      socket.destroy();
      return result;
    }

    if (opts.auth) {
      const authReply = await doAuth(socket, reader, ehlo.lines, opts.auth);
      if (authReply.code !== 235) {
        // 인증 실패는 자격증명·설정 문제 — 절대 permanent로 만들지 않는다(바운스/suppression 방지).
        const result: SmtpClientResult = {
          ok: false,
          code: authReply.code,
          message: `AUTH failed: ${authReply.lines.join(" ")}`,
          permanent: false,
          rcptResults,
        };
        await quit(socket, reader);
        socket.destroy();
        return result;
      }
    }

    const bodyParam = caps.has("8BITMIME") ? " BODY=8BITMIME" : "";
    socket.write(`MAIL FROM:<${opts.mailFrom}>${bodyParam}\r\n`);
    const mailReply = await reader.read();
    if (mailReply.code < 200 || mailReply.code >= 300) {
      const result: SmtpClientResult = {
        ok: false,
        code: mailReply.code,
        message: mailReply.lines.join(" "),
        permanent: isPermanent(mailReply.code),
        rcptResults,
      };
      await quit(socket, reader);
      socket.destroy();
      return result;
    }

    const acceptedRcpts: string[] = [];
    for (const rcpt of opts.rcptTo) {
      socket.write(`RCPT TO:<${rcpt}>\r\n`);
      const r = await reader.read();
      const ok = r.code >= 200 && r.code < 300;
      rcptResults.set(rcpt, { code: r.code, permanent: isPermanent(r.code), message: r.lines.join(" ") });
      if (ok) acceptedRcpts.push(rcpt);
    }

    if (acceptedRcpts.length === 0) {
      await quit(socket, reader);
      socket.destroy();
      return { ok: false, code: 550, message: "all recipients rejected", permanent: true, rcptResults };
    }

    socket.write("DATA\r\n");
    const dataReply = await reader.read();
    if (dataReply.code !== 354) {
      const result: SmtpClientResult = {
        ok: false,
        code: dataReply.code,
        message: dataReply.lines.join(" "),
        permanent: isPermanent(dataReply.code),
        rcptResults,
      };
      await quit(socket, reader);
      socket.destroy();
      return result;
    }

    const stuffed = dotStuff(opts.raw);
    socket.write(Buffer.from(stuffed));
    socket.write(endsWithCrlf(stuffed) ? ".\r\n" : "\r\n.\r\n");

    const finalReply = await reader.read();
    const ok = finalReply.code >= 200 && finalReply.code < 300;

    await quit(socket, reader);
    socket.destroy();
    return {
      ok,
      code: finalReply.code,
      message: finalReply.lines.join(" "),
      permanent: isPermanent(finalReply.code),
      rcptResults,
      // 여기까지 왔다면 DANE 대조를 통과한 것이다(불일치는 위에서 이미 돌아갔다).
      ...(daneActive ? { dane: "match" as const } : {}),
    };
  } catch (err) {
    socket.destroy();
    return connectFailure(err, rcptResults);
  }
}
