/**
 * ManageSieve 순수 상태머신 (RFC 5804). 소켓 I/O 없음(PLAN §4, proto-pop3 패턴).
 * 리터럴({n+}) 인식 라인 파싱은 @ionosphere/proto-imap의 ImapLineReader 재사용
 * (ManageSieve도 IMAP식 리터럴 문법 — RFC 5804 §1.2).
 *
 * 명령: CAPABILITY, NOOP, LOGOUT, STARTTLS, AUTHENTICATE PLAIN, PUTSCRIPT, LISTSCRIPTS,
 *       SETACTIVE, GETSCRIPT, DELETESCRIPT, RENAMESCRIPT, CHECKSCRIPT, HAVESPACE.
 *
 * STARTTLS(RFC 5804 §2.2)는 **어댑터가 인증서를 줬을 때만** 광고하고 그때만 수락한다.
 * `tlsAvailable`이 곧 광고 여부이자 수락 여부다 — 한 값이 둘을 지배해야 어긋날 수 없다.
 *
 * 왜 이 불변식을 코드로 묶는가(감사 L-5): 예전에는 평문 회선에서 `"STARTTLS"`를 능력 목록에
 * 실으면서 명령은 NO로 거절했다. POP3가 정확히 이 안티패턴을 경계한다(engine.ts cmdCapa 주석):
 * 제공하지 않는 것을 광고하면 클라이언트는 그것을 시도하고 실패한 뒤 **자격증명이 틀렸다고
 * 오해**한다. 그 뒤 광고만 지웠더니 이번엔 **인증 경로가 아예 없어졌다**(평문 SASL은 fail
 * closed로 막혀 있으므로 TLS로 갈 방법이 없으면 Sieve 관리가 불가능하다). 광고를 지우는 것이
 * 아니라 **구현을 붙여** 둘을 일치시키는 것이 L-5의 해법이다.
 *
 * 런타임 제약은 어댑터·조립층 소관이다(apps/server/src/starttls-support.ts): bun 1.3.14 이하는
 * 서버측 업그레이드가 완료되지 않아(oven-sh/bun#25044) 조립층이 인증서를 넘기지 않고,
 * 그러면 이 엔진은 광고도 수락도 하지 않는다 — 즉 fail closed가 자동으로 성립한다.
 */
import { decodeSaslBase64, parseSaslPlain,
  ScramServerSession,
  type ScramStep,
  type ScramStoredKeys,
} from "@ionosphere/core";
import { ImapLineReader, type LinePart, type ReaderEvent } from "@ionosphere/proto-imap";

export type ManageSieveAction =
  | { kind: "reply"; text: string }
  | { kind: "replyBytes"; bytes: Uint8Array }
  | { kind: "close" }
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
  | { kind: "putScript"; name: string; content: string }
  | { kind: "checkScript"; content: string }
  | { kind: "listScripts" }
  | { kind: "getScript"; name: string }
  | { kind: "deleteScript"; name: string }
  | { kind: "renameScript"; from: string; to: string }
  | { kind: "setActive"; name: string };

export type AuthResult = { accountId: string } | null;
/** OK 또는 NO(사유). 검증 실패 등은 NO. */
export type OpResult = { ok: true } | { ok: false; code?: string; message: string };
export type ListResult = { name: string; active: boolean }[];
export type GetResult = { ok: true; content: string } | { ok: false };

export interface ManageSieveEngineOptions {
  hostname: string;
  secure?: boolean;
  allowInsecureAuth?: boolean;
  /**
   * STARTTLS 제공 여부 — 어댑터가 인증서를 보유하고 **런타임이 서버측 업그레이드를 지원할 때만**
   * true. 광고와 수락을 동시에 지배한다(둘을 따로 두면 L-5가 되돌아온다).
   * 기본값 false: 옵션을 빠뜨린 호출부가 생겨도 없는 기능을 광고하지 않는다.
   */
  tlsAvailable?: boolean;
  /** SCRAM 광고 여부 — 어댑터가 백엔드의 키 조회·승인 존재로 판단해 넘긴다. */
  scramOffered?: boolean;
  /** SCRAM 가짜 salt 유도용 비밀 — **서버 전체가 같은 값**이어야 계정 열거가 막힌다. */
  scramDecoySecret?: Buffer;
  /** HAVESPACE/PUTSCRIPT 크기 상한(바이트). 기본 1MB. */
  maxScriptBytes?: number;
}

type Pending =
  | { kind: "auth"; sasl: "PLAIN" | "SCRAM-SHA-256" }
  | { kind: "scram-keys" }
  | { kind: "auth-line"; sasl: "PLAIN" | "SCRAM-SHA-256" }
  | { kind: "putScript"; name: string }
  | { kind: "checkScript" }
  | { kind: "list" }
  | { kind: "get"; name: string }
  | { kind: "op" };

import { randomBytes } from "node:crypto";

/** 프로세스 기본 decoy 비밀 — 모듈 로드 시 한 번. */
const PROCESS_SCRAM_DECOY = randomBytes(32);

const CAP_LINES = (hostname: string, authAllowed: boolean, starttlsOffered: boolean, scramOffered: boolean): string[] => [
  `"IMPLEMENTATION" "ionosphere ManageSieve"`,
  `"SIEVE" "fileinto envelope imap4flags copy"`,
  `"VERSION" "1.0"`,
  // ★광고 = 구현. `starttlsOffered`는 STARTTLS 명령을 실제로 수락할 수 있을 때만 true다
  //   (engine 옵션 tlsAvailable & 아직 평문). 없는 기능을 실으면 클라이언트가 시도하고 실패한 뒤
  //   자격증명을 의심한다(L-5). RFC 5804 §1.7: 이미 TLS면 STARTTLS를 다시 알리지 않는다.
  ...(starttlsOffered ? [`"STARTTLS"`] : []),
  // 평문 회선에서 인증을 열지 않으므로 빈 SASL만 알린다 — 클라이언트는 STARTTLS를 보고
  // 업그레이드 후 재조회에서 PLAIN을 발견한다(RFC 5804 §2.2가 요구하는 재조회).
  // ★SCRAM을 **먼저** 나열한다 — 클라이언트가 순서를 선호도로 읽는 경우가 많다.
  ...(authAllowed ? [scramOffered ? `"SASL" "SCRAM-SHA-256 PLAIN"` : `"SASL" "PLAIN"`] : [`"SASL" ""`]),
];

export class ManageSieveEngine {
  private readonly hostname: string;
  private secure: boolean;
  private readonly allowInsecureAuth: boolean;
  private readonly scramOffered: boolean;
  private readonly scramDecoySecret: Buffer;
  /** SCRAM 교환 상태 — 한 연결에 하나. */
  private scram: { session: ScramServerSession; stage: "clientFirst" | "clientFinal" | "serverFinal"; username?: string } | null = null;
  private readonly tlsAvailable: boolean;
  private readonly maxScriptBytes: number;
  /** 가변 — STARTTLS 업그레이드 시 **새 리더로 교체**해 평문 잔여 바이트를 버린다(주입 방어). */
  private reader: ImapLineReader;
  private authed = false;
  private closed = false;
  /** STARTTLS 220을 보낸 뒤 업그레이드 완료(tlsUpgraded)를 기다리는 중 — 그 사이 입력은 폐기. */
  private awaitingTls = false;
  private pending: Pending | null = null;
  private readonly queued: LinePart[][] = [];

  constructor(opts: ManageSieveEngineOptions) {
    this.hostname = opts.hostname;
    this.secure = opts.secure ?? false;
    this.allowInsecureAuth = opts.allowInsecureAuth ?? false;
    this.tlsAvailable = opts.tlsAvailable ?? false;
    this.scramOffered = opts.scramOffered ?? false;
    this.scramDecoySecret = opts.scramDecoySecret ?? PROCESS_SCRAM_DECOY;
    this.maxScriptBytes = opts.maxScriptBytes ?? 1024 * 1024;
    this.reader = new ImapLineReader({ maxLiteralBytes: this.maxScriptBytes });
  }

  private authAllowed(): boolean {
    return this.secure || this.allowInsecureAuth;
  }

  /** STARTTLS를 광고·수락할 수 있는가 — 인증서가 있고 아직 평문일 때만. */
  private starttlsOffered(): boolean {
    return this.tlsAvailable && !this.secure;
  }

  private capabilities(): ManageSieveAction[] {
    return CAP_LINES(this.hostname, this.authAllowed(), this.starttlsOffered(), this.scramOffered).map((l) => reply(l));
  }

  greeting(): ManageSieveAction[] {
    return [...this.capabilities(), reply(`OK "${this.hostname} ManageSieve ready"`)];
  }

  /**
   * 어댑터가 TLS 핸드셰이크 완료를 통보 — 이후 회선은 secure이므로 SASL PLAIN이 열린다.
   *
   * RFC 5804 §2.2: 업그레이드 직후 서버가 **능력 목록을 다시 보내야 한다**(클라이언트는
   * 평문에서 본 목록을 폐기한다). 그래서 여기서 CAPABILITY 응답 형태로 되돌린다 —
   * 클라이언트가 별도 CAPABILITY를 보내지 않아도 PLAIN을 발견할 수 있어야 한다.
   */
  tlsUpgraded(): ManageSieveAction[] {
    this.secure = true;
    this.awaitingTls = false;
    // 협상 상태를 버린다 — 평문 구간에서 시작된 인증/명령이 TLS 세션으로 넘어오면 안 된다.
    // 리더까지 새로 만드는 이유: 고전적 STARTTLS 명령 주입(CVE-2011-0411 계열)은 공격자가
    // `STARTTLS`와 같은 세그먼트에 평문 명령을 덧붙여, 서버가 그 바이트를 버리지 않으면
    // **TLS 세션의 명령인 것처럼** 실행되게 하는 것이다. 리더 내부 버퍼가 그 바이트를 들고 있다.
    this.authed = false;
    this.pending = null;
    this.queued.length = 0;
    this.reader = new ImapLineReader({ maxLiteralBytes: this.maxScriptBytes });
    return [...this.capabilities(), reply('OK "TLS negotiated"')];
  }

  feed(chunk: Uint8Array): ManageSieveAction[] {
    if (this.closed) return [];
    // 220을 보낸 뒤 도착한 평문 바이트는 **읽지도 않고 버린다** — 여기에 넣으면 업그레이드 후
    // 실행될 명령이 된다(STARTTLS 명령 주입). 어댑터도 raw 소켓에서 리스너를 떼지만,
    // 같은 tick에 이미 들어온 청크는 엔진까지 오므로 엔진에서도 막아야 한다(이중 방어).
    if (this.awaitingTls) return [];
    const out: ManageSieveAction[] = [];
    for (const ev of this.reader.feed(chunk)) {
      out.push(...this.onEvent(ev));
      if (this.closed || this.awaitingTls) break;
    }
    return out;
  }

  private onEvent(ev: ReaderEvent): ManageSieveAction[] {
    if (ev.kind === "continue") return [reply("OK")]; // sync 리터럴 continuation(클라가 {n+}면 안 옴)
    if (ev.kind === "error") return [reply(`NO "${ev.message}"`)];
    // ev.kind === "line"
    // AUTHENTICATE 챌린지 응답 대기 중 — 이 라인은 명령이 아니라 SASL base64 응답
    if (this.pending?.kind === "auth-line") {
      const sasl = this.pending.sasl;
      this.pending = null;
      const values = parseParts(ev.parts);
      const b64 = values[0]?.text ?? "";
      if (b64 === "*") {
        this.scram = null;
        return [reply('NO "authentication aborted"'), ...this.drain()];
      }
      // ★server-final 다음 줄은 **빈 줄**이다 — 그걸 "형식 오류"로 다루면 정상 교환이
      //   마지막 한 줄에서 깨진다(IMAP 배선에서 실제로 겪었다).
      if (sasl === "SCRAM-SHA-256") return this.handleScramLine(b64);
      return this.decodePlain(b64);
    }
    if (this.pending) {
      this.queued.push(ev.parts);
      return [];
    }
    return this.handleLine(ev.parts);
  }

  private drain(): ManageSieveAction[] {
    const out: ManageSieveAction[] = [];
    // awaitingTls도 정지 조건이다 — STARTTLS가 **큐에서** 꺼내진 경우(백엔드 왕복 중에 파이프라인
    // 된 STARTTLS) 뒤에 줄줄이 붙은 평문 명령이 여기서 계속 실행되면 주입 방어에 구멍이 난다.
    // cmdStartTls가 큐를 비우는 것과 이중 방어다.
    while (this.queued.length > 0 && !this.pending && !this.closed && !this.awaitingTls) {
      const parts = this.queued.shift();
      if (parts) out.push(...this.handleLine(parts));
    }
    return out;
  }

  // ── 백엔드 결과 재개 ──────────────────────────────────────────────────────
  authResult(r: AuthResult): ManageSieveAction[] {
    if (this.pending?.kind !== "auth" && this.pending?.kind !== "auth-line") throw new Error("authResult 순서 오류");
    this.pending = null;
    if (!r) return [reply('NO "authentication failed"'), ...this.drain()];
    this.authed = true;
    return [reply('OK "authenticated"'), ...this.drain()];
  }
  opResult(r: OpResult): ManageSieveAction[] {
    if (this.pending?.kind !== "putScript" && this.pending?.kind !== "checkScript" && this.pending?.kind !== "op") throw new Error("opResult 순서 오류");
    this.pending = null;
    const a = r.ok ? reply('OK') : reply(`NO ${r.code ? `(${r.code}) ` : ""}${quote(r.message)}`);
    return [a, ...this.drain()];
  }
  listResult(scripts: ListResult): ManageSieveAction[] {
    if (this.pending?.kind !== "list") throw new Error("listResult 순서 오류");
    this.pending = null;
    const lines = scripts.map((s) => `${quote(s.name)}${s.active ? " ACTIVE" : ""}`);
    return [...lines.map((l) => reply(l)), reply('OK'), ...this.drain()];
  }
  getResult(r: GetResult): ManageSieveAction[] {
    if (this.pending?.kind !== "get") throw new Error("getResult 순서 오류");
    this.pending = null;
    if (!r.ok) return [reply('NO "script not found"'), ...this.drain()];
    const bytes = new TextEncoder().encode(r.content);
    // {n}\r\n<bytes>\r\nOK\r\n
    const head = new TextEncoder().encode(`{${bytes.length}}\r\n`);
    const tail = new TextEncoder().encode(`\r\nOK\r\n`);
    const merged = new Uint8Array(head.length + bytes.length + tail.length);
    merged.set(head, 0);
    merged.set(bytes, head.length);
    merged.set(tail, head.length + bytes.length);
    return [{ kind: "replyBytes", bytes: merged }, ...this.drain()];
  }

  // ── 명령 파싱 ──────────────────────────────────────────────────────────────
  private handleLine(parts: LinePart[]): ManageSieveAction[] {
    // SASL 연속 라인(AUTHENTICATE 후 base64) 대기 상태는 pending으로 처리하지 않고 아래에서
    const values = parseParts(parts);
    if (values.length === 0) return [reply('NO "empty command"')];
    const cmd = (values[0]!.text ?? "").toUpperCase();

    switch (cmd) {
      case "LOGOUT":
        this.closed = true;
        return [reply('OK "bye"'), { kind: "close" }];
      case "NOOP":
        return [reply('OK "NOOP completed"')];
      case "CAPABILITY":
        return [...this.capabilities(), reply('OK')];
      case "AUTHENTICATE":
        return this.cmdAuthenticate(values);
      case "STARTTLS":
        return this.cmdStartTls();
      default:
        break;
    }
    if (!this.authed) return [reply('NO "Authenticate first"')];

    switch (cmd) {
      case "PUTSCRIPT": {
        const name = values[1]?.text;
        const content = values[2];
        if (name === undefined || !content) return [reply('NO "PUTSCRIPT needs name and script"')];
        this.pending = { kind: "putScript", name };
        return [{ kind: "putScript", name, content: content.text ?? "" }];
      }
      case "CHECKSCRIPT": {
        const content = values[1];
        if (!content) return [reply('NO "CHECKSCRIPT needs script"')];
        this.pending = { kind: "checkScript" };
        return [{ kind: "checkScript", content: content.text ?? "" }];
      }
      case "LISTSCRIPTS":
        this.pending = { kind: "list" };
        return [{ kind: "listScripts" }];
      case "SETACTIVE": {
        const name = values[1]?.text ?? "";
        this.pending = { kind: "op" };
        return [{ kind: "setActive", name }];
      }
      case "GETSCRIPT": {
        const name = values[1]?.text;
        if (name === undefined) return [reply('NO "GETSCRIPT needs name"')];
        this.pending = { kind: "get", name };
        return [{ kind: "getScript", name }];
      }
      case "DELETESCRIPT": {
        const name = values[1]?.text;
        if (name === undefined) return [reply('NO "DELETESCRIPT needs name"')];
        this.pending = { kind: "op" };
        return [{ kind: "deleteScript", name }];
      }
      case "RENAMESCRIPT": {
        const from = values[1]?.text;
        const to = values[2]?.text;
        if (from === undefined || to === undefined) return [reply('NO "RENAMESCRIPT needs old and new name"')];
        this.pending = { kind: "op" };
        return [{ kind: "renameScript", from, to }];
      }
      case "HAVESPACE": {
        // HAVESPACE "name" <size> — 상한 이내면 OK
        const size = Number(values[2]?.text ?? "0");
        if (Number.isFinite(size) && size <= this.maxScriptBytes) return [reply('OK')];
        return [reply('NO (QUOTA/MAXSIZE) "script too large"')];
      }
      default:
        return [reply('NO "unknown command"')];
    }
  }

  /**
   * STARTTLS (RFC 5804 §2.2). 광고 조건과 **같은 판정**을 쓴다 — 어긋나면 L-5가 되돌아온다.
   *
   * 순서: OK를 먼저 보내고 어댑터가 업그레이드한다. RFC 5804는 여기서 `OK`를 요구한다
   * (SMTP의 220과 역할은 같으나 응답 코드 체계가 다르다).
   */
  private cmdStartTls(): ManageSieveAction[] {
    if (this.secure) return [reply('NO "TLS already active"')];
    if (!this.tlsAvailable) return [reply('NO "STARTTLS not available"')];
    // 대기 중인 백엔드 왕복이 있으면 업그레이드 경계가 흐려진다 — 거절이 안전하다.
    if (this.pending) return [reply('NO "STARTTLS not allowed mid-command"')];
    this.awaitingTls = true;
    this.queued.length = 0;
    return [reply('OK "Begin TLS negotiation now"'), { kind: "startTls" }];
  }

  private cmdAuthenticate(values: { text?: string; bytes?: Uint8Array }[]): ManageSieveAction[] {
    if (this.authed) return [reply('NO "already authenticated"')];
    if (!this.authAllowed()) return [reply('NO "TLS required before AUTHENTICATE"')];
    const mech = (values[1]?.text ?? "").toUpperCase();
    if (mech === "SCRAM-SHA-256") {
      // 광고하지 않은 메커니즘은 받지 않는다 — 못 끝낼 교환을 시작하지 않는다.
      if (!this.scramOffered) return [reply('NO "unsupported SASL mechanism"')];
      this.scram = { session: new ScramServerSession(this.scramDecoySecret), stage: "clientFirst" };
      const irs = values[2]?.text;
      if (irs !== undefined) return this.handleScramLine(irs);
      this.pending = { kind: "auth-line", sasl: "SCRAM-SHA-256" };
      return [reply('""')];
    }
    if (mech !== "PLAIN") return [reply('NO "unsupported SASL mechanism"')];
    const ir = values[2]?.text; // initial response(base64) 동봉 가능
    if (ir !== undefined) return this.decodePlain(ir);
    this.pending = { kind: "auth-line", sasl: "PLAIN" };
    // 서버 continuation 요청(빈 챌린지)
    return [reply('""')];
  }

  /**
   * SCRAM 교환의 한 줄. 단계는 `stage`로 판정한다 — `start()` 반환값으로 갈래를 나누면
   * 이미 시작된 세션에 `start()`를 다시 불러 세션이 닫힌다(IMAP 배선에서 실제로 겪었다).
   */
  private handleScramLine(b64: string): ManageSieveAction[] {
    const sc = this.scram;
    if (!sc) return [reply('NO "authentication failed"')];
    if (sc.stage === "serverFinal") {
      // server-final에 대한 클라이언트의 빈 응답 — 여기서야 성공 처리한다.
      this.scram = null;
      this.pending = { kind: "auth", sasl: "SCRAM-SHA-256" };
      return [{ kind: "authVerified", user: sc.username ?? "" }];
    }
    const bytes = decodeSaslBase64(b64);
    if (bytes === null) {
      this.scram = null;
      return [reply('NO "invalid base64"')];
    }
    const text = new TextDecoder().decode(bytes);
    if (sc.stage === "clientFirst") {
      const step = sc.session.start(text);
      if (step.need !== "lookup") {
        this.scram = null;
        return [this.scramFailedAction(step), reply('NO "authentication failed"')];
      }
      this.scram = { ...sc, stage: "clientFinal" };
      this.pending = { kind: "scram-keys" };
      return [{ kind: "scramKeys", user: step.username }];
    }
    const fin = sc.session.final(text);
    if (fin.need !== "done") {
      this.scram = null;
      return [this.scramFailedAction(fin), reply('NO "authentication failed"')];
    }
    this.scram = { ...sc, stage: "serverFinal", username: fin.username };
    this.pending = { kind: "auth-line", sasl: "SCRAM-SHA-256" };
    return [reply(`{${Buffer.from(fin.message).toString("base64").length}+}\r\n${Buffer.from(fin.message).toString("base64")}`)];
  }

  /**
   * SCRAM 실패를 어댑터에 알리는 액션. **거절 응답과 늘 함께 나가야 한다** —
   * 응답만 내고 이걸 빼면 그 갈래가 다시 무기록이 된다(이 액션이 생긴 이유).
   */
  private scramFailedAction(step: ScramStep): ManageSieveAction {
    return {
      kind: "authFailed",
      mechanism: "SCRAM-SHA-256",
      ...(step.need === "failed" && step.username ? { user: step.username } : {}),
    };
  }

  /**
   * SCRAM 저장 키(없으면 null) — **null이어도 교환은 계속된다**(계정 열거 방어).
   */
  scramKeysResult(keys: ScramStoredKeys | null): ManageSieveAction[] {
    if (this.pending?.kind !== "scram-keys") throw new Error("scramKeysResult 순서 오류");
    const sc = this.scram;
    if (!sc) return [];
    const step = sc.session.provideKeys(keys);
    if (step.need !== "send") {
      this.scram = null;
      this.pending = null;
      return [this.scramFailedAction(step), reply('NO "authentication failed"')];
    }
    this.pending = { kind: "auth-line", sasl: "SCRAM-SHA-256" };
    const b64 = Buffer.from(step.message).toString("base64");
    return [reply(`{${b64.length}+}\r\n${b64}`)];
  }

  /** AUTHENTICATE PLAIN base64 디코드 → auth 액션. */
  private decodePlain(b64: string): ManageSieveAction[] {
    // 디코딩·PLAIN 파싱은 @ionosphere/core 정본 — 예전엔 base64 검증이 아예 없어 불량 입력을
    // 조용히 절단 수용했다(4개 프로토콜 중 가장 느슨했던 경로).
    const bytes = decodeSaslBase64(b64);
    if (bytes === null) return [reply('NO "invalid base64"')];
    const creds = parseSaslPlain(bytes);
    if (!creds) return [reply('NO "malformed PLAIN"')];
    this.pending = { kind: "auth", sasl: "PLAIN" };
    return [{ kind: "auth", user: creds.user, pass: creds.pass }];
  }
}

function reply(text: string): ManageSieveAction {
  return { kind: "reply", text };
}
function quote(s: string): string {
  return `"${s.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

/** LinePart[]를 값 목록으로 — atom/quoted는 text, 리터럴은 bytes(+text 디코드). 공백 구분. */
function parseParts(parts: LinePart[]): { text?: string; bytes?: Uint8Array }[] {
  const out: { text?: string; bytes?: Uint8Array }[] = [];
  for (const part of parts) {
    if (part.kind === "literal") {
      out.push({ bytes: part.bytes, text: new TextDecoder("utf-8").decode(part.bytes) });
      continue;
    }
    // 텍스트 조각을 토큰화(quoted string + atom)
    const s = part.text;
    let i = 0;
    while (i < s.length) {
      const c = s[i]!;
      if (c === " " || c === "\t") {
        i++;
        continue;
      }
      if (c === '"') {
        i++;
        let val = "";
        while (i < s.length && s[i] !== '"') {
          if (s[i] === "\\") {
            val += s[i + 1] ?? "";
            i += 2;
          } else val += s[i++]!;
        }
        i++; // 닫는 "
        out.push({ text: val });
        continue;
      }
      let val = "";
      while (i < s.length && s[i] !== " " && s[i] !== "\t") val += s[i++]!;
      out.push({ text: val });
    }
  }
  return out;
}
