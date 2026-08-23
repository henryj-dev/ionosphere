/**
 * LMTP 수신 엔진 (RFC 2033) — 순수 바이트 상태머신(소켓 I/O 없음). server.ts 어댑터가 소켓 담당.
 *
 * SMTP와의 핵심 차이:
 *  - 인사 후 반드시 LHLO(HELO/EHLO는 500). AUTH/STARTTLS 없음(신뢰된 로컬 배달 전제).
 *  - DATA 종료(.) 후 **수신자별 응답 1줄씩**(RCPT 순서대로) — 배달이 수신자마다 성공/실패 가능.
 *
 * 비동기 연속(proto-smtp와 동형): RCPT 검증·DATA 배달은 백엔드 확인이 필요해 액션만 emit하고
 * 멈춘다 — 어댑터가 rcptResult()/deliverResult()를 호출하면 재개. 그 사이 파이프라인 바이트는 버퍼링.
 */
import {
  MAX_COMMAND_LINE,
  MAX_MESSAGE_BYTES,
  MAX_PIPELINE_PENDING_BYTES,
  MAX_RCPT_PER_SESSION,
  MAX_SMTP_ERRORS_PER_SESSION,
} from "@ionosphere/core";

const CRLF = "\r\n";

/** 수신자별 배달 결과(어댑터가 백엔드에서 채움). */
export interface LmtpDelivery {
  rcpt: string;
  ok: boolean;
  code: number;
  enhanced?: string;
  message: string;
}

export interface LmtpDeliverEnv {
  mailFrom: string;
  lhloName: string;
  clientIp: string;
  rcptTo: string[];
  raw: Uint8Array;
}

export type LmtpAction =
  | { kind: "reply"; text: string } // 트레일링 CRLF 없음 — 어댑터가 붙인다
  | { kind: "verifyRcpt"; rcpt: string }
  | { kind: "deliver"; env: LmtpDeliverEnv }
  | { kind: "close" };

export interface LmtpEngineOptions {
  hostname: string;
  clientIp?: string;
  maxSizeBytes?: number;
}

type Awaiting = null | "rcpt" | "deliver";

function reply(text: string): LmtpAction {
  return { kind: "reply", text };
}

/** MAIL FROM:<addr> / RCPT TO:<addr> 의 <> 안 주소 추출(공백·파라미터 관용). null=형식오류. */
function extractPath(rest: string): string | null {
  const lt = rest.indexOf("<");
  const gt = rest.indexOf(">", lt + 1);
  if (lt === -1 || gt === -1) return null;
  return rest.slice(lt + 1, gt).trim();
}

export class LmtpEngine {
  private readonly hostname: string;
  private readonly clientIp: string;
  private readonly maxSizeBytes: number;

  private buffer = "";
  private greeted = false;
  private lhloName = "";
  private mailFrom: string | null = null;
  private rcptTo: string[] = [];
  private pendingRcpt: string | null = null;
  private inData = false;
  private dataLines: string[] = [];
  private dataOverflow = false;
  private awaiting: Awaiting = null;
  private closed = false;
  /**
   * 세션 누적 카운터 — 트랜잭션 리셋(RSET·DATA 종료)에도 초기화하지 않는다. 리셋되면
   * `RSET` 한 줄이 곧 한도 우회다. LMTP는 AUTH·TLS가 **둘 다 없는** 표면이라 SMTP보다 급하다.
   */
  private rcptCount = 0;
  private errorCount = 0;

  constructor(opts: LmtpEngineOptions) {
    this.hostname = opts.hostname;
    this.clientIp = opts.clientIp ?? "127.0.0.1";
    this.maxSizeBytes = opts.maxSizeBytes ?? MAX_MESSAGE_BYTES;
  }

  greeting(): LmtpAction[] {
    return [reply(`220 ${this.hostname} LMTP ready`)];
  }

  /**
   * 방출 직전에 4xx/5xx를 세고 세션 오류 상한을 넘으면 421로 끊는다 —
   * proto-smtp의 `guardErrors`와 같은 이유·같은 배치(공개 메서드가 전부 여기를 통과한다).
   */
  private guardErrors(actions: LmtpAction[]): LmtpAction[] {
    if (this.closed) return actions;
    for (const a of actions) {
      if (a.kind === "reply" && (a.text.startsWith("4") || a.text.startsWith("5"))) this.errorCount += 1;
    }
    if (this.errorCount <= MAX_SMTP_ERRORS_PER_SESSION) return actions;
    this.closed = true;
    this.buffer = "";
    actions.push(reply("421 4.7.0 too many errors, closing connection"), { kind: "close" });
    return actions;
  }

  feed(bytes: Uint8Array): LmtpAction[] {
    if (this.closed) return [];
    this.buffer += Buffer.from(bytes).toString("latin1");
    const actions: LmtpAction[] = [];
    this.pump(actions);
    // pump()의 라인 상한은 `awaiting === null`일 때만 도달한다 — 백엔드 응답을 기다리는 동안은
    // 루프가 아예 돌지 않아 버퍼가 무한히 자란다(proto-pop3에서 실사고로 확인된 것과 같은 구멍).
    // 재동기가 불가능한 지점이므로 끊는다.
    if (!this.closed && this.awaiting !== null && this.buffer.length > MAX_PIPELINE_PENDING_BYTES) {
      this.buffer = "";
      this.closed = true;
      actions.push(reply("421 4.7.0 too much pipelined data, closing connection"), { kind: "close" });
    }
    return this.guardErrors(actions);
  }

  /** RCPT 검증 결과 주입 → 재개. */
  rcptResult(outcome: { ok: true } | { ok: false; code: number; enhanced: string; message: string }): LmtpAction[] {
    if (this.awaiting !== "rcpt" || this.pendingRcpt === null) throw new Error("rcptResult() called without pending RCPT");
    const rcpt = this.pendingRcpt;
    this.pendingRcpt = null;
    this.awaiting = null;
    const actions: LmtpAction[] = [];
    if (outcome.ok) {
      this.rcptTo.push(rcpt);
      actions.push(reply("250 2.1.5 OK"));
    } else {
      actions.push(reply(`${outcome.code} ${outcome.enhanced} ${outcome.message}`));
    }
    this.pump(actions);
    return this.guardErrors(actions);
  }

  /** 배달 결과 주입(수신자별) → 수신자별 응답 1줄씩 emit 후 재개. */
  deliverResult(results: LmtpDelivery[]): LmtpAction[] {
    if (this.awaiting !== "deliver") throw new Error("deliverResult() called without pending delivery");
    this.awaiting = null;
    const actions: LmtpAction[] = [];
    // RCPT 순서대로 응답(누락 수신자는 안전망으로 성공 처리 금지 — 명시 실패)
    for (const rcpt of this.rcptTo) {
      const r = results.find((x) => x.rcpt === rcpt);
      if (r && r.ok) actions.push(reply(`${r.code} ${r.enhanced ?? "2.0.0"} ${r.message}`));
      else if (r) actions.push(reply(`${r.code} ${r.enhanced ?? "5.0.0"} ${r.message}`));
      else actions.push(reply("451 4.3.0 no delivery result"));
    }
    this.resetTransaction();
    this.pump(actions);
    return this.guardErrors(actions);
  }

  private resetTransaction(): void {
    this.mailFrom = null;
    this.rcptTo = [];
    this.pendingRcpt = null;
    this.inData = false;
    this.dataLines = [];
    this.dataOverflow = false;
  }

  private pump(actions: LmtpAction[]): void {
    while (this.awaiting === null && !this.closed) {
      const idx = this.buffer.indexOf(CRLF);
      if (idx === -1) {
        if (this.buffer.length > MAX_COMMAND_LINE) {
          this.buffer = "";
          actions.push(reply("500 5.5.2 line too long"));
        }
        return;
      }
      const line = this.buffer.slice(0, idx);
      this.buffer = this.buffer.slice(idx + 2);
      if (this.inData) this.handleDataLine(line, actions);
      else this.handleCommand(line, actions);
    }
  }

  private handleDataLine(line: string, actions: LmtpAction[]): void {
    if (line === ".") {
      this.inData = false;
      if (this.dataOverflow) {
        this.resetTransaction();
        actions.push(reply("552 5.3.4 message too large"));
        return;
      }
      const raw = Buffer.from(this.dataLines.join(CRLF) + (this.dataLines.length > 0 ? CRLF : ""), "latin1");
      this.awaiting = "deliver";
      actions.push({
        kind: "deliver",
        env: { mailFrom: this.mailFrom ?? "", lhloName: this.lhloName, clientIp: this.clientIp, rcptTo: [...this.rcptTo], raw: new Uint8Array(raw) },
      });
      return;
    }
    // dot-unstuffing (RFC 5321 §4.5.2)
    const unstuffed = line.startsWith("..") ? line.slice(1) : line;
    this.dataLines.push(unstuffed);
    if (this.dataLines.reduce((n, l) => n + l.length + 2, 0) > this.maxSizeBytes) this.dataOverflow = true;
  }

  private handleCommand(line: string, actions: LmtpAction[]): void {
    const sp = line.indexOf(" ");
    const verb = (sp === -1 ? line : line.slice(0, sp)).toUpperCase();
    const rest = sp === -1 ? "" : line.slice(sp + 1);

    switch (verb) {
      case "LHLO": {
        if (rest.trim().length === 0) return void actions.push(reply("501 5.5.4 LHLO requires domain"));
        this.lhloName = rest.trim();
        this.greeted = true;
        this.resetTransaction();
        // 멀티라인 250 (마지막만 공백)
        actions.push(reply(`250-${this.hostname}`));
        actions.push(reply("250-PIPELINING"));
        actions.push(reply("250-ENHANCEDSTATUSCODES"));
        actions.push(reply("250-8BITMIME"));
        actions.push(reply(`250 SIZE ${this.maxSizeBytes}`));
        return;
      }
      case "HELO":
      case "EHLO":
        actions.push(reply("500 5.5.1 LMTP requires LHLO"));
        return;
      case "MAIL": {
        if (!this.greeted) return void actions.push(reply("503 5.5.1 send LHLO first"));
        if (this.mailFrom !== null) return void actions.push(reply("503 5.5.1 nested MAIL command"));
        if (!/^FROM:/i.test(rest)) return void actions.push(reply("501 5.5.4 syntax: MAIL FROM:<addr>"));
        const addr = extractPath(rest.slice(rest.indexOf(":") + 1));
        if (addr === null) return void actions.push(reply("501 5.5.4 syntax: MAIL FROM:<addr>"));
        this.mailFrom = addr; // 빈 문자열(<>)은 반송 발신자로 허용
        actions.push(reply("250 2.1.0 OK"));
        return;
      }
      case "RCPT": {
        if (this.mailFrom === null) return void actions.push(reply("503 5.5.1 need MAIL before RCPT"));
        if (!/^TO:/i.test(rest)) return void actions.push(reply("501 5.5.4 syntax: RCPT TO:<addr>"));
        const addr = extractPath(rest.slice(rest.indexOf(":") + 1));
        if (addr === null || addr.length === 0) return void actions.push(reply("501 5.5.4 syntax: RCPT TO:<addr>"));
        // 452(일시)라 상한에 닿아도 정상 발신자는 새 세션 재시도로 배달된다(limits.ts 주석).
        if (this.rcptCount >= MAX_RCPT_PER_SESSION) return void actions.push(reply("452 4.5.3 too many recipients"));
        this.rcptCount += 1;
        this.pendingRcpt = addr;
        this.awaiting = "rcpt";
        actions.push({ kind: "verifyRcpt", rcpt: addr });
        return;
      }
      case "DATA": {
        if (this.mailFrom === null) return void actions.push(reply("503 5.5.1 need MAIL first"));
        if (this.rcptTo.length === 0) return void actions.push(reply("503 5.5.1 need RCPT first"));
        this.inData = true;
        this.dataLines = [];
        this.dataOverflow = false;
        actions.push(reply("354 end data with <CR><LF>.<CR><LF>"));
        return;
      }
      case "RSET":
        this.resetTransaction();
        actions.push(reply("250 2.0.0 OK"));
        return;
      case "NOOP":
        actions.push(reply("250 2.0.0 OK"));
        return;
      case "QUIT":
        actions.push(reply(`221 2.0.0 ${this.hostname} closing`));
        actions.push({ kind: "close" });
        this.closed = true;
        return;
      default:
        actions.push(reply("500 5.5.1 command not recognized"));
        return;
    }
  }
}
