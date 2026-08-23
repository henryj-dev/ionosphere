/**
 * IMAP 논리 라인 리더 — 리터럴 인식 증분 파서의 1단계 (RFC 9051 §4.3, RFC 7888).
 *
 * IMAP 명령은 POP3와 달리 라인 단위가 아니다: `{n}`(sync)/`{n+}`(non-sync) 리터럴이
 * 라인 중간에 나오면 이어지는 n바이트는 CRLF 구조를 무시하는 원시 데이터다.
 * 이 리더는 바이트를 투입받아 "논리 라인"(텍스트 조각 + 리터럴 바이트의 교차 배열)을
 * 조립하고, sync 리터럴 선언 시 continuation(`+ `) 필요 이벤트를 방출한다.
 *
 * 순수 상태머신 — 소켓 I/O 없음(PLAN.md §4). 정책(리터럴 상한 등)은 옵션으로 주입.
 */
import { MAX_IMAP_LINE_BYTES, MAX_MESSAGE_BYTES } from "@ionosphere/core";

const CR = 0x0d;
const LF = 0x0a;

/** 논리 라인 한 개 — 텍스트 조각과 리터럴 바이트의 교차 배열(등장 순서 보존). */
export type LinePart =
  | { kind: "text"; text: string }
  | { kind: "literal"; bytes: Uint8Array };

export type ReaderEvent =
  /** sync 리터럴 선언 — 어댑터가 `+ OK` continuation을 보내야 클라이언트가 데이터를 보낸다. */
  | { kind: "continue"; size: number }
  /** 논리 라인 완성. */
  | { kind: "line"; parts: LinePart[] }
  /**
   * 프로토콜 한도 초과 — 문제의 논리 라인은 끝(CRLF)까지 자동 폐기된 뒤 방출된다.
   * sync 리터럴 초과는 continuation을 보내지 않았으므로 데이터 수신 없이 라인만 폐기.
   */
  | { kind: "error"; message: string };

export interface LineReaderOptions {
  /** 텍스트 부분 총 길이 상한(리터럴 제외). 기본 64KB. */
  maxLineBytes?: number;
  /** 리터럴 한 개 크기 상한. 기본 25MB(메시지 APPEND 고려 — 엔진에서 명령별로 더 조일 것). */
  maxLiteralBytes?: number;
  /** non-sync 리터럴(`{n+}`) 크기 상한 — LITERAL- 광고 시 4096 (RFC 7888). 기본 4096. */
  maxNonSyncLiteralBytes?: number;
}

/** 라인 상한의 소유자는 @ionosphere/core — 프로토콜마다 흩어져 있던 값을 한 곳으로 모았다. */
const DEFAULT_MAX_LINE = MAX_IMAP_LINE_BYTES;
/** IMAP literal 상한 = 메시지 최대 크기(APPEND가 SMTP 수신 한도와 어긋나면 안 됨). */
const DEFAULT_MAX_LITERAL = MAX_MESSAGE_BYTES;
const DEFAULT_MAX_NONSYNC = 4096;

/** 라인 끝 `{n}` / `{n+}` 선언 탐지 — 반환은 [리터럴 앞 텍스트, 크기, non-sync 여부]. */
function matchLiteralTail(line: string): { before: string; size: number; nonSync: boolean } | null {
  const m = /\{(\d+)(\+?)\}$/.exec(line);
  if (!m || m[1] === undefined) return null;
  const size = Number(m[1]);
  if (!Number.isSafeInteger(size)) return null;
  return { before: line.slice(0, m.index), size, nonSync: m[2] === "+" };
}

export class ImapLineReader {
  private readonly maxLineBytes: number;
  /** 가변 — 인증 상태에 따라 상위 엔진이 조인다(setMaxLiteralBytes 주석 참조). */
  private maxLiteralBytes: number;
  private readonly maxNonSyncLiteralBytes: number;
  // 바이트 보존 디코드(latin1) — UTF-8 해석은 상위 계층 소관. Bun의 TextDecoder 타입이
  // latin1 라벨을 안 받아 Buffer 경유(런타임은 둘 다 지원).
  private decodeLatin1(bytes: Uint8Array): string {
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("latin1");
  }

  private buffer: Uint8Array = new Uint8Array(0);
  private parts: LinePart[] = [];
  /** 현재 조립 중인 텍스트 라인(마지막 CRLF 이전까지). */
  private textLen = 0;
  /** 리터럴 수신 모드 — 남은 바이트 수. null이면 라인 모드. */
  private literalRemaining: number | null = null;
  private literalChunks: Uint8Array[] = [];
  /** 한도 초과 후 현재 논리 라인을 끝까지 버리는 중 — 완료 시 방출할 에러 메시지. */
  private discarding: string | null = null;

  constructor(opts: LineReaderOptions = {}) {
    this.maxLineBytes = opts.maxLineBytes ?? DEFAULT_MAX_LINE;
    this.maxLiteralBytes = opts.maxLiteralBytes ?? DEFAULT_MAX_LITERAL;
    this.maxNonSyncLiteralBytes = opts.maxNonSyncLiteralBytes ?? DEFAULT_MAX_NONSYNC;
  }

  /**
   * 리터럴 상한을 갱신한다 — **리더는 인증 상태를 모르므로 정책은 엔진이 소유한다.**
   *
   * 왜 필요한가: 25MB 리터럴이 필요한 명령은 APPEND뿐이고 APPEND는 인증을 요구하는데,
   * 리더는 그 구분이 없어 **어차피 거절할 `LOGIN` 한 줄을 위해 미인증 연결마다 25MB를
   * 버퍼링**했다. 유휴 타임아웃 30분 × MAX_LISTENER_CONNECTIONS면 이론상 25GB다.
   * 인증 성공 시 엔진이 이 메서드로 원래 상한을 돌려주므로 APPEND는 영향받지 않는다.
   *
   * 이미 진행 중인 리터럴 수신에는 적용되지 않는다(경계가 깨진다) — 다음 선언부터 적용된다.
   */
  setMaxLiteralBytes(bytes: number): void {
    this.maxLiteralBytes = bytes;
  }

  feed(chunk: Uint8Array): ReaderEvent[] {
    // 버퍼 병합 — 리터럴 모드가 대부분을 즉시 소비하므로 단순 concat으로 충분
    if (this.buffer.length === 0) this.buffer = chunk;
    else {
      const merged = new Uint8Array(this.buffer.length + chunk.length);
      merged.set(this.buffer, 0);
      merged.set(chunk, this.buffer.length);
      this.buffer = merged;
    }

    const events: ReaderEvent[] = [];
    for (;;) {
      if (this.literalRemaining !== null) {
        if (!this.consumeLiteral()) break; // 리터럴 미완 — 다음 feed 대기
        continue;
      }
      const ev = this.consumeLine();
      if (ev === null) break; // CRLF 미도착
      if (ev !== undefined) events.push(ev);
    }
    return events;
  }

  /** 리터럴 바이트 소비 — 완료 시 true(라인 모드 복귀), 데이터 부족 시 false. */
  private consumeLiteral(): boolean {
    const remaining = this.literalRemaining;
    if (remaining === null) return true;
    const take = Math.min(remaining, this.buffer.length);
    if (take > 0) {
      if (this.discarding === null) this.literalChunks.push(this.buffer.subarray(0, take));
      this.buffer = this.buffer.subarray(take);
      this.literalRemaining = remaining - take;
    }
    if (this.literalRemaining === 0) {
      if (this.discarding === null) {
        this.parts.push({ kind: "literal", bytes: concat(this.literalChunks) });
      }
      this.literalChunks = [];
      this.literalRemaining = null;
      return true;
    }
    return false;
  }

  /**
   * 라인 모드에서 다음 CRLF까지 소비.
   * 반환: ReaderEvent(방출), undefined(내부 상태만 전이 — 계속), null(데이터 부족 — 중단).
   */
  private consumeLine(): ReaderEvent | undefined | null {
    const idx = this.buffer.indexOf(LF);
    if (idx === -1) {
      // CRLF 미도착 — 폭주 라인 방어: 지금까지의 길이만 검사
      if (this.discarding === null && this.textLen + this.buffer.length > this.maxLineBytes) {
        this.discarding = "line too long";
        // 초과분은 어차피 버릴 것 — 버퍼를 비워 메모리 상한 유지
        this.buffer = new Uint8Array(0);
        this.textLen = 0;
        this.parts = [];
      } else if (this.discarding !== null) {
        this.buffer = new Uint8Array(0); // 폐기 중 — CRLF 나올 때까지 전부 버림
      }
      return null;
    }

    let end = idx;
    if (end > 0 && this.buffer[end - 1] === CR) end -= 1;
    const lineBytes = this.buffer.subarray(0, end);
    this.buffer = this.buffer.subarray(idx + 1);

    if (this.discarding !== null) {
      // 폐기 중 라인 종료 — 에러 방출 후 초기화. 단, 폐기 라인이 리터럴을 선언했으면
      // (sync든 non-sync든 continuation을 안 보낸 sync는 데이터가 안 오지만, non-sync는 온다)
      // non-sync 데이터까지 마저 버려야 다음 명령 경계가 안 깨진다.
      const text = this.decodeLatin1(lineBytes);
      const lit = matchLiteralTail(text);
      if (lit && lit.nonSync) {
        this.literalRemaining = lit.size; // discarding 유지 — consumeLiteral이 버림
        return undefined;
      }
      const message = this.discarding;
      this.discarding = null;
      this.textLen = 0;
      this.parts = [];
      return { kind: "error", message };
    }

    const text = this.decodeLatin1(lineBytes);
    if (this.textLen + text.length > this.maxLineBytes) {
      this.textLen = 0;
      this.parts = [];
      return { kind: "error", message: "line too long" };
    }

    const lit = matchLiteralTail(text);
    if (!lit) {
      // 논리 라인 완성
      const parts = this.parts;
      this.parts = [];
      this.textLen = 0;
      if (text.length > 0 || parts.length > 0) parts.push({ kind: "text", text });
      return { kind: "line", parts };
    }

    // 리터럴 선언 — 텍스트 조각 확정 후 리터럴 모드 진입
    this.parts.push({ kind: "text", text: lit.before });
    this.textLen += lit.before.length;

    const cap = lit.nonSync ? Math.min(this.maxLiteralBytes, this.maxNonSyncLiteralBytes) : this.maxLiteralBytes;
    if (lit.size > cap) {
      if (lit.nonSync) {
        // 클라이언트가 이미 데이터를 보내는 중 — 소비하며 버린 뒤 라인 끝에서 에러
        this.discarding = "literal too large";
        this.literalRemaining = lit.size;
        return undefined;
      }
      // sync — continuation을 안 보내므로 데이터는 안 옴. 즉시 에러, 라인 상태 폐기.
      this.parts = [];
      this.textLen = 0;
      return { kind: "error", message: "literal too large" };
    }

    this.literalRemaining = lit.size;
    if (!lit.nonSync) return { kind: "continue", size: lit.size };
    return undefined;
  }
}

function concat(chunks: Uint8Array[]): Uint8Array {
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
