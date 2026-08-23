/**
 * 파일 기반 감사 싱크 — 이벤트를 일별 JSONL로 append한다.
 *
 * 왜 DB가 아니라 파일인가: 감사 범위가 "모든 작업"(조회 포함)이라 IMAP FETCH마다 한 건이 생긴다.
 * SQLite는 **전역 단일 라이터**라(SCHEMA §3-3, `db/src/sqlite.ts`의 `BEGIN IMMEDIATE`) 조회마다
 * 감사 행을 넣으면 계정을 가로질러 **모든 메일 쓰기와 직렬화**된다. 라이브 실측으로 커밋
 * 오버헤드가 append당 0.40ms(전체의 40%)다(`store/src/writer-queue.ts` 머리 주석).
 * 파일 append + 주기 flush는 그 경로를 아예 타지 않는다.
 *
 * 왜 일별로 나누는가: 날짜가 바뀌면 오브젝트 스토리지로 이관하는 것이 운영 설계다
 * (`audit-shipper.ts`). 파일 하나가 곧 이관 단위이므로 경계가 명확해야 한다.
 */
import { appendFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { auditDayUtc, formatAuditLine, noopLogger, type AuditEvent, type AuditSink, type Logger } from "@ionosphere/core";

export interface AuditFileSinkOptions {
  /** 로그 디렉터리. 없으면 만든다(0o700). */
  dir: string;
  /** 주기 flush 간격(ms). 기본 1초. */
  flushIntervalMs?: number;
  /**
   * 버퍼가 이 줄 수에 닿으면 간격을 기다리지 않고 즉시 flush. 기본 1000.
   *
   * 왜 상한이 필요한가: 간격만 믿으면 트래픽이 몰릴 때 버퍼가 무한히 자란다 — 메모리 압박이자,
   * 그 사이 프로세스가 죽으면 유실량이 그만큼 커진다.
   */
  maxBufferLines?: number;
  logger?: Logger;
  /** 이벤트 관측 훅 — 메트릭 배선용(`@ionosphere/metrics` 의존 없이 콜백만 받는다). */
  onRecord?: (e: AuditEvent) => void;
}

const DEFAULT_FLUSH_INTERVAL_MS = 1_000;
const DEFAULT_MAX_BUFFER_LINES = 1_000;

export class AuditFileSink implements AuditSink {
  private readonly dir: string;
  private readonly flushIntervalMs: number;
  private readonly maxBufferLines: number;
  private readonly log: Logger;
  private readonly onRecord?: (e: AuditEvent) => void;
  /** 일자별 버퍼 — 자정을 넘겨 두 날짜가 동시에 쌓일 수 있다(플러시 주기 안에 경계가 걸리면). */
  private buffers = new Map<string, string[]>();
  private lines = 0;
  private timer: ReturnType<typeof setInterval> | null = null;
  private flushing = false;
  private dirReady = false;

  constructor(opts: AuditFileSinkOptions) {
    this.dir = opts.dir;
    this.flushIntervalMs = opts.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS;
    this.maxBufferLines = opts.maxBufferLines ?? DEFAULT_MAX_BUFFER_LINES;
    this.log = (opts.logger ?? noopLogger).child({ component: "audit" });
    if (opts.onRecord) this.onRecord = opts.onRecord;
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.flush(), this.flushIntervalMs);
    this.timer.unref?.();
  }

  /**
   * 타이머를 끄고 **남은 버퍼를 반드시 flush한 뒤** 반환한다.
   *
   * ★이것이 이 클래스의 내구성 계약이다. 버퍼링을 택한 대가로 SIGKILL에서는 최대 한 주기분이
   * 유실되지만(사용자가 선택한 트레이드오프), **정상 종료·배포 재시작은 유실이 없어야 한다** —
   * 배포는 하루에 여러 번 일어나므로 그때마다 감사 구멍이 생기면 기록을 신뢰할 수 없다.
   */
  async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    // 진행 중인 flush가 끝나기를 기다린 뒤(그 사이 들어온 것까지) 마지막으로 비운다.
    while (this.flushing) await new Promise((r) => setTimeout(r, 10));
    await this.flush();
  }

  /**
   * 이벤트를 버퍼에 넣는다 — **동기·논블로킹**이고 던지지 않는다(`AuditSink` 계약).
   *
   * 직렬화가 여기서 일어나는 이유: 이벤트 객체를 그대로 버퍼에 담으면 호출부가 나중에 그 객체를
   * 변형할 수 있고(같은 객체를 재사용하는 루프), 그러면 기록된 값이 시점과 어긋난다.
   * 문자열로 굳혀 두면 그 창이 없다.
   */
  record(e: AuditEvent): void {
    try {
      const day = auditDayUtc(e.ts);
      const buf = this.buffers.get(day);
      if (buf) buf.push(formatAuditLine(e));
      else this.buffers.set(day, [formatAuditLine(e)]);
      this.lines++;
      this.onRecord?.(e);
      // 상한 도달 시 즉시 flush — void로 띄운다(record는 동기 계약).
      if (this.lines >= this.maxBufferLines) void this.flush();
    } catch (err) {
      // 감사 실패가 메일 처리를 멈추면 안 된다(blob GC 실패 처리와 같은 판단).
      this.log.warn("감사 이벤트 적재 실패", { error: err instanceof Error ? err.message : String(err) });
    }
  }

  /**
   * 버퍼를 디스크로 내린다. 실패는 삼키되 **버퍼를 되돌린다** — 다음 주기에 재시도한다.
   *
   * 되돌리는 이유: 디스크가 일시적으로 가득 찬 경우(또는 권한 문제를 운영자가 고치는 사이)
   * 버려버리면 그 구간의 감사 기록이 영구히 사라진다. 재시도하면 회복 가능하다.
   * 대신 버퍼가 무한히 자라지 않게 상한을 두고, 넘으면 오래된 것부터 버리며 **경고**한다 —
   * 조용히 버리면 "기록이 있다"는 믿음이 거짓이 된다.
   */
  async flush(): Promise<void> {
    if (this.flushing) return;
    const pending = this.buffers;
    if (pending.size === 0) return;
    this.flushing = true;
    this.buffers = new Map();
    const flushedLines = this.lines;
    this.lines = 0;
    try {
      if (!this.dirReady) {
        // 0o700 — IP·사용자명이 든 파일을 비특권 로컬 계정이 목록조차 보지 못하게.
        await mkdir(this.dir, { recursive: true, mode: 0o700 });
        this.dirReady = true;
      }
      for (const [day, lines] of pending) {
        // mode는 **파일이 새로 만들어질 때만** 적용된다(기존 파일의 모드는 바뀌지 않는다) —
        // 그래서 디렉터리 모드도 함께 좁혀 둔다.
        await appendFile(join(this.dir, `audit-${day}.jsonl`), lines.join(""), { mode: 0o600 });
      }
    } catch (err) {
      this.restore(pending);
      this.log.warn("감사 로그 쓰기 실패 — 다음 주기에 재시도한다", {
        dir: this.dir,
        lines: flushedLines,
        error: err instanceof Error ? err.message : String(err),
      });
    } finally {
      this.flushing = false;
    }
  }

  /** flush 실패분을 버퍼 앞에 되돌린다(시간 순서 유지). 상한을 넘으면 오래된 것부터 버리고 경고. */
  private restore(failed: Map<string, string[]>): void {
    for (const [day, lines] of failed) {
      const current = this.buffers.get(day) ?? [];
      this.buffers.set(day, [...lines, ...current]);
      this.lines += lines.length;
    }
    const cap = this.maxBufferLines * 10;
    if (this.lines <= cap) return;
    let over = this.lines - cap;
    for (const [day, lines] of this.buffers) {
      if (over <= 0) break;
      const drop = Math.min(over, lines.length);
      lines.splice(0, drop);
      over -= drop;
      this.lines -= drop;
      if (lines.length === 0) this.buffers.delete(day);
    }
    this.log.warn("감사 버퍼 상한 초과 — 오래된 줄을 버렸다(쓰기가 계속 실패하고 있다)", {
      cap,
      dir: this.dir,
    });
  }
}
