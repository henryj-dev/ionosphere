/**
 * 경량 구조화 로거 (의존성 제로).
 * - 프로토콜 엔진은 순수 유지(PLAN §4) — 로거는 어댑터/조립층에만 주입한다.
 * - 패키지 기본값은 noopLogger (테스트 조용, 라이브러리로 써도 무소음).
 * - 포맷: pretty(TTY 개발용) / json(운영·수집기용 한 줄 JSON).
 * - **민감 필드는 키 이름으로 마스킹한다**(SENSITIVE_KEY_PARTS) — 근거는 해당 주석 참조.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogFields {
  [key: string]: unknown;
}

export interface Logger {
  debug(msg: string, fields?: LogFields): void;
  info(msg: string, fields?: LogFields): void;
  warn(msg: string, fields?: LogFields): void;
  error(msg: string, fields?: LogFields): void;
  /** 필드를 바인딩한 자식 로거 (예: component, 연결 id). */
  child(fields: LogFields): Logger;
}

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

/**
 * 민감 필드 마스킹 — **키 이름 부분 일치**(대소문자 무시) 블랙리스트.
 *
 * 왜 필요한가: 예전에는 마스킹이 아예 없어서, 호출자 규율만이 유일한 방어였다.
 * 옵션 객체를 통째로 넘기는 한 줄(`log.info("smarthost", { opts })`)이면 스마트호스트
 * 비밀번호·CF DNS 토큰·root 토큰이 그대로 journald로 나간다. 로깅은 되돌릴 수 없다.
 *
 * 왜 **키 이름 기반**인가: 값 기반 추측(엔트로피·길이)은 이 저장소에서 오탐이 크다 —
 * blobId(sha256 hex 64자)·ULID·DKIM selector가 전부 "비밀처럼" 생겼다.
 * 반대로 비밀을 담는 자리는 이름이 정직하다(`password`·`apiToken`·`masterKey`).
 *
 * 목록 선정 근거: 현재 로깅 중인 필드 이름을 전수 수집해 대조했고, 아래 어느 조각과도
 * 겹치지 않는 것만 남겼다(`selector`·`domain`·`rcpt`·`accountId`·`mailboxId`·`tlsName` 등은 보존).
 * - `key`는 부분 일치라 `blobKey` 같은 이름도 잡지만, 그 대가로 `dkimKey`·`masterKey`·
 *   `privateKey`·`apiKey`를 전부 덮는다. **가려서 잃는 것보다 새어서 잃는 것이 크다.**
 * - `pass`가 아니라 `password`/`passwd`인 이유: `bypass*`·`passed` 오탐을 피한다.
 *   SASL 비밀번호를 담는 코드상 변수명은 `pass`지만 로그 필드로 나가는 자리는 없다.
 * - `auth`는 `authorization` 헤더까지 함께 덮는다.
 */
const SENSITIVE_KEY_PARTS = ["password", "passwd", "secret", "token", "credential", "auth", "key"] as const;
const REDACTED = "<redacted>";

function isSensitiveKey(key: string): boolean {
  const lower = key.toLowerCase();
  return SENSITIVE_KEY_PARTS.some((part) => lower.includes(part));
}

/**
 * 중첩까지 내려가야 하는 이유가 곧 M-9의 위협이다 — 위험한 것은 `{ password }`가 아니라
 * `{ opts: { smarthost: { password } } }`처럼 **한 겹 감싼 객체를 통째로 넘기는 실수**다.
 *
 * 평범한 객체(prototype이 Object 또는 null)와 배열만 파고든다. Error·Date·Buffer는
 * JSON.stringify가 고유한 표현을 갖고 있어(Date→ISO 문자열 등) 분해하면 출력이 망가진다.
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false;
  const proto = Object.getPrototypeOf(value) as object | null;
  return proto === Object.prototype || proto === null;
}

function redactValue(value: unknown, path: Set<object>): unknown {
  if (Array.isArray(value)) {
    if (path.has(value)) return "<circular>";
    path.add(value);
    const out = value.map((item) => redactValue(item, path));
    path.delete(value);
    return out;
  }
  if (!isPlainObject(value)) return value;
  // 순환 참조는 종전에도 JSON.stringify가 던졌다. 재귀가 먼저 도는 지금은 던지는 대신
  // 무한 루프에 빠질 자리라 표식으로 끊는다 — 로깅이 프로세스를 멈추면 안 된다.
  if (path.has(value)) return "<circular>";
  path.add(value);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = isSensitiveKey(k) ? REDACTED : redactValue(v, path);
  }
  path.delete(value);
  return out;
}

function redactFields(fields: LogFields): LogFields {
  const out: LogFields = {};
  const path = new Set<object>();
  for (const [k, v] of Object.entries(fields)) {
    out[k] = isSensitiveKey(k) ? REDACTED : redactValue(v, path);
  }
  return out;
}

export interface CreateLoggerOptions {
  level?: LogLevel;
  format?: "pretty" | "json";
  /** 출력 싱크 — 기본 process.stdout. 테스트에서 캡처용으로 교체 가능. */
  sink?: (line: string) => void;
}

function formatFields(fields: LogFields): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined) continue;
    const s = typeof v === "string" ? v : JSON.stringify(v);
    parts.push(`${k}=${s}`);
  }
  return parts.length > 0 ? " " + parts.join(" ") : "";
}

class RealLogger implements Logger {
  private readonly min: number;
  private readonly format: "pretty" | "json";
  private readonly sink: (line: string) => void;
  private readonly bound: LogFields;

  constructor(min: number, format: "pretty" | "json", sink: (line: string) => void, bound: LogFields) {
    this.min = min;
    this.format = format;
    this.sink = sink;
    this.bound = bound;
  }

  private emit(level: LogLevel, msg: string, fields?: LogFields): void {
    if (LEVEL_ORDER[level] < this.min) return;
    // 마스킹은 **여기 한 곳**에서만 한다 — 두 포맷(json/pretty)과 바인딩 필드(child)가
    // 전부 이 지점을 지나므로, 새 출력 경로가 생겨도 마스킹을 빠뜨릴 자리가 없다.
    // msg 문자열은 마스킹 대상이 아니다(키 이름이 없어 판정할 근거가 없다) — 비밀을
    // 메시지 본문에 문자열 보간하지 말 것.
    const merged = redactFields({ ...this.bound, ...fields });
    const ts = new Date().toISOString();
    if (this.format === "json") {
      this.sink(JSON.stringify({ ts, level, msg, ...merged }) + "\n");
    } else {
      const comp = typeof merged.component === "string" ? `[${merged.component}] ` : "";
      const rest = { ...merged };
      delete rest.component;
      this.sink(`${ts} ${level.toUpperCase().padEnd(5)} ${comp}${msg}${formatFields(rest)}\n`);
    }
  }

  debug(msg: string, fields?: LogFields): void {
    this.emit("debug", msg, fields);
  }
  info(msg: string, fields?: LogFields): void {
    this.emit("info", msg, fields);
  }
  warn(msg: string, fields?: LogFields): void {
    this.emit("warn", msg, fields);
  }
  error(msg: string, fields?: LogFields): void {
    this.emit("error", msg, fields);
  }
  child(fields: LogFields): Logger {
    return new RealLogger(this.min, this.format, this.sink, { ...this.bound, ...fields });
  }
}

export function createLogger(opts: CreateLoggerOptions = {}): Logger {
  const level = opts.level ?? "info";
  const format = opts.format ?? (process.stdout.isTTY ? "pretty" : "json");
  const sink = opts.sink ?? ((line: string) => void process.stdout.write(line));
  return new RealLogger(LEVEL_ORDER[level], format, sink, {});
}

class NoopLogger implements Logger {
  debug(): void {}
  info(): void {}
  warn(): void {}
  error(): void {}
  child(): Logger {
    return this;
  }
}

/** 패키지들의 기본값 — 주입 안 하면 무소음. */
export const noopLogger: Logger = new NoopLogger();
