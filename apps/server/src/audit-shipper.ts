/**
 * 감사 로그 이관 워커 — 날짜가 바뀐 JSONL을 gzip해 오브젝트 스토리지로 올리고 로컬에서 지운다.
 *
 * `MailboxReaper`/`BlobGcWorker`와 **동형**(interval + 재진입 가드 + 수동 tick) — 워커 형태를
 * 통일해 두면 기동·종료·로깅 규율이 한 곳에서 읽힌다.
 *
 * 왜 오브젝트 스토리지인가: 감사 로그는 **서버가 사라져도 남아야** 한다. 인스턴스가 교체되거나
 * (이 프로젝트에서 실제로 두 번 일어났다) 디스크가 차면 로컬 파일은 사라진다. journald도 회전돼
 * 사라진다 — 이번 세션에 그것 때문에 과거 판정 기록을 확인할 수 없었다.
 */
import { gzipSync } from "node:zlib";
import { readdir, readFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { auditDayUtc, noopLogger, type Logger } from "@ionosphere/core";
import { canonicalUri, formatAmzDate, signV4, type SigV4Credentials } from "@ionosphere/store";

/** 오브젝트 스토리지 접속 정보 — blob 버킷과 **분리된** 전용 버킷·자격증명. */
export interface AuditS3Target {
  /** 예: `https://minio.example.com` 또는 `https://<account>.r2.cloudflarestorage.com`. */
  endpoint: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  /** SigV4 서명 리전. R2는 `auto`, MinIO는 보통 `us-east-1`. */
  region?: string;
  /** 키 접두어(예: `audit`). */
  prefix?: string;
  /** MinIO 등 경로 스타일(`/bucket/key`). 미지정 시 가상 호스트 스타일. */
  forcePathStyle?: boolean;
  /** fetch 주입(테스트). */
  fetch?: typeof fetch;
}

export interface AuditShipperOptions {
  /** 감사 로그 디렉터리 — `AuditFileSink`와 같은 값이어야 한다. */
  dir: string;
  /**
   * 이 인스턴스를 식별하는 이름 — **키에 들어간다.**
   *
   * ★없으면 안 된다: 세 인스턴스(MX·MRA·MSA)가 **같은 버킷에 쓴다**. 키에 호스트가 없으면
   * 같은 날짜 파일이 서로를 덮어써 두 인스턴스의 기록 중 하나가 사라진다. 그것도 조용히.
   */
  host: string;
  /** 업로드 대상. 미지정 시 로컬 전용(이관하지 않고 보존기간만 적용). */
  target?: AuditS3Target;
  /** tick 간격(ms). 기본 1시간 — 일별 파일이라 더 자주 돌 이유가 없다. */
  intervalMs?: number;
  /**
   * 업로드에 실패해 로컬에 남은 파일을 며칠 뒤 버릴지. 기본 7일.
   *
   * 왜 버리는가: 디스크가 차서 **메일 수신이 멈추는 것**이 감사 기록 며칠보다 나쁘다.
   * 다만 조용히 버리면 안 되므로 `warn`으로 남긴다 — 그 경고가 곧 "이관이 계속 실패하고 있다"는
   * 신호다.
   */
  localRetainDays?: number;
  /**
   * 파일 하나의 업로드 상한(ms). 기본 5분.
   *
   * ★없으면 응답이 오지 않는 저장소 앞에서 tick이 끝나지 않고, 재진입 가드 때문에 그 뒤 tick은
   * **아무것도 세지 않고** 돌아간다 — 실패 카운터도 로그도 멈춰 「장애」가 「조용함」으로 보인다.
   * 하루치 파일 한 개를 느린 링크로 올릴 여유는 두되 주기(1시간)보다는 충분히 짧게 잡았다.
   */
  uploadTimeoutMs?: number;
  logger?: Logger;
  /** 이관 성공 관측 훅 — 실패 증분 0은 「복구됨」과 「시도할 파일이 없었음」을 가르지 못한다. */
  onShipped?: () => void;
  /** 이관 실패 관측 훅(메트릭 배선용). 파일이 로컬에 남아 재시도되는 경우도 포함한다. */
  onShipFailure?: () => void;
  /** 보존기간을 넘겨 파일을 **버렸을 때** 훅 — 실패와 달리 되돌릴 수 없는 유실이다. */
  onShipDropped?: () => void;
}

const DEFAULT_INTERVAL_MS = 60 * 60 * 1000;
const DEFAULT_LOCAL_RETAIN_DAYS = 7;
const DEFAULT_UPLOAD_TIMEOUT_MS = 5 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
/** `audit-YYYY-MM-DD.jsonl` — 이 형식만 이관 대상이다(다른 파일은 건드리지 않는다). */
const FILE_RE = /^audit-(\d{4}-\d{2}-\d{2})\.jsonl$/;
/** S3 오류 응답에서 읽는 양. `<Code>`는 본문 앞쪽에 있고, 나머지(Message·Key)는 진단에 필요 없다. */
const S3_ERROR_BODY_PEEK = 2048;
const S3_ERROR_CODE_RE = /<Code>([A-Za-z0-9.]{1,64})<\/Code>/;

/**
 * 예외를 로그 필드로 — `err.cause`까지 펼친다.
 *
 * ★왜(2026-10-15~16): 세 인스턴스가 31시간 동안 `"error":"fetch failed"`만 남겼다. node의
 * fetch(undici)는 연결 단계 실패를 전부 이 한 문장으로 감싸고 **실제 원인(ECONNREFUSED·
 * ETIMEDOUT·DNS)은 `cause`에만** 둔다. 그것이 없으면 「저장소가 죽었다」와 「경로가 막혔다」를
 * 로그로 가를 수 없어, 장애가 풀린 뒤에는 원인을 영영 알 수 없었다.
 */
function errorFields(err: unknown): { error: string; cause?: string } {
  if (!(err instanceof Error)) return { error: String(err) };
  const cause = err.cause;
  if (cause === undefined) return { error: errorText(err) };
  return { error: errorText(err), cause: cause instanceof Error ? errorText(cause) : String(cause) };
}

/** `TimeoutError`·`ECONNREFUSED`처럼 메시지보다 분류가 먼저 읽히게 이름과 코드를 앞에 붙인다. */
function errorText(e: Error): string {
  const code = (e as { code?: unknown }).code;
  const tags = [e.name !== "Error" ? e.name : "", typeof code === "string" && !e.message.includes(code) ? code : ""];
  const prefix = tags.filter((t) => t !== "").join(" ");
  return prefix ? `${prefix}: ${e.message}` : e.message;
}

export interface AuditShipResult {
  shipped: number;
  failed: number;
  /** 보존기간 초과로 버린 파일 수(업로드 실패 상태였던 것). */
  dropped: number;
}

export class AuditShipper {
  private readonly dir: string;
  private readonly host: string;
  private readonly target?: AuditS3Target;
  private readonly intervalMs: number;
  private readonly localRetainDays: number;
  private readonly uploadTimeoutMs: number;
  private readonly log: Logger;
  private readonly onShipped?: () => void;
  private readonly onShipFailure?: () => void;
  private readonly onShipDropped?: () => void;
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  constructor(opts: AuditShipperOptions) {
    this.dir = opts.dir;
    this.host = opts.host;
    if (opts.target) this.target = opts.target;
    this.intervalMs = opts.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.localRetainDays = opts.localRetainDays ?? DEFAULT_LOCAL_RETAIN_DAYS;
    this.uploadTimeoutMs = opts.uploadTimeoutMs ?? DEFAULT_UPLOAD_TIMEOUT_MS;
    this.log = (opts.logger ?? noopLogger).child({ component: "audit-ship" });
    if (opts.onShipped) this.onShipped = opts.onShipped;
    if (opts.onShipFailure) this.onShipFailure = opts.onShipFailure;
    if (opts.onShipDropped) this.onShipDropped = opts.onShipDropped;
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), this.intervalMs);
    this.timer.unref?.();
  }

  async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    while (this.running) await new Promise((r) => setTimeout(r, 10));
  }

  /**
   * 아직 이관되지 않은 지난 날짜 파일 수(적체) — tick과 무관하게 디렉터리에서 직접 센다.
   *
   * ★tick 결과로 세지 않는 이유: 첫 tick은 기동 1시간 뒤라, 재시작 직후 한 시간 동안 「밀린 파일
   * 0개」로 보인다. 이 값은 복구 판정의 근거라 그 공백이 곧 오판이 된다.
   */
  async pendingCount(now: number = Date.now()): Promise<number> {
    const today = auditDayUtc(now);
    let names: string[];
    try {
      names = await readdir(this.dir);
    } catch {
      return 0; // 디렉터리가 아직 없다 — 감사 이벤트가 한 건도 없었다는 뜻
    }
    return names.filter((name) => {
      const day = FILE_RE.exec(name)?.[1];
      return day !== undefined && day < today;
    }).length;
  }

  /** 한 사이클(수동 구동 가능). */
  async tick(now: number = Date.now()): Promise<AuditShipResult> {
    const result: AuditShipResult = { shipped: 0, failed: 0, dropped: 0 };
    if (this.running) return result;
    this.running = true;
    try {
      const today = auditDayUtc(now);
      let names: string[];
      try {
        names = await readdir(this.dir);
      } catch {
        return result; // 디렉터리가 아직 없다 — 감사 이벤트가 한 건도 없었다는 뜻
      }
      for (const name of names.sort()) {
        const m = FILE_RE.exec(name);
        if (!m) continue;
        const day = m[1]!;
        /**
         * ★오늘 파일은 건드리지 않는다 — `AuditFileSink`가 계속 append하는 중이다.
         * 올리는 순간의 스냅샷만 담기고 그 뒤 이벤트는 로컬에만 남는데, 파일을 지우면
         * 그것마저 사라진다. UTC 기준이라 싱크와 경계가 정확히 일치한다.
         */
        if (day >= today) continue;
        const path = join(this.dir, name);
        const ok = await this.ship(path, day);
        if (ok) {
          result.shipped++;
          this.onShipped?.();
          continue;
        }
        result.failed++;
        this.onShipFailure?.();
        // 보존기간을 넘겼으면 버린다 — 디스크가 차는 쪽이 더 나쁘다.
        if (now - Date.parse(`${day}T00:00:00.000Z`) > this.localRetainDays * DAY_MS) {
          try {
            await unlink(path);
            result.dropped++;
            this.onShipDropped?.();
            this.log.warn("이관 실패 상태로 보존기간을 넘겨 감사 로그를 버렸다 — 이관 경로를 점검할 것", {
              file: name,
              retainDays: this.localRetainDays,
            });
          } catch {
            /* 삭제 실패는 다음 tick에 재시도 */
          }
        }
      }
      if (result.shipped > 0 || result.failed > 0 || result.dropped > 0) {
        this.log.info("감사 로그 이관", { ...result });
      }
      return result;
    } finally {
      this.running = false;
    }
  }

  /**
   * 파일 하나를 올리고, **성공을 확인한 뒤에만** 로컬에서 지운다.
   *
   * ★순서가 보안이다(`s3-blob.ts`의 "검증 → 캐시 쓰기"와 같은 규율). 삭제를 먼저 하거나 응답
   * 코드를 보지 않고 지우면, 네트워크가 끊긴 순간의 감사 기록이 **영구히** 사라진다.
   * 되돌릴 방법이 없는 종류의 실수라 여기서만은 낙관하지 않는다.
   */
  private async ship(path: string, day: string): Promise<boolean> {
    try {
      const raw = await readFile(path);
      if (raw.byteLength === 0) {
        // 빈 파일은 올릴 것이 없다 — 지우고 넘어간다(빈 객체를 만들면 조회가 헷갈린다).
        await unlink(path);
        return true;
      }
      if (!this.target) return false; // 로컬 전용 구성 — 보존기간 정책만 적용된다
      const body = gzipSync(raw);
      const key = this.objectKey(day);
      const { status, s3Code } = await this.put(this.target, key, body);
      if (status !== 200 && status !== 201) {
        // 필드명이 `key`면 로거가 통째로 `<redacted>`로 가린다(`log.ts` SENSITIVE_KEY_PARTS —
        // `key` 부분 일치). 여기 값은 비밀이 아니라 **S3 객체 경로**이고, 업로드 실패를 진단하려면
        // 그 경로가 보여야 한다(라이브 실측에서 `key=<redacted>`만 남아 드러났다).
        // 마스킹 규칙을 느슨하게 푸는 대신 **이름을 정직하게** 바꾼다 — 규칙은 새는 쪽이 더 비싸다.
        this.log.warn("감사 로그 업로드 실패 — 로컬에 유지하고 다음 주기에 재시도한다", {
          file: `audit-${day}.jsonl`,
          objectPath: key,
          status,
          // 403 하나에 자격 폐기·시계 편차·정책 거부가 다 들어 있다 — 코드가 있어야 갈린다.
          ...(s3Code ? { s3Code } : {}),
        });
        return false;
      }
      await unlink(path);
      return true;
    } catch (err) {
      this.log.warn("감사 로그 이관 실패 — 로컬에 유지한다", {
        file: `audit-${day}.jsonl`,
        ...errorFields(err),
      });
      return false;
    }
  }

  /**
   * `<prefix>/<host>/YYYY/MM/audit-YYYY-MM-DD.jsonl.gz`
   *
   * `<host>`가 **반드시** 들어가야 한다(위 `host` 옵션 주석). 연/월로 나누는 이유는 한 접두어에
   * 객체가 수천 개 쌓이면 콘솔·`ls`가 느려지고 lifecycle 규칙을 기간별로 걸기 어려워서다.
   */
  private objectKey(day: string): string {
    const [y, mo] = day.split("-");
    const parts = [this.target?.prefix, this.host, y, mo, `audit-${day}.jsonl.gz`].filter(
      (p): p is string => p !== undefined && p !== "",
    );
    return parts.join("/");
  }

  /** SigV4 PUT — 서명 프리미티브는 `@ionosphere/store`의 것을 그대로 쓴다(재구현 금지). */
  private async put(t: AuditS3Target, key: string, body: Uint8Array): Promise<{ status: number; s3Code?: string }> {
    const url = new URL(t.endpoint);
    const host = t.forcePathStyle ? url.host : `${t.bucket}.${url.host}`;
    const path = t.forcePathStyle ? `/${t.bucket}/${key}` : `/${key}`;
    const amzDate = formatAmzDate(new Date());
    const { createHash } = await import("node:crypto");
    const payloadSha256 = createHash("sha256").update(body).digest("hex");
    const cred: SigV4Credentials = {
      accessKeyId: t.accessKeyId,
      secretAccessKey: t.secretAccessKey,
      region: t.region ?? "us-east-1",
      service: "s3",
    };
    const headers: Record<string, string> = {
      host,
      "x-amz-content-sha256": payloadSha256,
      "x-amz-date": amzDate,
      "content-type": "application/gzip",
    };
    const signed = signV4({ method: "PUT", path, query: "", headers, payloadSha256 }, cred, amzDate);
    const f = t.fetch ?? fetch;
    const res = await f(`${url.protocol}//${host}${canonicalUri(path)}`, {
      method: "PUT",
      headers: { ...headers, authorization: signed.authorization },
      body,
      signal: AbortSignal.timeout(this.uploadTimeoutMs),
    });
    if (res.status === 200 || res.status === 201) return { status: res.status };
    const s3Code = await peekS3ErrorCode(res);
    return s3Code ? { status: res.status, s3Code } : { status: res.status };
  }
}

/** 오류 응답 본문 앞부분에서 S3 `<Code>`만 읽는다. 본문을 못 읽어도 상태 코드 판정은 그대로다. */
async function peekS3ErrorCode(res: Response): Promise<string | undefined> {
  try {
    const text = (await res.text()).slice(0, S3_ERROR_BODY_PEEK);
    return S3_ERROR_CODE_RE.exec(text)?.[1];
  } catch {
    return undefined;
  }
}
