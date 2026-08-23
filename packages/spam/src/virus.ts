/**
 * 바이러스 검사 **플러그인 훅** — 스캐너 자체는 여기 없다.
 *
 * PLAN.md의 약속이 "옵셔널 플러그인 훅만 제공(기본 비활성)"인 이유: 시그니처 DB 생태계는
 * 복제할 수 없다. 우리가 만들 수 있는 것은 **판정을 끼워 넣을 자리**와 그 판정을 어떻게
 * 다룰지에 대한 규율뿐이다.
 *
 * ★이 파일이 실제로 정하는 것은 "스캐너가 무엇을 하는가"가 아니라
 * **"스캐너가 대답하지 못할 때 메일을 어떻게 할 것인가"**다. 거기가 유일하게 위험한 자리다.
 */

/** 스캐너 판정. `error`는 "감염 아님"이 아니라 **"모른다"**이다 — 둘을 섞으면 안 된다. */
export const VIRUS_VERDICT = {
  clean: "clean",
  infected: "infected",
  error: "error",
} as const;
export type VirusVerdict = (typeof VIRUS_VERDICT)[keyof typeof VIRUS_VERDICT];

export interface VirusScanResult {
  verdict: VirusVerdict;
  /** 시그니처 이름(있으면). 로그·거부 사유에 쓴다 — 본문은 절대 남기지 않는다. */
  signature?: string;
}

export interface VirusScanner {
  /** 원본 바이트를 받아 판정한다. 던져도 된다 — 호출부가 `error`로 다룬다. */
  scan(raw: Uint8Array): Promise<VirusScanResult>;
}

/**
 * 스캐너가 대답하지 못했을 때의 처리.
 *
 * ★기본이 `defer`인 이유: 이 세 갈래의 최악이 서로 다르다.
 *  - `accept`  : 스캐너가 죽은 동안 **검사되지 않은 메일이 그대로 배달된다**(fail open).
 *  - `reject`  : 스캐너 장애가 곧 **영구 거부**다. 보낸 쪽은 반송을 받고 메일은 사라진다.
 *  - `defer`   : 상대 MTA가 재시도한다. **메일도 안 잃고 검사 안 된 것도 안 들인다.**
 * 보안은 fail closed지만, "닫는다"가 "버린다"여서는 안 된다. 그 사이가 defer다.
 */
export const VIRUS_ON_ERROR = { defer: "defer", accept: "accept", reject: "reject" } as const;
export type VirusOnError = (typeof VIRUS_ON_ERROR)[keyof typeof VIRUS_ON_ERROR];

export interface VirusScanOptions {
  /** 스캐너 응답 상한(ms, 기본 10초). 넘으면 `error`로 다룬다. */
  timeoutMs?: number;
  /** 판정 불가 시 처리(기본 `defer`). */
  onError?: VirusOnError;
}

/** 호출부가 그대로 쓸 수 있는 조치 — SMTP 응답 코드까지 여기서 정한다. */
export type VirusScanAction =
  | { action: "accept" }
  | { action: "reject"; code: 554; enhanced: "5.7.1"; message: string }
  | { action: "defer"; code: 451; enhanced: "4.7.1"; message: string };

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * 스캐너를 돌리고 **조치**를 돌려준다. 절대 던지지 않는다.
 *
 * ⚠ 타임아웃이 필수인 이유: 이 호출은 SMTP 트랜잭션 **안에서** 일어난다. 스캐너가 멈추면
 * 그 커넥션이 물리고, 동시 연결 상한에 걸리면 **수신 전체가 멈춘다**. 스캐너 하나가
 * 메일 서버를 세우게 두지 않는다.
 */
export async function scanForVirus(
  scanner: VirusScanner,
  raw: Uint8Array,
  opts: VirusScanOptions = {},
): Promise<VirusScanAction> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const onError = opts.onError ?? VIRUS_ON_ERROR.defer;

  let result: VirusScanResult;
  try {
    result = await withTimeout(scanner.scan(raw), timeoutMs);
  } catch {
    // 예외·타임아웃 모두 "모른다"다. 스캐너가 왜 못 했는지는 조치를 바꾸지 않는다.
    result = { verdict: VIRUS_VERDICT.error };
  }

  if (result.verdict === VIRUS_VERDICT.clean) return { action: "accept" };
  if (result.verdict === VIRUS_VERDICT.infected) {
    // 시그니처 이름만 싣는다. 본문 조각을 응답에 넣으면 그 자체가 정보 노출이다.
    const named = result.signature ? `: ${sanitizeSignature(result.signature)}` : "";
    return { action: "reject", code: 554, enhanced: "5.7.1", message: `message rejected by virus scan${named}` };
  }
  if (onError === VIRUS_ON_ERROR.accept) return { action: "accept" };
  if (onError === VIRUS_ON_ERROR.reject) {
    return { action: "reject", code: 554, enhanced: "5.7.1", message: "virus scan unavailable" };
  }
  return { action: "defer", code: 451, enhanced: "4.7.1", message: "virus scan unavailable, retry later" };
}

/**
 * 시그니처 이름을 SMTP 응답에 실을 수 있는 형태로 좁힌다.
 *
 * 이름은 **스캐너가 주는 값**이라 우리가 정하지 않는다. CR/LF가 들어오면 응답 줄이 쪼개져
 * 프로토콜이 깨지고(스머글링과 같은 부류), 길면 응답 줄 상한을 넘는다.
 */
function sanitizeSignature(s: string): string {
  return s.replace(/[^\x20-\x7e]/g, "").slice(0, 80);
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("virus scan timeout")), ms);
    // ★unref: 스캐너가 응답해도 이 타이머가 이벤트 루프를 붙잡으면 프로세스 종료가 늦어진다.
    t.unref?.();
    p.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e: unknown) => {
        clearTimeout(t);
        reject(e instanceof Error ? e : new Error(String(e)));
      },
    );
  });
}
