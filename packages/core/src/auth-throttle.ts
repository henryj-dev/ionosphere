/**
 * 인증 실패 스로틀 — **프로토콜 공용**(SMTP·IMAP·POP3·ManageSieve·JMAP·관리 API).
 *
 * 왜 core가 소유하는가: 원래 관리 API 안에만 있었고, 나머지 프로토콜에는 인증 시도 제한이
 * **아예 없었다**. 자격증명 하나를 무제한으로 때려볼 수 있었고, 실패마다 scrypt가 돌아
 * 브루트포스가 곧 CPU 소모 공격이기도 했다. 갈래마다 손으로 다시 만들면 한쪽이 빠지므로
 * (SASL 파싱·프로토콜 한도를 core로 올린 것과 같은 이유) 여기서 한 번만 정의한다.
 *
 * 설계 요점:
 *  - **실패만** 센다. 성공은 세지 않고 즉시 카운터를 지운다 — 오타 뒤 정상 로그인이 벌받지 않게.
 *  - **축이 둘이다**: IP(프리픽스) 축 + 계정 축. 어느 한쪽이라도 한도를 넘으면 차단한다.
 *    IP 축만 있던 시절엔 봇넷·IPv6 프리픽스 전환으로 **한 계정 분산 대입이 무제한**이었다.
 *  - 키는 호출자가 아니라 **여기서** 정규화한다(`throttleKeyOf`). 정규화를 호출자에게 맡기면
 *    한 갈래가 빠지고 그 갈래만 스로틀이 무력해진다 — 실제로 IPv6에서 그랬다.
 *  - 상태는 인프로세스 Map(단일 프로세스 배포 전제). 여러 인스턴스면 각자 따로 센다 —
 *    그래서 조립층(`apps/server/src/app.ts`)이 **인스턴스 하나를 만들어 주입**한다.
 *  - 공격자가 IP를 바꿔가며 Map을 불리는 것을 막으려고 윈도우당 한 번 만료 엔트리를 쓸어낸다
 *    (요청마다 전수 순회하면 O(n) 비용이 요청 경로에 실린다).
 *
 * 이 모듈은 **비밀번호를 받지도 로깅하지도 않는다** — 들어오는 것은 주소와 사용자명뿐이다.
 */
import { isIP } from "node:net";
import { noopLogger, type Logger } from "./log.ts";

export interface AuthThrottleOptions {
  /** 실패를 세는 슬라이딩 윈도우 폭(ms). 기본 60초. */
  windowMs?: number;
  /** 윈도우 안에서 한 IP 프리픽스가 허용받는 실패 횟수. 기본 10. */
  limit?: number;
  /**
   * 윈도우 안에서 **한 계정**이 허용받는 실패 횟수. 기본 20 — IP 축보다 느슨하게 둔다.
   * 계정 축은 출처를 가리지 않으므로, 공격자가 남의 주소를 알면 그 계정을 윈도우 동안
   * 잠글 수 있다(가용성 대가). 윈도우가 60초라 피해가 유계이고, 그 대가로
   * "봇넷이 한 계정을 무제한 대입"이 닫힌다 — 이 스로틀의 존재 이유가 scrypt CPU 방어다.
   */
  accountLimit?: number;
  /** 스로틀 발동 로깅용. 미지정이면 무소음(라이브러리 기본). */
  logger?: Logger;
}

/**
 * 스로틀 대상.
 *
 * 문자열은 **IP만** 넘기는 축약형이다 — 소켓 프로토콜 어댑터(SMTP·IMAP·POP3·ManageSieve)가
 * 사용자명을 모르는 자리에서 이 형태로 부른다. 사용자명을 아는 자리는 객체 형태로 넘겨
 * 계정 축까지 함께 태운다.
 */
export interface AuthSubject {
  /** 소켓 상대 주소(또는 신뢰된 XFF 값). 내부에서 /64·/32로 정규화된다. */
  ip?: string | undefined;
  /** 인증 시도 대상 사용자명. 대소문자·공백을 정규화해 센다. */
  account?: string | undefined;
}

export type AuthThrottleSubject = string | AuthSubject;

const DEFAULT_WINDOW_MS = 60_000;
const DEFAULT_LIMIT = 10;
const DEFAULT_ACCOUNT_LIMIT = 20;

/** 축별 네임스페이스 — 사용자명이 IP 표기와 같아도 버킷이 섞이지 않게. */
const IP_PREFIX = "ip|";
const ACCOUNT_PREFIX = "account|";

type AxisName = "ip" | "account";

interface Axis {
  readonly axis: AxisName;
  /** 정규화된 대상(로그용). */
  readonly id: string;
  /** Map 키(네임스페이스 포함). */
  readonly key: string;
  readonly limit: number;
}

export class AuthFailureThrottle {
  private readonly fails = new Map<string, number[]>();
  private lastSweep = 0;
  private readonly windowMs: number;
  private readonly limit: number;
  private readonly accountLimit: number;
  private readonly log: Logger;

  constructor(opts: AuthThrottleOptions = {}) {
    this.windowMs = opts.windowMs ?? DEFAULT_WINDOW_MS;
    this.limit = opts.limit ?? DEFAULT_LIMIT;
    this.accountLimit = opts.accountLimit ?? DEFAULT_ACCOUNT_LIMIT;
    this.log = (opts.logger ?? noopLogger).child({ component: "auth-throttle" });
  }

  /** 차단 중이면 남은 대기 초(>=1), 통과면 0. 두 축 중 **더 오래 걸린 쪽**을 답한다. */
  retryAfterSeconds(subject: AuthThrottleSubject, now: number = Date.now()): number {
    let worst = 0;
    for (const axis of this.axesOf(subject)) {
      const recent = this.recent(axis.key, now);
      if (recent.length < axis.limit) continue;
      const oldest = recent[0]!;
      worst = Math.max(worst, Math.max(1, Math.ceil((oldest + this.windowMs - now) / 1000)));
    }
    return worst;
  }

  /** 차단 여부만 볼 때. */
  blocked(subject: AuthThrottleSubject, now: number = Date.now()): boolean {
    return this.retryAfterSeconds(subject, now) > 0;
  }

  recordFailure(subject: AuthThrottleSubject, now: number = Date.now()): void {
    for (const axis of this.axesOf(subject)) {
      const recent = this.recent(axis.key, now);
      recent.push(now);
      this.fails.set(axis.key, recent);
      // 발동은 **경계에서 한 번만** 로깅한다. 시도마다 찍으면 공격이 곧 로그 폭주가 되고,
      // 아예 안 찍으면 운영자가 "공격 중인지 정상 사용자가 잠긴 건지"를 알 방법이 없다.
      if (recent.length === axis.limit) {
        this.log.warn("인증 실패 스로틀 발동", {
          axis: axis.axis,
          subject: axis.id,
          fails: recent.length,
          windowMs: this.windowMs,
        });
      }
    }
    this.sweep(now);
  }

  /** 인증 성공 → 그 대상의 실패 기록을 지운다(두 축 모두). */
  clear(subject: AuthThrottleSubject): void {
    for (const axis of this.axesOf(subject)) this.fails.delete(axis.key);
  }

  private axesOf(subject: AuthThrottleSubject): Axis[] {
    const s: AuthSubject = typeof subject === "string" ? { ip: subject } : subject;
    const axes: Axis[] = [];
    if (s.ip !== undefined) {
      const id = throttleKeyOf(s.ip);
      axes.push({ axis: "ip", id, key: IP_PREFIX + id, limit: this.limit });
    }
    const account = accountKeyOf(s.account);
    if (account !== null) {
      axes.push({ axis: "account", id: account, key: ACCOUNT_PREFIX + account, limit: this.accountLimit });
    }
    return axes;
  }

  private recent(key: string, now: number): number[] {
    const arr = this.fails.get(key);
    if (!arr) return [];
    return arr.filter((t) => t > now - this.windowMs);
  }

  private sweep(now: number): void {
    if (now - this.lastSweep < this.windowMs) return;
    this.lastSweep = now;
    for (const [key, times] of this.fails) {
      if (times.every((t) => t <= now - this.windowMs)) this.fails.delete(key);
    }
  }
}

/** 판정 불가 주소가 모이는 버킷 — 형식이 아니면 흩어놓지 않고 한곳으로 모은다(fail closed). */
const UNKNOWN = "unknown";

/**
 * 계정 키 길이 상한 — RFC 5321 §4.5.3.1.3 forward-path 상한.
 * 사용자명은 공격자가 정하므로, 상한이 없으면 긴 문자열로 Map 메모리를 부풀릴 수 있다.
 */
const MAX_ACCOUNT_KEY_LEN = 254;

function accountKeyOf(account: string | undefined): string | null {
  const s = (account ?? "").trim().toLowerCase();
  if (!s) return null;
  return s.length > MAX_ACCOUNT_KEY_LEN ? s.slice(0, MAX_ACCOUNT_KEY_LEN) : s;
}

/** 루프백 주소 — 우리 HTTPS 프론트가 upstream에 붙을 때의 소켓 상대. */
function isLoopback(addr: string): boolean {
  return addr === "127.0.0.1" || addr === "::1" || addr === "::ffff:127.0.0.1";
}

/**
 * XFF를 신뢰할 상대인지 판정하는 정책.
 *
 * 기본은 `trustLoopbackOnly`다. 루프백이 아닌 리버스 프록시를 앞에 두는 구성으로 바뀌면
 * **이 정책을 명시적으로 넘겨야** 한다 — 예전엔 그 사실이 주석에만 있어서, 토폴로지가 바뀌어도
 * 코드·타입 어디에도 걸리는 곳이 없었다. 인자로 드러내면 최소한 호출부에서 보인다.
 */
export type PeerTrustPolicy = (peer: string) => boolean;

/** 기본 정책 — 소켓 상대가 루프백일 때만 XFF를 신뢰한다. */
export const trustLoopbackOnly: PeerTrustPolicy = isLoopback;

/**
 * XFF 헤더 값에서 클라이언트가 주장하는 주소 하나를 뽑는다.
 *
 * **듀얼 런타임 함정**: 같은 이름의 헤더가 여러 번 오면 node는 `", "`로 이어 붙이고
 * bun은 **마지막 값만** 남긴다(실측). 배열 형태는 node·bun 어느 쪽에서도 나오지 않지만
 * node 타입이 `string | string[]`이라 시그니처에는 남아 있다 — 배열이 오면 신뢰하지 않는다.
 * 우리 프론트는 값을 **덮어쓰므로**(https-front.ts) 정상 경로에서는 값이 하나뿐이고,
 * 여럿이 보이면 앞쪽(가장 바깥 클라이언트)을 쓴다.
 */
function claimedForwardedFor(forwardedFor: string | string[] | undefined): string | null {
  if (typeof forwardedFor !== "string") return null;
  const first = forwardedFor.split(",")[0]?.trim();
  return first ? first : null;
}

/**
 * 클라이언트 IP 판정(HTTP 표면용).
 *
 * TLS 종단 프론트(apps/server/src/https-front.ts)를 거치면 소켓 주소가 전부 127.0.0.1이라
 * 스로틀이 전역 카운터로 퇴화한다 — 그러면 공격자 하나가 정상 사용자 전부를 잠근다.
 * 프론트가 클라이언트 값을 **덮어써서** x-forwarded-for에 넣으므로 그 값을 쓴다.
 *
 * ⚠ 두 겹의 방어가 필요하다:
 *  1. **소켓 상대가 신뢰 대상일 때만** 헤더를 본다(기본: 루프백). 평문 포트에 직접 닿을 수 있는
 *     구성에서 무조건 신뢰하면 클라이언트가 XFF를 위조해 스로틀을 그냥 우회한다(헤더는 공짜다).
 *  2. 값이 **유효한 IP 리터럴**일 때만 채택한다. 같은 호스트의 프로세스나 `ssh -L` 포워딩은
 *     루프백 상대가 되므로 1번을 통과한다 — 검사가 없으면 쓰레기 문자열로 Map을 오염시키거나,
 *     매 요청 값을 바꿔 스로틀을 무력화할 수 있었다. 검증 실패는 헤더를 버리고 peer로 돌아간다.
 */
export function clientIpOf(
  forwardedFor: string | string[] | undefined,
  remoteAddress: string | undefined,
  trustPeer: PeerTrustPolicy = trustLoopbackOnly,
): string {
  const peer = remoteAddress ?? "";
  if (trustPeer(peer)) {
    const claimed = claimedForwardedFor(forwardedFor);
    // 대괄호 표기(`[2001:db8::1]`)는 벗겨서 본다. 포트가 붙어 있으면 IP 리터럴이 아니므로 버린다.
    const bare = claimed === null ? null : stripZone(stripBrackets(claimed));
    if (bare !== null && isIP(bare) !== 0) return normalizeIp(bare);
  }
  /**
   * ★`normalizeIp`를 통과시킨다 — IPv4-매핑 IPv6(`::ffff:1.2.3.4`)를 점표기로 되돌린다.
   *
   * 왜(2026-08-04 감사 로그가 드러낸 것): node의 이중스택 리스너는 IPv4 접속의
   * `remoteAddress`를 `::ffff:a.b.c.d`로 준다. 그래서 소켓 프로토콜(IMAP·POP3 등, `normalizeIp`
   * 사용)은 `1.2.3.4`를, HTTP 표면(JMAP·관리 API, 이 함수 사용)은 `::ffff:1.2.3.4`를 기록했다.
   * **같은 주소가 표면에 따라 두 표기로 남으면 감사 로그를 IP로 훑을 수 없다** — 실제로 라이브
   * 첫 관측에서 JMAP만 `::ffff:192.155.90.118`로 찍혔고, `grep 192.155.90.118`은 그 줄을 찾지만
   * `grep '"ip":"192'`나 IP 단위 집계는 갈라진다.
   *
   * 스로틀 버킷은 영향이 없었다(`throttleKeyOf`가 이미 매핑 주소를 IPv4로 되돌린다) — 즉 이건
   * **기록·표시의 일관성** 문제다. 그래서 한도 계산이 아니라 이 반환값을 고친다.
   */
  return normalizeIp(peer || undefined);
}

/** IPv4-mapped IPv6(`::ffff:1.2.3.4`)를 순수 IPv4로 — 소켓 주소를 **표시**할 때 표기를 통일한다. */
export function normalizeIp(ip: string | undefined): string {
  if (!ip) return UNKNOWN;
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  return m ? m[1]! : ip;
}

/**
 * 스로틀 버킷 키 — IPv4는 `/32`, IPv6는 `/64` 프리픽스 단위.
 *
 * 왜 프리픽스인가: VPS 하나면 라우팅된 /64를 받는 것이 관행이라, 공격자는 **위조 없이**
 * 매 연결마다 실제 소스 주소를 바꿀 수 있다. 키가 주소 전체면 시도마다 새 버킷이 생겨
 * 한도가 한 번도 걸리지 않는다. 비용 단위(= 한 명이 값싸게 확보하는 주소 묶음)로 세야 한다.
 *
 * IPv4-매핑 IPv6(`::ffff:a.b.c.d`, `::ffff:7f00:1`)는 **IPv4 규칙으로 되돌려** 태운다 —
 * 안 그러면 같은 IPv4가 표기에 따라 두 버킷을 써서 한도가 두 배가 된다.
 */
export function throttleKeyOf(addr: string | undefined): string {
  const raw = (addr ?? "").trim();
  if (!raw) return UNKNOWN;
  const bare = stripZone(stripBrackets(raw));
  const v4 = ipv4Of(bare);
  if (v4 !== null) return v4;
  if (isIP(bare) !== 6) return UNKNOWN;
  const hextets = expandIpv6(bare);
  if (hextets === null) return UNKNOWN;
  return `${hextets.slice(0, 4).join(":")}::/64`;
}

/** `[2001:db8::1]` → `2001:db8::1`. URL·프록시 헤더에서 오는 표기. */
function stripBrackets(addr: string): string {
  return addr.startsWith("[") && addr.endsWith("]") ? addr.slice(1, -1) : addr;
}

/** 링크로컬 zone id(`fe80::1%eth0`) 제거 — 붙어 있으면 isIP가 주소로 인정하지 않는다. */
function stripZone(addr: string): string {
  const i = addr.indexOf("%");
  return i === -1 ? addr : addr.slice(0, i);
}

/** 순수 IPv4 또는 IPv4-매핑 IPv6면 점표기 IPv4를, 아니면 null. */
function ipv4Of(addr: string): string | null {
  if (isIP(addr) === 4) return addr;
  if (isIP(addr) !== 6) return null;
  const hextets = expandIpv6(addr);
  if (hextets === null) return null;
  const mapped = hextets[0] === "0" && hextets[1] === "0" && hextets[2] === "0" && hextets[3] === "0" && hextets[4] === "0" && hextets[5] === "ffff";
  if (!mapped) return null;
  const hi = parseInt(hextets[6]!, 16);
  const lo = parseInt(hextets[7]!, 16);
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}

/** IPv6를 8개 hextet(선행 0 제거, 소문자)으로 펼친다. `::` 압축과 꼬리 점표기 IPv4를 함께 처리. */
function expandIpv6(addr: string): string[] | null {
  let s = addr.toLowerCase();
  const dotted = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (dotted) {
    const octets = [dotted[1]!, dotted[2]!, dotted[3]!, dotted[4]!].map((o) => Number(o));
    if (octets.some((n) => n > 255)) return null;
    const hi = ((octets[0]! << 8) | octets[1]!).toString(16);
    const lo = ((octets[2]! << 8) | octets[3]!).toString(16);
    s = `${s.slice(0, dotted.index)}${hi}:${lo}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = 8 - head.length - tail.length;
  if (halves.length === 1 ? head.length !== 8 : fill < 0) return null;
  const parts = halves.length === 1 ? head : [...head, ...Array<string>(fill).fill("0"), ...tail];
  const out: string[] = [];
  for (const p of parts) {
    if (!/^[0-9a-f]{1,4}$/.test(p)) return null;
    out.push(parseInt(p, 16).toString(16));
  }
  return out.length === 8 ? out : null;
}
