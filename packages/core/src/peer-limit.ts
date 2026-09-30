/**
 * IP(프리픽스)별 동시 연결 상한 — 소켓 프로토콜 5종 공용.
 *
 * ★왜 필요한가(2026-08-23 검수): `MAX_LISTENER_CONNECTIONS`(1024)는 **전역**이라 한 주소가
 * 혼자 소진할 수 있었다. 그러면 `limits.ts`가 그 값에 적어 둔 취지 —
 * "초과분을 즉시 끊으면 최소한 이미 붙은 세션은 살아남는다" — 가 성립하지 않는다.
 * 새 연결이 전부 거절되므로 **정상 사용자도 접속하지 못한다.**
 *
 * ★키를 프리픽스로 잡는 이유는 `AuthFailureThrottle`과 같다: VPS 하나면 라우팅된 /64를
 * 받는 것이 관행이라, 공격자는 **위조 없이** 매 연결마다 실제 소스 주소를 바꿀 수 있다.
 * 주소 전체를 키로 쓰면 연결마다 새 버킷이 생겨 상한이 한 번도 걸리지 않는다.
 * 정규화는 `throttleKeyOf`가 소유한다 — 갈래마다 다시 만들면 한쪽이 빠진다.
 *
 * ⚠ 인프로세스 상태다(단일 프로세스 배포 전제). 여러 인스턴스면 각자 따로 센다 —
 * 그래서 조립층이 **인스턴스 하나를 만들어 리스너들에 주입**한다. `AuthFailureThrottle`을
 * 그렇게 다루는 것과 같은 이유고, 안 그러면 "IP당 N개" 정책이 리스너 수만큼 곱해진다.
 */
import { throttleKeyOf } from "./auth-throttle.ts";
import { noopLogger, type Logger } from "./log.ts";

/**
 * 한 IP 프리픽스가 리스너 하나에 동시에 붙들 수 있는 연결 수.
 *
 * 값의 근거: 정상 메일 클라이언트는 계정당 IMAP 연결을 몇 개 연다(메일함별 IDLE 때문에
 * 흔히 5~10개고, 한 집·한 사무실에서 여러 사람이 같은 공인 IP를 쓰면 그만큼 곱해진다).
 * 64는 그 현실보다 넉넉하면서, 전역 상한(1024)을 한 주소가 혼자 먹는 것은 막는다.
 * CGNAT 뒤의 큰 출구 IP가 걸릴 수 있으므로 조립층이 조정할 수 있어야 한다.
 */
export const DEFAULT_MAX_CONNECTIONS_PER_PEER = 64;

export interface PeerLimitOptions {
  /** 프리픽스당 동시 연결 수. 기본 `DEFAULT_MAX_CONNECTIONS_PER_PEER`. */
  limit?: number;
  /** 포화 로깅용. 미지정이면 무소음(라이브러리 기본). */
  logger?: Logger;
  /** 거절 관측 훅(메트릭 배선용) — 거절마다 한 번. */
  onReject?: () => void;
}

export class PeerConnectionLimiter {
  private readonly counts = new Map<string, number>();
  private readonly limit: number;
  private readonly log: Logger;
  private readonly onReject: (() => void) | undefined;
  /**
   * 지금 포화 상태로 **이미 로깅한** 프리픽스. 거절마다 찍으면 공격이 곧 로그 폭주가 되고
   * (`AuthFailureThrottle`이 경계에서 한 번만 찍는 것과 같은 이유), 아예 안 찍으면 정상 사용자가
   * 조용히 튕겨도 알 방법이 없다 — 예전엔 거절이 **로그·메트릭 없이** 소켓만 끊었다.
   * 그 프리픽스의 연결이 상한의 절반 아래로 내려오면 지워서 다음 포화 구간을 다시 한 번 찍는다.
   */
  private readonly saturated = new Set<string>();

  /** 숫자만 넘기면 상한이다(단독 사용·테스트용 축약형). */
  constructor(opts: number | PeerLimitOptions = {}) {
    const o: PeerLimitOptions = typeof opts === "number" ? { limit: opts } : opts;
    this.limit = Math.max(1, o.limit ?? DEFAULT_MAX_CONNECTIONS_PER_PEER);
    this.log = (o.logger ?? noopLogger).child({ component: "peer-limit" });
    this.onReject = o.onReject;
  }

  /**
   * 자리를 잡는다. 성공이면 `release`를 **반드시** 부를 것(소켓 `close`에 걸면 된다).
   * 거절이면 카운터를 올리지 않으므로 release도 부르지 말아야 한다.
   */
  tryAcquire(address: string | undefined): boolean {
    const key = throttleKeyOf(address);
    const cur = this.counts.get(key) ?? 0;
    if (cur >= this.limit) {
      this.onReject?.();
      if (!this.saturated.has(key)) {
        this.saturated.add(key);
        this.log.warn("IP 프리픽스 동시 연결 상한 도달 — 새 연결을 거절한다", { subject: key, limit: this.limit });
      }
      return false;
    }
    this.counts.set(key, cur + 1);
    return true;
  }

  release(address: string | undefined): void {
    const key = throttleKeyOf(address);
    const cur = this.counts.get(key);
    if (cur === undefined) return;
    // 0이 되면 **엔트리를 지운다** — 안 지우면 스쳐 간 주소마다 키가 남아 맵이 계속 자란다.
    if (cur <= 1) this.counts.delete(key);
    else this.counts.set(key, cur - 1);
    /**
     * 포화 표시는 **절반 아래로 내려왔을 때** 지운다(히스테리시스). 한 자리 날 때마다 지우면
     * 상한에 붙어 들락거리는 동안 거절마다 다시 찍혀 로그 폭주가 되고, 0까지 기다리면 NAT 뒤에서
     * IDLE 연결 하나가 남은 프리픽스는 몇 시간 뒤 다시 포화돼도 영영 안 찍힌다.
     * counts에서 지워지는 키는 반드시 이 조건을 만족하므로 Set이 counts보다 커지지 않는다.
     */
    if (cur - 1 <= Math.floor(this.limit / 2)) this.saturated.delete(key);
  }

  /** 진단용 — 현재 그 프리픽스가 붙들고 있는 수. */
  countFor(address: string | undefined): number {
    return this.counts.get(throttleKeyOf(address)) ?? 0;
  }

  /** 진단용 — 추적 중인 프리픽스 수(0이면 누수가 없다는 뜻이다). */
  get size(): number {
    return this.counts.size;
  }
}
