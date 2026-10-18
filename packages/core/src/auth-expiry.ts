/**
 * 연결의 자격증명 만료 — 만료 시각에 연결을 닫는 타이머(2026-10-18 회원 정책 E4, 사용자 결정 "토큰 만료에 연결 끊기").
 *
 * ★"다음 명령에서 확인"만으로는 부족하다. IDLE처럼 명령 없이 열려 있는 연결은 그 확인 지점에 닿지 않아, 토큰이 만료돼도
 * 끝없이 열려 있을 수 있다. 그래서 인증할 때 만료 시각에 맞춰 닫는 타이머를 건다. 다음 명령 확인은 이중 안전장치로 남는다.
 *
 * 만료가 없는 자격증명(비밀번호·앱 비밀번호)에는 걸지 않는다. 타이머는 연결이 닫히면 지운다(누수 없음), unref라 종료를 막지 않는다.
 */
/** 너무 먼 만료는 setTimeout 상한(약 24.8일)을 넘는다 — 그 안에서만 건다(토큰 수명 상한이 훨씬 짧다). */
const MAX_TIMER_MS = 2 ** 31 - 1;

/** 소켓에서 쓰는 것만 — 닫혔는가, 닫힐 때 알림. */
export interface ExpiringConnection {
  readonly destroyed: boolean;
  once(event: "close", listener: () => void): unknown;
}

export function armAuthExpiry(socket: ExpiringConnection, expiresAt: number | undefined | null, onExpire: () => void): void {
  if (expiresAt === undefined || expiresAt === null) return;
  const delay = Math.min(Math.max(0, expiresAt - Date.now()), MAX_TIMER_MS);
  const timer = setTimeout(() => {
    if (!socket.destroyed) onExpire();
  }, delay);
  timer.unref?.();
  socket.once("close", () => clearTimeout(timer));
}
