/**
 * SMTP STARTTLS(25/587) 가용성 판정 — **런타임이 서버측 TLS 업그레이드를 지원할 때만** 켠다.
 *
 * 왜 판정이 필요한가: STARTTLS를 광고해놓고 업그레이드가 실패하면 **광고하지 않는 것보다 나쁘다**.
 * 발신 MTA는 220을 받고 핸드셰이크를 시작했다가 그대로 멈추고, 그 메일은 지연·바운스된다.
 * 즉 잘못 켜면 수신이 깨진다.
 *
 * 런타임 사실(실측):
 *  - node: 동작 (외부 openssl 클라이언트로 TLSv1.3 성립)
 *  - bun < 1.4.0: **실패** — 220까지 응답하고 핸드셰이크가 완료되지 않는다(oven-sh/bun#25044).
 *  - bun >= 1.4.0: 동작 — PR oven-sh/bun#29932(2026-04-30 머지)이 소켓 컨텍스트를 재설계하며
 *    node:tls 서버측 TLSSocket까지 지원. 1.4.0-canary.1에서 외부 클라이언트로 TLSv1.3 확인.
 *
 * MTA-STS를 enforce로 올리려면 25번 STARTTLS가 전제이므로, 이 판정이 곧 enforce 가능 여부다.
 */

/** bun이 서버측 STARTTLS 업그레이드를 지원하기 시작한 최소 버전. */
const BUN_STARTTLS_MIN = [1, 4, 0] as const;

/** "1.4.0-canary.1" → [1,4,0]. 파싱 실패 시 null. */
function parseVersion(v: string): [number, number, number] | null {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(v);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function gte(a: readonly [number, number, number], b: readonly [number, number, number]): boolean {
  for (let i = 0; i < 3; i++) {
    if (a[i]! > b[i]!) return true;
    if (a[i]! < b[i]!) return false;
  }
  return true;
}

export interface StartTlsSupport {
  supported: boolean;
  /** 사람이 읽을 판정 근거(로그용). */
  reason: string;
}

/**
 * 주어진 런타임이 SMTP STARTTLS(서버측 업그레이드)를 지원하는가 — 순수 함수.
 * `null`이면 bun이 아님(=node). 기본 파라미터를 쓰지 않아 테스트가 "node"를 명시할 수 있다.
 */
export function startTlsSupportFor(bunVersion: string | null): StartTlsSupport {
  if (bunVersion === null) return { supported: true, reason: "node — 서버측 TLS 업그레이드 지원" };
  const v = parseVersion(bunVersion);
  if (v === null) return { supported: false, reason: `bun 버전 파싱 실패(${bunVersion}) — 안전하게 비활성` };
  if (gte(v, BUN_STARTTLS_MIN)) return { supported: true, reason: `bun ${bunVersion} — 1.4.0+ 지원(oven-sh/bun#29932)` };
  return {
    supported: false,
    reason: `bun ${bunVersion}는 서버측 STARTTLS 미지원(oven-sh/bun#25044) — 광고 시 핸드셰이크가 멈춰 수신이 깨진다. bun 1.4.0+ 또는 node 필요`,
  };
}

/** 현재 실행 중인 런타임 기준 판정. */
export function startTlsSupport(): StartTlsSupport {
  return startTlsSupportFor(process.versions.bun ?? null);
}
