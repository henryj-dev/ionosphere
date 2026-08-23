/**
 * "이 cert/key를 리스너에 실제로 걸어도 되는가" 판정의 정본 — url·acme·sealed 소스 공용.
 *
 * 왜 한 곳으로 모았나: 소스마다 검사 강도가 갈라져 있었다. sealed는 페어링까지 봤지만
 * url은 파싱만 했고(호스트명·페어링 검사 없음), acme는 발급분을 **파싱조차 없이** 덮어썼다
 * (2026-07-30 감사 H-1). 검사가 소스마다 다르면 가장 약한 소스가 곧 시스템 전체의 강도다.
 */
import { X509Certificate } from "node:crypto";
import { createSecureContext } from "node:tls";

function reason(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * cert/key가 ① 파싱되고 ② 서로 **쌍**이며 ③ `expectedHosts` 중 하나에 유효한지 확인. 실패는 throw.
 *
 * 호출자는 **디스크에 쓰거나 리스너에 걸기 전에** 부른다. 검증 전에 캐시부터 쓰면 한 번 오염된
 * 인증서가 폴백 경로까지 영구히 오염시킨다(감사 H-1 "포이즈닝 영속성").
 *
 * 페어링을 node:tls 리슨 시점까지 미루면 안 되는 이유: 그 시점의 실패는 이미 **모든 TLS 리스너를
 * 한꺼번에 망가뜨린 뒤**이고, 되돌릴 수단(관리 콘솔)도 그 리스너 뒤에 있다.
 *
 * 호스트 대조는 `X509Certificate.checkHost`(RFC 6125 — SAN 우선, 와일드카드는 최좌측 라벨만)를 쓴다.
 * 직접 문자열 비교를 하면 와일드카드·CN 폴백에서 어긋난다.
 */
export function assertUsableCert(label: string, cert: string | Buffer, key: string | Buffer, expectedHosts?: readonly string[]): void {
  let x: X509Certificate;
  try {
    x = new X509Certificate(cert);
  } catch (err) {
    throw new Error(`${label}: 인증서 파싱 실패(PEM 확인) — ${reason(err)}`);
  }
  try {
    createSecureContext({ cert, key });
  } catch (err) {
    throw new Error(`${label}: 키/인증서 쌍이 맞지 않는다 — ${reason(err)}`);
  }
  if (expectedHosts && expectedHosts.length > 0 && !expectedHosts.some((h) => x.checkHost(h) !== undefined)) {
    throw new Error(
      `${label}: 인증서가 기대 호스트에 유효하지 않다 — 기대=${expectedHosts.join(",")} / subject=${x.subject} / SAN=${x.subjectAltName ?? "(없음)"}`,
    );
  }
}
