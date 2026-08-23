/**
 * SPF/DMARC가 공유하는 DNS 리졸버 계약. 순수 패키지 원칙에 따라 이 패키지는 node:dns를
 * 직접 import하지 않는다 — 호출자가 실제 리졸버 구현을 주입한다 (dkimVerify의 resolveTxt와
 * 동일한 패턴을 다중 레코드 타입으로 확장).
 *
 * 조회 실패 규약: 리졸버 구현은 실패를 **두 가지 예외 타입**으로 구분해 던져야 한다.
 * - DnsNotFoundError: NXDOMAIN 또는 "성공했지만 레코드 0건"(빈 응답) — 영구적으로 없음.
 * - DnsTemporaryError: SERVFAIL, 타임아웃, 네트워크 오류 등 일시적 실패 — 재시도하면 달라질 수 있음.
 * 이 둘을 던지지 않고 그냥 빈 배열을 반환해도 SPF/DMARC 쪽은 "없음"으로 해석하지만,
 * temperror를 정확히 판정하려면 리졸버가 반드시 DnsTemporaryError를 구분해 던져야 한다.
 */

export class DnsNotFoundError extends Error {
  constructor(message = "DNS: NXDOMAIN 또는 빈 응답") {
    super(message);
    this.name = "DnsNotFoundError";
  }
}

export class DnsTemporaryError extends Error {
  constructor(message = "DNS: 일시적 오류(SERVFAIL/timeout)") {
    super(message);
    this.name = "DnsTemporaryError";
  }
}

export interface DnsMxRecord {
  exchange: string;
  preference: number;
}

export interface DnsResolver {
  /** 각 레코드 = 조각(TXT chunk) 이어붙인 문자열. 성공 시 배열은 비어있지 않다. */
  txt(name: string): Promise<string[]>;
  mx(name: string): Promise<DnsMxRecord[]>;
  /** IPv4 A 레코드 (점 표기). */
  a(name: string): Promise<string[]>;
  /** IPv6 AAAA 레코드 (콜론 표기). */
  aaaa(name: string): Promise<string[]>;
  /** 역방향(PTR) 조회. 인자는 프레젠테이션 형식 IP 문자열. */
  ptr(ip: string): Promise<string[]>;
}
