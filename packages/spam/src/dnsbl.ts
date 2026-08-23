/**
 * DNSBL/RBL 조회 (RFC 5782, PROTOCOLS.md §7.1): IP를 역순으로 존 이름에 붙여 A 레코드를
 * 조회한다. `127.0.0.x` 응답이면 등재(listed) — x는 등재 사유 코드. 등재된 존들의 weight를
 * 합산해 score를 낸다. DNSWL(화이트리스트) 존은 음수 weight로 표현해 score를 낮추는 용도로도
 * 쓸 수 있다(호출자가 zones 배열에 negative-weight 항목을 섞어 넣으면 됨 — 이 모듈은 부호를
 * 그대로 합산할 뿐 특별 취급하지 않는다).
 *
 * ⚠️ CRITICAL — 프로덕션 전제조건 (PROTOCOLS.md §7.1 필독):
 * Spamhaus 등 주요 DNSBL은 **Google(8.8.8.8)/Cloudflare(1.1.1.1) 같은 퍼블릭 리졸버를 경유한
 * 조회를 차단**한다. 차단되면 응답이 조용히 "미등재"로만 나오므로(예외를 던지지 않음 —
 * DnsNotFoundError로 정상 응답과 구분이 안 됨) 겉보기엔 정상 작동하는 것처럼 보이지만
 * 실제로는 아무것도 걸러내지 못하는 "조용한 무력화" 상태가 된다. 이 모듈에 주입하는
 * DnsResolver는 **반드시 자체 재귀 리졸버**(예: unbound)를 거치거나 상용 DNSBL 데이터
 * 피드 계약을 사용해야 한다 — 이 계약은 코드로 강제할 수 없으므로 운영자가 배선 시점에
 * 책임져야 한다. 무료 티어는 쿼리량 한도도 있다(Spamhaus 공개 미러 기준 ~30만/일).
 *
 * IPv6는 니블(4비트) 단위로 역순 표기한다(RFC 5782 §2.4) — 이 모듈은 기본적인 확장/역순
 * 변환만 제공하고(`::` 압축 해제 포함) 그 이상의 정교화는 하지 않는다.
 */
import { DnsNotFoundError, DnsTemporaryError, type DnsResolver } from "@ionosphere/mail-auth";

export interface DnsblZone {
  zone: string;
  /** 등재 시 합산할 가중치. DNSWL(화이트리스트) 존은 음수로 지정해 score를 낮춘다. 기본 1. */
  weight?: number;
}

export interface DnsblHit {
  zone: string;
  /** 127.0.0.x 응답의 마지막 옥텟들(사유 코드) — 다중 A 레코드면 여러 개일 수 있다. */
  codes: string[];
  weight: number;
}

export interface DnsblResult {
  listed: boolean;
  hits: DnsblHit[];
  score: number;
}

export interface DnsblOptions {
  /** 존별 조회 중 DnsTemporaryError가 나면 그 존만 건너뛰고 나머지는 계속 평가(§7.1). */
  onSkip?: (zone: string, err: unknown) => void;
}

/** IPv4 옥텟 4개를 역순으로 뒤집는다: "1.2.3.4" → "4.3.2.1". */
function reverseIpv4(ip: string): string | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
  }
  return parts.reverse().join(".");
}

/**
 * IPv6를 32자리 니블로 완전히 확장한 뒤(`::` 압축 해제 포함) 역순으로 점 구분 표기한다
 * (RFC 5782 §2.4). 예: "2001:db8::1" → 마지막 니블부터 "1.0.0.0...8.b.d.0.1.0.0.2".
 */
function reverseIpv6(ip: string): string | null {
  if (!ip.includes(":")) return null;
  const halves = ip.split("::");
  if (halves.length > 2) return null;

  let groups: string[];
  if (halves.length === 1) {
    groups = halves[0]!.split(":");
    if (groups.length !== 8) return null;
  } else {
    const head = halves[0] === "" ? [] : halves[0]!.split(":");
    const tail = halves[1] === "" ? [] : halves[1]!.split(":");
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = [...head, ...Array(missing).fill("0"), ...tail];
  }
  if (groups.length !== 8) return null;

  const nibbles: string[] = [];
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{0,4}$/.test(g)) return null;
    const hex = g.padStart(4, "0").toLowerCase();
    nibbles.push(...hex.split(""));
  }
  return nibbles.reverse().join(".");
}

/** DNSBL 질의용 역순 이름의 도메인 부분(존 이름 제외)을 만든다. IPv4/IPv6 자동 판별. */
function reverseName(ip: string): string | null {
  return ip.includes(":") ? reverseIpv6(ip) : reverseIpv4(ip);
}

/** "127.0.0.2" → "2" (등재 사유 코드 — 마지막 옥텟). 127.0.0.0/8 범위가 아니면 null. */
function extractCode(aRecord: string): string | null {
  const parts = aRecord.split(".");
  if (parts.length !== 4 || parts[0] !== "127" || parts[1] !== "0") return null;
  return parts[3] ?? null;
}

export async function checkDnsbl(
  ip: string,
  zones: readonly DnsblZone[],
  resolver: DnsResolver,
  opts?: DnsblOptions,
): Promise<DnsblResult> {
  const reversed = reverseName(ip);
  if (!reversed) {
    // 파싱 불가능한 IP — 등재 여부를 판정할 수 없으므로 안전하게 미등재로 취급.
    return { listed: false, hits: [], score: 0 };
  }

  const hits: DnsblHit[] = [];
  let score = 0;

  for (const { zone, weight = 1 } of zones) {
    const name = `${reversed}.${zone}`;
    let answers: string[];
    try {
      answers = await resolver.a(name);
    } catch (err) {
      if (err instanceof DnsNotFoundError) {
        continue; // 정상 — 이 존에는 미등재.
      }
      if (err instanceof DnsTemporaryError) {
        opts?.onSkip?.(zone, err); // 일시 오류 — 이 존만 건너뛰고 나머지는 계속.
        continue;
      }
      throw err;
    }

    const codes = answers.map(extractCode).filter((c): c is string => c !== null);
    if (codes.length === 0) continue;

    hits.push({ zone, codes, weight });
    score += weight;
  }

  // DNSWL(음수 weight) 단독 히트는 "화이트리스트에 있음"이지 "블랙리스트 등재"가 아니므로
  // listed 판정에서 제외한다 — score에는 반영되지만 listed는 양수 weight 히트가 있어야 true.
  const listed = hits.some((h) => h.weight > 0);
  return { listed, hits, score };
}
