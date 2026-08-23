/**
 * RFC 9989 DMARC(DMARCbis) 평가. RFC 7489는 폐기됨 — 이 구현은 Public Suffix List(PSL)를
 * 전혀 사용하지 않고, "DNS Tree Walk"로 조직 도메인(Organizational Domain)을 찾는다
 * (RFC 9989 §4.6/§4.8 — psd= 태그로 레지스트리/서픽스 경계를 DNS에서 직접 신호받는다).
 * 순수 함수 — DNS 조회는 주입받은 DnsResolver로만 수행한다.
 *
 * RFC 모호점 해석(report에도 기재):
 * - psd= 신호가 전혀 없는 도메인(2026년 현재 절대다수)에 대해서는 고전적 "PSL 없는" 기본값인
 *   "마지막 2라벨"을 조직 도메인으로 채택한다 — 단일 라벨 TLD(gTLD/ccTLD 대부분)를 암묵적
 *   공용 서픽스로 가정하는 실용적 폴백이며, 라벨 하나짜리 경계보다 상위(예: co.uk류)로 올라가야
 *   하는 경우만 psd=y 신호가 실제로 그 경계를 정정한다.
 * - psd=y 경계 발견 시 조직 도메인 = 그 경계 바로 아래(더 구체적인) 레벨.
 * - _dmarc TXT가 존재하지만 v=DMARC1 아니거나 파싱 불가·2개 이상(모호)인 레벨은 "레코드 없음"과
 *   동일하게 취급하고 walk를 계속한다(RFC 7489 §6.6.3의 "discard and act as though absent" 관용을
 *   DMARCbis도 유지한다고 가정) — permerror로 즉시 중단하지 않는다.
 * - pct= 태그는 RFC 9989에서 제거됐으므로 파싱하되 무시한다(과제 명세의 "accept-and-ignore").
 * - np=는 fromDomain이 조직 도메인의 서브도메인이고 sp=가 없을 때 sp= 대체로 사용한다(실제
 *   "도메인 미존재" 판정은 이 패키지 범위 밖 — DmarcInput에 존재 여부 입력이 없음).
 */
import { DnsNotFoundError, DnsTemporaryError, type DnsResolver } from "./dns.ts";
import type { SpfResultValue } from "./spf.ts";

export type DmarcDisposition = "none" | "quarantine" | "reject";

export interface DmarcInput {
  /** From: 헤더 도메인(파싱은 호출자 책임). */
  fromDomain: string;
  /** MAIL FROM 도메인의 SPF 판정. */
  spf: { result: SpfResultValue; domain: string };
  /** 검증된 DKIM 서명들(d= 목록 포함) — pass가 아닌 것도 섞여 들어올 수 있으며 내부에서 필터링한다. */
  dkim: { result: "pass" | "fail" | "permerror" | "temperror"; domain: string }[];
}

export interface DmarcResult {
  result: "pass" | "fail" | "temperror" | "permerror" | "none";
  disposition: DmarcDisposition;
  /** 실제 적용된 정책 태그 값(p 또는 sp/np로 대체된 값). 정책을 찾지 못했으면 없음. */
  policy?: string;
  alignment: { spf: boolean; dkim: boolean };
}

class DmarcEvalError extends Error {
  kind: "permerror" | "temperror";
  constructor(kind: "permerror" | "temperror", message: string) {
    super(message);
    this.kind = kind;
    this.name = "DmarcEvalError";
  }
}

function describeErr(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function normalizeDomain(d: string): string {
  return d.trim().toLowerCase().replace(/\.$/, "");
}

// ---------------------------------------------------------------------------
// DMARC 레코드 조회/파싱
// ---------------------------------------------------------------------------

function parseDmarcTagMap(text: string): Map<string, string> | null {
  const map = new Map<string, string>();
  for (const seg of text.split(";")) {
    const trimmed = seg.trim();
    if (trimmed === "") continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) return null;
    const name = trimmed.slice(0, eq).trim().toLowerCase();
    if (!name) return null;
    const value = trimmed.slice(eq + 1).trim();
    if (!map.has(name)) map.set(name, value); // 중복 태그는 첫 값 채택
  }
  return map;
}

/**
 * `_dmarc.<domain>` TXT를 조회해 태그 맵을 반환한다.
 * NXDOMAIN/빈 응답/비-DMARC/모호(2개 이상)/파싱 불가 → null("이 레벨엔 없음"과 동일 취급).
 * DNS 일시 오류만 예외로 던진다(temperror로 상위에 전파).
 */
async function fetchDmarcTags(domain: string, resolver: DnsResolver): Promise<Map<string, string> | null> {
  let txts: string[];
  try {
    txts = await resolver.txt(`_dmarc.${domain}`);
  } catch (err) {
    if (err instanceof DnsNotFoundError) return null;
    if (err instanceof DnsTemporaryError) {
      throw new DmarcEvalError("temperror", `_dmarc.${domain} 조회 실패: ${describeErr(err)}`);
    }
    throw new DmarcEvalError("temperror", `_dmarc.${domain} 조회 실패: ${describeErr(err)}`);
  }
  if (txts.length === 0) return null;
  const dmarcTxts = txts.filter((t) => /^\s*v\s*=\s*DMARC1\s*(;|$)/i.test(t));
  if (dmarcTxts.length !== 1) return null; // 0개 또는 2개 이상 → 이 레벨은 "없음"과 동일
  const tags = parseDmarcTagMap(dmarcTxts[0]!);
  if (!tags || tags.get("v") !== "DMARC1") return null;
  return tags;
}

function isUsablePolicy(tags: Map<string, string>): boolean {
  const p = tags.get("p")?.toLowerCase();
  return p === "none" || p === "quarantine" || p === "reject";
}

const WALK_MAX_STEPS = 10; // SPF의 10-lookup 한도와 동일한 취지의 방어적 상한

/**
 * RFC 9989 DNS Tree Walk로 조직 도메인을 찾는다(정렬 판정·정책탐색 공용).
 * psd=y를 만나면 그 바로 아래 레벨을 조직 도메인으로 확정한다. 끝까지 못 찾으면
 * "마지막 2라벨"을 기본값으로 사용한다(§4.6 폴백 해석 — 위 파일 docblock 참고).
 */
async function computeOrgDomain(domain: string, resolver: DnsResolver): Promise<string> {
  const labels = domain.split(".");
  if (labels.length <= 2) return domain;
  const defaultOrg = labels.slice(-2).join(".");
  const maxSteps = Math.min(labels.length - 1, WALK_MAX_STEPS);
  for (let i = 1; i <= maxSteps; i++) {
    const candidate = labels.slice(i).join(".");
    const tags = await fetchDmarcTags(candidate, resolver);
    if (tags?.get("psd")?.toLowerCase() === "y") {
      return labels.slice(i - 1).join(".");
    }
  }
  return defaultOrg;
}

interface PolicyDiscovery {
  tags: Map<string, string>;
  orgDomain: string;
}

/** 1) 정확한 fromDomain의 정책을 먼저 찾고, 없으면 2) tree walk로 찾은 조직 도메인의 정책을 찾는다. */
async function discoverPolicy(fromDomain: string, resolver: DnsResolver): Promise<PolicyDiscovery | null> {
  const exact = await fetchDmarcTags(fromDomain, resolver);
  if (exact && isUsablePolicy(exact)) return { tags: exact, orgDomain: fromDomain };

  const orgDomain = await computeOrgDomain(fromDomain, resolver);
  if (orgDomain === fromDomain) return null; // 이미 조직 도메인 자체 — 더 볼 곳 없음

  const orgTags = await fetchDmarcTags(orgDomain, resolver);
  if (orgTags && isUsablePolicy(orgTags)) return { tags: orgTags, orgDomain };

  return null;
}

// ---------------------------------------------------------------------------
// 정렬(Alignment) 판정
// ---------------------------------------------------------------------------

async function isDkimAligned(
  dkimResults: DmarcInput["dkim"],
  fromDomain: string,
  mode: "strict" | "relaxed",
  resolver: DnsResolver,
): Promise<boolean> {
  for (const d of dkimResults) {
    if (d.result !== "pass") continue;
    const dDomain = normalizeDomain(d.domain);
    if (mode === "strict") {
      if (dDomain === fromDomain) return true;
      continue;
    }
    const [orgD, orgFrom] = await Promise.all([computeOrgDomain(dDomain, resolver), computeOrgDomain(fromDomain, resolver)]);
    if (orgD === orgFrom) return true;
  }
  return false;
}

async function isSpfAligned(
  spf: DmarcInput["spf"],
  fromDomain: string,
  mode: "strict" | "relaxed",
  resolver: DnsResolver,
): Promise<boolean> {
  if (spf.result !== "pass") return false;
  const spfDomain = normalizeDomain(spf.domain);
  if (mode === "strict") return spfDomain === fromDomain;
  const [orgSpf, orgFrom] = await Promise.all([computeOrgDomain(spfDomain, resolver), computeOrgDomain(fromDomain, resolver)]);
  return orgSpf === orgFrom;
}

// ---------------------------------------------------------------------------
// 공개 API
// ---------------------------------------------------------------------------

export async function checkDmarc(input: DmarcInput, resolver: DnsResolver): Promise<DmarcResult> {
  const fromDomain = normalizeDomain(input.fromDomain);
  if (!fromDomain) {
    return { result: "permerror", disposition: "none", alignment: { spf: false, dkim: false } };
  }

  try {
    const discovery = await discoverPolicy(fromDomain, resolver);
    if (!discovery) {
      return { result: "none", disposition: "none", alignment: { spf: false, dkim: false } };
    }
    const { tags, orgDomain } = discovery;

    const p = tags.get("p")!.toLowerCase() as DmarcDisposition; // isUsablePolicy가 이미 검증
    const spTag = tags.get("sp")?.toLowerCase();
    const npTag = tags.get("np")?.toLowerCase();
    const isValidDisposition = (v: string | undefined): v is DmarcDisposition =>
      v === "none" || v === "quarantine" || v === "reject";

    const isSubdomain = fromDomain !== orgDomain;
    let policyTag: DmarcDisposition;
    if (!isSubdomain) {
      policyTag = p;
    } else if (isValidDisposition(spTag)) {
      policyTag = spTag;
    } else if (isValidDisposition(npTag)) {
      policyTag = npTag;
    } else {
      policyTag = p;
    }

    const adkim = tags.get("adkim")?.trim().toLowerCase() === "s" ? "strict" : "relaxed";
    const aspf = tags.get("aspf")?.trim().toLowerCase() === "s" ? "strict" : "relaxed";

    const [dkimAligned, spfAligned] = await Promise.all([
      isDkimAligned(input.dkim, fromDomain, adkim, resolver),
      isSpfAligned(input.spf, fromDomain, aspf, resolver),
    ]);

    const passed = dkimAligned || spfAligned;
    return {
      result: passed ? "pass" : "fail",
      disposition: passed ? "none" : policyTag,
      policy: policyTag,
      alignment: { spf: spfAligned, dkim: dkimAligned },
    };
  } catch (err) {
    if (err instanceof DmarcEvalError) {
      return { result: err.kind, disposition: "none", alignment: { spf: false, dkim: false } };
    }
    return { result: "temperror", disposition: "none", alignment: { spf: false, dkim: false } };
  }
}
