/**
 * MTA-STS 발신측 정책 조회·강제 평가 — I/O는 주입(테스트 가능). RFC 8461 §3.
 *
 * 절차: `_mta-sts.<domain>` TXT 조회(있으면 정책 id) → https://mta-sts.<domain>/.well-known/
 * mta-sts.txt 페치 → 파싱. 캐싱은 호출자 몫(정책 id/max_age로 무효화).
 */
import { parseMtaStsPolicy, parseMtaStsTxt, type MtaStsMode, type MtaStsPolicy } from "./policy.ts";

export interface MtaStsFetchDeps {
  /** DNS TXT 조회 — 각 레코드 문자열 목록. 없으면 빈 배열/throw 모두 허용(감싼다). */
  resolveTxt: (name: string) => Promise<string[]>;
  /** HTTPS GET — mta-sts.<domain>/.well-known/mta-sts.txt 본문. 실패 시 throw. */
  httpsGet: (url: string) => Promise<string>;
}

export interface MtaStsLookup {
  /** 정책 존재·유효 여부. */
  found: boolean;
  policyId?: string;
  policy?: MtaStsPolicy;
}

/** 수신 도메인의 MTA-STS 정책 조회. 없거나 오류면 found:false(발신은 계속 — 정책 부재는 정상). */
export async function fetchMtaStsPolicy(domain: string, deps: MtaStsFetchDeps): Promise<MtaStsLookup> {
  let txts: string[];
  try {
    txts = await deps.resolveTxt(`_mta-sts.${domain}`);
  } catch {
    return { found: false };
  }
  let policyId: string | null = null;
  for (const t of txts) {
    const rec = parseMtaStsTxt(t);
    if (rec) {
      policyId = rec.id;
      break;
    }
  }
  if (!policyId) return { found: false };

  let body: string;
  try {
    body = await deps.httpsGet(`https://mta-sts.${domain}/.well-known/mta-sts.txt`);
  } catch {
    // TXT는 있으나 정책 페치 실패 — 정책 있음으로 보되 본문 없음(강제 불가)
    return { found: true, policyId };
  }
  const policy = parseMtaStsPolicy(body);
  return policy ? { found: true, policyId, policy } : { found: true, policyId };
}

export type StsEnforcement =
  | { action: "require-tls"; reason: "enforce" } // TLS 필수 + MX 일치 필수
  | { action: "report-only"; reason: "testing" } // 실패해도 배달, 관측만
  | { action: "none"; reason: "no-policy" | "mode-none" };

/**
 * 조회 결과 → 강제 동작. enforce면 TLS·MX일치 필수, testing이면 관측만, 그 외 none.
 * MX 일치 판정은 호출자가 mxMatchesPolicy로 수행(여기선 모드만 해석).
 */
export function stsEnforcement(lookup: MtaStsLookup): StsEnforcement {
  if (!lookup.found || !lookup.policy) return { action: "none", reason: "no-policy" };
  const mode: MtaStsMode = lookup.policy.mode;
  if (mode === "enforce") return { action: "require-tls", reason: "enforce" };
  if (mode === "testing") return { action: "report-only", reason: "testing" };
  return { action: "none", reason: "mode-none" };
}
