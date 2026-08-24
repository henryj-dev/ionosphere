/**
 * TLS-RPT 리포트 (RFC 8460) — **만들기**와 **보낼 곳 확인**. 순수 함수, I/O는 주입.
 *
 * ★우리가 MTA-STS를 **강제하면서** 이 리포트를 내지 않는 것은 특히 어긋난 상태였다.
 * 상대 도메인의 정책 설정 실수로 우리 발송이 막히면, 그 사실을 아는 것은 우리뿐이고
 * 고칠 수 있는 것은 상대뿐이다 — 리포트가 그 둘을 잇는 유일한 통로다.
 */

/** 한 정책 도메인에 대한 하루치 집계. */
export interface TlsRptRow {
  policyType: "sts" | "tlsa" | "no-policy-found";
  receivingMx: string;
  /** RFC 8460 §4.3의 result-type. 성공은 관례적으로 이 이름을 쓰지 않고 카운트만 센다. */
  resultType: string;
  count: number;
}

export interface TlsRptInput {
  organizationName: string;
  /** 기간 — ISO 8601 UTC(§4.4의 `start-datetime`/`end-datetime`). */
  startIso: string;
  endIso: string;
  reportId: string;
  contactInfo: string;
  policyDomain: string;
  /** MTA-STS 정책 본문 줄들 — 있으면 `policy-string`으로 싣는다(§4.4). */
  policyStrings?: readonly string[];
  rows: readonly TlsRptRow[];
}

/** 성공 카운트를 나타내는 내부 표식 — 규격의 `failure-details`에는 들어가지 않는다. */
export const TLSRPT_SUCCESS = "successful-session";

/**
 * RFC 8460 §4.4의 JSON 리포트.
 *
 * ★성공과 실패를 **다르게** 싣는다: 성공은 `successful-session-count`(숫자 하나)이고,
 * 실패는 `failure-details`의 항목이다. 성공을 failure-details에 넣으면 상대가 그것을
 * 실패로 세어 자기 정책이 망가진 줄 안다.
 */
export function buildTlsRptJson(input: TlsRptInput): string {
  const byPolicyType = new Map<string, TlsRptRow[]>();
  for (const r of input.rows) {
    const list = byPolicyType.get(r.policyType);
    if (list) list.push(r);
    else byPolicyType.set(r.policyType, [r]);
  }

  const policies = [...byPolicyType.entries()].map(([policyType, rows]) => {
    const success = rows.filter((r) => r.resultType === TLSRPT_SUCCESS).reduce((a, r) => a + r.count, 0);
    const failures = rows.filter((r) => r.resultType !== TLSRPT_SUCCESS);
    return {
      policy: {
        "policy-type": policyType,
        ...(policyType === "sts" && input.policyStrings ? { "policy-string": [...input.policyStrings] } : {}),
        "policy-domain": input.policyDomain,
      },
      summary: {
        "total-successful-session-count": success,
        "total-failure-session-count": failures.reduce((a, r) => a + r.count, 0),
      },
      "failure-details": failures.map((r) => ({
        "result-type": r.resultType,
        "receiving-mx-hostname": r.receivingMx,
        "failed-session-count": r.count,
      })),
    };
  });

  return JSON.stringify(
    {
      "organization-name": input.organizationName,
      "date-range": { "start-datetime": input.startIso, "end-datetime": input.endIso },
      "contact-info": input.contactInfo,
      "report-id": input.reportId,
      policies,
    },
    null,
    2,
  );
}

/**
 * 리포트 파일명 (RFC 8460 §5.1).
 *
 * `sender!policy-domain!begin-unixtime!end-unixtime.json.gz`
 */
export function tlsRptFilename(sender: string, policyDomain: string, beginSec: number, endSec: number): string {
  return `${sender}!${policyDomain}!${Math.floor(beginSec)}!${Math.floor(endSec)}.json.gz`;
}

/** `_smtp._tls.<domain>` TXT의 `rua=` 목적지 — `mailto:`만 다룬다(HTTPS 업로드는 미지원). */
export function parseTlsRptRua(txt: string): string[] {
  /**
   * ★`v=TLSRPTv1`이 없으면 **TLS-RPT 레코드가 아니다.** 같은 이름에 다른 TXT가 있을 수
   * 있으므로 이 확인 없이 `rua=`만 찾으면 엉뚱한 값을 목적지로 쓴다.
   */
  if (!/(^|;)\s*v\s*=\s*TLSRPTv1\s*(;|$)/i.test(txt)) return [];
  const out: string[] = [];
  for (const seg of txt.split(";")) {
    const t = seg.trim();
    if (!/^rua\s*=/i.test(t)) continue;
    for (const uri of t.slice(t.indexOf("=") + 1).split(",")) {
      const u = uri.trim();
      if (!/^mailto:/i.test(u)) continue; // https:는 우리가 보내지 않는다
      const email = u.slice("mailto:".length).trim().toLowerCase();
      if (email.includes("@")) out.push(email);
    }
  }
  return out;
}
