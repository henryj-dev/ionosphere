/**
 * TLS-RPT 리포트 (RFC 8460).
 *
 * ★우리가 MTA-STS를 **강제하면서** 이 리포트를 내지 않는 것은 특히 어긋난 상태였다.
 * 상대 도메인의 정책 설정 실수로 우리 발송이 막히면, 그 사실을 아는 것은 우리뿐이고
 * 고칠 수 있는 것은 상대뿐이다 — 리포트가 그 둘을 잇는 유일한 통로다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { buildTlsRptJson, parseTlsRptRua, tlsRptFilename, TLSRPT_SUCCESS } from "../src/tlsrpt-report.ts";

const base = {
  organizationName: "mx.ionosphere.test",
  startIso: "2026-08-23T00:00:00.000Z",
  endIso: "2026-08-23T23:59:59.999Z",
  reportId: "2026-08-23.peer.test@mx.ionosphere.test",
  contactInfo: "tlsrpt@ionosphere.test",
  policyDomain: "peer.test",
};

describe("parseTlsRptRua", () => {
  test("mailto 목적지", () => {
    expect(parseTlsRptRua("v=TLSRPTv1; rua=mailto:reports@peer.test")).toEqual(["reports@peer.test"]);
    expect(parseTlsRptRua("v=TLSRPTv1; rua=mailto:a@peer.test,mailto:b@peer.test")).toEqual(["a@peer.test", "b@peer.test"]);
  });

  /**
   * ★`v=TLSRPTv1`이 없으면 TLS-RPT 레코드가 **아니다**. 같은 이름에 다른 TXT가 있을 수
   * 있으므로 이 확인 없이 `rua=`만 찾으면 엉뚱한 값을 목적지로 쓴다.
   */
  test("버전 태그가 없으면 무시한다", () => {
    expect(parseTlsRptRua("rua=mailto:reports@peer.test")).toEqual([]);
    expect(parseTlsRptRua("v=spf1 -all")).toEqual([]);
  });

  test("https 업로드는 지원하지 않으므로 버린다", () => {
    expect(parseTlsRptRua("v=TLSRPTv1; rua=https://peer.test/tlsrpt")).toEqual([]);
    expect(parseTlsRptRua("v=TLSRPTv1; rua=https://peer.test/x,mailto:a@peer.test")).toEqual(["a@peer.test"]);
  });
});

describe("buildTlsRptJson", () => {
  /** ★성공과 실패를 **다르게** 싣는다 — 성공을 failure-details에 넣으면 상대가 실패로 센다. */
  test("성공은 카운트로, 실패는 failure-details로", () => {
    const json = JSON.parse(
      buildTlsRptJson({
        ...base,
        rows: [
          { policyType: "sts", receivingMx: "mx1.peer.test", resultType: TLSRPT_SUCCESS, count: 42 },
          { policyType: "sts", receivingMx: "mx2.peer.test", resultType: "starttls-not-supported", count: 3 },
        ],
      }),
    ) as {
      policies: { summary: Record<string, number>; "failure-details": { "result-type": string; "failed-session-count": number }[] }[];
    };
    const p = json.policies[0]!;
    expect(p.summary["total-successful-session-count"]).toBe(42);
    expect(p.summary["total-failure-session-count"]).toBe(3);
    expect(p["failure-details"]).toHaveLength(1);
    expect(p["failure-details"][0]!["result-type"]).toBe("starttls-not-supported");
    expect(p["failure-details"][0]!["failed-session-count"]).toBe(3);
  });

  test("정책 종류별로 묶는다", () => {
    const json = JSON.parse(
      buildTlsRptJson({
        ...base,
        rows: [
          { policyType: "sts", receivingMx: "mx1.peer.test", resultType: TLSRPT_SUCCESS, count: 1 },
          { policyType: "tlsa", receivingMx: "mx1.peer.test", resultType: "dane-required", count: 2 },
        ],
      }),
    ) as { policies: { policy: Record<string, unknown> }[] };
    expect(json.policies).toHaveLength(2);
    expect(json.policies.map((p) => p.policy["policy-type"]).sort()).toEqual(["sts", "tlsa"]);
  });

  test("메타데이터를 싣는다", () => {
    const json = JSON.parse(buildTlsRptJson({ ...base, rows: [] })) as Record<string, unknown>;
    expect(json["organization-name"]).toBe("mx.ionosphere.test");
    expect(json["report-id"]).toBe(base.reportId);
    expect(json["contact-info"]).toBe("tlsrpt@ionosphere.test");
    expect((json["date-range"] as Record<string, string>)["start-datetime"]).toBe(base.startIso);
  });

  test("MTA-STS 정책 본문이 있으면 policy-string으로", () => {
    const json = JSON.parse(
      buildTlsRptJson({
        ...base,
        policyStrings: ["version: STSv1", "mode: enforce", "mx: mx1.peer.test", "max_age: 604800"],
        rows: [{ policyType: "sts", receivingMx: "mx1.peer.test", resultType: TLSRPT_SUCCESS, count: 1 }],
      }),
    ) as { policies: { policy: { "policy-string"?: string[] } }[] };
    expect(json.policies[0]!.policy["policy-string"]).toContain("mode: enforce");
  });

  /** 정책이 sts가 아니면 policy-string이 없다 — 없는 정책 본문을 지어내지 않는다. */
  test("sts가 아니면 policy-string이 없다", () => {
    const json = JSON.parse(
      buildTlsRptJson({
        ...base,
        policyStrings: ["version: STSv1"],
        rows: [{ policyType: "no-policy-found", receivingMx: "mx1.peer.test", resultType: TLSRPT_SUCCESS, count: 1 }],
      }),
    ) as { policies: { policy: { "policy-string"?: string[] } }[] };
    expect(json.policies[0]!.policy["policy-string"]).toBe(undefined);
  });
});

describe("파일명 (§5.1)", () => {
  test("sender!domain!begin!end.json.gz", () => {
    expect(tlsRptFilename("mx.test", "peer.test", 100, 200)).toBe("mx.test!peer.test!100!200.json.gz");
  });
});
