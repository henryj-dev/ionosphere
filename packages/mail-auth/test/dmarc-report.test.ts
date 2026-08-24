/**
 * DMARC 집계 리포트 (RFC 7489 §7.2).
 *
 * ★`isRuaAuthorized`가 이 파일의 핵심이다. 이 검사가 없으면 누구나 자기 도메인의 DMARC
 * 레코드에 **피해자 주소**를 `rua`로 적어 두고, 전 세계 수신 서버가 매일 그 주소로 리포트를
 * 보내게 만들 수 있다 — 분산 증폭 공격이다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { buildDmarcReportXml, dmarcReportFilename, isRuaAuthorized, parseRua } from "../src/dmarc-report.ts";
import { DnsNotFoundError, type DnsResolver } from "../src/dns.ts";

function resolver(txts: Record<string, string[]>): DnsResolver {
  return {
    txt: async (name: string) => {
      const v = txts[name.toLowerCase()];
      if (!v) throw new DnsNotFoundError(`no TXT: ${name}`);
      return v;
    },
    mx: async () => [],
    a: async () => [],
    aaaa: async () => [],
    ptr: async () => [],
  };
}

describe("parseRua", () => {
  test("mailto: 목록", () => {
    expect(parseRua("mailto:a@x.test,mailto:b@y.test")).toEqual([
      { email: "a@x.test", maxBytes: null },
      { email: "b@y.test", maxBytes: null },
    ]);
  });

  test("크기 접미사", () => {
    expect(parseRua("mailto:a@x.test!10m")).toEqual([{ email: "a@x.test", maxBytes: 10 * 1024 * 1024 }]);
    expect(parseRua("mailto:a@x.test!512k")[0]!.maxBytes).toBe(512 * 1024);
  });

  /** 지원하지 않는 것을 목록에 남기면 "보냈다고 생각했는데 안 갔다"가 된다. */
  test("mailto가 아닌 스킴은 버린다", () => {
    expect(parseRua("https://x.test/report,mailto:a@x.test")).toEqual([{ email: "a@x.test", maxBytes: null }]);
    expect(parseRua("https://x.test/report")).toEqual([]);
  });

  test("주소 형식이 아니면 버린다", () => {
    expect(parseRua("mailto:nonsense")).toEqual([]);
    expect(parseRua("")).toEqual([]);
  });
});

describe("isRuaAuthorized (RFC 7489 §7.1)", () => {
  /** 같은 도메인이면 확인이 필요 없다 — 자기 리포트를 자기가 받는 것이라 남을 끌어들이지 않는다. */
  test("같은 도메인은 확인 없이 허용", async () => {
    const r = resolver({});
    expect(await isRuaAuthorized("x.test", "dmarc@x.test", r)).toBe(true);
    expect(await isRuaAuthorized("mail.x.test", "dmarc@x.test", r, "x.test")).toBe(true);
  });

  /** ★다른 도메인은 **그 도메인의 동의**가 있어야 한다. 이 한 줄이 증폭 공격을 막는다. */
  test("다른 도메인은 승인 레코드가 있어야 허용", async () => {
    const ok = resolver({ "x.test._report._dmarc.reports.test": ["v=DMARC1"] });
    expect(await isRuaAuthorized("x.test", "agg@reports.test", ok)).toBe(true);

    const missing = resolver({});
    expect(await isRuaAuthorized("x.test", "agg@reports.test", missing)).toBe(false);
  });

  test("승인 레코드가 DMARC1이 아니면 거절", async () => {
    const r = resolver({ "x.test._report._dmarc.reports.test": ["v=spf1 -all"] });
    expect(await isRuaAuthorized("x.test", "agg@reports.test", r)).toBe(false);
  });

  /** ★조회 실패도 **거절**이다. 보안은 fail closed — 하루치를 못 보내는 것이 남을 공격하는 것보다 낫다. */
  test("조회가 터져도 거절한다", async () => {
    const boom: DnsResolver = {
      txt: async () => {
        throw new Error("network down");
      },
      mx: async () => [],
      a: async () => [],
      aaaa: async () => [],
      ptr: async () => [],
    };
    expect(await isRuaAuthorized("x.test", "agg@reports.test", boom)).toBe(false);
  });

  test("주소가 아니면 거절", async () => {
    expect(await isRuaAuthorized("x.test", "nonsense", resolver({}))).toBe(false);
  });
});

describe("buildDmarcReportXml", () => {
  const base = {
    orgName: "mx.ionosphere.test",
    orgEmail: "dmarc@ionosphere.test",
    reportId: "R1",
    beginSec: 1_700_000_000,
    endSec: 1_700_086_399,
    policyDomain: "sender.test",
    policy: { p: "reject", sp: "quarantine", adkim: "s", aspf: "r", pct: 100 },
  };

  test("메타데이터와 정책을 싣는다", () => {
    const xml = buildDmarcReportXml({ ...base, rows: [] });
    expect(xml).toContain("<org_name>mx.ionosphere.test</org_name>");
    expect(xml).toContain("<report_id>R1</report_id>");
    expect(xml).toContain("<begin>1700000000</begin>");
    expect(xml).toContain("<domain>sender.test</domain>");
    expect(xml).toContain("<p>reject</p>");
    expect(xml).toContain("<sp>quarantine</sp>");
    expect(xml).toContain("<adkim>s</adkim>");
  });

  /** ★`policy_evaluated`는 **정렬**, `auth_results`는 인증 결과다 — 섞으면 원인을 못 좁힌다. */
  test("정렬과 인증 결과를 따로 싣는다", () => {
    const xml = buildDmarcReportXml({
      ...base,
      rows: [
        {
          sourceIp: "203.0.113.5",
          count: 3,
          disposition: "reject",
          dkimAligned: false,
          spfAligned: false,
          headerFrom: "sender.test",
          dkimResult: "pass", // 서명은 통과했지만 정렬은 실패 — 흔한 오설정이다
          spfResult: "pass",
          dkimDomain: "other.test",
          spfDomain: "bounce.other.test",
        },
      ],
    });
    expect(xml).toContain("<source_ip>203.0.113.5</source_ip>");
    expect(xml).toContain("<count>3</count>");
    // policy_evaluated: 정렬 실패
    expect(xml).toContain("<disposition>reject</disposition>");
    expect(xml.split("<policy_evaluated>")[1]!.split("</policy_evaluated>")[0]!).toContain("<dkim>fail</dkim>");
    // auth_results: 서명 자체는 pass
    const auth = xml.split("<auth_results>")[1]!.split("</auth_results>")[0]!;
    expect(auth).toContain("<domain>other.test</domain>");
    expect(auth).toContain("<result>pass</result>");
  });

  /**
   * ★`header_from`은 **발신자가 정하는 값**이다. 이스케이프를 빠뜨리면 우리가 만든 리포트가
   * 깨진 XML이 되고, 받는 쪽 파서에 따라서는 그 이상이다.
   */
  test("XML 특수문자를 이스케이프한다", () => {
    const xml = buildDmarcReportXml({
      ...base,
      rows: [
        {
          sourceIp: "203.0.113.5",
          count: 1,
          disposition: "none",
          dkimAligned: true,
          spfAligned: true,
          headerFrom: `evil<&">'`,
          dkimResult: "pass",
          spfResult: "pass",
        },
      ],
    });
    expect(xml).toContain("<header_from>evil&lt;&amp;&quot;&gt;&apos;</header_from>");
    // 원문 그대로 새어 나가지 않았다
    expect(xml.includes('<header_from>evil<')).toBe(false);
  });

  test("XML이 허용하지 않는 제어문자는 뺀다", () => {
    const xml = buildDmarcReportXml({
      ...base,
      rows: [
        {
          sourceIp: "203.0.113.5",
          count: 1,
          disposition: "none",
          dkimAligned: true,
          spfAligned: true,
          headerFrom: `a${String.fromCharCode(0)}b${String.fromCharCode(1)}c`,
          dkimResult: "pass",
          spfResult: "pass",
        },
      ],
    });
    expect(xml).toContain("<header_from>abc</header_from>");
  });

  test("dkimDomain이 없으면 dkim 절을 넣지 않는다", () => {
    const xml = buildDmarcReportXml({
      ...base,
      rows: [
        {
          sourceIp: "203.0.113.5",
          count: 1,
          disposition: "none",
          dkimAligned: false,
          spfAligned: true,
          headerFrom: "sender.test",
          dkimResult: "none",
          spfResult: "pass",
          dkimDomain: null,
        },
      ],
    });
    const auth = xml.split("<auth_results>")[1]!.split("</auth_results>")[0]!;
    expect(auth.includes("<dkim>")).toBe(false);
    expect(auth).toContain("<spf>");
  });
});

describe("파일명 (§7.2.1.1)", () => {
  test("receiver!domain!begin!end.xml.gz", () => {
    expect(dmarcReportFilename("mx.test", "sender.test", 100, 200)).toBe("mx.test!sender.test!100!200.xml.gz");
  });
});
