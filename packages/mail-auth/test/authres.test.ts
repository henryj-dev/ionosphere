import { describe, expect, test } from "@ionosphere/testkit";
import { buildAuthenticationResults, mapToStorageCodes } from "../src/authres.ts";
import { checkSpf } from "../src/spf.ts";
import { checkDmarc } from "../src/dmarc.ts";
import { DnsNotFoundError, type DnsResolver } from "../src/dns.ts";
import type { DkimVerifyResult } from "../src/verify.ts";

function fakeResolver(txt: Record<string, string[]>): DnsResolver {
  return {
    txt: (name) => (txt[name] ? Promise.resolve(txt[name]) : Promise.reject(new DnsNotFoundError(`없음: ${name}`))),
    mx: () => Promise.reject(new DnsNotFoundError("mx 미사용")),
    a: () => Promise.reject(new DnsNotFoundError("a 미사용")),
    aaaa: () => Promise.reject(new DnsNotFoundError("aaaa 미사용")),
    ptr: () => Promise.reject(new DnsNotFoundError("ptr 미사용")),
  };
}

describe("buildAuthenticationResults", () => {
  test("spf=pass/dkim=pass/dmarc=pass 조합", () => {
    const dkimResults: DkimVerifyResult[] = [{ domain: "example.com", selector: "sel1", result: "pass" }];
    const header = buildAuthenticationResults("mail.example.com", {
      spf: { result: "pass", domain: "example.com", identity: "mailfrom" },
      dkim: dkimResults,
      dmarc: { result: "pass", fromDomain: "example.com" },
    });
    expect(header).toBe(
      "mail.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com header.s=sel1; dmarc=pass header.from=example.com",
    );
  });

  /**
   * `header.a=`(RFC 8601 §2.7.1) — 알고리즘별 판정 집계를 가능하게 한다.
   *
   * ★왜 필요한가(2026-08-01): Ed25519 구현이 RFC 8463 §3을 위반해 규격을 지키는 외부 발신자를
   * 전부 `dkim=fail`로 판정해 왔는데, 우리가 남긴 기록에 알고리즘이 없어 **그 규모를 소급해서
   * 셀 수 없었다.** 셀렉터 이름으로 유추할 수도 없다 — 그건 운영자가 정하는 값이다.
   */
  test("★알고리즘이 있으면 header.a=로 남는다 (알고리즘별 집계 근거)", () => {
    const header = buildAuthenticationResults("mx.test", {
      dkim: [
        { domain: "x.test", selector: "rsa1", result: "pass", algorithm: "rsa-sha256" },
        { domain: "x.test", selector: "ed1", result: "fail", algorithm: "ed25519-sha256" },
      ],
    });
    expect(header).toContain("dkim=pass header.d=x.test header.s=rsa1 header.a=rsa-sha256");
    expect(header).toContain("dkim=fail header.d=x.test header.s=ed1 header.a=ed25519-sha256");
  });

  test("알고리즘을 모르면 header.a=를 넣지 않는다 (a= 파싱 전 실패 경로)", () => {
    // 헤더 파싱 자체가 실패한 경우엔 a=를 읽을 수 없다 — 없는 값을 추측해 채우면 안 된다.
    const header = buildAuthenticationResults("mx.test", {
      dkim: [{ domain: "x.test", selector: "old", result: "permerror" }],
    });
    expect(header).not.toContain("header.a=");
  });

  test("spf만 pass, dkim 없음, dmarc pass(SPF 정렬) — Kakao류", () => {
    const header = buildAuthenticationResults("mail.example.com", {
      spf: { result: "pass", domain: "outside.test", identity: "mailfrom" },
      dkim: [],
      dmarc: { result: "pass", fromDomain: "outside.test" },
    });
    expect(header).toBe(
      "mail.example.com; spf=pass smtp.mailfrom=outside.test; dkim=none; dmarc=pass header.from=outside.test",
    );
  });

  test("아무 것도 검사 안 하면 authservId; none", () => {
    expect(buildAuthenticationResults("mail.example.com", {})).toBe("mail.example.com; none");
  });
});

describe("mapToStorageCodes", () => {
  test("pass/pass/pass → 1/1/1", () => {
    expect(mapToStorageCodes("pass", "pass", "pass")).toEqual({ spf: 1, dkim: 1, dmarc: 1 });
  });

  test("softfail/none(dkim)/none → 3/0/0", () => {
    expect(mapToStorageCodes("softfail", "none", "none")).toEqual({ spf: 3, dkim: 0, dmarc: 0 });
  });

  test("permerror/permerror/permerror → 6/6/6", () => {
    expect(mapToStorageCodes("permerror", "permerror", "permerror")).toEqual({ spf: 6, dkim: 6, dmarc: 6 });
  });

  test("neutral/fail/fail → 4/2/2", () => {
    expect(mapToStorageCodes("neutral", "fail", "fail")).toEqual({ spf: 4, dkim: 2, dmarc: 2 });
  });

  test("temperror/temperror/temperror → 5/5/5", () => {
    expect(mapToStorageCodes("temperror", "temperror", "temperror")).toEqual({ spf: 5, dkim: 5, dmarc: 5 });
  });
});

describe("실전 벡터 — Kakao류(From jang@outside.test, SPF pass, DKIM 없음, DMARC는 SPF 정렬로 pass)", () => {
  test("checkSpf + checkDmarc + buildAuthenticationResults + mapToStorageCodes 종단 흐름", async () => {
    const resolver = fakeResolver({
      "outside.test": ["v=spf1 ip4:203.0.113.9/32 -all"],
      "_dmarc.outside.test": ["v=DMARC1; p=quarantine;"],
    });

    const spfResult = await checkSpf(
      { ip: "203.0.113.9", helo: "mx.kakao.com", mailFrom: "jang@outside.test" },
      resolver,
    );
    expect(spfResult.result).toBe("pass");
    expect(spfResult.domain).toBe("outside.test");

    const dkimResults: DkimVerifyResult[] = []; // 카카오는 이 메시지에 DKIM 서명을 하지 않음

    const dmarcResult = await checkDmarc(
      {
        fromDomain: "outside.test",
        spf: { result: spfResult.result, domain: spfResult.domain },
        dkim: dkimResults,
      },
      resolver,
    );
    expect(dmarcResult.result).toBe("pass");
    expect(dmarcResult.alignment).toEqual({ spf: true, dkim: false });

    const header = buildAuthenticationResults("mx.ionosphere.example", {
      spf: { result: spfResult.result, domain: spfResult.domain, identity: "mailfrom" },
      dkim: dkimResults,
      dmarc: { result: dmarcResult.result, fromDomain: "outside.test" },
    });
    expect(header).toBe(
      "mx.ionosphere.example; spf=pass smtp.mailfrom=outside.test; dkim=none; dmarc=pass header.from=outside.test",
    );

    const codes = mapToStorageCodes(spfResult.result, "none", dmarcResult.result);
    expect(codes).toEqual({ spf: 1, dkim: 0, dmarc: 1 });
  });
});
