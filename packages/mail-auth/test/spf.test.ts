import { describe, expect, test } from "@ionosphere/testkit";
import { checkSpf, type SpfInput } from "../src/spf.ts";
import { DnsNotFoundError, DnsTemporaryError, type DnsMxRecord, type DnsResolver } from "../src/dns.ts";

interface FakeZone {
  txt?: Record<string, string[]>;
  mx?: Record<string, DnsMxRecord[]>;
  a?: Record<string, string[]>;
  aaaa?: Record<string, string[]>;
  ptr?: Record<string, string[]>;
  tempFail?: Set<string>; // `${kind}:${key}` — 일시 오류로 취급할 조회
}

/** Map 기반 가짜 DnsResolver. 정의 안 된 키는 DnsNotFoundError, tempFail에 등록된 키는 DnsTemporaryError. */
function fakeResolver(zone: FakeZone): DnsResolver {
  function get<T>(map: Record<string, T[]> | undefined, key: string, kind: string): Promise<T[]> {
    if (zone.tempFail?.has(`${kind}:${key}`)) {
      return Promise.reject(new DnsTemporaryError(`임시 오류: ${kind}:${key}`));
    }
    const val = map?.[key];
    if (!val || val.length === 0) return Promise.reject(new DnsNotFoundError(`없음: ${kind}:${key}`));
    return Promise.resolve(val);
  }
  return {
    txt: (name) => get(zone.txt, name, "txt"),
    mx: (name) => get(zone.mx, name, "mx"),
    a: (name) => get(zone.a, name, "a"),
    aaaa: (name) => get(zone.aaaa, name, "aaaa"),
    ptr: (ip) => get(zone.ptr, ip, "ptr"),
  };
}

function input(overrides: Partial<SpfInput> = {}): SpfInput {
  return { ip: "192.0.2.10", helo: "mail.example.net", mailFrom: "alice@example.com", ...overrides };
}

describe("checkSpf — 메커니즘별 pass", () => {
  test("ip4 메커니즘으로 pass", async () => {
    const resolver = fakeResolver({ txt: { "example.com": ["v=spf1 ip4:192.0.2.0/24 -all"] } });
    const result = await checkSpf(input({ ip: "192.0.2.10" }), resolver);
    expect(result).toEqual({ result: "pass", domain: "example.com" });
  });

  test("a 메커니즘으로 pass", async () => {
    const resolver = fakeResolver({
      txt: { "example.com": ["v=spf1 a -all"] },
      a: { "example.com": ["192.0.2.10"] },
    });
    const result = await checkSpf(input({ ip: "192.0.2.10" }), resolver);
    expect(result.result).toBe("pass");
  });

  test("mx 메커니즘으로 pass", async () => {
    const resolver = fakeResolver({
      txt: { "example.com": ["v=spf1 mx -all"] },
      mx: { "example.com": [{ exchange: "mail.example.com", preference: 10 }] },
      a: { "mail.example.com": ["192.0.2.20"] },
    });
    const result = await checkSpf(input({ ip: "192.0.2.20" }), resolver);
    expect(result.result).toBe("pass");
  });

  test("include 메커니즘으로 재귀 pass", async () => {
    const resolver = fakeResolver({
      txt: {
        "example.com": ["v=spf1 include:_spf.example.net -all"],
        "_spf.example.net": ["v=spf1 ip4:198.51.100.0/24 -all"],
      },
    });
    const result = await checkSpf(input({ ip: "198.51.100.5" }), resolver);
    expect(result.result).toBe("pass");
    expect(result.domain).toBe("example.com"); // 최상위 발신 도메인 기준으로 보고
  });
});

describe("checkSpf — 한정자(qualifier)", () => {
  test("-all → fail", async () => {
    const resolver = fakeResolver({ txt: { "example.com": ["v=spf1 -all"] } });
    const result = await checkSpf(input(), resolver);
    expect(result.result).toBe("fail");
  });

  test("~all → softfail", async () => {
    const resolver = fakeResolver({ txt: { "example.com": ["v=spf1 ~all"] } });
    const result = await checkSpf(input(), resolver);
    expect(result.result).toBe("softfail");
  });

  test("?all → neutral", async () => {
    const resolver = fakeResolver({ txt: { "example.com": ["v=spf1 ?all"] } });
    const result = await checkSpf(input(), resolver);
    expect(result.result).toBe("neutral");
  });

  test("매치 없음 + redirect 없음 → 암묵적 neutral", async () => {
    const resolver = fakeResolver({ txt: { "example.com": ["v=spf1 ip4:203.0.113.0/24"] } });
    const result = await checkSpf(input({ ip: "192.0.2.1" }), resolver);
    expect(result.result).toBe("neutral");
  });
});

describe("checkSpf — none/permerror/temperror", () => {
  test("SPF 레코드 없음 → none", async () => {
    const resolver = fakeResolver({});
    const result = await checkSpf(input(), resolver);
    expect(result.result).toBe("none");
  });

  test("v=spf1 레코드 2개 → permerror", async () => {
    const resolver = fakeResolver({
      txt: { "example.com": ["v=spf1 -all", "v=spf1 +all"] },
    });
    const result = await checkSpf(input(), resolver);
    expect(result.result).toBe("permerror");
  });

  test("알 수 없는 항목(malformed) → permerror", async () => {
    const resolver = fakeResolver({ txt: { "example.com": ["v=spf1 badmechanism -all"] } });
    const result = await checkSpf(input(), resolver);
    expect(result.result).toBe("permerror");
  });

  test("10회 초과 DNS 조회(include 11개) → permerror", async () => {
    const includes = Array.from({ length: 11 }, (_, i) => `include:i${i + 1}.example.com`).join(" ");
    const txt: Record<string, string[]> = { "example.com": [`v=spf1 ${includes} -all`] };
    for (let i = 1; i <= 11; i++) txt[`i${i}.example.com`] = ["v=spf1 ~all"]; // 매치 없이 계속 통과시킴
    const resolver = fakeResolver({ txt });
    const result = await checkSpf(input(), resolver);
    expect(result.result).toBe("permerror");
  });

  test("void lookup 3회(한도 2) → permerror", async () => {
    const resolver = fakeResolver({
      txt: { "example.com": ["v=spf1 a:void1.test a:void2.test a:void3.test -all"] },
      // void1/void2/void3에 대한 a 레코드를 아예 정의하지 않아 매번 NotFound(void)가 되도록 함
    });
    const result = await checkSpf(input(), resolver);
    expect(result.result).toBe("permerror");
  });

  test("리졸버 temperror → temperror", async () => {
    const resolver = fakeResolver({ tempFail: new Set(["txt:example.com"]) });
    const result = await checkSpf(input(), resolver);
    expect(result.result).toBe("temperror");
  });
});

describe("checkSpf — CIDR 매칭", () => {
  test("/28 범위 안 → pass, 범위 밖 → fail", async () => {
    const resolver = fakeResolver({ txt: { "example.com": ["v=spf1 ip4:203.0.113.0/28 -all"] } });
    const inside = await checkSpf(input({ ip: "203.0.113.5" }), resolver);
    const outside = await checkSpf(input({ ip: "203.0.113.20" }), resolver);
    expect(inside.result).toBe("pass");
    expect(outside.result).toBe("fail");
  });
});

describe("checkSpf — 매크로 확장", () => {
  test("%{d}/%{i} 도메인-스펙 확장 후 exists 매치", async () => {
    const resolver = fakeResolver({
      txt: { "example.com": ["v=spf1 exists:%{i}.%{d}.spf.test -all"] },
      a: { "192.0.2.10.example.com.spf.test": ["127.0.0.2"] },
    });
    const result = await checkSpf(input({ ip: "192.0.2.10" }), resolver);
    expect(result.result).toBe("pass");
  });

  test("%{s} exp= 설명 텍스트에서 확장(도메인 제약 없는 문맥)", async () => {
    const resolver = fakeResolver({
      txt: {
        "example.com": ["v=spf1 -all exp=explain.example.com"],
        "explain.example.com": ["Rejected: %{s} said no from %{i}"],
      },
    });
    const result = await checkSpf(input({ ip: "192.0.2.10", mailFrom: "alice@example.com" }), resolver);
    expect(result.result).toBe("fail");
    expect(result.explanation).toBe("Rejected: alice@example.com said no from 192.0.2.10");
  });
});
