import { describe, expect, test } from "@ionosphere/testkit";
import { checkDmarc, type DmarcInput } from "../src/dmarc.ts";
import { DnsNotFoundError, DnsTemporaryError, type DnsResolver } from "../src/dns.ts";

interface FakeZone {
  txt?: Record<string, string[]>;
  tempFail?: Set<string>;
}

function fakeResolver(zone: FakeZone): DnsResolver {
  function get(map: Record<string, string[]> | undefined, key: string, kind: string): Promise<string[]> {
    if (zone.tempFail?.has(`${kind}:${key}`)) return Promise.reject(new DnsTemporaryError(`임시 오류: ${kind}:${key}`));
    const val = map?.[key];
    if (!val || val.length === 0) return Promise.reject(new DnsNotFoundError(`없음: ${kind}:${key}`));
    return Promise.resolve(val);
  }
  return {
    txt: (name) => get(zone.txt, name, "txt"),
    mx: () => Promise.reject(new DnsNotFoundError("mx 미사용")),
    a: () => Promise.reject(new DnsNotFoundError("a 미사용")),
    aaaa: () => Promise.reject(new DnsNotFoundError("aaaa 미사용")),
    ptr: () => Promise.reject(new DnsNotFoundError("ptr 미사용")),
  };
}

function baseInput(overrides: Partial<DmarcInput> = {}): DmarcInput {
  return {
    fromDomain: "example.com",
    spf: { result: "none", domain: "example.com" },
    dkim: [],
    ...overrides,
  };
}

describe("checkDmarc — DKIM 정렬로 pass", () => {
  test("relaxed(기본): 서브도메인 d=도 조직 도메인 동일하면 정렬", async () => {
    const resolver = fakeResolver({ txt: { "_dmarc.example.com": ["v=DMARC1; p=reject;"] } });
    const result = await checkDmarc(
      baseInput({ fromDomain: "example.com", dkim: [{ result: "pass", domain: "mail.example.com" }] }),
      resolver,
    );
    expect(result.result).toBe("pass");
    expect(result.alignment).toEqual({ spf: false, dkim: true });
  });

  test("strict(adkim=s): 정확히 일치해야 정렬", async () => {
    const resolver = fakeResolver({ txt: { "_dmarc.example.com": ["v=DMARC1; p=reject; adkim=s;"] } });
    const result = await checkDmarc(
      baseInput({ fromDomain: "example.com", dkim: [{ result: "pass", domain: "example.com" }] }),
      resolver,
    );
    expect(result.result).toBe("pass");
    expect(result.alignment.dkim).toBe(true);
  });

  test("strict인데 d=가 서브도메인이면 불일치(다른 정렬 수단 없으면 fail)", async () => {
    const resolver = fakeResolver({ txt: { "_dmarc.example.com": ["v=DMARC1; p=reject; adkim=s;"] } });
    const result = await checkDmarc(
      baseInput({ fromDomain: "example.com", dkim: [{ result: "pass", domain: "mail.example.com" }] }),
      resolver,
    );
    expect(result.result).toBe("fail");
    expect(result.alignment.dkim).toBe(false);
  });
});

describe("checkDmarc — SPF 정렬로 pass", () => {
  test("SPF pass + 도메인 정렬 → pass (DKIM 없어도)", async () => {
    const resolver = fakeResolver({ txt: { "_dmarc.example.com": ["v=DMARC1; p=quarantine;"] } });
    const result = await checkDmarc(
      baseInput({ fromDomain: "example.com", spf: { result: "pass", domain: "example.com" }, dkim: [] }),
      resolver,
    );
    expect(result.result).toBe("pass");
    expect(result.alignment).toEqual({ spf: true, dkim: false });
  });
});

describe("checkDmarc — fail / none", () => {
  test("SPF·DKIM 모두 비정렬 → fail, disposition=p 값", async () => {
    const resolver = fakeResolver({ txt: { "_dmarc.example.com": ["v=DMARC1; p=reject;"] } });
    const result = await checkDmarc(
      baseInput({
        fromDomain: "example.com",
        spf: { result: "pass", domain: "attacker.example" },
        dkim: [{ result: "pass", domain: "attacker.example" }],
      }),
      resolver,
    );
    expect(result.result).toBe("fail");
    expect(result.disposition).toBe("reject");
    expect(result.policy).toBe("reject");
  });

  test("_dmarc 레코드 어디에도 없음 → none", async () => {
    const resolver = fakeResolver({});
    const result = await checkDmarc(baseInput({ fromDomain: "nodmarc.example.com" }), resolver);
    expect(result.result).toBe("none");
    expect(result.disposition).toBe("none");
  });
});

describe("checkDmarc — DNS Tree Walk로 조직 도메인 정책 발견", () => {
  test("서브도메인 자체엔 _dmarc 없음 → 상위(조직) 도메인 정책으로 평가", async () => {
    const resolver = fakeResolver({
      txt: { "_dmarc.example.com": ["v=DMARC1; p=quarantine; sp=reject;"] },
    });
    const result = await checkDmarc(
      baseInput({
        fromDomain: "sub.example.com",
        spf: { result: "pass", domain: "sub.example.com" },
      }),
      resolver,
    );
    expect(result.result).toBe("pass"); // relaxed 기본값 → sub.example.com의 조직 도메인 example.com과 일치
  });

  test("sp= 적용: 서브도메인이 비정렬이면 sp의 disposition을 사용", async () => {
    const resolver = fakeResolver({
      txt: { "_dmarc.example.com": ["v=DMARC1; p=quarantine; sp=reject;"] },
    });
    const result = await checkDmarc(
      baseInput({
        fromDomain: "sub.example.com",
        spf: { result: "pass", domain: "attacker.example" },
        dkim: [],
      }),
      resolver,
    );
    expect(result.result).toBe("fail");
    expect(result.disposition).toBe("reject"); // sp 값 — p(quarantine)가 아님
    expect(result.policy).toBe("reject");
  });

  test("Tree Walk 중 temperror(SERVFAIL) → temperror", async () => {
    const resolver = fakeResolver({
      tempFail: new Set(["txt:_dmarc.example.com"]),
      // _dmarc.sub.example.com은 NXDOMAIN(없음) → walk가 example.com까지 올라가서 temp 오류를 만남
    });
    const result = await checkDmarc(baseInput({ fromDomain: "sub.example.com" }), resolver);
    expect(result.result).toBe("temperror");
  });
});

describe("checkDmarc — adkim/aspf 태그 파싱", () => {
  test("aspf=s면 서브도메인 SPF는 정렬 실패", async () => {
    const resolver = fakeResolver({ txt: { "_dmarc.example.com": ["v=DMARC1; p=reject; aspf=s;"] } });
    const result = await checkDmarc(
      baseInput({
        fromDomain: "example.com",
        spf: { result: "pass", domain: "mail.example.com" },
      }),
      resolver,
    );
    expect(result.alignment.spf).toBe(false);
    expect(result.result).toBe("fail");
  });

  test("aspf 미지정(기본 relaxed)이면 서브도메인 SPF도 정렬", async () => {
    const resolver = fakeResolver({ txt: { "_dmarc.example.com": ["v=DMARC1; p=reject;"] } });
    const result = await checkDmarc(
      baseInput({
        fromDomain: "example.com",
        spf: { result: "pass", domain: "mail.example.com" },
      }),
      resolver,
    );
    expect(result.alignment.spf).toBe(true);
    expect(result.result).toBe("pass");
  });
});
