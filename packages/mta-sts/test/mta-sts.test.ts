/** MTA-STS/TLS-RPT — 빌드·파싱·MX매칭·발신측 조회·강제 판정. */
import { describe, expect, test } from "@ionosphere/testkit";
import {
  buildMtaStsPolicy,
  fetchMtaStsPolicy,
  mxMatchesPolicy,
  parseMtaStsPolicy,
  parseMtaStsTxt,
  parseTlsRptTxt,
  stsDnsRecords,
  stsEnforcement,
} from "@ionosphere/mta-sts";

describe("빌드", () => {
  test("mta-sts.txt 본문 왕복(build → parse)", () => {
    const txt = buildMtaStsPolicy({ mx: ["mx.example.com", "*.example.com"], mode: "enforce", maxAge: 86400 });
    expect(txt).toContain("version: STSv1");
    expect(txt).toContain("mode: enforce");
    expect(txt).toContain("mx: mx.example.com");
    expect(txt).toContain("mx: *.example.com");
    expect(txt).toContain("max_age: 86400");
    const p = parseMtaStsPolicy(txt);
    expect(p).toEqual({ version: "STSv1", mode: "enforce", mx: ["mx.example.com", "*.example.com"], maxAge: 86400 });
  });

  test("기본 mode=testing, max_age=7일", () => {
    const p = parseMtaStsPolicy(buildMtaStsPolicy({ mx: ["mx.a.com"] }))!;
    expect(p.mode).toBe("testing");
    expect(p.maxAge).toBe(604800);
  });

  test("DNS 레코드: _mta-sts + (rua 있으면) _smtp._tls", () => {
    const recs = stsDnsRecords("example.com", { policyId: "20260726T000000", rua: "mailto:tls@example.com" });
    expect(recs).toContainEqual({ name: "_mta-sts.example.com", value: "v=STSv1; id=20260726T000000", purpose: expect.any(String) });
    expect(recs.find((r) => r.name === "_smtp._tls.example.com")?.value).toBe("v=TLSRPTv1; rua=mailto:tls@example.com");
    // rua 생략 시 TLS-RPT 레코드 없음
    expect(stsDnsRecords("example.com", { policyId: "x" })).toHaveLength(1);
  });
});

describe("파싱", () => {
  test("잘못된 정책은 null(version/mode/mx/max_age 필수)", () => {
    expect(parseMtaStsPolicy("mode: enforce\nmx: a\nmax_age: 1")).toBeNull(); // version 없음
    expect(parseMtaStsPolicy("version: STSv1\nmode: enforce\nmax_age: 1")).toBeNull(); // mx 없음
  });

  test("_mta-sts TXT → id", () => {
    expect(parseMtaStsTxt("v=STSv1; id=abc123")).toEqual({ id: "abc123" });
    expect(parseMtaStsTxt("v=spf1 mx")).toBeNull();
  });

  test("TLS-RPT TXT → rua(콤마 다중)", () => {
    expect(parseTlsRptTxt("v=TLSRPTv1; rua=mailto:a@x.com,https://y.com/r")).toEqual({
      rua: ["mailto:a@x.com", "https://y.com/r"],
    });
    expect(parseTlsRptTxt("v=STSv1; id=x")).toBeNull();
  });
});

describe("MX 매칭", () => {
  test("정확 매치·와일드카드 1레벨·대소문자·후행점", () => {
    expect(mxMatchesPolicy("mx.example.com", ["mx.example.com"])).toBe(true);
    expect(mxMatchesPolicy("MX.Example.com.", ["mx.example.com"])).toBe(true);
    expect(mxMatchesPolicy("a.example.com", ["*.example.com"])).toBe(true);
    expect(mxMatchesPolicy("a.b.example.com", ["*.example.com"])).toBe(false); // 2레벨 불가
    expect(mxMatchesPolicy("example.com", ["*.example.com"])).toBe(false); // 0레벨 불가
    expect(mxMatchesPolicy("mx.other.com", ["mx.example.com"])).toBe(false);
  });
});

describe("발신측 조회·강제", () => {
  const policyBody = buildMtaStsPolicy({ mx: ["mx.example.com"], mode: "enforce" });

  test("TXT + 정책 페치 성공 → found + enforce", async () => {
    const lookup = await fetchMtaStsPolicy("example.com", {
      resolveTxt: async (n) => (n === "_mta-sts.example.com" ? ["v=STSv1; id=v1"] : []),
      httpsGet: async (u) => {
        expect(u).toBe("https://mta-sts.example.com/.well-known/mta-sts.txt");
        return policyBody;
      },
    });
    expect(lookup.found).toBe(true);
    expect(lookup.policyId).toBe("v1");
    expect(stsEnforcement(lookup)).toEqual({ action: "require-tls", reason: "enforce" });
    expect(mxMatchesPolicy("mx.example.com", lookup.policy!.mx)).toBe(true);
  });

  test("TXT 없음 → found:false, 강제 none", async () => {
    const lookup = await fetchMtaStsPolicy("nopolicy.com", {
      resolveTxt: async () => [],
      httpsGet: async () => {
        throw new Error("페치되면 안 됨");
      },
    });
    expect(lookup.found).toBe(false);
    expect(stsEnforcement(lookup)).toEqual({ action: "none", reason: "no-policy" });
  });

  test("TXT 있으나 페치 실패 → found:true·정책본문 없음(강제 불가)", async () => {
    const lookup = await fetchMtaStsPolicy("example.com", {
      resolveTxt: async () => ["v=STSv1; id=v1"],
      httpsGet: async () => {
        throw new Error("timeout");
      },
    });
    expect(lookup.found).toBe(true);
    expect(lookup.policy).toBeUndefined();
    expect(stsEnforcement(lookup)).toEqual({ action: "none", reason: "no-policy" });
  });

  test("testing 모드 → report-only", async () => {
    const lookup = await fetchMtaStsPolicy("example.com", {
      resolveTxt: async () => ["v=STSv1; id=v1"],
      httpsGet: async () => buildMtaStsPolicy({ mx: ["mx.example.com"], mode: "testing" }),
    });
    expect(stsEnforcement(lookup)).toEqual({ action: "report-only", reason: "testing" });
  });

  test("resolveTxt throw → found:false(발신 계속)", async () => {
    const lookup = await fetchMtaStsPolicy("x.com", {
      resolveTxt: async () => {
        throw new Error("dns fail");
      },
      httpsGet: async () => "",
    });
    expect(lookup.found).toBe(false);
  });
});

/**
 * 2026-07-31 실측 — 페치 상한(64KB) 안에서 `mx:` 줄을 최대로 채우면 한 정책이 3,087개가 되고,
 * 워커 캐시(4096개)가 가득 차면 RSS 360MB다. 전 프로토콜이 단일 프로세스라 그 메모리는
 * 메일 서비스 전체와 경합한다. 상한을 넘는 정책은 무효로 본다.
 */
describe("mx 개수 상한 (캐시 메모리 증폭 차단)", () => {
  const head = "version: STSv1\nmode: enforce\nmax_age: 604800\n";

  test("정상 범위의 mx는 그대로 파싱된다", () => {
    const mx = Array.from({ length: 100 }, (_, i) => `mx: m${i}.example`).join("\n");
    const p = parseMtaStsPolicy(`${head}${mx}\n`);
    expect(p?.mx).toHaveLength(100);
  });

  test("상한을 넘는 mx 목록은 정책 무효로 본다(잘라 쓰지 않는다)", () => {
    const mx = Array.from({ length: 101 }, (_, i) => `mx: m${i}.example`).join("\n");
    expect(parseMtaStsPolicy(`${head}${mx}\n`)).toBeNull();
  });

  test("페치 상한을 가득 채운 악성 정책이 거부된다", () => {
    let body = head;
    let n = 0;
    while (body.length + 24 < 64 * 1024) { body += `mx: ${n.toString(36)}.a${n}.example\n`; n += 1; }
    expect(n).toBeGreaterThan(1000); // 실제로 대량이어야 의미 있는 테스트다
    expect(parseMtaStsPolicy(body)).toBeNull();
  });
});
