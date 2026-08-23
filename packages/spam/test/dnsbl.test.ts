import { describe, expect, test } from "@ionosphere/testkit";
import { DnsNotFoundError, DnsTemporaryError, type DnsResolver } from "@ionosphere/mail-auth";
import { checkDnsbl, type DnsblZone } from "../src/dnsbl.ts";

interface FakeZone {
  /** name(질의된 정확한 문자열) → A 레코드 배열. */
  a?: Record<string, string[]>;
  tempFail?: Set<string>;
}

function fakeResolver(zone: FakeZone): DnsResolver {
  function get<T>(map: Record<string, T[]> | undefined, key: string): Promise<T[]> {
    if (zone.tempFail?.has(key)) {
      return Promise.reject(new DnsTemporaryError(`임시 오류: ${key}`));
    }
    const val = map?.[key];
    if (!val || val.length === 0) return Promise.reject(new DnsNotFoundError(`없음: ${key}`));
    return Promise.resolve(val);
  }
  return {
    txt: () => Promise.reject(new DnsNotFoundError()),
    mx: () => Promise.reject(new DnsNotFoundError()),
    a: (name) => get(zone.a, name),
    aaaa: () => Promise.reject(new DnsNotFoundError()),
    ptr: () => Promise.reject(new DnsNotFoundError()),
  };
}

describe("checkDnsbl — 역순 이름 구성", () => {
  test("1.2.3.4 → 4.3.2.1.<zone> 정확히 질의", async () => {
    const queried: string[] = [];
    const resolver: DnsResolver = {
      txt: () => Promise.reject(new DnsNotFoundError()),
      mx: () => Promise.reject(new DnsNotFoundError()),
      a: (name) => {
        queried.push(name);
        return Promise.reject(new DnsNotFoundError());
      },
      aaaa: () => Promise.reject(new DnsNotFoundError()),
      ptr: () => Promise.reject(new DnsNotFoundError()),
    };
    await checkDnsbl("1.2.3.4", [{ zone: "zen.spamhaus.org" }], resolver);
    expect(queried).toEqual(["4.3.2.1.zen.spamhaus.org"]);
  });
});

describe("checkDnsbl — 등재/점수", () => {
  const ZEN: DnsblZone = { zone: "zen.spamhaus.org", weight: 100 };

  test("127.0.0.2 응답 → listed, score=weight, hits에 zone 포함", async () => {
    const resolver = fakeResolver({ a: { "2.0.0.127.zen.spamhaus.org": ["127.0.0.2"] } });
    const result = await checkDnsbl("127.0.0.2", [ZEN], resolver);
    expect(result.listed).toBe(true);
    expect(result.score).toBe(100);
    expect(result.hits).toEqual([{ zone: "zen.spamhaus.org", codes: ["2"], weight: 100 }]);
  });

  test("미등재 IP(NotFound) → listed:false score:0", async () => {
    const resolver = fakeResolver({});
    const result = await checkDnsbl("203.0.113.5", [ZEN], resolver);
    expect(result).toEqual({ listed: false, hits: [], score: 0 });
  });

  test("두 존 중 하나만 히트 → score는 히트한 존의 weight만 합산", async () => {
    const revIp = "1.2.0.10"; // reverse -> 10.0.2.1
    const zoneA: DnsblZone = { zone: "zonea.example", weight: 50 };
    const zoneB: DnsblZone = { zone: "zoneb.example", weight: 30 };
    const resolver = fakeResolver({ a: { "10.0.2.1.zonea.example": ["127.0.0.4"] } });
    const result = await checkDnsbl(revIp, [zoneA, zoneB], resolver);
    expect(result.listed).toBe(true);
    expect(result.score).toBe(50);
    expect(result.hits).toEqual([{ zone: "zonea.example", codes: ["4"], weight: 50 }]);
  });

  test("DNSWL(음수 weight) — 화이트리스트 히트가 score를 낮춘다", async () => {
    const ip = "9.9.9.9"; // reverse -> 9.9.9.9
    const bl: DnsblZone = { zone: "bl.example", weight: 100 };
    const wl: DnsblZone = { zone: "list.dnswl.org", weight: -20 };
    const resolver = fakeResolver({
      a: {
        "9.9.9.9.bl.example": ["127.0.0.2"],
        "9.9.9.9.list.dnswl.org": ["127.0.5.1"],
      },
    });
    const result = await checkDnsbl(ip, [bl, wl], resolver);
    expect(result.score).toBe(80);
    expect(result.listed).toBe(true); // 블랙리스트 히트가 있으므로 listed
  });

  test("한 존에서 일시 오류 → 그 존만 건너뛰고 나머지는 계속 평가", async () => {
    const ip = "5.6.7.8"; // reverse -> 8.7.6.5
    const zoneA: DnsblZone = { zone: "temp.example", weight: 10 };
    const zoneB: DnsblZone = { zone: "ok.example", weight: 20 };
    const resolver = fakeResolver({
      a: { "8.7.6.5.ok.example": ["127.0.0.3"] },
      tempFail: new Set(["8.7.6.5.temp.example"]),
    });
    const skipped: string[] = [];
    const result = await checkDnsbl(ip, [zoneA, zoneB], resolver, {
      onSkip: (zone) => skipped.push(zone),
    });
    expect(skipped).toEqual(["temp.example"]);
    expect(result.listed).toBe(true);
    expect(result.score).toBe(20);
    expect(result.hits).toEqual([{ zone: "ok.example", codes: ["3"], weight: 20 }]);
  });

  test("weight 생략 시 기본값 1", async () => {
    const resolver = fakeResolver({ a: { "2.0.0.127.zen.spamhaus.org": ["127.0.0.2"] } });
    const result = await checkDnsbl("127.0.0.2", [{ zone: "zen.spamhaus.org" }], resolver);
    expect(result.score).toBe(1);
  });
});

describe("checkDnsbl — IPv6 역순 이름", () => {
  test("전체 확장 주소를 니블 단위로 역순 표기", async () => {
    const queried: string[] = [];
    const resolver: DnsResolver = {
      txt: () => Promise.reject(new DnsNotFoundError()),
      mx: () => Promise.reject(new DnsNotFoundError()),
      a: (name) => {
        queried.push(name);
        return Promise.reject(new DnsNotFoundError());
      },
      aaaa: () => Promise.reject(new DnsNotFoundError()),
      ptr: () => Promise.reject(new DnsNotFoundError()),
    };
    await checkDnsbl("2001:db8::1", [{ zone: "example.org" }], resolver);
    // 2001:0db8:0000:0000:0000:0000:0000:0001 → 32니블 역순 + 존.
    const expectedName = [
      "1",
      ...Array(23).fill("0"),
      "8",
      "b",
      "d",
      "0",
      "1",
      "0",
      "0",
      "2",
      "example",
      "org",
    ].join(".");
    expect(queried).toEqual([expectedName]);
  });
});
