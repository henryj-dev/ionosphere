import { describe, expect, test } from "@ionosphere/testkit";
import { DnsCache } from "../src/cache.ts";
import { RRClass, RRType, type DnsRecord } from "../src/wire.ts";

/** 주입 시계 — now 값을 직접 조작해 만료를 결정적으로 검증. */
function fakeClock(start = 0): { now: () => number; set: (t: number) => void } {
  let t = start;
  return { now: () => t, set: (v) => (t = v) };
}

function aRecord(name: string, ttl: number, addr = "1.2.3.4"): DnsRecord {
  return { name, type: RRType.A, class: RRClass.IN, ttl, rdata: { kind: "A", address: addr } };
}

describe("DnsCache: 포지티브 TTL", () => {
  test("TTL 이내 히트, 만료 후 미스", () => {
    const clock = fakeClock(0);
    const cache = new DnsCache({ clock: clock.now });
    cache.setPositive("example.com", RRType.A, [aRecord("example.com", 300)]);

    expect(cache.get("example.com", RRType.A)?.records).toHaveLength(1);
    clock.set(299_000);
    expect(cache.get("example.com", RRType.A)).toBeDefined();
    clock.set(300_000);
    expect(cache.get("example.com", RRType.A)).toBeUndefined(); // 만료
  });

  test("여러 레코드면 최소 TTL 적용", () => {
    const clock = fakeClock(0);
    const cache = new DnsCache({ clock: clock.now });
    cache.setPositive("example.com", RRType.A, [aRecord("example.com", 300), aRecord("example.com", 60, "5.6.7.8")]);
    clock.set(60_000);
    expect(cache.get("example.com", RRType.A)).toBeUndefined(); // 60초에 만료
  });

  test("TTL 0은 저장 안 함", () => {
    const cache = new DnsCache({ clock: () => 0 });
    cache.setPositive("example.com", RRType.A, [aRecord("example.com", 0)]);
    expect(cache.get("example.com", RRType.A)).toBeUndefined();
  });

  test("maxTtlSec 상한 적용", () => {
    const clock = fakeClock(0);
    const cache = new DnsCache({ clock: clock.now, maxTtlSec: 100 });
    cache.setPositive("example.com", RRType.A, [aRecord("example.com", 999999)]);
    clock.set(100_000);
    expect(cache.get("example.com", RRType.A)).toBeUndefined();
  });
});

describe("DnsCache: 네거티브 캐시", () => {
  test("SOA minimum만큼 유효", () => {
    const clock = fakeClock(0);
    const cache = new DnsCache({ clock: clock.now });
    cache.setNegative("nope.example.com", RRType.A, 120);
    const e = cache.get("nope.example.com", RRType.A);
    expect(e?.negative).toBe(true);
    clock.set(119_000);
    expect(cache.get("nope.example.com", RRType.A)?.negative).toBe(true);
    clock.set(120_000);
    expect(cache.get("nope.example.com", RRType.A)).toBeUndefined();
  });

  test("SOA 없으면 기본 네거티브 TTL", () => {
    const clock = fakeClock(0);
    const cache = new DnsCache({ clock: clock.now, defaultNegativeTtlSec: 30 });
    cache.setNegative("nope.example.com", RRType.A);
    clock.set(30_000);
    expect(cache.get("nope.example.com", RRType.A)).toBeUndefined();
  });
});

describe("DnsCache: 키/축출", () => {
  test("이름 대소문자·후행 점 비구분", () => {
    const cache = new DnsCache({ clock: () => 0 });
    cache.setPositive("Example.COM.", RRType.A, [aRecord("Example.COM.", 300)]);
    expect(cache.get("example.com", RRType.A)).toBeDefined();
  });

  test("타입이 다르면 별개 키", () => {
    const cache = new DnsCache({ clock: () => 0 });
    cache.setPositive("example.com", RRType.A, [aRecord("example.com", 300)]);
    expect(cache.get("example.com", RRType.AAAA)).toBeUndefined();
  });

  test("maxEntries 초과 시 FIFO 축출", () => {
    const cache = new DnsCache({ clock: () => 0, maxEntries: 2 });
    cache.setPositive("a.com", RRType.A, [aRecord("a.com", 300)]);
    cache.setPositive("b.com", RRType.A, [aRecord("b.com", 300)]);
    cache.setPositive("c.com", RRType.A, [aRecord("c.com", 300)]);
    expect(cache.get("a.com", RRType.A)).toBeUndefined(); // 가장 먼저 것 축출
    expect(cache.get("b.com", RRType.A)).toBeDefined();
    expect(cache.get("c.com", RRType.A)).toBeDefined();
    expect(cache.size).toBe(2);
  });
});
