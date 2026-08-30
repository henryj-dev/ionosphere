import { describe, expect, test } from "@ionosphere/testkit";
import { getOrLoadListing, listingCacheKey, ListingCache } from "../src/listing-cache.ts";

const base = { principalId: "p1", mailboxId: "m1", mailboxModseq: 1, aclVersion: 1, permissionsVersion: 1, query: { filter: { text: "hello" }, sort: ["date"], offset: 0, limit: 50, collapseThreads: false, anchor: null, calculateTotal: true, projection: ["subject"] } } as const;

describe("listing cache", () => {
  test("principal과 mailbox가 다르면 cache key가 격리된다", () => {
    expect(listingCacheKey(base)).not.toBe(listingCacheKey({ ...base, principalId: "p2" }));
    expect(listingCacheKey(base)).not.toBe(listingCacheKey({ ...base, mailboxId: "m2" }));
  });

  test("mailbox/ACL/permission version 변화는 miss key를 만든다", () => {
    for (const field of ["mailboxModseq", "aclVersion", "permissionsVersion"] as const) expect(listingCacheKey(base)).not.toBe(listingCacheKey({ ...base, [field]: base[field] + 1 }));
  });

  test("query fingerprint는 listing 의미를 바꾸는 모든 필드를 구별한다", () => {
    for (const query of [{ collapseThreads: true }, { anchor: "x" }, { offset: 1 }, { calculateTotal: false }, { sort: ["subject"] }, { filter: { text: "other" } }, { projection: ["from"] }]) expect(listingCacheKey(base)).not.toBe(listingCacheKey({ ...base, query: { ...base.query, ...query } }));
  });

  test("set은 결과를 2,000개로 제한한다", () => {
    const cache = new ListingCache<number>({ ttlMs: 5000 });
    expect(cache.set("k", Array.from({ length: 2001 }, (_, index) => index)).length).toBe(2000);
  });

  test("TTL 5초 경계에서 만료된다", () => {
    let now = 0;
    const cache = new ListingCache<number>({ ttlMs: 5000, now: () => now });
    cache.set("k", [1]);
    now = 4999;
    expect(cache.get("k")).toEqual([1]);
    now = 5000;
    expect(cache.get("k")).toBe(null);
  });

  test("LRU는 가장 오래 사용하지 않은 항목을 제거한다", () => {
    const cache = new ListingCache<number>({ maxEntries: 2, ttlMs: 5000 });
    cache.set("a", [1]); cache.set("b", [2]);
    expect(cache.get("a")).toEqual([1]);
    cache.set("c", [3]);
    expect(cache.get("b")).toBe(null);
    expect(cache.size).toBe(2);
  });

  test("cache miss는 loader를 한 번 호출하고 이후 hit를 반환한다", async () => {
    const cache = new ListingCache<number>({ ttlMs: 5000 });
    let calls = 0;
    const loader = async (): Promise<readonly number[]> => { calls++; return [7]; };
    expect(await getOrLoadListing(cache, "k", loader)).toEqual([7]);
    expect(await getOrLoadListing(cache, "k", loader)).toEqual([7]);
    expect(calls).toBe(1);
  });

  test("delete와 clear는 권한 변경 시 stale 결과를 제거한다", () => {
    const cache = new ListingCache<number>({ ttlMs: 5000 });
    cache.set("a", [1]); cache.set("b", [2]);
    cache.delete("a");
    expect(cache.get("a")).toBe(null);
    cache.clear();
    expect(cache.size).toBe(0);
  });
});
