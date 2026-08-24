/**
 * DMARC의 DNS 조회 **횟수** 회귀.
 *
 * ★SPF는 이 교훈을 사고로 배웠다(`spf.ts EvalCtx.pMacroValue`: 캐시가 레코드마다 리셋돼
 * "예산 10회 정책에 실제 130회"). DMARC에는 그 캐시도 **예산도 없었다** — `isDkimAligned`가
 * 서명마다 `computeOrgDomain(fromDomain)`을 다시 계산했고(답은 항상 같다) 조회 대상은
 * `From:` 도메인의 라벨 수와 통과한 서명들의 `d=`, 즉 **공격자가 정하는 값**이었다.
 */
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { checkDmarc, DnsNotFoundError, type DnsResolver } from "@ionosphere/mail-auth";

/** TXT 조회 횟수를 세는 리졸버. `_dmarc.x.test`에만 정책을 둔다. */
function countingResolver(policy: Record<string, string> = { "_dmarc.x.test": "v=DMARC1; p=reject" }) {
  let txtCalls = 0;
  const names: string[] = [];
  const resolver: DnsResolver = {
    txt: async (name: string) => {
      txtCalls++;
      names.push(name);
      const v = policy[name];
      if (v === undefined) throw new DnsNotFoundError(name);
      return [v];
    },
    a: async () => [],
    aaaa: async () => [],
    mx: async () => [],
    ptr: async () => [],
  };
  return { resolver, calls: () => txtCalls, names };
}

const PASSING_DKIM = (n: number): { result: "pass"; domain: string }[] =>
  Array.from({ length: n }, (_, i) => ({ result: "pass" as const, domain: `s${i}.x.test` }));

describe("DMARC 조회 횟수", () => {
  test("서명이 여러 개여도 fromDomain walk를 한 번만 한다", async () => {
    const { resolver, calls } = countingResolver();
    const r = await checkDmarc(
      { fromDomain: "a.b.c.x.test", spf: { result: "none", domain: "" }, dkim: PASSING_DKIM(10) },
      resolver,
    );
    expect(r.result).toBe("pass"); // s0.x.test 등이 조직 도메인 x.test로 정렬된다

    /**
     * 캐시가 없던 시절에는 서명 10개 × (dDomain walk + fromDomain walk)로 100회 가까이 나갔다.
     * 지금은 도메인마다 한 번씩만 묻는다 — 40은 예산(MAX_DMARC_LOOKUPS)이기도 하다.
     */
    expect(calls() < 40).toBe(true);
  });

  test("같은 이름을 두 번 묻지 않는다", async () => {
    const { resolver, names } = countingResolver();
    await checkDmarc(
      { fromDomain: "deep.a.b.x.test", spf: { result: "pass", domain: "deep.a.b.x.test" }, dkim: PASSING_DKIM(5) },
      resolver,
    );
    expect(names.length).toBe(new Set(names).size);
  });

  test("조회 예산을 넘기면 temperror로 끊는다", async () => {
    // 라벨이 아주 많은 도메인 + 서명마다 다른 긴 d= — 예산이 없으면 폭주하는 형태다.
    const { resolver, calls } = countingResolver({});
    const deep = Array.from({ length: 12 }, (_, i) => `l${i}`).join(".") + ".x.test";
    const dkim = Array.from({ length: 10 }, (_, i) => ({
      result: "pass" as const,
      domain: `${Array.from({ length: 12 }, (_, j) => `m${i}${j}`).join(".")}.y.test`,
    }));
    const r = await checkDmarc({ fromDomain: deep, spf: { result: "none", domain: "" }, dkim }, resolver);
    // 정책이 없으므로 none이거나, 예산에 걸리면 temperror다 — 어느 쪽이든 **폭주하지 않는다**.
    expect(r.result === "none" || r.result === "temperror").toBe(true);
    expect(calls() <= 41).toBe(true); // 예산 40 + 마지막 한 번
  });

  test("정상 평가는 조회가 몇 번이면 끝난다", async () => {
    const { resolver, calls } = countingResolver();
    const r = await checkDmarc(
      { fromDomain: "x.test", spf: { result: "pass", domain: "x.test" }, dkim: [] },
      resolver,
    );
    expect(r.result).toBe("pass");
    expect(calls() <= 3).toBe(true);
  });
});
