/**
 * TLSA 조회 배선 — 검증 판정이 발송 계약으로 **정확히** 옮겨지는지.
 *
 * ★여기가 틀리면 위아래가 다 맞아도 DANE가 무너진다. 특히 `insecure`(보호 없음)와
 * `bogus`(조작 신호)를 뭉개면, DNS를 만질 수 있는 공격자가 TLSA를 망가뜨리는 것만으로
 * DANE를 끌 수 있다 — 즉 고정을 우회한다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { RRType, type DnsRecord, type ValidatedAnswer } from "@ionosphere/dns";
import { createTlsaLookup, type TlsaValidator } from "../src/dane-lookup.ts";

const tlsaRr = (data: number[]): DnsRecord => ({
  name: "_25._tcp.mx.example.test",
  type: RRType.TLSA,
  class: 1,
  ttl: 300,
  rdata: { kind: "TLSA", usage: 3, selector: 1, matchingType: 1, data: new Uint8Array(data) },
});

function fakeResolver(answer: ValidatedAnswer | (() => ValidatedAnswer)): TlsaValidator & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async validated(name) {
      calls.push(name);
      return typeof answer === "function" ? answer() : answer;
    },
  };
}

describe("createTlsaLookup", () => {
  test("secure + TLSA → 검증됨으로 넘긴다", async () => {
    const resolver = fakeResolver({ status: "secure", records: [tlsaRr([1, 2, 3])] });
    const lookup = createTlsaLookup({ resolver });
    const got = await lookup("mx.example.test", 25);

    expect(got.kind).toBe("tlsa");
    if (got.kind === "tlsa") {
      expect(got.set.dnssecValidated).toBe(true);
      expect(got.set.records.length).toBe(1);
      expect(got.set.records[0]!.usage).toBe(3);
    }
    // 조회 이름이 RFC 7672 형식이어야 한다 — 틀리면 항상 "TLSA 없음"이 되어 조용히 꺼진다.
    expect(resolver.calls[0]).toBe("_25._tcp.mx.example.test");
  });

  test("★insecure는 미적용 — 서명 없는 존은 DANE 이전 동작으로 간다", async () => {
    const lookup = createTlsaLookup({ resolver: fakeResolver({ status: "insecure", reason: "서명되지 않은 위임" }) });
    expect((await lookup("mx.example.test", 25)).kind).toBe("none");
  });

  test("★bogus는 미적용이 아니라 조작 신호로 넘긴다", async () => {
    // none으로 뭉개면 TLSA를 망가뜨리는 것만으로 DANE를 끌 수 있다.
    const got = await createTlsaLookup({ resolver: fakeResolver({ status: "bogus", reason: "서명 검증 실패" }) })(
      "mx.example.test",
      25,
    );
    expect(got.kind).toBe("bogus");
  });

  test("secure인데 TLSA가 없으면 미적용", async () => {
    const lookup = createTlsaLookup({ resolver: fakeResolver({ status: "secure", records: [] }) });
    expect((await lookup("mx.example.test", 25)).kind).toBe("none");
  });

  test("포트가 조회 이름에 반영된다(465·587도 각자 TLSA를 갖는다)", async () => {
    const resolver = fakeResolver({ status: "insecure", reason: "x" });
    await createTlsaLookup({ resolver })("mx.example.test", 465);
    expect(resolver.calls[0]).toBe("_465._tcp.mx.example.test");
  });

  test("★캐시가 재조회를 막는다 — 실패 판정도 캐시한다", async () => {
    // 실패를 캐시하지 않으면 문제 있는 도메인마다 매 통이 루트부터 재귀 질의를 낸다.
    const resolver = fakeResolver({ status: "bogus", reason: "x" });
    const lookup = createTlsaLookup({ resolver });
    await lookup("mx.example.test", 25);
    await lookup("mx.example.test", 25);
    expect(resolver.calls.length).toBe(1);
  });

  test("캐시는 MX·포트별로 갈린다", async () => {
    const resolver = fakeResolver({ status: "insecure", reason: "x" });
    const lookup = createTlsaLookup({ resolver });
    await lookup("mx1.example.test", 25);
    await lookup("mx2.example.test", 25);
    await lookup("mx1.example.test", 587);
    expect(resolver.calls.length).toBe(3);
  });

  test("TTL이 지나면 다시 묻는다", async () => {
    const resolver = fakeResolver({ status: "insecure", reason: "x" });
    const lookup = createTlsaLookup({ resolver, cacheTtlMs: 0 });
    await lookup("mx.example.test", 25);
    await lookup("mx.example.test", 25);
    expect(resolver.calls.length).toBe(2);
  });
});
