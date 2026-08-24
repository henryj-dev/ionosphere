/**
 * 위임 bailiwick 검사 — 상대가 우리를 **다른 zone으로 끌고 갈 수 있는가**.
 *
 * NS 레코드의 소유 이름이 질의 이름의 조상이 아니면 그건 "이 zone에 대한 위임"이 아니다
 * (RFC 1034 §4.3.2의 전제). 검사가 없으면 `evil.test`의 네임서버가 authority에
 * `gmail.com NS ns.evil.test`를 실어 그 뒤의 해석을 자기 서버로 가져갈 수 있다.
 */
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { RecursiveResolver, RRType, RCode, decodeMessage, encodeMessage, type DnsTransport } from "@ionosphere/dns";

interface Spec {
  rcode?: number;
  answers?: unknown[];
  authorities?: unknown[];
  additionals?: unknown[];
}

const NS = (owner: string, target: string): unknown => ({
  name: owner, type: RRType.NS, class: 1, ttl: 300, rdata: { kind: "NS", target },
});
const A = (owner: string, address: string): unknown => ({
  name: owner, type: RRType.A, class: 1, ttl: 300, rdata: { kind: "A", address },
});

function makeResolver(handler: (server: string, name: string) => Spec) {
  const asked: string[] = [];
  const transport: DnsTransport = {
    queryUdp: async (server: string, packet: Uint8Array) => {
      const q = decodeMessage(packet).questions[0]!;
      asked.push(server);
      const spec = handler(server, q.name);
      return encodeMessage({
        header: { id: decodeMessage(packet).header.id, qr: true, opcode: 0, aa: false, tc: false, rd: false, ra: false, rcode: spec.rcode ?? RCode.NOERROR },
        questions: [q],
        answers: (spec.answers ?? []) as never[],
        authorities: (spec.authorities ?? []) as never[],
        additionals: (spec.additionals ?? []) as never[],
      });
    },
    queryTcp: async () => {
      throw new Error("TCP 미사용");
    },
  };
  return { resolver: new RecursiveResolver({ transport, rootHints: ["10.0.0.1"] }), asked };
}

describe("referral bailiwick", () => {
  /**
   * ★핵심 — 루트가 `victim.test`에 대한 답 대신 **무관한 zone**의 NS를 실어 준다.
   * 그것을 따라가면 우리가 공격자 서버에게 `victim.test`를 물어보게 된다.
   */
  test("질의 이름의 조상이 아닌 NS는 위임으로 받아들이지 않는다", async () => {
    const { resolver, asked } = makeResolver((server, name) => {
      if (server === "10.0.0.1") {
        // authority가 전혀 다른 zone(other.test)을 가리킨다 — 위임이 아니다.
        return { authorities: [NS("other.test", "ns.evil.test")], additionals: [A("ns.evil.test", "10.9.9.9")] };
      }
      return { answers: [A(name, "1.2.3.4")] };
    });

    await expect(resolver.a("victim.test")).rejects.toThrow();
    // 공격자 주소로는 한 번도 묻지 않아야 한다.
    expect(asked.includes("10.9.9.9")).toBe(false);
  });

  test("정상 위임(조상 이름)은 그대로 따라간다", async () => {
    const { resolver, asked } = makeResolver((server, name) => {
      if (server === "10.0.0.1") {
        return { authorities: [NS("test", "ns.tld.test")], additionals: [A("ns.tld.test", "10.0.0.2")] };
      }
      if (server === "10.0.0.2") {
        return { authorities: [NS("ok.test", "ns.ok.test")], additionals: [A("ns.ok.test", "10.0.0.3")] };
      }
      return { answers: [A(name, "1.2.3.4")] };
    });

    expect(await resolver.a("host.ok.test")).toEqual(["1.2.3.4"]);
    expect(asked).toEqual(["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
  });

  /**
   * ★zone **밖의 글루 이름**은 막지 않는다. 실제 위임 상당수가 그렇게 생겼고
   * (`example.com NS ns1.provider.net`), 거부하면 정상 도메인이 해석되지 않는다.
   * 캐시 키가 질의 이름이라 다른 이름을 오염시킬 수도 없다.
   */
  test("zone 밖 글루 이름은 정상 처리한다", async () => {
    const { resolver } = makeResolver((server, name) => {
      if (server === "10.0.0.1") {
        // `ok.test`를 `.test` 밖의 이름으로 위임 — 현실에서 흔한 형태다.
        return { authorities: [NS("ok.test", "ns1.provider.example")], additionals: [A("ns1.provider.example", "10.0.0.5")] };
      }
      return { answers: [A(name, "5.6.7.8")] };
    });
    expect(await resolver.a("host.ok.test")).toEqual(["5.6.7.8"]);
  });
});
