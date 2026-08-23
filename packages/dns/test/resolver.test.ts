import { describe, expect, test } from "@ionosphere/testkit";
import { DnsNotFoundError, DnsTemporaryError } from "@ionosphere/mail-auth";
import { RecursiveResolver } from "../src/resolver.ts";
import { UdpTcpTransport, type DnsTransport } from "../src/transport.ts";
import {
  decodeMessage,
  encodeMessage,
  RCode,
  RRClass,
  RRType,
  type DnsQuestion,
  type DnsRecord,
} from "../src/wire.ts";

// ─────────── 레코드 헬퍼 ───────────
function A(name: string, addr: string, ttl = 300): DnsRecord {
  return { name, type: RRType.A, class: RRClass.IN, ttl, rdata: { kind: "A", address: addr } };
}
function NS(name: string, target: string, ttl = 300): DnsRecord {
  return { name, type: RRType.NS, class: RRClass.IN, ttl, rdata: { kind: "NS", target } };
}
function CNAME(name: string, target: string, ttl = 300): DnsRecord {
  return { name, type: RRType.CNAME, class: RRClass.IN, ttl, rdata: { kind: "CNAME", target } };
}
function TXT(name: string, chunks: string[], ttl = 300): DnsRecord {
  return { name, type: RRType.TXT, class: RRClass.IN, ttl, rdata: { kind: "TXT", text: chunks.join(""), chunks } };
}
function SOA(name: string, minimum: number, ttl = 300): DnsRecord {
  return {
    name,
    type: RRType.SOA,
    class: RRClass.IN,
    ttl,
    rdata: {
      kind: "SOA",
      mname: "ns.auth",
      rname: "hostmaster.auth",
      serial: 1,
      refresh: 7200,
      retry: 3600,
      expire: 1209600,
      minimum,
    },
  };
}

interface ResponseSpec {
  rcode?: number;
  aa?: boolean;
  tc?: boolean;
  answers?: DnsRecord[];
  authorities?: DnsRecord[];
  additionals?: DnsRecord[];
}

type Handler = (server: string, q: DnsQuestion) => ResponseSpec;

/** 캔드 응답을 서빙하는 mock transport — 질의 ID/질문을 그대로 에코. */
class MockTransport implements DnsTransport {
  udpCalls = 0;
  tcpCalls = 0;
  private handler: Handler;

  constructor(handler: Handler) {
    this.handler = handler;
  }

  private encode(id: number, q: DnsQuestion, spec: ResponseSpec, forceNoTc: boolean): Uint8Array {
    return encodeMessage({
      header: {
        id,
        qr: true,
        opcode: 0,
        aa: spec.aa ?? true,
        tc: forceNoTc ? false : (spec.tc ?? false),
        rd: false,
        ra: false,
        rcode: spec.rcode ?? RCode.NOERROR,
      },
      questions: [q],
      answers: spec.answers ?? [],
      authorities: spec.authorities ?? [],
      additionals: spec.additionals ?? [],
    });
  }

  queryUdp(server: string, packet: Uint8Array): Promise<Uint8Array> {
    this.udpCalls++;
    const query = decodeMessage(packet);
    const q = query.questions[0]!;
    const spec = this.handler(server, q);
    return Promise.resolve(this.encode(query.header.id, q, spec, false));
  }

  queryTcp(server: string, packet: Uint8Array): Promise<Uint8Array> {
    this.tcpCalls++;
    const query = decodeMessage(packet);
    const q = query.questions[0]!;
    const spec = this.handler(server, q);
    // TCP 재시도에서는 TC 비트를 끈다(실서버 동작 모사).
    return Promise.resolve(this.encode(query.header.id, q, spec, true));
  }
}

/**
 * 위임 계층 시뮬레이션:
 *   root(10.0.0.1) → TLD "test"(10.0.0.2) → authoritative "dnsbl.test"(10.0.0.3)
 */
function makeResolver(handler: Handler, extra?: { transport?: MockTransport }): {
  resolver: RecursiveResolver;
  transport: MockTransport;
} {
  const transport = extra?.transport ?? new MockTransport(handler);
  const resolver = new RecursiveResolver({
    rootHints: ["10.0.0.1"],
    transport,
    randomId: () => 0x4242,
    timeoutMs: 500,
  });
  return { resolver, transport };
}

/** 표준 위임(root→tld→auth) 후 auth 서버 응답만 authFn으로 커스터마이즈. */
function delegatingHandler(authFn: (q: DnsQuestion) => ResponseSpec): Handler {
  return (server, q) => {
    if (server === "10.0.0.1") {
      return { aa: false, authorities: [NS("test", "ns.tld")], additionals: [A("ns.tld", "10.0.0.2")] };
    }
    if (server === "10.0.0.2") {
      return { aa: false, authorities: [NS("dnsbl.test", "ns.dnsbl")], additionals: [A("ns.dnsbl", "10.0.0.3")] };
    }
    if (server === "10.0.0.3") return authFn(q);
    return { rcode: RCode.SERVFAIL };
  };
}

describe("RecursiveResolver: iterative 위임 따라가기", () => {
  test("root → TLD → authoritative 를 거쳐 A 응답", async () => {
    const { resolver, transport } = makeResolver(
      delegatingHandler((q) =>
        q.name === "listed.dnsbl.test" && q.type === RRType.A
          ? { answers: [A("listed.dnsbl.test", "127.0.0.2")] }
          : { rcode: RCode.NXDOMAIN, authorities: [SOA("dnsbl.test", 300)] },
      ),
    );
    const addrs = await resolver.a("listed.dnsbl.test");
    expect(addrs).toEqual(["127.0.0.2"]);
    // root + tld + auth = 3회 UDP
    expect(transport.udpCalls).toBe(3);
  });

  test("글루 없는 위임 → NS 이름 A를 재귀 해석", async () => {
    // dnsbl.test를 글루 없이 ns.dnsbl.test로 위임. ns.dnsbl.test의 A는 같은 TLD가 직접 답할 수
    // 있으므로(.test 하위) 리졸버가 별도 재귀로 그 주소를 얻어 auth(10.0.0.3)에 질의한다.
    const handler: Handler = (server, q) => {
      if (server === "10.0.0.1") {
        return { aa: false, authorities: [NS("test", "ns.tld")], additionals: [A("ns.tld", "10.0.0.2")] };
      }
      if (server === "10.0.0.2") {
        if (q.name === "ns.dnsbl.test" && q.type === RRType.A) {
          return { answers: [A("ns.dnsbl.test", "10.0.0.3")] }; // NS 이름 A를 TLD가 직접 응답
        }
        return { aa: false, authorities: [NS("dnsbl.test", "ns.dnsbl.test")] }; // 글루 없는 위임
      }
      if (server === "10.0.0.3") {
        if (q.name === "host.dnsbl.test") return { answers: [A("host.dnsbl.test", "5.6.7.8")] };
        return { rcode: RCode.NXDOMAIN, authorities: [SOA("dnsbl.test", 300)] };
      }
      return { rcode: RCode.SERVFAIL };
    };
    const { resolver } = makeResolver(handler);
    const addrs = await resolver.a("host.dnsbl.test");
    expect(addrs).toEqual(["5.6.7.8"]);
  });
});

describe("RecursiveResolver: CNAME", () => {
  test("동일 응답 내 CNAME 체인을 따라 A 반환", async () => {
    const { resolver } = makeResolver(
      delegatingHandler((q) => {
        if (q.name === "alias.dnsbl.test") {
          return {
            answers: [CNAME("alias.dnsbl.test", "canon.dnsbl.test"), A("canon.dnsbl.test", "9.9.9.9")],
          };
        }
        return { rcode: RCode.NXDOMAIN, authorities: [SOA("dnsbl.test", 300)] };
      }),
    );
    const addrs = await resolver.a("alias.dnsbl.test");
    expect(addrs).toEqual(["9.9.9.9"]);
  });
});

describe("RecursiveResolver: 에러 매핑", () => {
  test("NXDOMAIN → DnsNotFoundError", async () => {
    const { resolver } = makeResolver(
      delegatingHandler(() => ({ rcode: RCode.NXDOMAIN, authorities: [SOA("dnsbl.test", 300)] })),
    );
    await expect(resolver.a("nope.dnsbl.test")).rejects.toBeInstanceOf(DnsNotFoundError);
  });

  test("NODATA(NOERROR + SOA, 답 없음) → DnsNotFoundError", async () => {
    const { resolver } = makeResolver(
      delegatingHandler(() => ({ rcode: RCode.NOERROR, authorities: [SOA("dnsbl.test", 300)] })),
    );
    await expect(resolver.a("nodata.dnsbl.test")).rejects.toBeInstanceOf(DnsNotFoundError);
  });

  test("SERVFAIL → DnsTemporaryError", async () => {
    const { resolver } = makeResolver(delegatingHandler(() => ({ rcode: RCode.SERVFAIL })));
    await expect(resolver.a("fail.dnsbl.test")).rejects.toBeInstanceOf(DnsTemporaryError);
  });
});

describe("RecursiveResolver: TXT 청크", () => {
  test("여러 조각을 이어붙여 반환", async () => {
    const p1 = "v=DKIM1; k=rsa; p=".concat("A".repeat(237)); // 255바이트
    const p2 = "BBBBCCCC";
    const { resolver } = makeResolver(
      delegatingHandler((q) =>
        q.type === RRType.TXT
          ? { answers: [TXT("sel._domainkey.dnsbl.test", [p1, p2])] }
          : { rcode: RCode.NXDOMAIN, authorities: [SOA("dnsbl.test", 300)] },
      ),
    );
    const txt = await resolver.txt("sel._domainkey.dnsbl.test");
    expect(txt).toEqual([p1 + p2]);
  });
});

describe("RecursiveResolver: TC 비트 → TCP 폴백", () => {
  test("UDP TC=1 이면 TCP로 재질의", async () => {
    const handler = delegatingHandler((q) =>
      q.name === "big.dnsbl.test" ? { tc: true, answers: [A("big.dnsbl.test", "1.1.1.1")] } : { rcode: RCode.SERVFAIL },
    );
    const { resolver, transport } = makeResolver(handler);
    const addrs = await resolver.a("big.dnsbl.test");
    expect(addrs).toEqual(["1.1.1.1"]);
    expect(transport.tcpCalls).toBeGreaterThan(0);
  });
});

describe("RecursiveResolver: 캐시", () => {
  test("두 번째 조회는 캐시 히트(전송 없음)", async () => {
    const { resolver, transport } = makeResolver(
      delegatingHandler((q) =>
        q.name === "cached.dnsbl.test" ? { answers: [A("cached.dnsbl.test", "2.2.2.2")] } : { rcode: RCode.SERVFAIL },
      ),
    );
    await resolver.a("cached.dnsbl.test");
    const after = transport.udpCalls;
    await resolver.a("cached.dnsbl.test");
    expect(transport.udpCalls).toBe(after); // 증가 없음
  });

  test("네거티브 캐시 — NXDOMAIN 재조회도 전송 없이 NotFound", async () => {
    const { resolver, transport } = makeResolver(
      delegatingHandler(() => ({ rcode: RCode.NXDOMAIN, authorities: [SOA("dnsbl.test", 300)] })),
    );
    await expect(resolver.a("gone.dnsbl.test")).rejects.toBeInstanceOf(DnsNotFoundError);
    const after = transport.udpCalls;
    await expect(resolver.a("gone.dnsbl.test")).rejects.toBeInstanceOf(DnsNotFoundError);
    expect(transport.udpCalls).toBe(after);
  });
});

describe("RecursiveResolver: PTR", () => {
  test("IP → in-addr.arpa PTR 조회", async () => {
    // 역방향은 in-addr.arpa 트리 — root가 arpa로 위임한다고 가정하고 auth에서 답.
    const handler: Handler = (server, q) => {
      if (server === "10.0.0.1") {
        return { aa: false, authorities: [NS("arpa", "ns.arpa")], additionals: [A("ns.arpa", "10.0.0.9")] };
      }
      if (server === "10.0.0.9") {
        if (q.type === RRType.PTR) {
          return { answers: [{ name: q.name, type: RRType.PTR, class: RRClass.IN, ttl: 300, rdata: { kind: "PTR", target: "host.example.com" } }] };
        }
        return { rcode: RCode.NXDOMAIN, authorities: [SOA("arpa", 300)] };
      }
      return { rcode: RCode.SERVFAIL };
    };
    const { resolver } = makeResolver(handler);
    const names = await resolver.ptr("1.2.3.4");
    expect(names).toEqual(["host.example.com"]);
  });
});

// ─────────── 실제 네트워크 조회(오프라인/CI에서 스킵) ───────────
// IONOSPHERE_TEST_DNS_LIVE=1 일 때만 실행. 실제 재귀(루트힌트→...)로 A 레코드 1건 조회.
const liveEnabled = process.env.IONOSPHERE_TEST_DNS_LIVE === "1";
describe.skipIf(!liveEnabled)("RecursiveResolver: 실제 네트워크(게이트)", () => {
  test("iterative 로 example.com A 해석", async () => {
    const resolver = new RecursiveResolver({ transport: new UdpTcpTransport(), timeoutMs: 5000 });
    const addrs = await resolver.a("example.com");
    expect(addrs.length).toBeGreaterThan(0);
    expect(addrs[0]).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
  });
});
