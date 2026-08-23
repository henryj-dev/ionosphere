import { describe, expect, test } from "@ionosphere/testkit";
import {
  decodeMessage,
  encodeMessage,
  encodeQuery,
  ptrQueryName,
  RCode,
  RRClass,
  RRType,
  type DnsMessage,
  type DnsRecord,
} from "../src/wire.ts";

/** 헬퍼: 헤더 기본값 채운 응답 메시지 생성. */
function msg(over: Partial<DnsMessage> & { answers?: DnsRecord[] }): DnsMessage {
  return {
    header: {
      id: 0x1234,
      qr: true,
      opcode: 0,
      aa: true,
      tc: false,
      rd: false,
      ra: false,
      rcode: RCode.NOERROR,
      ...(over.header ?? {}),
    },
    questions: over.questions ?? [{ name: "example.com", type: RRType.A, class: RRClass.IN }],
    answers: over.answers ?? [],
    authorities: over.authorities ?? [],
    additionals: over.additionals ?? [],
  };
}

function rr(name: string, ttl: number, rdata: DnsRecord["rdata"], type: number): DnsRecord {
  return { name, type, class: RRClass.IN, ttl, rdata };
}

describe("wire: 질의 인코딩", () => {
  test("encodeQuery 라운드트립 — 이름/타입/RD 플래그", () => {
    const packet = encodeQuery(0xabcd, "mail.example.com", RRType.MX, true);
    const decoded = decodeMessage(packet);
    expect(decoded.header.id).toBe(0xabcd);
    expect(decoded.header.qr).toBe(false);
    expect(decoded.header.rd).toBe(true);
    expect(decoded.questions).toHaveLength(1);
    expect(decoded.questions[0]!.name).toBe("mail.example.com");
    expect(decoded.questions[0]!.type).toBe(RRType.MX);
    expect(decoded.questions[0]!.class).toBe(RRClass.IN);
  });

  test("루트 이름(빈 문자열) 인코딩", () => {
    const packet = encodeQuery(1, "", RRType.NS, false);
    const decoded = decodeMessage(packet);
    expect(decoded.questions[0]!.name).toBe("");
  });
});

describe("wire: 레코드 라운드트립", () => {
  test("A", () => {
    const m = msg({ answers: [rr("example.com", 300, { kind: "A", address: "93.184.216.34" }, RRType.A)] });
    const d = decodeMessage(encodeMessage(m));
    expect(d.answers[0]!.rdata).toEqual({ kind: "A", address: "93.184.216.34" });
    expect(d.answers[0]!.ttl).toBe(300);
  });

  test("AAAA — 압축/해제 라운드트립", () => {
    const m = msg({ answers: [rr("example.com", 60, { kind: "AAAA", address: "2606:2800:220:1:248:1893:25c8:1946" }, RRType.AAAA)] });
    const d = decodeMessage(encodeMessage(m));
    expect(d.answers[0]!.rdata).toEqual({ kind: "AAAA", address: "2606:2800:220:1:248:1893:25c8:1946" });
  });

  test("AAAA — :: 압축 표기(모두 0)", () => {
    const m = msg({ answers: [rr("x.", 1, { kind: "AAAA", address: "::" }, RRType.AAAA)] });
    const d = decodeMessage(encodeMessage(m));
    expect((d.answers[0]!.rdata as { address: string }).address).toBe("::");
  });

  test("AAAA — 선행 0 압축", () => {
    const m = msg({ answers: [rr("x.", 1, { kind: "AAAA", address: "2001:db8::1" }, RRType.AAAA)] });
    const d = decodeMessage(encodeMessage(m));
    expect((d.answers[0]!.rdata as { address: string }).address).toBe("2001:db8::1");
  });

  test("MX", () => {
    const m = msg({
      answers: [
        rr("example.com", 3600, { kind: "MX", preference: 10, exchange: "mx1.example.com" }, RRType.MX),
        rr("example.com", 3600, { kind: "MX", preference: 20, exchange: "mx2.example.com" }, RRType.MX),
      ],
    });
    const d = decodeMessage(encodeMessage(m));
    expect(d.answers).toHaveLength(2);
    expect(d.answers[0]!.rdata).toEqual({ kind: "MX", preference: 10, exchange: "mx1.example.com" });
    expect(d.answers[1]!.rdata).toEqual({ kind: "MX", preference: 20, exchange: "mx2.example.com" });
  });

  test("NS/CNAME/PTR", () => {
    const m = msg({
      answers: [
        rr("example.com", 100, { kind: "NS", target: "ns1.example.com" }, RRType.NS),
        rr("www.example.com", 100, { kind: "CNAME", target: "example.com" }, RRType.CNAME),
        rr("34.216.184.93.in-addr.arpa", 100, { kind: "PTR", target: "example.com" }, RRType.PTR),
      ],
    });
    const d = decodeMessage(encodeMessage(m));
    expect(d.answers[0]!.rdata).toEqual({ kind: "NS", target: "ns1.example.com" });
    expect(d.answers[1]!.rdata).toEqual({ kind: "CNAME", target: "example.com" });
    expect(d.answers[2]!.rdata).toEqual({ kind: "PTR", target: "example.com" });
  });

  test("SOA", () => {
    const m = msg({
      authorities: [
        rr(
          "example.com",
          900,
          {
            kind: "SOA",
            mname: "ns1.example.com",
            rname: "hostmaster.example.com",
            serial: 2024010101,
            refresh: 7200,
            retry: 3600,
            expire: 1209600,
            minimum: 300,
          },
          RRType.SOA,
        ),
      ],
    });
    const d = decodeMessage(encodeMessage(m));
    expect(d.authorities[0]!.rdata).toEqual({
      kind: "SOA",
      mname: "ns1.example.com",
      rname: "hostmaster.example.com",
      serial: 2024010101,
      refresh: 7200,
      retry: 3600,
      expire: 1209600,
      minimum: 300,
    });
  });
});

describe("wire: TXT 청크 재조합", () => {
  test("단일 조각", () => {
    const m = msg({ answers: [rr("example.com", 300, { kind: "TXT", text: "v=spf1 -all", chunks: ["v=spf1 -all"] }, RRType.TXT)] });
    const d = decodeMessage(encodeMessage(m));
    expect((d.answers[0]!.rdata as { text: string }).text).toBe("v=spf1 -all");
  });

  test("255바이트 초과 → 여러 조각 이어붙이기(RSA DKIM 키 케이스)", () => {
    const part1 = "p=".concat("A".repeat(253)); // 255바이트
    const part2 = "B".repeat(200);
    const full = part1 + part2;
    const m = msg({
      answers: [rr("sel._domainkey.example.com", 300, { kind: "TXT", text: full, chunks: [part1, part2] }, RRType.TXT)],
    });
    const encoded = encodeMessage(m);
    const d = decodeMessage(encoded);
    const rdata = d.answers[0]!.rdata as { kind: string; text: string; chunks: string[] };
    expect(rdata.text).toBe(full);
    expect(rdata.chunks).toHaveLength(2);
    expect(rdata.chunks[0]!.length).toBe(255);
  });
});

describe("wire: 이름 압축 포인터 디코딩", () => {
  test("0xC0 포인터로 압축된 이름 해제", () => {
    // 손수 만든 버퍼: 헤더 + 질문(example.com A) + 답(포인터로 example.com 재사용)
    const header = new Uint8Array([
      0x12, 0x34, // id
      0x81, 0x80, // flags: qr, rd, ra
      0x00, 0x01, // qd=1
      0x00, 0x01, // an=1
      0x00, 0x00, // ns=0
      0x00, 0x00, // ar=0
    ]);
    // 질문: 7 example 3 com 0, type A, class IN — QNAME 시작 오프셋 12
    const qname = new Uint8Array([
      7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
      3, 0x63, 0x6f, 0x6d, // "com"
      0,
    ]);
    const qtail = new Uint8Array([0x00, 0x01, 0x00, 0x01]); // A IN
    // 답: NAME=포인터(0xC00C → 오프셋 12), type A, class IN, ttl 60, rdlen 4, 1.2.3.4
    const ans = new Uint8Array([
      0xc0, 0x0c, // 포인터 → offset 12
      0x00, 0x01, // A
      0x00, 0x01, // IN
      0x00, 0x00, 0x00, 0x3c, // ttl 60
      0x00, 0x04, // rdlen 4
      1, 2, 3, 4,
    ]);
    const buf = new Uint8Array([...header, ...qname, ...qtail, ...ans]);
    const d = decodeMessage(buf);
    expect(d.questions[0]!.name).toBe("example.com");
    expect(d.answers[0]!.name).toBe("example.com"); // 포인터 해제됨
    expect(d.answers[0]!.rdata).toEqual({ kind: "A", address: "1.2.3.4" });
    expect(d.answers[0]!.ttl).toBe(60);
  });
});

describe("wire: ptrQueryName", () => {
  test("IPv4 → in-addr.arpa", () => {
    expect(ptrQueryName("1.2.3.4")).toBe("4.3.2.1.in-addr.arpa");
  });

  test("IPv6 → ip6.arpa (니블 역순)", () => {
    // 2001:db8::1 → 32 니블 역순 + .ip6.arpa
    expect(ptrQueryName("2001:db8::1")).toBe(
      "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
    );
  });

  test("잘못된 IP → null", () => {
    expect(ptrQueryName("999.1.1.1")).toBeNull();
    expect(ptrQueryName("not-an-ip")).toBeNull();
  });
});

describe("wire: 에러", () => {
  test("잘린 버퍼 → DnsWireError", () => {
    expect(() => decodeMessage(new Uint8Array([0x12, 0x34]))).toThrow();
  });
});
