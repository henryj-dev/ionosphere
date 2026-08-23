/**
 * DNSSEC 검증 리졸버 — 루트 앵커부터 TLSA까지 체인 전체.
 *
 * ★여기서 지키는 것도 "통과시키는가"가 아니라 **"틀린 것을 통과시키지 않는가"**다.
 * DANE가 이 판정 위에 서므로, 서명이 끊긴 체인을 secure로 돌려주면 공격자가 심은 TLSA를
 * 우리가 고정하게 된다 — DANE가 막으려던 바로 그 공격이다.
 *
 * 실제 키로 3단(루트 → test → example.test) 위임을 세우고, 각 단계를 하나씩 망가뜨려
 * 판정이 어떻게 바뀌는지 본다. 망가뜨렸는데 secure가 유지되면 그 검사는 없는 것이다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { createHash, generateKeyPairSync, sign as signOneShot } from "node:crypto";
import { ValidatingResolver } from "../src/validating.ts";
import { DNSSEC_ALGO, keyTag } from "../src/dnssec.ts";
import { RCode, RRType, type DnsMessage, type DnsRecord, type RData } from "../src/wire.ts";

const NOW = Date.UTC(2026, 7, 7);
const INCEPTION = Math.floor(NOW / 1000) - 3600;
const EXPIRATION = Math.floor(NOW / 1000) + 3600;
const TTL = 300;
const TARGET = "_25._tcp.mx.example.test";

const u16 = (n: number): number[] => [(n >> 8) & 0xff, n & 0xff];
const u32 = (n: number): number[] => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];

function nameBytes(name: string): number[] {
  const out: number[] = [];
  for (const l of name.replace(/\.$/, "").toLowerCase().split(".").filter(Boolean)) {
    const b = [...new TextEncoder().encode(l)];
    out.push(b.length, ...b);
  }
  out.push(0);
  return out;
}

/** 정규 RDATA — 검증기와 **독립으로** 다시 짠다(둘이 맞아야 서명이 성립한다). */
function rdataBytes(rd: RData): number[] {
  if (rd.kind === "DNSKEY") return [...u16(rd.flags), rd.protocol, rd.algorithm, ...rd.publicKey];
  if (rd.kind === "DS") return [...u16(rd.keyTag), rd.algorithm, rd.digestType, ...rd.digest];
  if (rd.kind === "TLSA") return [rd.usage, rd.selector, rd.matchingType, ...rd.data];
  throw new Error(`테스트가 다루지 않는 rdata: ${rd.kind}`);
}

interface Signer {
  dnskey: Extract<RData, { kind: "DNSKEY" }>;
  tag: number;
  sign: (d: Buffer) => Buffer;
}

/** ECDSA P-256 — 루트가 실제로 쓰는 알고리즘 계열 중 가장 짧아 테스트가 빠르다. */
function makeSigner(): Signer {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const dnskey: Extract<RData, { kind: "DNSKEY" }> = {
    kind: "DNSKEY",
    flags: 257,
    protocol: 3,
    algorithm: DNSSEC_ALGO.ECDSAP256SHA256,
    publicKey: new Uint8Array(spki.subarray(spki.length - 64)),
  };
  return { dnskey, tag: keyTag(dnskey), sign: (d) => signOneShot("sha256", d, { key: privateKey, dsaEncoding: "ieee-p1363" }) };
}

/** RRset에 서명해 RRSIG RR을 만든다. */
function signRrset(rrs: readonly DnsRecord[], signer: Signer, signerZone: string, expiration = EXPIRATION): DnsRecord {
  const covered = rrs[0]!.type;
  const prefix = [
    ...u16(covered),
    signer.dnskey.algorithm,
    2,
    ...u32(TTL),
    ...u32(expiration),
    ...u32(INCEPTION),
    ...u16(signer.tag),
    ...nameBytes(signerZone),
  ];
  const rows = rrs.map((rr) => {
    const rd = rdataBytes(rr.rdata);
    return Buffer.from([...nameBytes(rr.name), ...u16(rr.type), ...u16(rr.class), ...u32(TTL), ...u16(rd.length), ...rd]);
  });
  rows.sort(Buffer.compare);
  const signature = signer.sign(Buffer.concat([Buffer.from(prefix), ...rows]));
  return {
    name: rrs[0]!.name,
    type: RRType.RRSIG,
    class: 1,
    ttl: TTL,
    rdata: {
      kind: "RRSIG",
      typeCovered: covered,
      algorithm: signer.dnskey.algorithm,
      labels: 2,
      originalTtl: TTL,
      expiration,
      inception: INCEPTION,
      keyTag: signer.tag,
      signerName: signerZone,
      signature: new Uint8Array(signature),
      rdataPrefix: new Uint8Array(prefix),
    },
  };
}

/** DS RR — 부모가 자식 키를 고정하는 값. `dsMatchesKey`와 같은 공식으로 만든다. */
function dsFor(zone: string, signer: Signer): DnsRecord {
  const digest = createHash("sha256")
    .update(Buffer.from(nameBytes(zone)))
    .update(Buffer.from(rdataBytes(signer.dnskey)))
    .digest();
  return {
    name: zone,
    type: RRType.DS,
    class: 1,
    ttl: TTL,
    rdata: { kind: "DS", keyTag: signer.tag, algorithm: signer.dnskey.algorithm, digestType: 2, digest: new Uint8Array(digest) },
  };
}

function msg(over: Partial<DnsMessage> & { question: { name: string; type: number } }): DnsMessage {
  return {
    header: { id: 1, qr: true, opcode: 0, aa: true, tc: false, rd: false, ra: false, rcode: RCode.NOERROR, ...(over.header ?? {}) },
    questions: [{ name: over.question.name, type: over.question.type, class: 1 }],
    answers: over.answers ?? [],
    authorities: over.authorities ?? [],
    additionals: over.additionals ?? [],
  };
}

const rr = (name: string, type: number, rdata: RData): DnsRecord => ({ name, type, class: 1, ttl: TTL, rdata });

interface Zone {
  root: Signer;
  tld: Signer;
  leaf: Signer;
}

interface Knobs {
  /** 자식 위임에서 DS를 뺀다 — 비서명 위임 흉내. */
  dropDs?: "test" | "example.test";
  /** TLSA 데이터를 서명 뒤에 바꾼다 — 중간자 흉내. */
  tamperTlsa?: boolean;
  /** 자식 DNSKEY 집합에 서명 없이 키를 끼워 넣는다. */
  injectKey?: boolean;
  /** DS가 가리키지 않는 키로 존을 운영한다. */
  swapLeafKey?: boolean;
  /** TLSA 서명을 만료시킨다. */
  expireTlsa?: boolean;
}

/** 3단 위임을 통째로 흉내내는 가짜 망. `servers[0]`이 어느 존에 물었는지를 나타낸다. */
function fakeNet(z: Zone, knobs: Knobs = {}) {
  const rogue = makeSigner();
  const leafOperating = knobs.swapLeafKey ? rogue : z.leaf;

  const tlsaData = new Uint8Array(32).fill(7);
  const tlsaRr = rr(TARGET, RRType.TLSA, { kind: "TLSA", usage: 3, selector: 1, matchingType: 1, data: tlsaData });
  const tlsaSig = signRrset([tlsaRr], leafOperating, "example.test", knobs.expireTlsa ? INCEPTION + 1 : EXPIRATION);
  const servedTlsa = knobs.tamperTlsa
    ? rr(TARGET, RRType.TLSA, { kind: "TLSA", usage: 3, selector: 1, matchingType: 1, data: new Uint8Array(32).fill(9) })
    : tlsaRr;

  function dnskeyMsg(zone: string, signer: Signer): DnsMessage {
    const keys = [rr(zone, RRType.DNSKEY, signer.dnskey)];
    const sig = signRrset(keys, signer, zone);
    // 서명을 만든 **뒤에** 키를 끼워 넣는다 — 공격자가 할 수 있는 일이 정확히 이것이다.
    const served = knobs.injectKey && zone === "example.test" ? [...keys, rr(zone, RRType.DNSKEY, rogue.dnskey)] : keys;
    return msg({ question: { name: zone, type: RRType.DNSKEY }, answers: [...served, sig] });
  }

  function referral(child: string, parentSigner: Signer, parentZone: string, childSigner: Signer, glue: string): DnsMessage {
    const ns = rr(child, RRType.NS, { kind: "NS", target: `ns.${child}` });
    const authorities: DnsRecord[] = [ns];
    if (knobs.dropDs !== child) {
      const ds = dsFor(child, childSigner);
      authorities.push(ds, signRrset([ds], parentSigner, parentZone));
    }
    return msg({
      question: { name: TARGET, type: RRType.TLSA },
      authorities,
      additionals: [rr(`ns.${child}`, RRType.A, { kind: "A", address: glue })],
    });
  }

  return async (servers: readonly string[], name: string, qtype: number): Promise<DnsMessage> => {
    const at = servers[0];
    if (qtype === RRType.DNSKEY) {
      if (name === ".") return dnskeyMsg(".", z.root);
      if (name === "test") return dnskeyMsg("test", z.tld);
      if (name === "example.test") return dnskeyMsg("example.test", leafOperating);
    }
    if (at === "198.41.0.4") return referral("test", z.root, ".", z.tld, "10.0.0.1");
    // ★DS는 **정상 키**를 고정한다. `swapLeafKey`면 존이 다른 키로 답하므로 DS와 어긋난다 —
    // 바꿔치기한 키에 맞춰 DS까지 발행하면 체인이 일관돼 아무것도 검사하지 못한다.
    if (at === "10.0.0.1") return referral("example.test", z.tld, "test", z.leaf, "10.0.0.2");
    if (at === "10.0.0.2") {
      return msg({ question: { name: TARGET, type: RRType.TLSA }, answers: [servedTlsa, tlsaSig] });
    }
    throw new Error(`가짜 망이 모르는 서버: ${at}`);
  };
}

function makeResolver(knobs: Knobs = {}, anchorOverride?: Signer): ValidatingResolver {
  const z: Zone = { root: makeSigner(), tld: makeSigner(), leaf: makeSigner() };
  const anchorSigner = anchorOverride ?? z.root;
  const anchor = dsFor(".", anchorSigner).rdata as Extract<RData, { kind: "DS" }>;
  return new ValidatingResolver({
    rootHints: ["198.41.0.4"],
    trustAnchors: [anchor],
    now: () => NOW,
    query: fakeNet(z, knobs),
  });
}

describe("ValidatingResolver — 정상 체인", () => {
  test("루트 앵커부터 TLSA까지 이어지면 secure", async () => {
    const r = await makeResolver().validated(TARGET, RRType.TLSA);
    expect(r.status).toBe("secure");
    if (r.status === "secure") {
      expect(r.records.length).toBe(1);
      expect(r.records[0]!.rdata.kind).toBe("TLSA");
    }
  });
});

describe("ValidatingResolver — 체인이 끊기면", () => {
  test("★신뢰앵커가 다르면 bogus — 루트가 출발점이라는 뜻이다", async () => {
    // 우리 앵커가 가리키지 않는 키로 루트가 서명했다. 값이 멀쩡해도 신뢰할 근거가 없다.
    const r = await makeResolver({}, makeSigner()).validated(TARGET, RRType.TLSA);
    expect(r.status).toBe("bogus");
  });

  test("★DS 없는 위임은 insecure — 조작 신호가 아니라 '보호 없음'이다", async () => {
    const r = await makeResolver({ dropDs: "example.test" }).validated(TARGET, RRType.TLSA);
    expect(r.status).toBe("insecure");
    if (r.status === "insecure") expect(r.reason).toContain("서명되지 않은 위임");
  });

  test("★상위 위임에서 끊겨도 아래를 신뢰하지 않는다", async () => {
    // TLD의 DS가 없으면 그 아래 example.test의 서명이 아무리 멀쩡해도 근거가 없다.
    const r = await makeResolver({ dropDs: "test" }).validated(TARGET, RRType.TLSA);
    expect(r.status).toBe("insecure");
  });

  test("★DS가 가리키지 않는 키로 존을 운영하면 bogus", async () => {
    const r = await makeResolver({ swapLeafKey: true }).validated(TARGET, RRType.TLSA);
    expect(r.status).toBe("bogus");
  });

  test("★DNSKEY 집합에 서명 없이 키를 끼워 넣으면 bogus — KSK가 집합 전체를 덮어야 한다", async () => {
    // 이 검사를 빼면 공격자가 자기 키를 집합에 넣고 그것으로 아래를 전부 위조한다.
    const r = await makeResolver({ injectKey: true }).validated(TARGET, RRType.TLSA);
    expect(r.status).toBe("bogus");
  });
});

describe("ValidatingResolver — 답이 조작되면", () => {
  test("★TLSA를 서명 뒤에 바꾸면 bogus — 중간자 신호", async () => {
    const r = await makeResolver({ tamperTlsa: true }).validated(TARGET, RRType.TLSA);
    expect(r.status).toBe("bogus");
  });

  test("★만료된 서명은 secure가 아니다 — 재생 공격 방지", async () => {
    const r = await makeResolver({ expireTlsa: true }).validated(TARGET, RRType.TLSA);
    expect(r.status).not.toBe("secure");
  });
});

describe("ValidatingResolver — 조회가 실패하면", () => {
  test("★던지지 않고 insecure로 돌려준다 — 상대 DNS가 흔들려도 배달은 계속돼야 한다", async () => {
    const res = new ValidatingResolver({
      rootHints: ["198.41.0.4"],
      trustAnchors: [dsFor(".", makeSigner()).rdata as Extract<RData, { kind: "DS" }>],
      now: () => NOW,
      query: async () => {
        throw new Error("network down");
      },
    });
    const r = await res.validated(TARGET, RRType.TLSA);
    expect(r.status).toBe("insecure");
    if (r.status === "insecure") expect(r.reason).toContain("조회 실패");
  });

  test("NXDOMAIN은 insecure — 부재를 증명하지 못한다(NSEC 미구현)", async () => {
    const res = new ValidatingResolver({
      rootHints: ["198.41.0.4"],
      trustAnchors: [dsFor(".", makeSigner()).rdata as Extract<RData, { kind: "DS" }>],
      now: () => NOW,
      query: async (_s, name, qtype) => {
        if (qtype === RRType.DNSKEY) throw new Error("여기까지 오면 안 된다");
        return msg({ question: { name, type: qtype }, header: { rcode: RCode.NXDOMAIN } as DnsMessage["header"] });
      },
    });
    const r = await res.validated(TARGET, RRType.TLSA);
    expect(r.status).toBe("insecure");
  });
});
