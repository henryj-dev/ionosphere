/**
 * DNSSEC 검증기.
 *
 * ★이 파일이 지키는 것은 "통과시키는가"가 아니라 **"틀린 것을 통과시키지 않는가"**다.
 * 검증기의 버그는 곧 **거짓 보안**이다 — DANE가 그 위에 서기 때문에, 서명이 틀렸는데
 * secure를 돌려주면 없는 보호를 있다고 주장하게 된다.
 *
 * 실제 키로 서명을 만들어 왕복 검증한다. 고정 벡터가 아니라 왕복인 이유: 우리가 만드는
 * **정규 형식(canonical form)**이 맞아야 서명이 성립하므로, 왕복이 통과하면 정규화도 맞다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { createHash, createSign, generateKeyPairSync, sign as signOneShot } from "node:crypto";
import { DNSSEC_ALGO, dsMatchesKey, keyTag, verifyRrset } from "../src/dnssec.ts";
import { RRType, type DnsRecord, type RData } from "../src/wire.ts";

const NOW = Date.UTC(2026, 7, 7) ;
const INCEPTION = Math.floor(NOW / 1000) - 3600;
const EXPIRATION = Math.floor(NOW / 1000) + 3600;

function nameBytes(name: string): number[] {
  const out: number[] = [];
  for (const l of name.replace(/\.$/, "").toLowerCase().split(".").filter(Boolean)) {
    const b = [...new TextEncoder().encode(l)];
    out.push(b.length, ...b);
  }
  out.push(0);
  return out;
}
const u16 = (n: number): number[] => [(n >> 8) & 0xff, n & 0xff];
const u32 = (n: number): number[] => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];

/** TLSA RR 하나. */
function tlsaRecord(name: string, data: number[]): DnsRecord {
  return {
    name,
    type: RRType.TLSA,
    class: 1,
    ttl: 300,
    rdata: { kind: "TLSA", usage: 3, selector: 1, matchingType: 1, data: new Uint8Array(data) },
  };
}

/** 검증기와 **같은 규칙**으로 서명 대상 바이트를 만든다(테스트 쪽 독립 구현). */
function buildSignedData(prefix: number[], rrs: DnsRecord[]): Buffer {
  const owner = nameBytes(rrs[0]!.name);
  const rows = rrs.map((rr) => {
    const d = rr.rdata as Extract<RData, { kind: "TLSA" }>;
    const rdata = [d.usage, d.selector, d.matchingType, ...d.data];
    return Buffer.from([...owner, ...u16(rr.type), ...u16(rr.class), ...u32(300), ...u16(rdata.length), ...rdata]);
  });
  rows.sort(Buffer.compare);
  return Buffer.concat([Buffer.from(prefix), ...rows]);
}

/** RRSIG의 "서명 제외 앞부분" — 검증기가 원본 바이트로 쓰는 그 값. */
function rrsigPrefix(algorithm: number, tag: number, signer: string): number[] {
  return [
    ...u16(RRType.TLSA),
    algorithm,
    2, // labels
    ...u32(300),
    ...u32(EXPIRATION),
    ...u32(INCEPTION),
    ...u16(tag),
    ...nameBytes(signer),
  ];
}

function rrsigRecord(name: string, prefix: number[], signature: Uint8Array, algorithm: number, tag: number, signer: string): DnsRecord {
  return {
    name,
    type: RRType.RRSIG,
    class: 1,
    ttl: 300,
    rdata: {
      kind: "RRSIG",
      typeCovered: RRType.TLSA,
      algorithm,
      labels: 2,
      originalTtl: 300,
      expiration: EXPIRATION,
      inception: INCEPTION,
      keyTag: tag,
      signerName: signer,
      signature,
      rdataPrefix: new Uint8Array(prefix),
    },
  };
}

/** Ed25519 키 한 쌍 → DNSKEY RDATA(raw 32바이트). */
function ed25519Key(): { dnskey: Extract<RData, { kind: "DNSKEY" }>; sign: (d: Buffer) => Buffer } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const raw = spki.subarray(spki.length - 32); // SPKI 꼬리 32바이트가 원시 공개키
  return {
    dnskey: { kind: "DNSKEY", flags: 256, protocol: 3, algorithm: DNSSEC_ALGO.ED25519, publicKey: new Uint8Array(raw) },
    sign: (d) => signOneShot(null, d, privateKey),
  };
}

/** ECDSA P-256 키 한 쌍 → DNSKEY RDATA(X||Y 64바이트). */
function ecdsaKey(): { dnskey: Extract<RData, { kind: "DNSKEY" }>; sign: (d: Buffer) => Buffer } {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const raw = spki.subarray(spki.length - 64);
  return {
    dnskey: { kind: "DNSKEY", flags: 256, protocol: 3, algorithm: DNSSEC_ALGO.ECDSAP256SHA256, publicKey: new Uint8Array(raw) },
    sign: (d) => signOneShot("sha256", d, { key: privateKey, dsaEncoding: "ieee-p1363" }),
  };
}

/** RSA-2048 키 한 쌍 → DNSKEY RDATA(RFC 3110: expLen|exp|mod). */
function rsaKey(): { dnskey: Extract<RData, { kind: "DNSKEY" }>; sign: (d: Buffer) => Buffer } {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" }) as { n: string; e: string };
  const mod = Buffer.from(jwk.n, "base64url");
  const exp = Buffer.from(jwk.e, "base64url");
  const rdataKey = Buffer.concat([Buffer.from([exp.length]), exp, mod]);
  return {
    dnskey: { kind: "DNSKEY", flags: 256, protocol: 3, algorithm: DNSSEC_ALGO.RSASHA256, publicKey: new Uint8Array(rdataKey) },
    sign: (d) => {
      const s = createSign("sha256");
      s.update(d);
      s.end();
      return s.sign(privateKey);
    },
  };
}

function keyRecord(zone: string, dnskey: Extract<RData, { kind: "DNSKEY" }>): DnsRecord {
  return { name: zone, type: RRType.DNSKEY, class: 1, ttl: 300, rdata: dnskey };
}

/** 한 알고리즘으로 왕복 검증 시나리오를 만든다. */
function scenario(mk: () => { dnskey: Extract<RData, { kind: "DNSKEY" }>; sign: (d: Buffer) => Buffer }) {
  const zone = "example.test";
  const owner = "_25._tcp.mx.example.test";
  const { dnskey, sign } = mk();
  const tag = keyTag(dnskey);
  const rrs = [tlsaRecord(owner, [1, 2, 3, 4]), tlsaRecord(owner, [9, 9, 9, 9])];
  const prefix = rrsigPrefix(dnskey.algorithm, tag, zone);
  const sig = sign(buildSignedData(prefix, rrs));
  return { zone, rrs, keys: [keyRecord(zone, dnskey)], sig: rrsigRecord(owner, prefix, new Uint8Array(sig), dnskey.algorithm, tag, zone), dnskey, tag };
}

describe("verifyRrset — 알고리즘 3종 왕복", () => {
  for (const [label, mk] of [
    ["Ed25519", ed25519Key],
    ["ECDSA P-256", ecdsaKey],
    ["RSA-SHA256", rsaKey],
  ] as const) {
    test(`★${label}: 올바른 서명은 secure`, () => {
      const s = scenario(mk);
      expect(verifyRrset(s.rrs, [s.sig], s.keys, NOW)).toEqual({ status: "secure" });
    });

    test(`★${label}: 데이터를 한 바이트 바꾸면 bogus`, () => {
      const s = scenario(mk);
      // RRset을 조작한다 — 서명은 그대로. 이걸 secure로 통과시키면 검증기가 무용하다.
      const tampered = [tlsaRecord(s.rrs[0]!.name, [1, 2, 3, 5]), s.rrs[1]!];
      expect(verifyRrset(tampered, [s.sig], s.keys, NOW).status).toBe("bogus");
    });
  }
});

describe("verifyRrset — 거절해야 하는 것", () => {
  test("★만료된 서명은 쓰지 않는다 — 재생 공격 방지", () => {
    const s = scenario(ed25519Key);
    // 유효기간 밖의 시각으로 검증
    const later = (EXPIRATION + 10) * 1000;
    expect(verifyRrset(s.rrs, [s.sig], s.keys, later).status).not.toBe("secure");
  });

  test("★아직 유효하지 않은 서명도 쓰지 않는다", () => {
    const s = scenario(ed25519Key);
    const earlier = (INCEPTION - 10) * 1000;
    expect(verifyRrset(s.rrs, [s.sig], s.keys, earlier).status).not.toBe("secure");
  });

  test("★다른 키로는 통과하지 못한다", () => {
    const s = scenario(ed25519Key);
    const other = ed25519Key();
    // keyTag가 우연히 같을 수 있어 태그를 맞춰 준다 — 그래도 서명은 안 맞아야 한다.
    const forged = { ...other.dnskey };
    expect(verifyRrset(s.rrs, [s.sig], [keyRecord(s.zone, forged)], NOW).status).not.toBe("secure");
  });

  test("RRSIG이 없으면 insecure (bogus가 아니다 — 조작이 아니라 서명 부재다)", () => {
    const s = scenario(ed25519Key);
    expect(verifyRrset(s.rrs, [], s.keys, NOW).status).toBe("insecure");
  });

  test("DNSKEY가 없으면 insecure", () => {
    const s = scenario(ed25519Key);
    expect(verifyRrset(s.rrs, [s.sig], [], NOW).status).toBe("insecure");
  });

  test("★미지원 알고리즘은 insecure — 추측해서 통과시키지 않는다", () => {
    const s = scenario(ed25519Key);
    const unsupported: DnsRecord = {
      ...s.keys[0]!,
      rdata: { ...s.dnskey, algorithm: 5 }, // RSASHA1 — 받지 않는다
    };
    const sigUnsupported = {
      ...s.sig,
      rdata: { ...(s.sig.rdata as Extract<RData, { kind: "RRSIG" }>), algorithm: 5 },
    };
    expect(verifyRrset(s.rrs, [sigUnsupported], [unsupported], NOW).status).toBe("insecure");
  });

  test("빈 RRset은 insecure", () => {
    const s = scenario(ed25519Key);
    expect(verifyRrset([], [s.sig], s.keys, NOW).status).toBe("insecure");
  });
});

describe("dsMatchesKey", () => {
  test("★올바른 DS는 키와 맞는다", () => {
    const { dnskey } = ed25519Key();
    const zone = "example.test";
    const rdata = Buffer.from([...u16(dnskey.flags), dnskey.protocol, dnskey.algorithm, ...dnskey.publicKey]);
    const digest = createHash("sha256")
      .update(Buffer.from(nameBytes(zone)))
      .update(rdata)
      .digest();
    const ds: Extract<RData, { kind: "DS" }> = {
      kind: "DS",
      keyTag: keyTag(dnskey),
      algorithm: dnskey.algorithm,
      digestType: 2,
      digest: new Uint8Array(digest),
    };
    expect(dsMatchesKey(ds, zone, dnskey)).toBe(true);
  });

  test("★SHA-1 digest는 받지 않는다 — 이미 안전하지 않다", () => {
    const { dnskey } = ed25519Key();
    const ds: Extract<RData, { kind: "DS" }> = {
      kind: "DS",
      keyTag: keyTag(dnskey),
      algorithm: dnskey.algorithm,
      digestType: 1, // SHA-1
      digest: new Uint8Array(20),
    };
    expect(dsMatchesKey(ds, "example.test", dnskey)).toBe(false);
  });

  test("digest가 다르면 안 맞는다", () => {
    const { dnskey } = ed25519Key();
    const ds: Extract<RData, { kind: "DS" }> = {
      kind: "DS",
      keyTag: keyTag(dnskey),
      algorithm: dnskey.algorithm,
      digestType: 2,
      digest: new Uint8Array(32),
    };
    expect(dsMatchesKey(ds, "example.test", dnskey)).toBe(false);
  });
});
