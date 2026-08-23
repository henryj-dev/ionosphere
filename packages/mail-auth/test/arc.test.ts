/** ARC(RFC 8617) — seal→verify 왕복(RSA/Ed25519), 체인 확장(i=2), 변조 탐지, 무체인 none. */
import { describe, expect, test } from "@ionosphere/testkit";
import { arcSeal, arcVerify, generateDkimKeyPair, parseArcChain, type DkimAlgorithm } from "@ionosphere/mail-auth";
import type { DnsResolver } from "@ionosphere/mail-auth";

const MESSAGE = ["From: alice@origin.example", "To: bob@dest.example", "Subject: hello", "Date: Mon, 1 Jan 2026 00:00:00 +0000", "", "body line 1", "body line 2", ""].join("\r\n");

/** selector._domainkey.domain → TXT(dnsRecord) 맵으로 DNS 조회를 흉내낸다. */
function resolverFor(entries: Record<string, string>): Pick<DnsResolver, "txt"> {
  return {
    txt: async (name: string) => {
      const rec = entries[name];
      if (!rec) throw new Error(`no txt: ${name}`);
      return [rec];
    },
  };
}

function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

describe.each<DkimAlgorithm>(["rsa-sha256", "ed25519-sha256"])("ARC seal/verify (%s)", (algo) => {
  test("최초 홉 seal → verify cv=pass, i=1", async () => {
    const kp = generateDkimKeyPair(algo);
    const resolver = resolverFor({ "arc1._domainkey.fwd.example": kp.dnsRecord });
    const arc = arcSeal(bytes(MESSAGE), {
      domain: "fwd.example",
      selector: "arc1",
      privateKey: kp.privateKeyPem,
      algorithm: algo,
      authResults: "fwd.example; spf=pass smtp.mailfrom=origin.example; dkim=pass",
      timestamp: 1_700_000_000,
    });
    const sealed = arc + "\r\n" + MESSAGE;
    const chain = parseArcChain(bytes(sealed));
    expect(chain).toHaveLength(1);
    expect(chain[0]!.instance).toBe(1);
    expect(chain[0]!.aar).toBeDefined();
    expect(chain[0]!.ams).toBeDefined();
    expect(chain[0]!.seal).toBeDefined();

    const result = await arcVerify(bytes(sealed), resolver);
    expect(result).toEqual({ cv: "pass", instances: 1 });
  });

  test("체인 확장: 2번째 홉 seal(cv=pass) → verify cv=pass, i=2", async () => {
    const kp1 = generateDkimKeyPair(algo);
    const kp2 = generateDkimKeyPair(algo);
    const resolver = resolverFor({
      "a._domainkey.hop1.example": kp1.dnsRecord,
      "b._domainkey.hop2.example": kp2.dnsRecord,
    });
    const arc1 = arcSeal(bytes(MESSAGE), {
      domain: "hop1.example",
      selector: "a",
      privateKey: kp1.privateKeyPem,
      algorithm: algo,
      authResults: "hop1.example; dkim=pass",
      timestamp: 1_700_000_000,
    });
    const sealed1 = arc1 + "\r\n" + MESSAGE;
    // hop2가 hop1의 체인을 검증하고(cv=pass) 자기 세트 추가
    const arc2 = arcSeal(bytes(sealed1), {
      domain: "hop2.example",
      selector: "b",
      privateKey: kp2.privateKeyPem,
      algorithm: algo,
      authResults: "hop2.example; dkim=pass",
      cv: "pass",
      timestamp: 1_700_000_100,
    });
    const sealed2 = arc2 + "\r\n" + sealed1;
    const chain = parseArcChain(bytes(sealed2));
    expect(chain.map((s) => s.instance)).toEqual([1, 2]);

    const result = await arcVerify(bytes(sealed2), resolver);
    expect(result).toEqual({ cv: "pass", instances: 2 });
  });

  test("본문 변조 → AMS 실패로 cv=fail", async () => {
    const kp = generateDkimKeyPair(algo);
    const resolver = resolverFor({ "arc1._domainkey.fwd.example": kp.dnsRecord });
    const arc = arcSeal(bytes(MESSAGE), {
      domain: "fwd.example",
      selector: "arc1",
      privateKey: kp.privateKeyPem,
      algorithm: algo,
      authResults: "fwd.example; dkim=pass",
      timestamp: 1_700_000_000,
    });
    const tampered = arc + "\r\n" + MESSAGE.replace("body line 1", "body line HACKED");
    const result = await arcVerify(bytes(tampered), resolver);
    expect(result.cv).toBe("fail");
  });

  test("ARC-Seal 변조(cv 위조) → AS 서명 실패로 cv=fail", async () => {
    const kp = generateDkimKeyPair(algo);
    const resolver = resolverFor({ "arc1._domainkey.fwd.example": kp.dnsRecord });
    const arc = arcSeal(bytes(MESSAGE), {
      domain: "fwd.example",
      selector: "arc1",
      privateKey: kp.privateKeyPem,
      algorithm: algo,
      authResults: "fwd.example; dkim=pass",
      timestamp: 1_700_000_000,
    });
    // cv=none → cv=pass로 몰래 바꿔치기(서명은 그대로) → AS 검증 실패해야 함
    const forged = arc.replace("cv=none", "cv=pass") + "\r\n" + MESSAGE;
    const result = await arcVerify(bytes(forged), resolver);
    expect(result.cv).toBe("fail");
  });
  /**
   * `k=`(키 타입)가 `a=`(서명 알고리즘)와 어긋나면 거부한다 — RFC 6376 §3.6.1.
   *
   * ★이 검사가 DKIM(`verify.ts`)에는 있고 ARC에는 **없었다**(2026-08-01 발견). 임포트 실패로
   * 수렴하니 안전한 쪽이었지만, 실패 이유가 "타입 불일치"가 아니라 "키 없음"으로 보고돼
   * 운영자가 "DNS 레코드가 없다"로 오독하게 된다 — 실제로는 잘못된 타입으로 게시한 것이다.
   */
  test("★k= 타입이 a=와 어긋나면 cv=fail (DKIM에는 있던 검사가 ARC에는 없었다)", async () => {
    const kp = generateDkimKeyPair(algo);
    const arc = arcSeal(bytes(MESSAGE), {
      domain: "fwd.example",
      selector: "arc1",
      privateKey: kp.privateKeyPem,
      algorithm: algo,
      authResults: "fwd.example; spf=pass",
      timestamp: 1_700_000_000,
    });
    const sealed = arc + "\r\n" + MESSAGE;

    // 키는 올바른데 k= 태그만 반대 타입으로 게시된 레코드.
    const wrongK = algo === "ed25519-sha256" ? "rsa" : "ed25519";
    const p = /p=([^;]*)/.exec(kp.dnsRecord)?.[1] ?? "";
    const mismatched = `v=DKIM1; k=${wrongK}; p=${p}`;
    expect((await arcVerify(bytes(sealed), resolverFor({ "arc1._domainkey.fwd.example": mismatched }))).cv).toBe("fail");

    // 대조: 같은 키를 올바른 k=로 게시하면 pass다 — 거부가 k= 때문임을 고정한다.
    expect((await arcVerify(bytes(sealed), resolverFor({ "arc1._domainkey.fwd.example": kp.dnsRecord }))).cv).toBe("pass");
  });

  test("k=가 생략된 레코드는 통과한다 (기본값 rsa — 정상 발신자를 막지 않는다)", async () => {
    const kp = generateDkimKeyPair(algo);
    const arc = arcSeal(bytes(MESSAGE), {
      domain: "fwd.example",
      selector: "arc1",
      privateKey: kp.privateKeyPem,
      algorithm: algo,
      authResults: "fwd.example; spf=pass",
      timestamp: 1_700_000_000,
    });
    const sealed = arc + "\r\n" + MESSAGE;
    const p = /p=([^;]*)/.exec(kp.dnsRecord)?.[1] ?? "";
    // k= 없는 레코드. ed25519도 통과해야 한다 — 생략을 거부하면 fail closed가 과해진다.
    const noK = `v=DKIM1; p=${p}`;
    expect((await arcVerify(bytes(sealed), resolverFor({ "arc1._domainkey.fwd.example": noK }))).cv).toBe("pass");
  });
});

describe("ARC 무체인/불완전", () => {
  test("ARC 헤더 없음 → cv=none", async () => {
    const resolver = resolverFor({});
    expect(await arcVerify(bytes(MESSAGE), resolver)).toEqual({ cv: "none", instances: 0 });
  });

  test("불완전 세트(AMS 없음) → cv=fail", async () => {
    const withOnlyAar = "ARC-Authentication-Results: i=1; x.example; dkim=pass\r\n" + MESSAGE;
    expect((await arcVerify(bytes(withOnlyAar), resolverFor({}))).cv).toBe("fail");
  });

});
