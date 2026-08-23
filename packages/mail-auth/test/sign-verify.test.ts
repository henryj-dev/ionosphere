import { describe, expect, test } from "@ionosphere/testkit";
import { dkimSign, type DkimAlgorithm } from "../src/sign.ts";
import { dkimVerify, type DkimVerifyResult } from "../src/verify.ts";
import { generateDkimKeyPair } from "../src/keys.ts";

// 픽스처는 항상 유효한 UTF-8 텍스트로 다룬다 — 헤더 프리픽스(ASCII)와 문자열 concat 후
// 마지막에 딱 한 번만 TextEncoder로 바이트화한다. (Buffer latin1 왕복 후 TextEncoder로 다시
// 인코딩하면 8비트 바이트가 이중 인코딩되어 깨진다 — 이는 라이브러리가 아니라 테스트 헬퍼가
// 저지르기 쉬운 실수라 여기 남겨 설명한다.)
function toBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function crlf(lines: string[]): string {
  return lines.join("\r\n");
}

const FIXED_TS = 1_700_000_000;

/** 8비트 UTF-8 본문 + 접힌(folded) Subject 헤더를 포함한 픽스처 메시지. */
function buildFixture(): string {
  return crlf([
    "From: Alice <alice@example.com>",
    "To: Bob <bob@example.com>",
    "Subject: DKIM  \t 접힌 제목 테스트\r\n \t 두번째 줄입니다",
    "Date: Wed, 22 Jul 2026 10:00:00 +0900",
    "Message-ID: <fixture@example.com>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "안녕하세요, DKIM 서명 테스트입니다.",
    "8비트 UTF-8 본문 — 한글 포함.",
    "",
  ]);
}

function fakeResolver(map: Record<string, string[]>): (name: string) => Promise<string[]> {
  return async (name: string) => {
    const rec = map[name];
    if (!rec) return [];
    return rec;
  };
}

function dnsName(selector: string, domain: string): string {
  return `${selector}._domainkey.${domain}`;
}

/** dkimSign이 반환한 헤더 줄을 원본 메시지 문자열 앞에 붙인다 (바이트 왕복 없이 문자열 그대로). */
function prepend(sigLine: string, fixtureText: string): Uint8Array {
  return toBytes(sigLine + "\r\n" + fixtureText);
}

describe("dkimSign/dkimVerify — 라운드트립", () => {
  const combos: Array<{ algorithm: DkimAlgorithm; canon: "relaxed" | "simple" }> = [
    { algorithm: "rsa-sha256", canon: "relaxed" },
    { algorithm: "rsa-sha256", canon: "simple" },
    { algorithm: "ed25519-sha256", canon: "relaxed" },
    { algorithm: "ed25519-sha256", canon: "simple" },
  ];

  for (const { algorithm, canon } of combos) {
    test(`${algorithm} / ${canon}-${canon} 서명 → 검증 pass`, async () => {
      const domain = "example.com";
      const selector = `sel-${algorithm}-${canon}`;
      const keyPair = generateDkimKeyPair(algorithm);
      const fixtureText = buildFixture();
      const raw = toBytes(fixtureText);

      const sigLine = dkimSign(raw, {
        domain,
        selector,
        privateKey: keyPair.privateKeyPem,
        algorithm,
        headerCanon: canon,
        bodyCanon: canon,
        timestamp: FIXED_TS,
      });
      const signed = prepend(sigLine, fixtureText);

      const resolveTxt = fakeResolver({ [dnsName(selector, domain)]: [keyPair.dnsRecord] });
      const results = await dkimVerify(signed, resolveTxt);

      expect(results).toHaveLength(1);
      expect(results[0]?.result).toBe("pass");
      expect(results[0]?.domain).toBe(domain);
      expect(results[0]?.selector).toBe(selector);
      expect(results[0]?.error).toBeUndefined();
    });
  }
});

describe("분할 키 레코드 (RSA-2048 > 255바이트)", () => {
  // 실세계 회귀: RSA-2048 DKIM 키는 항상 255바이트를 넘어 여러 character-string으로 분할되고,
  // node의 resolveTxt는 이를 여러 레코드로 쪼개 반환하기도 한다(예: 네이버 s20171208).
  // 검증기는 연접본으로 재구성해 pass해야 한다 (RFC 6376 §3.6.2.2).
  test("키가 여러 조각으로 반환돼도 pass", async () => {
    const domain = "example.com";
    const selector = "split";
    const keyPair = generateDkimKeyPair("rsa-sha256"); // RSA → dnsRecord는 255자 초과
    const fixtureText = buildFixture();
    const raw = toBytes(fixtureText);
    const sigLine = dkimSign(raw, {
      domain, selector, privateKey: keyPair.privateKeyPem, algorithm: "rsa-sha256", timestamp: FIXED_TS,
    });
    const signed = toBytes(sigLine + "\r\n" + fixtureText);

    // node 동작 재현: dnsRecord를 254자 경계로 쪼개 "여러 레코드"로 반환
    const rec = keyPair.dnsRecord;
    const chunks = [rec.slice(0, 254), rec.slice(254)];
    expect(chunks.length).toBeGreaterThan(1); // RSA는 실제로 분할됨
    const resolver = async (name: string): Promise<string[]> =>
      name === `${selector}._domainkey.${domain}` ? chunks : [];

    const results = await dkimVerify(signed, resolver);
    expect(results[0]?.result).toBe("pass");
  });
});

describe("dkimSign — 필수 필드", () => {
  test("From 헤더가 없으면 throw", () => {
    const raw = toBytes(crlf(["To: Bob <bob@example.com>", "Subject: no from", "", "body"]));
    expect(() =>
      dkimSign(raw, {
        domain: "example.com",
        selector: "sel1",
        privateKey: generateDkimKeyPair("rsa-sha256").privateKeyPem,
        algorithm: "rsa-sha256",
      }),
    ).toThrow();
  });
});

describe("변조 탐지", () => {
  const domain = "example.com";
  const selector = "tamper-sel";
  const algorithm: DkimAlgorithm = "rsa-sha256";

  function buildSigned(): { fixtureText: string; sigLine: string; resolveTxt: (n: string) => Promise<string[]> } {
    const keyPair = generateDkimKeyPair(algorithm);
    const fixtureText = buildFixture();
    const raw = toBytes(fixtureText);
    const sigLine = dkimSign(raw, {
      domain,
      selector,
      privateKey: keyPair.privateKeyPem,
      algorithm,
      timestamp: FIXED_TS,
    });
    const resolveTxt = fakeResolver({ [dnsName(selector, domain)]: [keyPair.dnsRecord] });
    return { fixtureText, sigLine, resolveTxt };
  }

  test("정상 메시지는 pass", async () => {
    const { fixtureText, sigLine, resolveTxt } = buildSigned();
    const results = await dkimVerify(prepend(sigLine, fixtureText), resolveTxt);
    expect(results[0]?.result).toBe("pass");
  });

  test("본문 변조 → fail", async () => {
    const { fixtureText, sigLine, resolveTxt } = buildSigned();
    const tampered = fixtureText.replace("한글 포함.", "한글 변조됨!!");
    expect(tampered).not.toBe(fixtureText);
    const results = await dkimVerify(prepend(sigLine, tampered), resolveTxt);
    expect(results[0]?.result).toBe("fail");
  });

  test("서명된 헤더(Subject) 변조 → fail", async () => {
    const { fixtureText, sigLine, resolveTxt } = buildSigned();
    const tampered = fixtureText.replace("접힌 제목 테스트", "완전히 다른 제목");
    expect(tampered).not.toBe(fixtureText);
    const results = await dkimVerify(prepend(sigLine, tampered), resolveTxt);
    expect(results[0]?.result).toBe("fail");
  });

  test("서명되지 않은 헤더 추가 → 여전히 pass", async () => {
    const { fixtureText, sigLine, resolveTxt } = buildSigned();
    const withExtra = fixtureText.replace("\r\n\r\n", "\r\nX-Added-Later: harmless\r\n\r\n");
    expect(withExtra).not.toBe(fixtureText);
    const results = await dkimVerify(prepend(sigLine, withExtra), resolveTxt);
    expect(results[0]?.result).toBe("pass");
  });

  test("From 헤더 추가(오버서명 방어) → fail", async () => {
    const { fixtureText, sigLine, resolveTxt } = buildSigned();
    // 서명 직후(최상단)에 두번째 From을 삽입 — 클라이언트가 "마지막 From"을 신뢰하는 공격 시나리오.
    const withExtraFrom = sigLine + "\r\nFrom: evil@attacker.example\r\n" + fixtureText;
    const results = await dkimVerify(toBytes(withExtraFrom), resolveTxt);
    expect(results[0]?.result).toBe("fail");
  });
});

describe("다중 서명 (RSA + Ed25519 동시 서명)", () => {
  test("각 서명이 독립적으로 검증된다", async () => {
    const domain = "example.com";
    const rsaSelector = "dual-rsa";
    const edSelector = "dual-ed";
    const rsaKeys = generateDkimKeyPair("rsa-sha256");
    const edKeys = generateDkimKeyPair("ed25519-sha256");
    const fixtureText = buildFixture();
    const raw = toBytes(fixtureText);

    const rsaSig = dkimSign(raw, {
      domain,
      selector: rsaSelector,
      privateKey: rsaKeys.privateKeyPem,
      algorithm: "rsa-sha256",
      timestamp: FIXED_TS,
    });
    const edSig = dkimSign(raw, {
      domain,
      selector: edSelector,
      privateKey: edKeys.privateKeyPem,
      algorithm: "ed25519-sha256",
      timestamp: FIXED_TS,
    });

    const signed = toBytes(`${rsaSig}\r\n${edSig}\r\n${fixtureText}`);
    const resolveTxt = fakeResolver({
      [dnsName(rsaSelector, domain)]: [rsaKeys.dnsRecord],
      [dnsName(edSelector, domain)]: [edKeys.dnsRecord],
    });

    const results = await dkimVerify(signed, resolveTxt);
    expect(results).toHaveLength(2);
    const bySelector = new Map(results.map((r) => [r.selector, r]));
    expect(bySelector.get(rsaSelector)?.result).toBe("pass");
    expect(bySelector.get(edSelector)?.result).toBe("pass");
  });
});

describe("키 레코드 엣지 케이스", () => {
  const domain = "example.com";
  const algorithm: DkimAlgorithm = "rsa-sha256";

  function buildSigned(selector: string): {
    fixtureText: string;
    sigLine: string;
    keyPair: ReturnType<typeof generateDkimKeyPair>;
  } {
    const keyPair = generateDkimKeyPair(algorithm);
    const fixtureText = buildFixture();
    const raw = toBytes(fixtureText);
    const sigLine = dkimSign(raw, {
      domain,
      selector,
      privateKey: keyPair.privateKeyPem,
      algorithm,
      timestamp: FIXED_TS,
    });
    return { fixtureText, sigLine, keyPair };
  }

  test("t=y 테스트 플래그가 결과에 표시된다", async () => {
    const selector = "edge-testing";
    const { fixtureText, sigLine, keyPair } = buildSigned(selector);
    const resolveTxt = fakeResolver({ [dnsName(selector, domain)]: [`${keyPair.dnsRecord}; t=y`] });

    const results = await dkimVerify(prepend(sigLine, fixtureText), resolveTxt);
    expect(results[0]?.result).toBe("pass");
    expect(results[0]?.testing).toBe(true);
  });

  test("k=ed25519 레코드로 RSA 서명 검증 시도 → permerror", async () => {
    const selector = "edge-keymismatch";
    const { fixtureText, sigLine } = buildSigned(selector);
    const edKeys = generateDkimKeyPair("ed25519-sha256");
    const resolveTxt = fakeResolver({ [dnsName(selector, domain)]: [edKeys.dnsRecord] });

    const results = await dkimVerify(prepend(sigLine, fixtureText), resolveTxt);
    expect(results[0]?.result).toBe("permerror");
  });

  test("resolveTxt가 throw하면 temperror", async () => {
    const selector = "edge-dnsfail";
    const { fixtureText, sigLine } = buildSigned(selector);
    const resolveTxt = async () => {
      throw new Error("DNS 서버 응답 없음");
    };

    const results = await dkimVerify(prepend(sigLine, fixtureText), resolveTxt);
    expect(results[0]?.result).toBe("temperror");
  });

  test("가비지 키 레코드 → permerror", async () => {
    const selector = "edge-garbage";
    const { fixtureText, sigLine } = buildSigned(selector);
    const resolveTxt = fakeResolver({ [dnsName(selector, domain)]: ["이것은 유효한 DKIM 레코드가 아닙니다"] });

    const results = await dkimVerify(prepend(sigLine, fixtureText), resolveTxt);
    expect(results[0]?.result).toBe("permerror");
  });

  test("resolveTxt가 빈 배열 → permerror(키 없음)", async () => {
    const selector = "edge-nokey";
    const { fixtureText, sigLine } = buildSigned(selector);
    const resolveTxt = fakeResolver({});

    const results = await dkimVerify(prepend(sigLine, fixtureText), resolveTxt);
    expect(results[0]?.result).toBe("permerror");
  });
});

describe("RFC 8463 Ed25519 와이어 포맷", () => {
  test("dnsRecord의 p=는 정확히 44 base64 문자(32바이트 raw)", () => {
    const { dnsRecord, publicKeyBase64 } = generateDkimKeyPair("ed25519-sha256");
    expect(publicKeyBase64).toHaveLength(44);
    const match = dnsRecord.match(/p=([^;]+)/);
    expect(match?.[1]).toHaveLength(44);
    expect(Buffer.from(publicKeyBase64, "base64")).toHaveLength(32);
  });
});
