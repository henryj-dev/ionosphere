/**
 * DANE for SMTP (RFC 7672).
 *
 * ★가장 중요한 계약은 **DNSSEC 미검증 TLSA를 쓰지 않는 것**이다. 검증되지 않은 TLSA를
 * 받아들이면, DNS를 속일 수 있는 공격자가 TLSA를 심어 **우리가 그의 인증서를 고정하게** 만든다 —
 * DANE가 방어하려던 바로 그 공격이 DANE를 통해 성립한다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { createHash } from "node:crypto";
import { checkDane, tlsaQueryName, TLSA_MATCHING, TLSA_SELECTOR, TLSA_USAGE, type TlsaRecord } from "../src/dane.ts";

const EE = { raw: new Uint8Array([1, 1, 1, 1]), spki: new Uint8Array([2, 2, 2, 2]) };
const CA = { raw: new Uint8Array([3, 3, 3, 3]), spki: new Uint8Array([4, 4, 4, 4]) };
const CHAIN = [EE, CA];

const sha256 = (b: Uint8Array): Uint8Array => new Uint8Array(createHash("sha256").update(b).digest());

function rec(over: Partial<TlsaRecord>): TlsaRecord {
  return {
    usage: TLSA_USAGE.DANE_EE,
    selector: TLSA_SELECTOR.SPKI,
    matchingType: TLSA_MATCHING.SHA256,
    data: sha256(EE.spki),
    ...over,
  };
}

describe("checkDane — DNSSEC 게이트", () => {
  test("★DNSSEC 미검증 TLSA는 쓰지 않는다 — 맞는 값이어도", () => {
    // 값 자체는 정확히 맞는다. 그래도 적용하면 안 된다 —
    // 공격자가 심은 TLSA를 우리가 신뢰하게 되는 경로가 정확히 이것이다.
    const r = checkDane(CHAIN, { records: [rec({})], dnssecValidated: false });
    expect(r.status).toBe("not-applicable");
  });

  test("검증된 TLSA는 적용된다", () => {
    expect(checkDane(CHAIN, { records: [rec({})], dnssecValidated: true }).status).toBe("match");
  });
});

describe("checkDane — 대조", () => {
  test("DANE-EE + SPKI + SHA-256 일치", () => {
    expect(checkDane(CHAIN, { records: [rec({})], dnssecValidated: true })).toEqual({
      status: "match",
      usage: TLSA_USAGE.DANE_EE,
    });
  });

  test("전체 인증서(selector=0) + 원본 대조(matching=0)도 된다", () => {
    const r = rec({ selector: TLSA_SELECTOR.FULL_CERT, matchingType: TLSA_MATCHING.EXACT, data: EE.raw });
    expect(checkDane(CHAIN, { records: [r], dnssecValidated: true }).status).toBe("match");
  });

  test("SHA-512도 된다", () => {
    const d = new Uint8Array(createHash("sha512").update(EE.spki).digest());
    const r = rec({ matchingType: TLSA_MATCHING.SHA512, data: d });
    expect(checkDane(CHAIN, { records: [r], dnssecValidated: true }).status).toBe("match");
  });

  test("★DANE-EE는 말단만 본다 — 중간 CA와 맞는 것을 EE로 착각하면 안 된다", () => {
    // CA의 SPKI 해시를 DANE-EE로 넣는다. EE가 아니므로 맞으면 안 된다.
    const r = rec({ usage: TLSA_USAGE.DANE_EE, data: sha256(CA.spki) });
    expect(checkDane(CHAIN, { records: [r], dnssecValidated: true }).status).toBe("mismatch");
  });

  test("★DANE-TA는 체인 어디든 맞으면 된다 — 그게 'CA를 신뢰하라'의 뜻이다", () => {
    const r = rec({ usage: TLSA_USAGE.DANE_TA, data: sha256(CA.spki) });
    expect(checkDane(CHAIN, { records: [r], dnssecValidated: true })).toEqual({
      status: "match",
      usage: TLSA_USAGE.DANE_TA,
    });
  });

  test("★맞지 않으면 mismatch — 중간자 신호다", () => {
    const r = rec({ data: new Uint8Array(32) });
    expect(checkDane(CHAIN, { records: [r], dnssecValidated: true }).status).toBe("mismatch");
  });
});

describe("checkDane — 무시해야 하는 것", () => {
  test("★SMTP에서 PKIX-TA·PKIX-EE는 쓰지 않는다 (RFC 7672 §3.1)", () => {
    // 값이 맞아도 usage 0·1은 무시한다 — 공개 CA 신뢰 전제가 SMTP MX에는 없다.
    for (const usage of [TLSA_USAGE.PKIX_TA, TLSA_USAGE.PKIX_EE]) {
      const r = checkDane(CHAIN, { records: [rec({ usage })], dnssecValidated: true });
      expect(r.status).toBe("not-applicable");
    }
  });

  test("★모르는 selector·matching type만 있으면 not-applicable — '통과'가 아니다", () => {
    // 전부 무시했더니 남은 게 없는 상태를 "검증 통과"로 읽으면 고정이 조용히 사라진다.
    const unknownSel = checkDane(CHAIN, { records: [rec({ selector: 99 })], dnssecValidated: true });
    expect(unknownSel.status).toBe("not-applicable");
    const unknownMatch = checkDane(CHAIN, { records: [rec({ matchingType: 99 })], dnssecValidated: true });
    expect(unknownMatch.status).toBe("not-applicable");
  });

  test("모르는 레코드와 맞는 레코드가 섞이면 맞는 쪽이 이긴다", () => {
    const set = { records: [rec({ selector: 99 }), rec({})], dnssecValidated: true };
    expect(checkDane(CHAIN, set).status).toBe("match");
  });

  test("TLSA가 비면 not-applicable", () => {
    expect(checkDane(CHAIN, { records: [], dnssecValidated: true }).status).toBe("not-applicable");
  });

  test("체인이 비면 mismatch — 고정할 대상이 없다", () => {
    expect(checkDane([], { records: [rec({})], dnssecValidated: true }).status).toBe("mismatch");
  });
});

describe("tlsaQueryName", () => {
  test("`_<port>._tcp.<host>` 형태 (RFC 7672 §3)", () => {
    expect(tlsaQueryName("mx.example.com", 25)).toBe("_25._tcp.mx.example.com");
    // 끝점(trailing dot)이 있어도 이름이 이상해지지 않는다.
    expect(tlsaQueryName("mx.example.com.", 25)).toBe("_25._tcp.mx.example.com");
  });
});
