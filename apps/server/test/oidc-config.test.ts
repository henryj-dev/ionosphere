import { describe, expect, test } from "@ionosphere/testkit";
import { oidcProvidersFromJson } from "../src/oidc-config.ts";

const base = { id: "corp", realm: "admin", issuer: "https://idp.ionosphere.test", clientId: "c", clientSecret: "not-a-live-secret" };
const json = (items: unknown[]) => JSON.stringify(items);

describe("OIDC 공급자 설정", () => {
  test("최소 설정과 계약 설정을 받는다", () => {
    expect(oidcProvidersFromJson(json([base]))[0]!.config.id).toBe("corp");
    const withContract = oidcProvidersFromJson(json([{ ...base, mfaContract: { acceptAcr: ["urn:x"], maxAgeSec: 300 } }]));
    expect(withContract[0]!.config.mfaContract?.maxAgeSec).toBe(300);
  });

  test("기동 전에 거부: 평문 issuer, 중복 id, account에 tenantId 없음, 빈 계약, 잘못된 maxAgeSec", () => {
    expect(() => oidcProvidersFromJson(json([{ ...base, issuer: "http://idp.ionosphere.test" }]))).toThrow(/https/);
    expect(() => oidcProvidersFromJson(json([base, base]))).toThrow(/중복/);
    expect(() => oidcProvidersFromJson(json([{ ...base, realm: "account" }]))).toThrow(/tenantId/);
    expect(() => oidcProvidersFromJson(json([{ ...base, mfaContract: { maxAgeSec: 300 } }]))).toThrow(/빈 계약/);
    expect(() => oidcProvidersFromJson(json([{ ...base, mfaContract: { acceptAcr: ["x"], maxAgeSec: 0 } }]))).toThrow(/maxAgeSec/);
  });

  test("오류에 clientSecret을 싣지 않는다", () => {
    const secret = "oidc-secret-must-not-leak";
    try {
      oidcProvidersFromJson(json([{ ...base, clientSecret: secret, realm: "nope" }]));
      throw new Error("expected failure");
    } catch (e) {
      expect(String(e)).not.toContain(secret);
    }
  });
});
