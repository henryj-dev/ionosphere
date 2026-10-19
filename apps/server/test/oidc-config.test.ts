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

describe("같은 issuer 중복 (SSO 연결 기록 우회 방지)", () => {
  test("같은 영역에서 같은 issuer를 두 id로 쓰면 기동을 거부한다", () => {
    expect(() => oidcProvidersFromJson(JSON.stringify([base, { ...base, id: "corp2", issuer: "https://idp.ionosphere.test/" }]))).toThrow(/같은 IdP를 두 id로/);
  });
  test("영역이 다르면(관리 콘솔·셀프서비스) 같은 issuer를 허용한다", () => {
    expect(oidcProvidersFromJson(JSON.stringify([base, { ...base, id: "corp-self", realm: "account", tenantId: "t1" }]))).toHaveLength(2);
  });
  test("account 영역은 테넌트가 다르면 허용한다", () => {
    const a = { ...base, realm: "account", tenantId: "t1" };
    expect(oidcProvidersFromJson(JSON.stringify([a, { ...a, id: "corp-t2", tenantId: "t2" }]))).toHaveLength(2);
    expect(() => oidcProvidersFromJson(JSON.stringify([a, { ...a, id: "corp-t1b" }]))).toThrow(/같은 IdP를 두 id로/);
  });
});

