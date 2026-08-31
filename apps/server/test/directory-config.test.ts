import { describe, expect, test } from "@ionosphere/testkit";
import { directorySourcesFromJson } from "../src/directory-config.ts";

function config(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify([{
    provider: "corp-ad",
    tenantId: "tenant-1",
    transport: "ldaps",
    url: "ldaps://directory.ionosphere.test",
    bindDn: "cn=service,dc=ionosphere,dc=test",
    bindPassword: "not-a-live-secret",
    baseDn: "dc=ionosphere,dc=test",
    ...overrides,
  }]);
}

describe("directory config", () => {
  test("완전한 LDAPS 설정은 provider source 하나를 만든다", () => {
    expect(Object.keys(directorySourcesFromJson(config()) ?? {})).toEqual(["corp-ad"]);
    expect(Object.keys(directorySourcesFromJson(config({ attributes: { objectGuid: "entryUUID", samAccountName: "uid", groupMember: "member" } })) ?? {})).toEqual(["corp-ad"]);
  });

  test("평문 LDAP와 provider 중복은 기동 전에 거부한다", () => {
    expect(() => directorySourcesFromJson(config({ transport: "ldap" }))).toThrow(/ldaps 또는 starttls/);
    const duplicated = JSON.stringify([JSON.parse(config())[0], JSON.parse(config())[0]]);
    expect(() => directorySourcesFromJson(duplicated)).toThrow(/provider 중복/);
  });

  test("설정 오류에 bind password를 포함하지 않는다", () => {
    const secret = "directory-password-must-not-leak";
    try {
      directorySourcesFromJson(config({ bindPassword: secret, timeoutMs: "wrong" }));
      throw new Error("expected failure");
    } catch (error) {
      expect(String(error)).not.toContain(secret);
    }
  });
});
