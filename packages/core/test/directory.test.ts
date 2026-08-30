import { describe, expect, test } from "@ionosphere/testkit";
import { DIRECTORY_TRANSPORT, DirectoryError, DirectoryProvider, externalIdentityKey, mapDirectoryIdentity, resolveNestedGroups, validateDirectoryConfig } from "../src/directory.ts";

describe("directory mapping", () => {
  test("LDAPS와 StartTLS만 simple bind 설정을 통과시킨다", () => {
    validateDirectoryConfig({ transport: DIRECTORY_TRANSPORT.ldaps, url: "ldaps://directory.test", bindDn: "cn=reader", bindPassword: "secret", timeoutMs: 1000 });
    validateDirectoryConfig({ transport: DIRECTORY_TRANSPORT.starttls, url: "ldap://directory.test", bindDn: "cn=reader", bindPassword: "secret", timeoutMs: 1000 });
    expect(() => validateDirectoryConfig({ transport: DIRECTORY_TRANSPORT.ldap, url: "ldap://directory.test", bindDn: "cn=reader", bindPassword: "secret", timeoutMs: 1000 })).toThrow(DirectoryError);
  });

  test("timeout과 URL scheme 오류를 부팅 전에 거부한다", () => {
    expect(() => validateDirectoryConfig({ transport: DIRECTORY_TRANSPORT.ldaps, url: "ldap://directory.test", bindDn: "cn=reader", bindPassword: "secret", timeoutMs: 1000 })).toThrow(DirectoryError);
    expect(() => validateDirectoryConfig({ transport: DIRECTORY_TRANSPORT.ldaps, url: "ldaps://directory.test", bindDn: "cn=reader", bindPassword: "secret", timeoutMs: 31_000 })).toThrow(DirectoryError);
  });

  test("objectGUID를 immutable external key로 우선한다", () => {
    expect(externalIdentityKey({ dn: "cn=a", objectGuid: new Uint8Array([1, 2]), objectSid: "S-1-5-1" })).toBe("guid:AQI");
  });

  test("GUID가 없으면 objectSid를 쓰고 둘 다 없으면 거부한다", () => {
    expect(externalIdentityKey({ dn: "cn=a", objectSid: "S-1-5-21" })).toBe("sid:S-1-5-21");
    expect(() => externalIdentityKey({ dn: "cn=a" })).toThrow(DirectoryError);
  });

  test("UPN과 sAMAccountName을 login alias로 합친다", () => {
    expect(mapDirectoryIdentity({ dn: "cn=a", objectSid: "S-1", upn: "A@EXAMPLE.TEST", samAccountName: "a", mail: "A@EXAMPLE.TEST" })).toEqual({ externalKey: "sid:S-1", loginNames: ["A@EXAMPLE.TEST", "a"], email: "a@example.test", displayName: null });
  });

  test("nested group을 cycle 없이 평탄화한다", () => {
    expect(resolveNestedGroups([{ id: "g1", memberGroupIds: ["g2"] }, { id: "g2", memberGroupIds: [] }], ["g1"])).toEqual(["g2", "g1"]);
  });

  test("nested group cycle은 부분 결과 대신 fail closed 한다", () => {
    expect(() => resolveNestedGroups([{ id: "g1", memberGroupIds: ["g2"] }, { id: "g2", memberGroupIds: ["g1"] }], ["g1"])).toThrow(DirectoryError);
  });

  test("nested group 깊이 초과는 fail closed 한다", () => {
    expect(() => resolveNestedGroups([{ id: "g1", memberGroupIds: ["g2"] }, { id: "g2", memberGroupIds: ["g3"] }, { id: "g3", memberGroupIds: [] }], ["g1"], 1)).toThrow(DirectoryError);
  });

  test("provider는 세 transport 설정을 검증한 뒤 client bind를 호출한다", async () => {
    const calls: string[] = [];
    const client = { bindService: async () => { calls.push("bind"); }, authenticateUser: async () => ({ dn: "cn=a", objectSid: "S-1", upn: "a@x.test" }), close: async () => { calls.push("close"); } };
    for (const [transport, url] of [[DIRECTORY_TRANSPORT.ldaps, "ldaps://directory.test"], [DIRECTORY_TRANSPORT.starttls, "ldap://directory.test"]] as const) {
      const result = await new DirectoryProvider({ transport, url, bindDn: "cn=reader", bindPassword: "secret", timeoutMs: 1000 }, client).authenticate("a@x.test", "password");
      expect(result?.externalKey).toBe("sid:S-1");
    }
    expect(calls).toEqual(["bind", "bind"]);
  });

  test("provider client 장애는 권한을 열지 않고 null로 수렴한다", async () => {
    const client = { bindService: async () => { throw new Error("timeout"); }, authenticateUser: async () => null, close: async () => {} };
    const result = await new DirectoryProvider({ transport: DIRECTORY_TRANSPORT.ldaps, url: "ldaps://directory.test", bindDn: "cn=reader", bindPassword: "secret", timeoutMs: 1000 }, client).authenticate("a", "password");
    expect(result).toBe(null);
  });
});
