import { describe, expect, test } from "@ionosphere/testkit";
import { readFile } from "node:fs/promises";
import { createServer } from "node:tls";
import { DIRECTORY_TRANSPORT } from "@ionosphere/core";
import { directoryProvider, directorySnapshotReader } from "../src/directory-ldap.ts";

function length(value: number): Uint8Array { return value < 128 ? Uint8Array.of(value) : value < 256 ? Uint8Array.of(0x81, value) : Uint8Array.of(0x82, value >>> 8, value & 0xff); }
function tlv(tag: number, value: Uint8Array): Uint8Array { return Uint8Array.from([tag, ...length(value.length), ...value]); }
function join(...parts: Uint8Array[]): Uint8Array { return Uint8Array.from(parts.flatMap((part) => [...part])); }
function seq(...parts: Uint8Array[]): Uint8Array { return tlv(0x30, join(...parts)); }
function integer(value: number): Uint8Array { return tlv(0x02, Uint8Array.of(value)); }
function octet(value: string | Uint8Array): Uint8Array { return tlv(0x04, typeof value === "string" ? new TextEncoder().encode(value) : value); }
function ldapResponse(id: number, tag: number, body: Uint8Array): Uint8Array {
  const bodyLength = body[1]! < 128 ? 2 : 3;
  return seq(integer(id), tlv(tag, body.slice(bodyLength)));
}
function resultBody(code: number): Uint8Array { return seq(tlv(0x0a, Uint8Array.of(code)), octet(""), octet("")); }
function packetHeader(packet: Uint8Array): number { return packet[1]! < 128 ? 2 : 2 + (packet[1]! & 0x7f); }
function requestId(packet: Uint8Array): number { return packet[packetHeader(packet) + 2]!; }
function requestTag(packet: Uint8Array): number { return packet[packetHeader(packet) + 3]!; }
function attribute(name: string, ...values: Array<string | Uint8Array>): Uint8Array { return seq(octet(name), tlv(0x31, join(...values.map(octet)))); }
function searchEntry(id: number, dn: string, ...attributes: Uint8Array[]): Uint8Array { return ldapResponse(id, 0x64, seq(octet(dn), seq(...attributes))); }
function pageControls(cookie: string): Uint8Array {
  const value = seq(integer(0), octet(cookie));
  return tlv(0xa0, seq(octet("1.2.840.113556.1.4.319"), octet(value)));
}
function searchDone(id: number, cookie = ""): Uint8Array { return seq(integer(id), tlv(0x65, resultBody(0).slice(2)), pageControls(cookie)); }

describe("LDAP directory adapter", () => {
  test("설정 오류는 네트워크를 열지 않고 인증 실패로 닫힌다", async () => {
    const provider = directoryProvider({ transport: DIRECTORY_TRANSPORT.ldap, url: "ldap://directory.test", bindDn: "cn=reader", bindPassword: "secret", timeoutMs: 1000 }, { baseDn: "dc=directory,dc=test" });
    expect(await provider.authenticate("user", "password")).toBe(null);
  });

  test("잘못된 StartTLS scheme은 fail closed 한다", async () => {
    const provider = directoryProvider({ transport: DIRECTORY_TRANSPORT.starttls, url: "ldaps://directory.test", bindDn: "cn=reader", bindPassword: "secret", timeoutMs: 1000 }, { baseDn: "dc=directory,dc=test" });
    expect(await provider.authenticate("user", "password")).toBe(null);
  });

  test("LDAPS BER bind/search와 사용자 비밀번호 bind를 실제 소켓에서 검증한다", async () => {
    const cert = await readFile(new URL("../../../packages/proto-smtp/test/fixtures/cert.pem", import.meta.url));
    const key = await readFile(new URL("../../../packages/proto-smtp/test/fixtures/key.pem", import.meta.url));
    const server = createServer({ cert, key }, (socket) => {
      let data = Buffer.alloc(0);
      let serviceBound = false;
      socket.on("data", (chunk) => {
        data = Buffer.concat([data, chunk]);
        while (data.length >= 2) {
          const packetLength = data[1]! < 128 ? data[1]! : data[2]!;
          const header = data[1]! < 128 ? 2 : 3;
          if (data.length < header + packetLength) break;
          const packet = data.subarray(0, header + packetLength);
          data = data.subarray(header + packetLength);
          const protocolTag = requestTag(packet);
          const id = requestId(packet);
          if (protocolTag === 0x60) {
            const password = packet.toString("utf8");
            const code = password.includes("wrong") ? 49 : 0;
            socket.write(ldapResponse(id, 0x61, resultBody(code)));
            serviceBound = code === 0 && !serviceBound;
          } else if (protocolTag === 0x63 && serviceBound) {
            const attrs = seq(
              seq(octet("objectGUID"), tlv(0x31, octet(Uint8Array.of(1, 2)))),
              seq(octet("userPrincipalName"), tlv(0x31, octet("user@directory.test"))),
            );
            const entry = seq(octet("cn=user,dc=directory,dc=test"), attrs);
            socket.write(ldapResponse(id, 0x64, entry));
            socket.write(ldapResponse(id, 0x65, resultBody(0)));
          }
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    const config = { transport: DIRECTORY_TRANSPORT.ldaps, url: `ldaps://127.0.0.1:${port}`, serverName: "localhost", tlsCa: cert.toString(), bindDn: "cn=reader", bindPassword: "secret", timeoutMs: 1000 } as const;
    const provider = directoryProvider(config, { baseDn: "dc=directory,dc=test" });
    expect((await provider.authenticate("user@directory.test", "password"))?.externalKey).toBe("guid:AQI");
    await provider.close();
    const wrong = directoryProvider(config, { baseDn: "dc=directory,dc=test" });
    expect(await wrong.authenticate("user@directory.test", "wrong")).toBe(null);
    await wrong.close();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  });

  test("subtree search의 여러 entry와 AD paged-results cookie를 모아 사용자·중첩 그룹 snapshot으로 매핑한다", async () => {
    const cert = await readFile(new URL("../../../packages/proto-smtp/test/fixtures/cert.pem", import.meta.url));
    const key = await readFile(new URL("../../../packages/proto-smtp/test/fixtures/key.pem", import.meta.url));
    const seenSearchPackets: Buffer[] = [];
    let searchNumber = 0;
    const server = createServer({ cert, key }, (socket) => {
      let data = Buffer.alloc(0);
      socket.on("data", (chunk) => {
        data = Buffer.concat([data, chunk]);
        while (data.length >= 2) {
          const header = packetHeader(data);
          if (data.length < header) break;
          const packetLength = data[1]! < 128 ? data[1]! : data.subarray(2, header).reduce((value, byte) => value * 256 + byte, 0);
          if (data.length < header + packetLength) break;
          const packet = data.subarray(0, header + packetLength);
          data = data.subarray(header + packetLength);
          const id = requestId(packet);
          if (requestTag(packet) === 0x60) {
            socket.write(ldapResponse(id, 0x61, resultBody(0)));
            continue;
          }
          if (requestTag(packet) !== 0x63) continue;
          seenSearchPackets.push(packet);
          searchNumber++;
          if (searchNumber === 1) {
            socket.write(searchEntry(id, "cn=one,ou=users,dc=directory,dc=test",
              attribute("entryGuid", Uint8Array.of(1)), attribute("loginUpn", "one@directory.test"), attribute("loginSam", "one"), attribute("emailAddress", "ONE@DIRECTORY.TEST"), attribute("commonName", "One")));
            socket.write(searchDone(id, "next-page"));
          } else if (searchNumber === 2) {
            socket.write(searchEntry(id, "cn=two,ou=users,dc=directory,dc=test",
              attribute("entryGuid", Uint8Array.of(2)), attribute("loginUpn", "two@directory.test"), attribute("loginSam", "two")));
            socket.write(searchDone(id));
          } else {
            socket.write(searchEntry(id, "cn=child,ou=groups,dc=directory,dc=test",
              attribute("entryGuid", Uint8Array.of(10)), attribute("commonName", "Child"), attribute("members", "cn=one,ou=users,dc=directory,dc=test")));
            socket.write(searchEntry(id, "cn=parent,ou=groups,dc=directory,dc=test",
              attribute("entryGuid", Uint8Array.of(11)), attribute("commonName", "Parent"), attribute("members", "cn=child,ou=groups,dc=directory,dc=test", "cn=two,ou=users,dc=directory,dc=test")));
            socket.write(searchDone(id));
          }
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    const reader = directorySnapshotReader(
      { transport: DIRECTORY_TRANSPORT.ldaps, url: `ldaps://127.0.0.1:${port}`, serverName: "localhost", tlsCa: cert.toString(), bindDn: "cn=reader", bindPassword: "secret", timeoutMs: 1000 },
      {
        baseDn: "dc=directory,dc=test",
        userBaseDn: "ou=users,dc=directory,dc=test",
        groupBaseDn: "ou=groups,dc=directory,dc=test",
        userFilter: { attribute: "recordType", value: "person" },
        groupFilter: { attribute: "recordType", value: "team" },
        attributes: { objectGuid: "entryGuid", upn: "loginUpn", samAccountName: "loginSam", mail: "emailAddress", displayName: "commonName", groupMember: "members" },
        pageSize: 1,
      },
    );
    const snapshot = await reader.readSnapshot();
    expect(snapshot.identities).toEqual([
      { externalKey: "guid:AQ", loginNames: ["one@directory.test", "one"], email: "one@directory.test", displayName: "One", groupExternalKeys: ["guid:Cg", "guid:Cw"] },
      { externalKey: "guid:Ag", loginNames: ["two@directory.test", "two"], email: null, displayName: null, groupExternalKeys: ["guid:Cw"] },
    ]);
    expect(snapshot.groups).toEqual([
      { externalKey: "guid:Cg", displayName: "Child", memberExternalKeys: ["guid:AQ"] },
      { externalKey: "guid:Cw", displayName: "Parent", memberExternalKeys: ["guid:Cg", "guid:Ag"] },
    ]);
    expect(seenSearchPackets.length).toBe(3);
    expect(seenSearchPackets[0]!.includes(Buffer.from("next-page"))).toBe(false);
    expect(seenSearchPackets[1]!.includes(Buffer.from("next-page"))).toBe(true);
    // base DN 뒤의 scope ENUMERATED 값이 subtree(2)다.
    expect(seenSearchPackets.every((packet) => packet.includes(Buffer.from([0x0a, 0x01, 0x02])))).toBe(true);
    expect(seenSearchPackets[0]!.includes(Buffer.from("recordType"))).toBe(true);
    await reader.close();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  });

  test("snapshot 상한과 잘못된 field mapping은 부분 snapshot 대신 실패한다", async () => {
    expect(() => directorySnapshotReader(
      { transport: DIRECTORY_TRANSPORT.ldaps, url: "ldaps://directory.test", bindDn: "cn=reader", bindPassword: "secret", timeoutMs: 1000 },
      { baseDn: "dc=directory,dc=test", pageSize: 1001 },
    )).toThrow();
    expect(() => directorySnapshotReader(
      { transport: DIRECTORY_TRANSPORT.ldaps, url: "ldaps://directory.test", bindDn: "cn=reader", bindPassword: "secret", timeoutMs: 1000 },
      { baseDn: "dc=directory,dc=test", attributes: { groupMember: "member)(objectClass=*" } },
    )).toThrow();
  });
});
