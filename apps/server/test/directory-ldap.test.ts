import { describe, expect, test } from "@ionosphere/testkit";
import { readFile } from "node:fs/promises";
import { createServer } from "node:tls";
import { DIRECTORY_TRANSPORT } from "@ionosphere/core";
import { directoryProvider } from "../src/directory-ldap.ts";

function length(value: number): Uint8Array { return value < 128 ? Uint8Array.of(value) : Uint8Array.of(0x81, value); }
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
          const protocolTag = packet[header + 3]!;
          const id = packet[4]!;
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
});
