import { connect as tcpConnect, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { DIRECTORY_TRANSPORT, DirectoryError, DirectoryProvider, type DirectoryClient, type DirectoryConfig, type DirectoryEntry } from "@ionosphere/core";

type LdapSocket = Socket | TLSSocket;

function encodeLength(length: number): Uint8Array {
  if (length < 128) return Uint8Array.of(length);
  const bytes: number[] = [];
  let rest = length;
  while (rest > 0) { bytes.unshift(rest & 0xff); rest >>>= 8; }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function tlv(tag: number, value: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + encodeLength(value.length).length + value.length);
  out[0] = tag;
  out.set(encodeLength(value.length), 1);
  out.set(value, 1 + encodeLength(value.length).length);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}

function text(value: string): Uint8Array { return new TextEncoder().encode(value); }
function sequence(...parts: Uint8Array[]): Uint8Array { return tlv(0x30, concat(...parts)); }
function integer(value: number): Uint8Array { return tlv(0x02, Uint8Array.of(value)); }
function octet(value: string | Uint8Array): Uint8Array { return tlv(0x04, typeof value === "string" ? text(value) : value); }

interface BerNode { tag: number; value: Uint8Array; children: BerNode[]; }

function parseNode(bytes: Uint8Array, offset = 0): { node: BerNode; next: number } {
  const tag = bytes[offset]!;
  let at = offset + 1;
  const first = bytes[at]!;
  at += 1;
  let length = first;
  if ((first & 0x80) !== 0) {
    length = 0;
    for (let i = 0; i < (first & 0x7f); i++) length = length * 256 + bytes[at++]!;
  }
  const end = at + length;
  const value = bytes.slice(at, end);
  const constructed = (tag & 0x20) !== 0;
  const children: BerNode[] = [];
  if (constructed) for (let childAt = at; childAt < end;) { const parsed = parseNode(bytes, childAt); children.push(parsed.node); childAt = parsed.next; }
  return { node: { tag, value, children }, next: end };
}

function numberValue(node: BerNode): number {
  let value = 0;
  for (const byte of node.value) value = value * 256 + byte;
  return value;
}

function stringValue(node: BerNode): string { return new TextDecoder().decode(node.value); }

class LdapConnection {
  private socket: LdapSocket;
  private readonly timeoutMs: number;
  private pending = Buffer.alloc(0);
  private nextMessageId = 1;
  private ended = false;

  private constructor(socket: LdapSocket, timeoutMs: number) {
    this.socket = socket;
    this.timeoutMs = timeoutMs;
    socket.setTimeout(timeoutMs);
    socket.on("timeout", () => socket.destroy(new DirectoryError("LDAP timeout")));
  }

  static async open(config: DirectoryConfig): Promise<LdapConnection> {
    const parsed = new URL(config.url);
    const port = parsed.port ? Number(parsed.port) : config.transport === DIRECTORY_TRANSPORT.ldaps ? 636 : 389;
    const host = parsed.hostname;
    const socket = await new Promise<LdapSocket>((resolve, reject) => {
      const onError = (error: Error): void => reject(error);
      if (config.transport === DIRECTORY_TRANSPORT.ldaps) {
        const tls = tlsConnect({ host, port, servername: config.serverName ?? host, rejectUnauthorized: true, ...(config.tlsCa ? { ca: config.tlsCa } : {}) });
        tls.once("secureConnect", () => resolve(tls));
        tls.once("error", onError);
      } else {
        const plain = tcpConnect({ host, port });
        plain.once("connect", () => resolve(plain));
        plain.once("error", onError);
      }
    });
    const connection = new LdapConnection(socket, config.timeoutMs);
    if (config.transport === DIRECTORY_TRANSPORT.starttls) await connection.startTls(host, config.serverName, config.tlsCa);
    return connection;
  }

  private async startTls(host: string, serverName?: string, tlsCa?: string): Promise<void> {
    const response = await this.request(tlv(0x77, sequence(octet("1.3.6.1.4.1.1466.20037"))));
    if (resultCode(response) !== 0) throw new DirectoryError("LDAP StartTLS 거부");
    const upgraded = await new Promise<TLSSocket>((resolve, reject) => {
      const tls = tlsConnect({ socket: this.socket, servername: serverName ?? host, rejectUnauthorized: true, ...(tlsCa ? { ca: tlsCa } : {}) });
      tls.once("secureConnect", () => resolve(tls));
      tls.once("error", reject);
    });
    this.socket = upgraded;
  }

  async bind(bindDn: string, password: string): Promise<void> {
    const request = tlv(0x60, sequence(integer(3), octet(bindDn), tlv(0x80, text(password))));
    const response = await this.request(request);
    if (resultCode(response) !== 0) throw new DirectoryError("LDAP bind 실패");
  }

  async search(baseDn: string, loginName: string, attribute = "userPrincipalName"): Promise<DirectoryEntry | null> {
    const attrs = sequence(...["objectGUID", "objectSid", "userPrincipalName", "sAMAccountName", "mail", "displayName"].map(octet));
    const filter = tlv(0xa3, sequence(octet(attribute), octet(loginName)));
    const body = sequence(octet(baseDn), tlv(0x0a, Uint8Array.of(0)), tlv(0x0a, Uint8Array.of(0)), integer(1), integer(0), tlv(0x01, Uint8Array.of(0)), filter, attrs);
    let response = await this.request(tlv(0x63, body));
    const entry = response.tag === 0x64 ? response : null;
    while (response.tag === 0x64) response = await this.readMessage();
    if (response.tag !== 0x65 || resultCode(response) !== 0) throw new DirectoryError("LDAP search 실패");
    if (!entry) return null;
    const dn = stringValue(entry.children[0]!);
    const values = new Map<string, Uint8Array>();
    for (const attribute of entry.children[1]?.children ?? []) {
      const name = stringValue(attribute.children[0]!);
      const value = attribute.children[1]?.children[0]?.value;
      if (value) values.set(name.toLowerCase(), value);
    }
    const guid = values.get("objectguid");
    const sid = values.get("objectsid");
    return {
      dn,
      ...(guid ? { objectGuid: guid } : {}),
      ...(sid ? { objectSid: sidToString(sid) } : {}),
      ...(values.has("userprincipalname") ? { upn: stringValue({ tag: 4, value: values.get("userprincipalname")!, children: [] }) } : {}),
      ...(values.has("samaccountname") ? { samAccountName: stringValue({ tag: 4, value: values.get("samaccountname")!, children: [] }) } : {}),
      ...(values.has("mail") ? { mail: stringValue({ tag: 4, value: values.get("mail")!, children: [] }) } : {}),
      ...(values.has("displayname") ? { displayName: stringValue({ tag: 4, value: values.get("displayname")!, children: [] }) } : {}),
    };
  }

  private async request(protocol: Uint8Array): Promise<BerNode> {
    if (this.ended) throw new DirectoryError("LDAP connection closed");
    const id = this.nextMessageId++;
    this.socket.write(Buffer.from(sequence(integer(id), protocol)));
    return this.readMessage();
  }

  private async readMessage(): Promise<BerNode> {
    const read = (): BerNode | null => {
      if (this.pending.length < 2) return null;
      const lengthByte = this.pending[1]!;
      const lengthBytes = (lengthByte & 0x80) === 0 ? 0 : lengthByte & 0x7f;
      const header = 2 + lengthBytes;
      if (this.pending.length < header) return null;
      const length = (lengthByte & 0x80) === 0 ? lengthByte : this.pending.slice(2, header).reduce((value, byte) => value * 256 + byte, 0);
      if (this.pending.length < header + length) return null;
      const packet = this.pending.subarray(0, header + length);
      this.pending = this.pending.subarray(header + length);
      return parseNode(new Uint8Array(packet)).node;
    };
    const immediate = read();
    if (immediate) return immediate.children[1]!;
    return new Promise<BerNode>((resolve, reject) => {
      const onData = (chunk: Buffer): void => {
        this.pending = Buffer.concat([this.pending, chunk]);
        const node = read();
        if (node) { cleanup(); resolve(node.children[1]!); }
      };
      const onError = (error: Error): void => { cleanup(); reject(error); };
      const cleanup = (): void => { this.socket.off("data", onData); this.socket.off("error", onError); this.socket.off("close", onClose); };
      const onClose = (): void => { cleanup(); reject(new DirectoryError("LDAP connection closed")); };
      this.socket.on("data", onData);
      this.socket.once("error", onError);
      this.socket.once("close", onClose);
    });
  }

  async close(): Promise<void> {
    if (this.ended) return;
    this.ended = true;
    this.socket.end();
  }
}

function resultCode(response: BerNode): number {
  const result = response.tag === 0x61 || response.tag === 0x65 || response.tag === 0x78
    ? response
    : response.children.find((child) => child.tag === 0x61 || child.tag === 0x65 || child.tag === 0x78);
  return result?.children[0] ? numberValue(result.children[0]) : 80;
}

function sidToString(bytes: Uint8Array): string {
  if (bytes.length < 8) return "";
  const authority = bytes.slice(2, 8).reduce((value, byte) => value * 256 + byte, 0);
  const parts: string[] = [];
  for (let at = 8; at + 4 <= bytes.length; at += 4) parts.push(String(bytes[at]! | (bytes[at + 1]! << 8) | (bytes[at + 2]! << 16) | (bytes[at + 3]! << 24 >>> 0)));
  return `S-${bytes[0]}-${authority}${parts.length ? `-${parts.join("-")}` : ""}`;
}

export interface DirectoryLdapClientOptions { baseDn: string; }

/** Node의 표준 net/tls만 사용한 최소 LDAP simple bind/search 어댑터. Kerberos·referral은 의도적으로 지원하지 않는다. */
export class DirectoryLdapClient implements DirectoryClient {
  private readonly config: DirectoryConfig;
  private readonly baseDn: string;
  private service: LdapConnection | null = null;

  constructor(config: DirectoryConfig, options: DirectoryLdapClientOptions) {
    this.config = config;
    this.baseDn = options.baseDn;
  }

  async bindService(bindDn: string, bindPassword: string): Promise<void> {
    this.service = await LdapConnection.open(this.config);
    try {
      await this.service.bind(bindDn, bindPassword);
    } catch (error) {
      await this.service.close().catch(() => undefined);
      this.service = null;
      throw error;
    }
  }

  async authenticateUser(loginName: string, password: string): Promise<DirectoryEntry | null> {
    if (!this.service || password.length === 0) return null;
    const entry = await this.service.search(this.baseDn, loginName, "userPrincipalName") ?? await this.service.search(this.baseDn, loginName, "sAMAccountName");
    if (!entry) return null;
    const user = await LdapConnection.open(this.config);
    try { await user.bind(entry.dn, password); return entry; } finally { await user.close(); }
  }

  async close(): Promise<void> { await this.service?.close(); this.service = null; }
}

export function directoryProvider(config: DirectoryConfig, options: DirectoryLdapClientOptions): DirectoryProvider {
  return new DirectoryProvider(config, new DirectoryLdapClient(config, options));
}
