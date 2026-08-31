import { connect as tcpConnect, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import {
  DIRECTORY_TRANSPORT,
  DirectoryError,
  DirectoryProvider,
  externalIdentityKey,
  mapDirectoryIdentity,
  validateDirectoryConfig,
  type DirectoryClient,
  type DirectoryConfig,
  type DirectoryEntry,
  type DirectorySnapshot,
  type DirectorySnapshotReader,
} from "@ionosphere/core";

type LdapSocket = Socket | TLSSocket;

const PAGED_RESULTS_OID = "1.2.840.113556.1.4.319";
const STARTTLS_OID = "1.3.6.1.4.1.1466.20037";
const DEFAULT_PAGE_SIZE = 500;
const DEFAULT_MAX_ENTRIES = 100_000;
const DEFAULT_NESTED_GROUP_DEPTH = 16;

function encodeLength(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) throw new DirectoryError("BER length가 유효하지 않음");
  if (length < 128) return Uint8Array.of(length);
  const bytes: number[] = [];
  let rest = length;
  while (rest > 0) { bytes.unshift(rest & 0xff); rest = Math.floor(rest / 256); }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function tlv(tag: number, value: Uint8Array): Uint8Array {
  const length = encodeLength(value.length);
  const out = new Uint8Array(1 + length.length + value.length);
  out[0] = tag;
  out.set(length, 1);
  out.set(value, 1 + length.length);
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
function octet(value: string | Uint8Array): Uint8Array { return tlv(0x04, typeof value === "string" ? text(value) : value); }
function bool(value: boolean): Uint8Array { return tlv(0x01, Uint8Array.of(value ? 0xff : 0)); }
function enumerated(value: number): Uint8Array { return tlv(0x0a, integerBytes(value)); }

function integerBytes(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) throw new DirectoryError("BER integer가 유효하지 않음");
  if (value === 0) return Uint8Array.of(0);
  const bytes: number[] = [];
  let rest = value;
  while (rest > 0) { bytes.unshift(rest & 0xff); rest = Math.floor(rest / 256); }
  if ((bytes[0]! & 0x80) !== 0) bytes.unshift(0);
  return Uint8Array.from(bytes);
}

function integer(value: number): Uint8Array { return tlv(0x02, integerBytes(value)); }

interface BerNode { tag: number; value: Uint8Array; children: BerNode[]; }

function parseNode(bytes: Uint8Array, offset = 0, depth = 0): { node: BerNode; next: number } {
  if (depth > 32 || offset + 2 > bytes.length) throw new DirectoryError("잘린 LDAP BER 응답");
  const tag = bytes[offset]!;
  let at = offset + 1;
  const first = bytes[at++]!;
  let length = first;
  if ((first & 0x80) !== 0) {
    const count = first & 0x7f;
    if (count === 0 || count > 6 || at + count > bytes.length) throw new DirectoryError("지원하지 않는 LDAP BER length");
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[at++]!;
  }
  const end = at + length;
  if (end > bytes.length) throw new DirectoryError("잘린 LDAP BER value");
  const value = bytes.slice(at, end);
  const children: BerNode[] = [];
  if ((tag & 0x20) !== 0) {
    for (let childAt = at; childAt < end;) {
      const parsed = parseNode(bytes, childAt, depth + 1);
      if (parsed.next <= childAt) throw new DirectoryError("LDAP BER child 길이가 유효하지 않음");
      children.push(parsed.node);
      childAt = parsed.next;
    }
  }
  return { node: { tag, value, children }, next: end };
}

function numberValue(node: BerNode): number {
  let value = 0;
  for (const byte of node.value) value = value * 256 + byte;
  return value;
}

function stringValue(node: BerNode): string { return new TextDecoder().decode(node.value); }

interface LdapMessage { id: number; protocol: BerNode; controls: readonly BerNode[]; }

function decodeMessage(root: BerNode): LdapMessage {
  if (root.tag !== 0x30 || root.children.length < 2) throw new DirectoryError("LDAP message 형식이 유효하지 않음");
  const id = numberValue(root.children[0]!);
  const protocol = root.children[1]!;
  const controlsNode = root.children[2];
  return { id, protocol, controls: controlsNode?.tag === 0xa0 ? controlsNode.children : [] };
}

function control(oid: string, value: Uint8Array): Uint8Array {
  // Controls는 [0] IMPLICIT SEQUENCE OF Control이라 a0 아래에 Control SEQUENCE를 바로 둔다.
  return tlv(0xa0, sequence(octet(oid), bool(false), octet(value)));
}

function pagedControl(pageSize: number, cookie: Uint8Array): Uint8Array {
  return control(PAGED_RESULTS_OID, sequence(integer(pageSize), octet(cookie)));
}

function responsePageCookie(controls: readonly BerNode[]): Uint8Array {
  for (const item of controls) {
    if (item.tag !== 0x30 || !item.children[0] || stringValue(item.children[0]) !== PAGED_RESULTS_OID) continue;
    const value = item.children.find((child, index) => index > 0 && child.tag === 0x04);
    if (!value) return new Uint8Array();
    const decoded = parseNode(value.value).node;
    return decoded.children[1]?.value ?? new Uint8Array();
  }
  return new Uint8Array();
}

function resultCode(response: BerNode): number {
  return response.children[0] ? numberValue(response.children[0]) : 80;
}

export interface LdapSearchFilter { attribute: string; value: string; }
interface LdapSearchOptions {
  baseDn: string;
  filter: LdapSearchFilter;
  attributes: readonly string[];
  pageSize: number;
  maxEntries: number;
}

interface LdapRecord { dn: string; attributes: ReadonlyMap<string, readonly Uint8Array[]>; }

function attributeName(value: string): string {
  if (!/^[a-z][a-z0-9-]*(?:;[a-z0-9-]+)*$/iu.test(value)) throw new DirectoryError(`LDAP attribute 이름이 유효하지 않음: ${value}`);
  return value;
}

function encodeSearch(options: LdapSearchOptions, timeoutMs: number): Uint8Array {
  const filter = tlv(0xa3, concat(octet(attributeName(options.filter.attribute)), octet(options.filter.value)));
  const attributes = sequence(...options.attributes.map((name) => octet(attributeName(name))));
  // subtree(2), neverDerefAliases(0), page 단위 size limit, 초 단위 server time limit, typesOnly=false.
  return tlv(0x63, concat(
    octet(options.baseDn),
    enumerated(2),
    enumerated(0),
    integer(options.pageSize),
    integer(Math.max(1, Math.ceil(timeoutMs / 1000))),
    bool(false),
    filter,
    attributes,
  ));
}

function recordFromEntry(entry: BerNode): LdapRecord {
  const attributes = new Map<string, readonly Uint8Array[]>();
  for (const attribute of entry.children[1]?.children ?? []) {
    const nameNode = attribute.children[0];
    if (!nameNode) continue;
    const values = attribute.children[1]?.children.map((node) => node.value) ?? [];
    attributes.set(stringValue(nameNode).toLowerCase(), values);
  }
  return { dn: stringValue(entry.children[0]!), attributes };
}

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
    try {
      if (config.transport === DIRECTORY_TRANSPORT.starttls) await connection.startTls(host, config.serverName, config.tlsCa);
      return connection;
    } catch (error) {
      await connection.close().catch(() => undefined);
      throw error;
    }
  }

  private async startTls(host: string, serverName?: string, tlsCa?: string): Promise<void> {
    const response = await this.exchange(tlv(0x77, tlv(0x80, text(STARTTLS_OID))));
    if (response.protocol.tag !== 0x78 || resultCode(response.protocol) !== 0) throw new DirectoryError("LDAP StartTLS 거부");
    const upgraded = await new Promise<TLSSocket>((resolve, reject) => {
      const tls = tlsConnect({ socket: this.socket, servername: serverName ?? host, rejectUnauthorized: true, ...(tlsCa ? { ca: tlsCa } : {}) });
      tls.once("secureConnect", () => resolve(tls));
      tls.once("error", reject);
    });
    this.socket = upgraded;
    upgraded.setTimeout(this.timeoutMs);
    upgraded.on("timeout", () => upgraded.destroy(new DirectoryError("LDAP timeout")));
  }

  async bind(bindDn: string, password: string): Promise<void> {
    const response = await this.exchange(tlv(0x60, concat(integer(3), octet(bindDn), tlv(0x80, text(password)))));
    if (response.protocol.tag !== 0x61 || resultCode(response.protocol) !== 0) throw new DirectoryError("LDAP bind 실패");
  }

  async search(options: LdapSearchOptions): Promise<LdapRecord[]> {
    const out: LdapRecord[] = [];
    let cookie: Uint8Array<ArrayBufferLike> = new Uint8Array();
    const seenCookies = new Set<string>();
    do {
      const id = this.send(encodeSearch(options, this.timeoutMs), pagedControl(options.pageSize, cookie));
      let done = false;
      while (!done) {
        const message = await this.readMessage();
        if (message.id !== id) throw new DirectoryError("LDAP 응답 message id 불일치");
        if (message.protocol.tag === 0x64) {
          out.push(recordFromEntry(message.protocol));
          if (out.length > options.maxEntries) throw new DirectoryError(`LDAP snapshot 상한 초과: ${options.maxEntries}`);
          continue;
        }
        if (message.protocol.tag !== 0x65 || resultCode(message.protocol) !== 0) throw new DirectoryError("LDAP search 실패");
        cookie = responsePageCookie(message.controls);
        if (cookie.length > 0) {
          const encoded = Buffer.from(cookie).toString("base64url");
          if (seenCookies.has(encoded)) throw new DirectoryError("LDAP paged-results cookie가 반복됨");
          seenCookies.add(encoded);
        }
        done = true;
      }
    } while (cookie.length > 0);
    return out;
  }

  private send(protocol: Uint8Array, controls?: Uint8Array): number {
    if (this.ended) throw new DirectoryError("LDAP connection closed");
    const id = this.nextMessageId++;
    this.socket.write(Buffer.from(sequence(integer(id), protocol, ...(controls ? [controls] : []))));
    return id;
  }

  private async exchange(protocol: Uint8Array): Promise<LdapMessage> {
    const id = this.send(protocol);
    const response = await this.readMessage();
    if (response.id !== id) throw new DirectoryError("LDAP 응답 message id 불일치");
    return response;
  }

  private async readMessage(): Promise<LdapMessage> {
    const read = (): LdapMessage | null => {
      if (this.pending.length < 2) return null;
      const lengthByte = this.pending[1]!;
      const lengthBytes = (lengthByte & 0x80) === 0 ? 0 : lengthByte & 0x7f;
      if (lengthBytes > 6) throw new DirectoryError("지원하지 않는 LDAP packet length");
      const header = 2 + lengthBytes;
      if (this.pending.length < header) return null;
      const length = lengthBytes === 0 ? lengthByte : this.pending.slice(2, header).reduce((value, byte) => value * 256 + byte, 0);
      if (length > 16 * 1024 * 1024) throw new DirectoryError("LDAP 응답이 16MiB 상한을 초과함");
      if (this.pending.length < header + length) return null;
      const packet = this.pending.subarray(0, header + length);
      this.pending = this.pending.subarray(header + length);
      return decodeMessage(parseNode(new Uint8Array(packet)).node);
    };
    const immediate = read();
    if (immediate) return immediate;
    return new Promise<LdapMessage>((resolve, reject) => {
      const onData = (chunk: Buffer): void => {
        this.pending = Buffer.concat([this.pending, chunk]);
        try {
          const message = read();
          if (message) { cleanup(); resolve(message); }
        } catch (error) {
          cleanup();
          reject(error);
        }
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

function sidToString(bytes: Uint8Array): string {
  if (bytes.length < 8) return "";
  const authority = bytes.slice(2, 8).reduce((value, byte) => value * 256 + byte, 0);
  const parts: string[] = [];
  for (let at = 8; at + 4 <= bytes.length; at += 4) parts.push(String((bytes[at]! | (bytes[at + 1]! << 8) | (bytes[at + 2]! << 16) | (bytes[at + 3]! << 24)) >>> 0));
  return `S-${bytes[0]}-${authority}${parts.length ? `-${parts.join("-")}` : ""}`;
}

export interface DirectoryLdapAttributeMap {
  objectGuid: string;
  objectSid: string;
  upn: string;
  samAccountName: string;
  mail: string;
  displayName: string;
  groupMember: string;
}

const DEFAULT_ATTRIBUTES: DirectoryLdapAttributeMap = {
  objectGuid: "objectGUID",
  objectSid: "objectSid",
  upn: "userPrincipalName",
  samAccountName: "sAMAccountName",
  mail: "mail",
  displayName: "displayName",
  groupMember: "member",
};

export interface DirectoryLdapClientOptions {
  baseDn: string;
  userBaseDn?: string;
  groupBaseDn?: string;
  userFilter?: LdapSearchFilter;
  groupFilter?: LdapSearchFilter;
  attributes?: Partial<DirectoryLdapAttributeMap>;
  pageSize?: number;
  maxEntries?: number;
  nestedGroupMaxDepth?: number;
}

interface NormalizedOptions {
  userBaseDn: string;
  groupBaseDn: string;
  userFilter: LdapSearchFilter;
  groupFilter: LdapSearchFilter;
  attributes: DirectoryLdapAttributeMap;
  pageSize: number;
  maxEntries: number;
  nestedGroupMaxDepth: number;
}

function normalizeOptions(options: DirectoryLdapClientOptions): NormalizedOptions {
  const pageSize = options.pageSize ?? DEFAULT_PAGE_SIZE;
  const maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const nestedGroupMaxDepth = options.nestedGroupMaxDepth ?? DEFAULT_NESTED_GROUP_DEPTH;
  if (!options.baseDn.trim()) throw new DirectoryError("LDAP baseDn이 비어 있음");
  if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 1000) throw new DirectoryError("LDAP pageSize는 1~1000");
  if (!Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > 1_000_000) throw new DirectoryError("LDAP maxEntries는 1~1000000");
  if (!Number.isInteger(nestedGroupMaxDepth) || nestedGroupMaxDepth < 1 || nestedGroupMaxDepth > 64) throw new DirectoryError("nested group maxDepth는 1~64");
  const attributes = { ...DEFAULT_ATTRIBUTES, ...options.attributes };
  for (const value of Object.values(attributes)) attributeName(value);
  const userFilter = options.userFilter ?? { attribute: "objectClass", value: "user" };
  const groupFilter = options.groupFilter ?? { attribute: "objectClass", value: "group" };
  attributeName(userFilter.attribute);
  attributeName(groupFilter.attribute);
  return {
    userBaseDn: options.userBaseDn ?? options.baseDn,
    groupBaseDn: options.groupBaseDn ?? options.baseDn,
    userFilter,
    groupFilter,
    attributes,
    pageSize,
    maxEntries,
    nestedGroupMaxDepth,
  };
}

function first(record: LdapRecord, name: string): Uint8Array | undefined { return record.attributes.get(name.toLowerCase())?.[0]; }
function strings(record: LdapRecord, name: string): string[] { return (record.attributes.get(name.toLowerCase()) ?? []).map((value) => new TextDecoder().decode(value)); }

function directoryEntry(record: LdapRecord, attributes: DirectoryLdapAttributeMap): DirectoryEntry {
  const guid = first(record, attributes.objectGuid);
  const sid = first(record, attributes.objectSid);
  const upn = first(record, attributes.upn);
  const sam = first(record, attributes.samAccountName);
  const mail = first(record, attributes.mail);
  const displayName = first(record, attributes.displayName);
  return {
    dn: record.dn,
    ...(guid ? { objectGuid: guid } : {}),
    ...(sid ? { objectSid: sidToString(sid) } : {}),
    ...(upn ? { upn: new TextDecoder().decode(upn) } : {}),
    ...(sam ? { samAccountName: new TextDecoder().decode(sam) } : {}),
    ...(mail ? { mail: new TextDecoder().decode(mail) } : {}),
    ...(displayName ? { displayName: new TextDecoder().decode(displayName) } : {}),
  };
}

function uniqueExternalKeys(entries: readonly { dn: string; externalKey: string }[]): Map<string, string> {
  const keys = new Set<string>();
  const byDn = new Map<string, string>();
  for (const entry of entries) {
    if (keys.has(entry.externalKey)) throw new DirectoryError(`중복 directory external key: ${entry.externalKey}`);
    keys.add(entry.externalKey);
    byDn.set(entry.dn.trim().toLowerCase(), entry.externalKey);
  }
  return byDn;
}

function inheritedGroups(direct: readonly string[], parents: ReadonlyMap<string, readonly string[]>, maxDepth: number): string[] {
  const out = new Set<string>();
  const active = new Set<string>();
  const visit = (key: string, depth: number): void => {
    if (depth > maxDepth) throw new DirectoryError("nested group depth 초과");
    if (active.has(key)) throw new DirectoryError("nested group cycle 감지");
    if (out.has(key)) return;
    active.add(key);
    out.add(key);
    for (const parent of parents.get(key) ?? []) visit(parent, depth + 1);
    active.delete(key);
  };
  for (const key of direct) visit(key, 0);
  return [...out];
}

/** 인증 client와 별개 연결로 완성된 subtree snapshot을 읽어 중간 page를 외부에 노출하지 않는다. */
export class DirectoryLdapSnapshotReader implements DirectorySnapshotReader {
  private readonly config: DirectoryConfig;
  private readonly options: NormalizedOptions;
  private active = new Set<LdapConnection>();

  constructor(config: DirectoryConfig, options: DirectoryLdapClientOptions) {
    validateDirectoryConfig(config);
    this.config = config;
    this.options = normalizeOptions(options);
  }

  async readSnapshot(): Promise<DirectorySnapshot> {
    const connection = await LdapConnection.open(this.config);
    this.active.add(connection);
    try {
      await connection.bind(this.config.bindDn, this.config.bindPassword);
      const a = this.options.attributes;
      const common = [a.objectGuid, a.objectSid, a.displayName] as const;
      const users = await connection.search({ baseDn: this.options.userBaseDn, filter: this.options.userFilter, attributes: [...common, a.upn, a.samAccountName, a.mail], pageSize: this.options.pageSize, maxEntries: this.options.maxEntries });
      const groups = await connection.search({ baseDn: this.options.groupBaseDn, filter: this.options.groupFilter, attributes: [...common, a.groupMember], pageSize: this.options.pageSize, maxEntries: this.options.maxEntries });

      const userRows = users.map((record) => ({ record, entry: directoryEntry(record, a) })).map(({ record, entry }) => ({ record, identity: mapDirectoryIdentity(entry), dn: entry.dn, externalKey: externalIdentityKey(entry) }));
      const groupRows = groups.map((record) => {
        const entry = directoryEntry(record, a);
        return { record, dn: entry.dn, externalKey: externalIdentityKey(entry), displayName: entry.displayName ?? null };
      });
      const byDn = uniqueExternalKeys([...userRows, ...groupRows]);
      const groupKeys = new Set(groupRows.map((group) => group.externalKey));
      const directByIdentity = new Map<string, string[]>();
      const parents = new Map<string, string[]>();
      const snapshotGroups = groupRows.map((group) => {
        const memberExternalKeys = [...new Set(strings(group.record, a.groupMember).map((dn) => byDn.get(dn.trim().toLowerCase())).filter((key): key is string => key !== undefined))];
        for (const member of memberExternalKeys) {
          if (groupKeys.has(member)) {
            const current = parents.get(member) ?? [];
            current.push(group.externalKey);
            parents.set(member, current);
          } else {
            const current = directByIdentity.get(member) ?? [];
            current.push(group.externalKey);
            directByIdentity.set(member, current);
          }
        }
        return { externalKey: group.externalKey, displayName: group.displayName, memberExternalKeys };
      });
      // 사용자에게 직접 닿지 않는 그룹 cycle도 다음 동기화에서 권한 그래프가 될 수 있으므로 전부 검증한다.
      for (const group of groupKeys) inheritedGroups([group], parents, this.options.nestedGroupMaxDepth);
      const identities = userRows.map(({ identity }) => ({
        ...identity,
        groupExternalKeys: inheritedGroups(directByIdentity.get(identity.externalKey) ?? [], parents, this.options.nestedGroupMaxDepth),
      }));
      return { identities, groups: snapshotGroups };
    } finally {
      this.active.delete(connection);
      await connection.close().catch(() => undefined);
    }
  }

  async close(): Promise<void> {
    const active = [...this.active];
    this.active.clear();
    await Promise.all(active.map(async (connection) => await connection.close().catch(() => undefined)));
  }
}

/** 기존 단건 인증 어댑터. snapshot reader는 동시 실행 안전성을 위해 별도 연결을 쓴다. */
export class DirectoryLdapClient implements DirectoryClient {
  private readonly config: DirectoryConfig;
  private readonly options: NormalizedOptions;
  private service: LdapConnection | null = null;

  constructor(config: DirectoryConfig, options: DirectoryLdapClientOptions) {
    this.config = config;
    this.options = normalizeOptions(options);
  }

  async bindService(bindDn: string, bindPassword: string): Promise<void> {
    await this.service?.close().catch(() => undefined);
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
    const a = this.options.attributes;
    const attributes = [a.objectGuid, a.objectSid, a.upn, a.samAccountName, a.mail, a.displayName];
    const search = async (attribute: string): Promise<LdapRecord | null> => {
      const records = await this.service!.search({ baseDn: this.options.userBaseDn, filter: { attribute, value: loginName }, attributes, pageSize: 2, maxEntries: 2 });
      if (records.length > 1) throw new DirectoryError("LDAP login name이 둘 이상과 일치함");
      return records[0] ?? null;
    };
    const record = await search(a.upn) ?? await search(a.samAccountName);
    if (!record) return null;
    const entry = directoryEntry(record, a);
    const user = await LdapConnection.open(this.config);
    try { await user.bind(entry.dn, password); return entry; } finally { await user.close(); }
  }

  async close(): Promise<void> { await this.service?.close(); this.service = null; }
}

export function directoryProvider(config: DirectoryConfig, options: DirectoryLdapClientOptions): DirectoryProvider {
  return new DirectoryProvider(config, new DirectoryLdapClient(config, options));
}

export function directorySnapshotReader(config: DirectoryConfig, options: DirectoryLdapClientOptions): DirectorySnapshotReader {
  return new DirectoryLdapSnapshotReader(config, options);
}
