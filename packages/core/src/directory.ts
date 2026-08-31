/** LDAP/AD 연동의 순수 계약. 네트워크 어댑터는 이 타입을 구현하고 core는 I/O를 하지 않는다. */

export const DIRECTORY_TRANSPORT = { ldaps: "ldaps", starttls: "starttls", ldap: "ldap" } as const;
export type DirectoryTransport = (typeof DIRECTORY_TRANSPORT)[keyof typeof DIRECTORY_TRANSPORT];

export interface DirectoryConfig {
  transport: DirectoryTransport;
  url: string;
  bindDn: string;
  bindPassword: string;
  timeoutMs: number;
  serverName?: string;
  tlsCa?: string;
}

export interface DirectoryEntry {
  dn: string;
  objectGuid?: Uint8Array;
  objectSid?: string;
  upn?: string;
  samAccountName?: string;
  mail?: string;
  displayName?: string;
}

export interface DirectoryIdentity {
  externalKey: string;
  loginNames: readonly string[];
  email: string | null;
  displayName: string | null;
}

/** 디렉터리 전체 조회 결과의 사용자. accountId는 로컬 DB가 소유하므로 외부 reader가 만들지 않는다. */
export interface DirectorySnapshotIdentity extends DirectoryIdentity {
  groupExternalKeys: readonly string[];
}

/** 그룹 member는 사용자·하위 그룹 모두 immutable external key로 표현한다. */
export interface DirectorySnapshotGroup {
  externalKey: string;
  displayName: string | null;
  memberExternalKeys: readonly string[];
}

export interface DirectorySnapshot {
  identities: readonly DirectorySnapshotIdentity[];
  groups: readonly DirectorySnapshotGroup[];
}

/** 네트워크·paging은 어댑터가 맡고 core 소비자는 완성된 snapshot만 받는다. */
export interface DirectorySnapshotReader {
  readSnapshot(): Promise<DirectorySnapshot>;
  close(): Promise<void>;
}

export class DirectoryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DirectoryError";
  }
}

/** 단순 bind는 암호화된 transport에서만 허용한다. 설정 오류는 부팅 때 fail closed 한다. */
export function validateDirectoryConfig(config: DirectoryConfig): void {
  let parsed: URL;
  try { parsed = new URL(config.url); } catch { throw new DirectoryError("directory URL이 유효하지 않음"); }
  const expected = config.transport === DIRECTORY_TRANSPORT.ldaps ? "ldaps:" : "ldap:";
  if (parsed.protocol !== expected) throw new DirectoryError(`transport와 URL scheme 불일치: ${config.transport}`);
  if (!config.bindDn || !config.bindPassword) throw new DirectoryError("simple bind 자격증명이 비어 있음");
  if (!Number.isInteger(config.timeoutMs) || config.timeoutMs < 100 || config.timeoutMs > 30_000) throw new DirectoryError("directory timeout은 100~30000ms");
  if (config.transport === DIRECTORY_TRANSPORT.ldap) throw new DirectoryError("암호화되지 않은 LDAP simple bind는 금지됨");
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

/** objectGUID를 우선하고 없을 때만 objectSid를 쓴다. email은 immutable identity가 아니다. */
export function externalIdentityKey(entry: DirectoryEntry): string {
  if (entry.objectGuid && entry.objectGuid.length > 0) return `guid:${base64Url(entry.objectGuid)}`;
  if (entry.objectSid && entry.objectSid.length > 0) return `sid:${entry.objectSid}`;
  throw new DirectoryError(`immutable external identity 없음: ${entry.dn}`);
}

export function mapDirectoryIdentity(entry: DirectoryEntry): DirectoryIdentity {
  const loginNames = [...new Set([entry.upn, entry.samAccountName].filter((v): v is string => typeof v === "string" && v.length > 0))];
  return { externalKey: externalIdentityKey(entry), loginNames, email: entry.mail?.length ? entry.mail.toLowerCase() : null, displayName: entry.displayName ?? null };
}

export interface DirectoryGroup { id: string; memberGroupIds: readonly string[]; }

export interface DirectoryClient {
  bindService(bindDn: string, bindPassword: string): Promise<void>;
  authenticateUser(loginName: string, password: string): Promise<DirectoryEntry | null>;
  close(): Promise<void>;
}

/** 전송 구현을 주입받는 directory provider. 외부 장애·매핑 실패는 인증 실패로 수렴한다. */
export class DirectoryProvider {
  private readonly config: DirectoryConfig;
  private readonly client: DirectoryClient;

  constructor(config: DirectoryConfig, client: DirectoryClient) {
    this.config = config;
    this.client = client;
  }

  async authenticate(loginName: string, password: string): Promise<DirectoryIdentity | null> {
    try {
      validateDirectoryConfig(this.config);
      await this.client.bindService(this.config.bindDn, this.config.bindPassword);
      const entry = await this.client.authenticateUser(loginName, password);
      if (!entry) return null;
      const identity = mapDirectoryIdentity(entry);
      if (identity.loginNames.length === 0) return null;
      return identity;
    } catch {
      await this.client.close().catch(() => undefined);
      return null;
    }
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}

/** nested group 해석. cycle과 깊이 초과는 부분 권한을 반환하지 않고 모두 실패시킨다. */
export function resolveNestedGroups(groups: readonly DirectoryGroup[], roots: readonly string[], maxDepth = 16): string[] {
  if (!Number.isInteger(maxDepth) || maxDepth < 1) throw new DirectoryError("nested group maxDepth는 양의 정수");
  const graph = new Map(groups.map((group) => [group.id, group.memberGroupIds]));
  const visited = new Set<string>();
  const active = new Set<string>();
  const visit = (id: string, depth: number): void => {
    if (depth > maxDepth) throw new DirectoryError("nested group depth 초과");
    if (active.has(id)) throw new DirectoryError("nested group cycle 감지");
    if (visited.has(id)) return;
    active.add(id);
    for (const child of graph.get(id) ?? []) visit(child, depth + 1);
    active.delete(id);
    visited.add(id);
  };
  for (const root of roots) visit(root, 0);
  return [...visited];
}
