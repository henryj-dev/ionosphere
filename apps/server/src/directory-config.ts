import { readFileSync } from "node:fs";
import { DIRECTORY_TRANSPORT, type DirectoryConfig } from "@ionosphere/core";
import type { DirectoryLdapAttributeMap, DirectoryLdapClientOptions, LdapSearchFilter } from "./directory-ldap.ts";
import { LdapDirectorySource } from "./directory-source.ts";
import type { DirectorySnapshotSource } from "./shared-mailbox-runtime.ts";

interface RawDirectoryConfig {
  provider?: unknown;
  tenantId?: unknown;
  transport?: unknown;
  url?: unknown;
  bindDn?: unknown;
  bindPassword?: unknown;
  baseDn?: unknown;
  userBaseDn?: unknown;
  groupBaseDn?: unknown;
  userFilter?: unknown;
  groupFilter?: unknown;
  timeoutMs?: unknown;
  serverName?: unknown;
  tlsCaFile?: unknown;
  pageSize?: unknown;
  maxEntries?: unknown;
  nestedGroupMaxDepth?: unknown;
  attributes?: unknown;
}

function required(value: unknown, field: string, index: number): string {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`IONOSPHERE_DIRECTORIES[${index}].${field}가 비어 있음`);
  return value;
}

function optionalString(value: unknown, field: string, index: number): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.trim() === "") throw new Error(`IONOSPHERE_DIRECTORIES[${index}].${field}가 문자열이 아님`);
  return value;
}

function optionalInteger(value: unknown, field: string, index: number): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value)) throw new Error(`IONOSPHERE_DIRECTORIES[${index}].${field}가 정수가 아님`);
  return value;
}

function filter(value: unknown, field: string, index: number): LdapSearchFilter | undefined {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`IONOSPHERE_DIRECTORIES[${index}].${field}가 객체가 아님`);
  const item = value as Record<string, unknown>;
  return { attribute: required(item.attribute, `${field}.attribute`, index), value: required(item.value, `${field}.value`, index) };
}

function attributes(value: unknown, index: number): Partial<DirectoryLdapAttributeMap> | undefined {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`IONOSPHERE_DIRECTORIES[${index}].attributes가 객체가 아님`);
  const allowed = new Set(["objectGuid", "objectSid", "upn", "samAccountName", "mail", "displayName", "groupMember"]);
  const out: Partial<DirectoryLdapAttributeMap> = {};
  for (const [key, item] of Object.entries(value)) {
    if (!allowed.has(key)) throw new Error(`IONOSPHERE_DIRECTORIES[${index}].attributes.${key}는 지원하지 않음`);
    out[key as keyof DirectoryLdapAttributeMap] = required(item, `attributes.${key}`, index);
  }
  return out;
}

/** JSON 하나를 정본으로 써 provider 여러 개의 부분 env 조합 사고를 막는다. 오류에는 비밀값을 싣지 않는다. */
export function directorySourcesFromJson(raw: string | undefined): Readonly<Record<string, DirectorySnapshotSource>> | undefined {
  if (raw === undefined || raw.trim() === "") return undefined;
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error("IONOSPHERE_DIRECTORIES가 유효한 JSON이 아님"); }
  if (!Array.isArray(parsed) || parsed.length === 0) throw new Error("IONOSPHERE_DIRECTORIES는 비어 있지 않은 배열이어야 함");
  const sources: Record<string, DirectorySnapshotSource> = {};
  for (const [index, value] of parsed.entries()) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`IONOSPHERE_DIRECTORIES[${index}]가 객체가 아님`);
    const item = value as RawDirectoryConfig;
    const provider = required(item.provider, "provider", index);
    if (!/^[a-zA-Z0-9._-]{1,32}$/u.test(provider)) throw new Error(`IONOSPHERE_DIRECTORIES[${index}].provider 형식 오류`);
    if (sources[provider]) throw new Error(`IONOSPHERE_DIRECTORIES provider 중복: ${provider}`);
    const transport = item.transport;
    if (transport !== DIRECTORY_TRANSPORT.ldaps && transport !== DIRECTORY_TRANSPORT.starttls) throw new Error(`IONOSPHERE_DIRECTORIES[${index}].transport는 ldaps 또는 starttls`);
    const tlsCaFile = optionalString(item.tlsCaFile, "tlsCaFile", index);
    const serverName = optionalString(item.serverName, "serverName", index);
    const userBaseDn = optionalString(item.userBaseDn, "userBaseDn", index);
    const groupBaseDn = optionalString(item.groupBaseDn, "groupBaseDn", index);
    const userFilter = filter(item.userFilter, "userFilter", index);
    const groupFilter = filter(item.groupFilter, "groupFilter", index);
    const pageSize = optionalInteger(item.pageSize, "pageSize", index);
    const maxEntries = optionalInteger(item.maxEntries, "maxEntries", index);
    const nestedGroupMaxDepth = optionalInteger(item.nestedGroupMaxDepth, "nestedGroupMaxDepth", index);
    const attributeMap = attributes(item.attributes, index);
    const config: DirectoryConfig = {
      transport,
      url: required(item.url, "url", index),
      bindDn: required(item.bindDn, "bindDn", index),
      bindPassword: required(item.bindPassword, "bindPassword", index),
      timeoutMs: optionalInteger(item.timeoutMs, "timeoutMs", index) ?? 5000,
      ...(serverName ? { serverName } : {}),
      ...(tlsCaFile ? { tlsCa: readFileSync(tlsCaFile, "utf8") } : {}),
    };
    const ldap: DirectoryLdapClientOptions = {
      baseDn: required(item.baseDn, "baseDn", index),
      ...(userBaseDn ? { userBaseDn } : {}),
      ...(groupBaseDn ? { groupBaseDn } : {}),
      ...(userFilter ? { userFilter } : {}),
      ...(groupFilter ? { groupFilter } : {}),
      ...(pageSize !== undefined ? { pageSize } : {}),
      ...(maxEntries !== undefined ? { maxEntries } : {}),
      ...(nestedGroupMaxDepth !== undefined ? { nestedGroupMaxDepth } : {}),
      ...(attributeMap ? { attributes: attributeMap } : {}),
    };
    sources[provider] = new LdapDirectorySource({ tenantId: required(item.tenantId, "tenantId", index), config, ldap });
  }
  return sources;
}
