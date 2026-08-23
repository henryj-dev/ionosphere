/**
 * 표준 /get · /changes 메서드 헬퍼 (RFC 8620 §5.1/§5.2). 타입 불문 공통 로직:
 * accountId 검증, ids(null=전체)·properties 필터, state/notFound 포맷, cannotCalculateChanges.
 * 데이터 소스는 주입(스토어 연동은 상위 계층) — 이 파일은 순수.
 */
import { MethodError } from "./types.ts";

/** JMAP 객체 — 반드시 문자열 id를 가진다. */
export interface JmapObject {
  id: string;
  [key: string]: unknown;
}

export interface GetResult {
  list: JmapObject[];
  notFound: string[];
}

/** /get 데이터 소스. ids=null이면 전체(maxObjectsInGet 상한은 소스가 처리 가능). */
export interface GetSource {
  state(accountId: string): Promise<string>;
  get(accountId: string, ids: readonly string[] | null): Promise<GetResult>;
}

/** /changes 결과(RFC 8620 §5.2). cannotCalculate면 클라이언트 전체 재동기화. */
export type ChangesResult =
  | { cannotCalculate: true }
  | { cannotCalculate: false; oldState: string; newState: string; hasMoreChanges: boolean; created: string[]; updated: string[]; destroyed: string[] };

export interface ChangesSource {
  changes(accountId: string, sinceState: string, maxChanges: number): Promise<ChangesResult>;
}

const DEFAULT_MAX_CHANGES = 500;

/** 인자에서 accountId 검증 — 주 계정과 불일치 시 accountNotFound(RFC 8620 §5). */
export function requireAccountId(args: Record<string, unknown>, expected: string): string {
  const a = args.accountId;
  if (typeof a !== "string" || a.length === 0) throw new MethodError("invalidArguments", { description: "accountId 누락" });
  if (a !== expected) throw new MethodError("accountNotFound");
  return a;
}

function asStringArrayOrNull(v: unknown, field: string): string[] | null {
  if (v === null || v === undefined) return null;
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    throw new MethodError("invalidArguments", { description: `${field}는 문자열 배열이어야 함` });
  }
  return v as string[];
}

/** properties 배열이면 id + 지정 프로퍼티만 남긴다(id는 항상 포함, RFC 8620 §5.1). */
function projectProperties(obj: JmapObject, properties: string[] | null): JmapObject {
  if (properties === null) return obj;
  const out: JmapObject = { id: obj.id };
  for (const p of properties) {
    if (p !== "id" && p in obj) out[p] = obj[p];
  }
  return out;
}

/** 표준 /get (RFC 8620 §5.1). */
export async function standardGet(args: Record<string, unknown>, accountId: string, source: GetSource): Promise<Record<string, unknown>> {
  const acc = requireAccountId(args, accountId);
  const ids = asStringArrayOrNull(args.ids, "ids");
  const properties = asStringArrayOrNull(args.properties, "properties");
  const state = await source.state(acc);
  const { list, notFound } = await source.get(acc, ids);
  return {
    accountId: acc,
    state,
    list: list.map((o) => projectProperties(o, properties)),
    notFound,
  };
}

/** 표준 /changes (RFC 8620 §5.2). cannotCalculate → MethodError(cannotCalculateChanges). */
export async function standardChanges(args: Record<string, unknown>, accountId: string, source: ChangesSource): Promise<Record<string, unknown>> {
  const acc = requireAccountId(args, accountId);
  if (typeof args.sinceState !== "string") throw new MethodError("invalidArguments", { description: "sinceState 누락" });
  let maxChanges = DEFAULT_MAX_CHANGES;
  if (args.maxChanges !== null && args.maxChanges !== undefined) {
    if (typeof args.maxChanges !== "number" || !Number.isInteger(args.maxChanges) || args.maxChanges < 1) {
      throw new MethodError("invalidArguments", { description: "maxChanges는 양의 정수" });
    }
    maxChanges = args.maxChanges;
  }
  const r = await source.changes(acc, args.sinceState, maxChanges);
  if (r.cannotCalculate) throw new MethodError("cannotCalculateChanges");
  return {
    accountId: acc,
    oldState: r.oldState,
    newState: r.newState,
    hasMoreChanges: r.hasMoreChanges,
    created: r.created,
    updated: r.updated,
    destroyed: r.destroyed,
  };
}
