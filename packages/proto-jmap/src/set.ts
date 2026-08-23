/**
 * 표준 /set 메서드 헬퍼 (RFC 8620 §5.3). 타입 불문 공통 봉투:
 * accountId·ifInState 검증, create→update→destroy 순 처리, SetError 집계, createdIds 갱신.
 * 타입별 실제 변이(스토어 배치)는 주입된 소스 콜백이 수행 — 이 파일은 순수.
 */
import { MethodError, type MethodContext, type SetError } from "./types.ts";
import { requireAccountId } from "./standard.ts";
import { isUnsafeKey } from "./safe-key.ts";

/** 소스 콜백이 throw하면 해당 항목이 notCreated/notUpdated/notDestroyed로 집계된다. */
export class SetItemError extends Error {
  readonly setError: SetError;
  constructor(type: string, detail: Record<string, unknown> = {}) {
    super(type);
    this.name = "SetItemError";
    this.setError = { type, ...detail };
  }
}

export interface SetSource {
  /** 현재 타입 state 문자열(ifInState 검증·oldState/newState). */
  state(accountId: string): Promise<string>;
  /** 생성 — 성공 시 {id, serverProps(서버가 세팅한 값, 예: id)} 반환. 실패 시 SetItemError. */
  create?(accountId: string, props: Record<string, unknown>, ctx: MethodContext): Promise<{ id: string; serverProps: Record<string, unknown> }>;
  /** 수정 — patch 객체 해석은 소스 소관. 서버 재계산 프로퍼티(없으면 null). 실패 시 SetItemError. */
  update?(accountId: string, id: string, patch: Record<string, unknown>, ctx: MethodContext): Promise<Record<string, unknown> | null>;
  /** 삭제 — 실패 시 SetItemError. */
  destroy?(accountId: string, id: string, ctx: MethodContext): Promise<void>;
}

/**
 * update/destroy의 id가 "#creationId"면 이번 요청의 createdIds로 해석.
 *
 * 심층방어(safe-key.ts): `createdIds["__proto__"]`는 이번 요청에서 만든 게 없어도 언제나
 * `Object.prototype`을 돌려주므로 `?? null`을 통과한다. 반환 타입은 `string | null`인데 실제로는
 * 객체가 흘러 소스의 `update(acc, id, …)`까지 내려간다 — 호출자가 방어할 수 없는 형태다.
 */
function resolveId(id: string, createdIds: Record<string, string>): string | null {
  if (!id.startsWith("#")) return id;
  const creationId = id.slice(1);
  if (isUnsafeKey(creationId)) return null; // 미해석 creationId와 같은 취급(notFound)
  return createdIds[creationId] ?? null;
}

export async function standardSet(args: Record<string, unknown>, accountId: string, ctx: MethodContext, source: SetSource): Promise<Record<string, unknown>> {
  const acc = requireAccountId(args, accountId);
  const oldState = await source.state(acc);

  if (args.ifInState !== undefined && args.ifInState !== null) {
    if (typeof args.ifInState !== "string") throw new MethodError("invalidArguments", { description: "ifInState" });
    if (args.ifInState !== oldState) throw new MethodError("stateMismatch");
  }

  /**
   * 집계 객체는 **프로토타입 없이** 만든다(심층방어: safe-key.ts).
   *
   * 키가 전부 클라이언트가 준 문자열(creationId·id)이라, 평범한 `{}`에 `obj["__proto__"] = v`를
   * 하면 프로퍼티가 추가되는 대신 프로토타입 교체 시도가 되어 **그 항목이 응답에서 조용히
   * 사라진다**. 거절을 보고해야 할 자리(notCreated/notUpdated)에서 이러면 클라이언트는 성공도
   * 실패도 못 받는다. `JSON.stringify`는 프로토타입 없는 객체도 그대로 직렬화한다.
   */
  const created = Object.create(null) as Record<string, Record<string, unknown>>;
  const updated = Object.create(null) as Record<string, Record<string, unknown> | null>;
  const destroyed: string[] = [];
  const notCreated = Object.create(null) as Record<string, SetError>;
  const notUpdated = Object.create(null) as Record<string, SetError>;
  const notDestroyed = Object.create(null) as Record<string, SetError>;

  // 1) create (RFC 8620 §5.3 순서: create → update → destroy)
  const createArg = asObject(args.create);
  if (createArg) {
    for (const [creationId, props] of Object.entries(createArg)) {
      // creationId는 created/notCreated/createdIds 세 객체의 **키가 된다**. 프로토타입 체인에
      // 닿는 이름이면 `created[id] = …`이 프로퍼티 추가가 아니라 프로토타입 교체가 돼
      // 응답에서 항목이 조용히 사라진다(심층방어: safe-key.ts).
      if (isUnsafeKey(creationId)) {
        notCreated[creationId] = { type: "invalidProperties", description: "허용되지 않는 creationId" };
        continue;
      }
      if (!source.create) {
        notCreated[creationId] = { type: "forbidden", description: "create 미지원" };
        continue;
      }
      const p = asObject(props);
      if (!p) {
        notCreated[creationId] = { type: "invalidProperties", description: "객체가 아님" };
        continue;
      }
      try {
        const { id, serverProps } = await source.create(acc, p, ctx);
        created[creationId] = { id, ...serverProps };
        ctx.createdIds[creationId] = id; // 같은 요청 내 이후 참조(#creationId) 가능
      } catch (err) {
        notCreated[creationId] = toSetError(err);
      }
    }
  }

  // 2) update
  const updateArg = asObject(args.update);
  if (updateArg) {
    for (const [rawId, patch] of Object.entries(updateArg)) {
      const id = resolveId(rawId, ctx.createdIds);
      if (id === null) {
        notUpdated[rawId] = { type: "notFound", description: "미해석 creationId" };
        continue;
      }
      if (!source.update) {
        notUpdated[rawId] = { type: "forbidden", description: "update 미지원" };
        continue;
      }
      const p = asObject(patch);
      if (!p) {
        notUpdated[rawId] = { type: "invalidPatch" };
        continue;
      }
      try {
        updated[id] = await source.update(acc, id, p, ctx);
      } catch (err) {
        notUpdated[rawId] = toSetError(err);
      }
    }
  }

  // 3) destroy
  const destroyArg = args.destroy;
  if (Array.isArray(destroyArg)) {
    for (const rawId of destroyArg) {
      if (typeof rawId !== "string") continue;
      const id = resolveId(rawId, ctx.createdIds);
      if (id === null) {
        notDestroyed[rawId] = { type: "notFound", description: "미해석 creationId" };
        continue;
      }
      if (!source.destroy) {
        notDestroyed[rawId] = { type: "forbidden", description: "destroy 미지원" };
        continue;
      }
      try {
        await source.destroy(acc, id, ctx);
        destroyed.push(id);
      } catch (err) {
        notDestroyed[rawId] = toSetError(err);
      }
    }
  }

  const newState = await source.state(acc);
  return { accountId: acc, oldState, newState, created, updated, destroyed, notCreated, notUpdated, notDestroyed };
}

function asObject(v: unknown): Record<string, unknown> | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  return v as Record<string, unknown>;
}

function toSetError(err: unknown): SetError {
  if (err instanceof SetItemError) return err.setError;
  // 예기치 못한 예외 — 항목 단위 serverFail(요청 전체는 안 죽임)
  return { type: "serverFail", description: err instanceof Error ? err.message : String(err) };
}
