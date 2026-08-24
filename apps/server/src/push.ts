/**
 * JMAP `PushSubscription` (RFC 8620 §7.2) — 메서드와 **밖으로 나가는 POST**.
 *
 * ## 이 파일이 다루는 위험
 *
 * 사용자가 준 URL로 **서버가 나간다.** 그게 SSRF 표면이고, 메일 서버에서는 특히 아프다 —
 * 내부망에 있는 우리가 임의 주소로 POST를 꽂는 도구가 되기 때문이다. 두 겹으로 막는다:
 *
 *  ① **가드가 걸린 fetch**(`@ionosphere/webhook`의 정본). URL 문자열 검사 + 해석된 IP로
 *    직접 연결(피닝)이라 DNS 리바인딩까지 막는다. 여기서 새로 구현하지 않는 것이 요점이다 —
 *    우회 표기가 하나 발견될 때 한 곳만 고치면 두 경로가 함께 고쳐진다.
 *  ② **확인 절차**(§7.2.2). 등록 직후에는 `PushVerification`만 보내고, 클라이언트가 그
 *    코드를 되돌려줘야 `StateChange`가 나간다. ①이 막지 못하는 "공개 인터넷의 남의 주소"를
 *    이것이 막는다 — 그 주소의 주인은 코드를 우리에게 돌려줄 수 없다.
 *
 * ## 계정이 아니라 사용자에 묶인다
 *
 * §7.2가 명시한다("not tied to an Account"). 그래서 `accountId` 인자를 받지 않고 표준
 * `/get`·`/set` 헬퍼도 쓰지 않는다 — 그 헬퍼들은 `accountId` 검증이 전제다.
 */
import { encryptWebPush, ulid, type Logger } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import { MethodError, type CapabilityModule, type MethodContext } from "@ionosphere/proto-jmap";
import {
  deletePushSubscription,
  listPushSubscriptions,
  pushSubjects,
  pushTargets,
  updatePushSubscription,
  upsertPushSubscription,
  verifyPushSubscription,
  type PushSubscriptionRow,
} from "@ionosphere/store";
import { BlockedAddressError, isAllowedWebhookUrl, type FetchFn } from "@ionosphere/webhook";

/**
 * 구독 만료 상한 — 클라이언트가 더 먼 값을 줘도 여기로 깎는다.
 *
 * ★§7.2.1이 서버가 상한을 걸 수 있다고 명시한다. 없으면 클라이언트가 100년 뒤를 적어 두고
 * 사라지고, 우리는 죽은 엔드포인트로 영원히 POST한다 — 그건 우리가 남에게 보내는 무한
 * 트래픽이다. 7일이면 정상 클라이언트가 갱신하기에 넉넉하다.
 */
const MAX_EXPIRES_MS = 7 * 24 * 60 * 60 * 1000;

/** 한 사용자가 둘 수 있는 구독 수 — 기기 몇 대를 넘을 이유가 없다. */
const MAX_SUBSCRIPTIONS = 10;

export interface PushModuleOptions {
  db: DbDriver;
  logger: Logger;
  /** 가드가 걸린 fetch — 조립층이 `createGuardedFetch()`로 만들어 넘긴다. */
  fetch: FetchFn;
}

/** `/get`으로 나가는 형태 — **확인 코드는 없다**(push-store.ts 주석). */
function toJmap(row: PushSubscriptionRow): Record<string, unknown> {
  return {
    id: row.id,
    deviceClientId: row.deviceClientId,
    url: row.url,
    // 서버가 keys를 되돌려주지 않는다(§7.2.1: "the server MUST NOT return the keys").
    keys: null,
    verificationCode: null,
    expires: new Date(row.expires).toISOString(),
    types: row.types,
  };
}

/**
 * 이 구독으로 JSON 하나를 보낸다.
 *
 * ★`keys`가 있으면 **암호화한다**(RFC 8291). 중계자가 남이라 평문이면 "이 사람이 언제 메일을
 * 받았는지"의 시계열이 그에게 남는다.
 *
 * ★응답 본문을 읽지 않는다. 우리가 필요한 것은 "받았나"뿐이고, 본문을 읽으면 SSRF가
 * 블라인드가 아니게 된다.
 */
async function postToSubscription(opts: PushModuleOptions, row: PushSubscriptionRow, payload: unknown): Promise<void> {
  const json = JSON.stringify(payload);
  if (row.keys) {
    const { body } = encryptWebPush(new TextEncoder().encode(json), row.keys);
    await opts.fetch(row.url, {
      method: "POST",
      headers: { "content-type": "application/json", "content-encoding": "aes128gcm", ttl: "60" },
      // FetchFn은 문자열 본문을 받는다 — 바이너리를 latin1로 실어 바이트를 보존한다.
      body: body.toString("latin1"),
    });
    return;
  }
  await opts.fetch(row.url, { method: "POST", headers: { "content-type": "application/json", ttl: "60" }, body: json });
}

/**
 * 상태 변화 알림 — **검증된** 구독에만 간다.
 *
 * ★실패를 삼킨다. 푸시는 부가 기능이고, 부가 기능이 상태 갱신을 막으면 안 된다.
 * 차단 주소(`BlockedAddressError`)는 **경고로 남긴다** — 등록 시점에 통과했는데 지금 막혔다면
 * 그 사이 DNS가 바뀐 것이고, 그건 리바인딩 시도일 수 있어 운영자가 알아야 한다.
 */
export async function pushStateChange(
  opts: PushModuleOptions,
  subjectId: string,
  accountId: string,
  changed: Record<string, string>,
): Promise<number> {
  const targets = await pushTargets(opts.db, subjectId);
  let sent = 0;
  for (const row of targets) {
    // `types`가 있으면 관심 타입만 추린다(§7.2.1) — 안 추리면 클라이언트가 요청하지 않은 것을 받는다.
    const filtered = row.types === null ? changed : Object.fromEntries(Object.entries(changed).filter(([t]) => row.types!.includes(t)));
    if (Object.keys(filtered).length === 0) continue;
    try {
      await postToSubscription(opts, row, { "@type": "StateChange", changed: { [accountId]: filtered } });
      sent += 1;
    } catch (err) {
      if (err instanceof BlockedAddressError) {
        opts.logger.warn("push 대상이 차단 주소로 해석됐다 — 등록 이후 DNS가 바뀌었다", { id: row.id, url: row.url });
      } else {
        opts.logger.warn("push 실패", { id: row.id, error: err instanceof Error ? err.message : String(err) });
      }
    }
  }
  return sent;
}

function asString(v: unknown, field: string): string {
  if (typeof v !== "string" || v.length === 0) throw new MethodError("invalidArguments", { description: field });
  return v;
}

/** JMAP `PushSubscription` 메서드 묶음 — core capability에 속한다(§7.2). */
export function buildPushMethods(opts: PushModuleOptions): CapabilityModule["methods"] {
  /**
   * ★주체 id는 **컨텍스트에서** 온다. 인자로 받으면 남의 구독을 조회·삭제할 수 있다 —
   * 이 객체들은 계정 스코프가 아니라 그것이 유일한 경계다.
   */
  const subjectOf = (ctx: MethodContext): string => ctx.accountId;

  return {
    "PushSubscription/get": async (args, ctx) => {
      const ids = args.ids === null || args.ids === undefined ? null : args.ids;
      if (ids !== null && (!Array.isArray(ids) || ids.some((x) => typeof x !== "string"))) {
        throw new MethodError("invalidArguments", { description: "ids" });
      }
      const all = await listPushSubscriptions(opts.db, subjectOf(ctx));
      const list = ids === null ? all : all.filter((s) => (ids as string[]).includes(s.id));
      const found = new Set(list.map((s) => s.id));
      return {
        // ★`accountId`가 없다 — 계정에 묶이지 않는 객체다(§7.2). 넣으면 클라이언트가 계정별로 나눈다.
        state: null,
        list: list.map(toJmap),
        notFound: ids === null ? [] : (ids as string[]).filter((i) => !found.has(i)),
      };
    },

    "PushSubscription/set": async (args, ctx) => {
      const subjectId = subjectOf(ctx);
      const now = Date.now();
      const created: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      const notCreated: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      const updated: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      const notUpdated: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      const destroyed: string[] = [];
      const notDestroyed: Record<string, unknown> = Object.create(null) as Record<string, unknown>;

      const createArg = args.create;
      if (createArg && typeof createArg === "object" && !Array.isArray(createArg)) {
        for (const [cid, raw] of Object.entries(createArg as Record<string, unknown>)) {
          try {
            if (typeof raw !== "object" || raw === null) throw new MethodError("invalidProperties");
            const props = raw as Record<string, unknown>;
            const url = asString(props.url, "url");
            /**
             * ★등록 시점에도 가드를 통과시킨다. 배달 시점 검사만 두면 사용자가 사설 주소를
             * **등록해 두는 것**까지는 성공하고, 실패 이유를 알 방법이 없다.
             */
            if (!isAllowedWebhookUrl(url)) {
              notCreated[cid] = { type: "invalidProperties", properties: ["url"], description: "차단된 주소입니다" };
              continue;
            }
            if ((await listPushSubscriptions(opts.db, subjectId, now)).length >= MAX_SUBSCRIPTIONS) {
              notCreated[cid] = { type: "overQuota", description: `구독은 최대 ${MAX_SUBSCRIPTIONS}개입니다` };
              continue;
            }

            const keysRaw = props.keys;
            let keys: { p256dh: string; auth: string } | null = null;
            if (keysRaw && typeof keysRaw === "object" && !Array.isArray(keysRaw)) {
              const k = keysRaw as Record<string, unknown>;
              keys = { p256dh: asString(k.p256dh, "keys.p256dh"), auth: asString(k.auth, "keys.auth") };
            }
            // 상한을 넘는 만료는 **깎는다**(거절하지 않는다) — §7.2.1이 서버 상한을 허용한다.
            const wanted = typeof props.expires === "string" ? Date.parse(props.expires) : NaN;
            const expires = Number.isNaN(wanted) ? now + MAX_EXPIRES_MS : Math.min(wanted, now + MAX_EXPIRES_MS);
            const types = Array.isArray(props.types) ? (props.types as unknown[]).map(String) : null;

            const { id, verificationCode } = await upsertPushSubscription(
              opts.db,
              subjectId,
              { deviceClientId: asString(props.deviceClientId, "deviceClientId"), url, keys, expires, types },
              now,
            );

            /**
             * ★§7.2.2 — 등록 즉시 `PushVerification`을 보낸다. 이것이 성공해야 그 엔드포인트가
             * 구독자의 것임이 증명된다. **실패해도 구독은 남긴다** — 일시적 장애일 수 있고,
             * 검증되지 않은 구독으로는 어차피 아무것도 나가지 않는다.
             */
            try {
              await postToSubscription(
                opts,
                { id, deviceClientId: "", url, keys, verifiedAt: null, expires, types },
                { "@type": "PushVerification", pushSubscriptionId: id, verificationCode },
              );
            } catch (err) {
              opts.logger.warn("push 확인 요청 실패 — 구독은 미검증으로 남는다", {
                id,
                error: err instanceof Error ? err.message : String(err),
              });
            }
            created[cid] = { id, keys: null, verificationCode: null, expires: new Date(expires).toISOString() };
          } catch (err) {
            notCreated[cid] = err instanceof MethodError ? { type: err.type, ...err.detail } : { type: "invalidProperties" };
          }
        }
      }

      const updateArg = args.update;
      if (updateArg && typeof updateArg === "object" && !Array.isArray(updateArg)) {
        for (const [id, raw] of Object.entries(updateArg as Record<string, unknown>)) {
          const patch = (raw ?? {}) as Record<string, unknown>;
          /**
           * ★`verificationCode`를 되돌려주는 것이 **확인 절차**다(§7.2.2). URL도 keys도
           * 바꿀 수 없다 — 바꿀 수 있으면 검증된 구독의 목적지를 갈아치워 확인을 우회한다.
           */
          if (typeof patch.verificationCode === "string") {
            if (!(await verifyPushSubscription(opts.db, subjectId, id, patch.verificationCode, now))) {
              notUpdated[id] = { type: "invalidProperties", properties: ["verificationCode"] };
              continue;
            }
          }
          if ("url" in patch || "keys" in patch || "deviceClientId" in patch) {
            notUpdated[id] = { type: "invalidProperties", description: "url·keys·deviceClientId는 바꿀 수 없습니다" };
            continue;
          }
          const next: { expires?: number; types?: string[] | null } = {};
          if (typeof patch.expires === "string") {
            const ms = Date.parse(patch.expires);
            if (Number.isNaN(ms)) {
              notUpdated[id] = { type: "invalidProperties", properties: ["expires"] };
              continue;
            }
            next.expires = Math.min(ms, now + MAX_EXPIRES_MS);
          }
          if ("types" in patch) next.types = Array.isArray(patch.types) ? (patch.types as unknown[]).map(String) : null;
          if (!(await updatePushSubscription(opts.db, subjectId, id, next))) {
            notUpdated[id] = { type: "notFound" };
            continue;
          }
          updated[id] = next.expires !== undefined ? { expires: new Date(next.expires).toISOString() } : null;
        }
      }

      const destroyArg = args.destroy;
      if (Array.isArray(destroyArg)) {
        for (const raw of destroyArg) {
          const id = String(raw);
          if (await deletePushSubscription(opts.db, subjectId, id)) destroyed.push(id);
          else notDestroyed[id] = { type: "notFound" };
        }
      }

      return { created, notCreated, updated, notUpdated, destroyed, notDestroyed };
    },
  };
}

/** JMAP 타입명 ↔ `JmapStates` 키 — EventSource(§7.3)와 **같은 표**를 봐야 한다. */
const PUSH_STATE_TYPES: readonly [string, "email" | "mailbox" | "thread" | "submission"][] = [
  ["Email", "email"],
  ["Mailbox", "mailbox"],
  ["Thread", "thread"],
  ["EmailSubmission", "submission"],
];

/** 상태 조회만 쓴다 — `Store` 전체를 요구하지 않아야 테스트가 가짜를 넘길 수 있다. */
export interface PushStateSource {
  jmapState(accountId: string): Promise<{ email: string; mailbox: string; thread: string; submission: string }>;
}

export interface PushWatcherOptions extends PushModuleOptions {
  store: PushStateSource;
  /** 상태 폴링 주기(ms). 기본 5초 — EventSource(2초)보다 느슨하다(아래 주석). */
  intervalMs?: number;
}

/**
 * 상태 변화를 감시해 등록된 구독으로 밀어 준다.
 *
 * ★**구독을 가진 주체만** 폴링한다. 전체 계정을 돌면 이 기능을 안 쓰는 사람이 비용을 낸다.
 *
 * ★EventSource(2초)보다 주기가 느슨한 이유: 푸시는 연결이 없는 클라이언트를 위한 것이라
 * 초 단위 지연이 의미가 없다. 반대로 폴링이 잦으면 그 부하는 **메일 처리와 같은 프로세스**에
 * 얹힌다 — 이 서버의 모든 결정을 지배하는 제약이다.
 *
 * ★첫 폴은 **기준선**이다. 시작 직후 현재 상태를 변화로 보내면 재기동 때마다 모든 구독자가
 * 알림을 받는다.
 */
export class PushWatcher {
  private readonly opts: PushWatcherOptions;
  private readonly last = new Map<string, { email: string; mailbox: string; thread: string; submission: string }>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  constructor(opts: PushWatcherOptions) {
    this.opts = opts;
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), this.opts.intervalMs ?? 5000);
    // 프로세스 종료를 막지 않는다 — 리퍼·웹훅 워커와 같은 규율.
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** 한 사이클. 겹쳐 돌지 않는다 — 느린 엔드포인트가 다음 tick을 밀어내면 안 된다. */
  async tick(): Promise<number> {
    if (this.running) return 0;
    this.running = true;
    try {
      const subjects = await pushSubjects(this.opts.db);
      // 구독이 사라진 주체의 기준선은 버린다 — 안 그러면 맵이 계속 자란다.
      for (const key of [...this.last.keys()]) if (!subjects.includes(key)) this.last.delete(key);

      let sent = 0;
      for (const subjectId of subjects) {
        try {
          /**
           * ★이 저장소는 계정 하나가 곧 사용자다(`subject_id`가 곧 accountId). 다계정이
           * 생기면 여기서 그 사람의 계정들을 돌아야 한다 — 그 자리를 주석으로 남긴다.
           */
          const states = await this.opts.store.jmapState(subjectId);
          const prev = this.last.get(subjectId);
          this.last.set(subjectId, states);
          if (!prev) continue; // 첫 폴은 기준선

          const changed: Record<string, string> = {};
          for (const [type, key] of PUSH_STATE_TYPES) {
            if (states[key] !== prev[key]) changed[type] = states[key];
          }
          if (Object.keys(changed).length === 0) continue;
          sent += await pushStateChange(this.opts, subjectId, subjectId, changed);
        } catch (err) {
          this.opts.logger.warn("push 감시 실패", { subjectId, error: err instanceof Error ? err.message : String(err) });
        }
      }
      return sent;
    } finally {
      this.running = false;
    }
  }
}

/** 확인 코드 발급용 — 테스트가 같은 형식을 만들 수 있게 노출한다. */
export { ulid as newVerificationCode };
