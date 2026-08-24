/**
 * JMAP `PushSubscription` (RFC 8620 §7.2).
 *
 * ★이 기능은 **사용자가 준 URL로 서버가 나간다.** 그래서 이 파일이 지키는 것은 기능이
 * 아니라 그 표면이다:
 *  · 사설·루프백 주소는 **등록조차** 안 된다(SSRF)
 *  · 확인 전에는 `StateChange`가 **한 번도** 나가지 않는다(§7.2.2)
 *  · 확인 코드는 조회로 **새어 나가지 않는다** — 새면 절차가 형식만 남는다
 *  · 검증된 구독의 URL은 **바꿀 수 없다** — 바꿀 수 있으면 확인을 우회한다
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { listPushSubscriptions } from "@ionosphere/store";
import { buildPushMethods, PushWatcher, pushStateChange, type PushModuleOptions } from "../src/push.ts";
import { BlockedAddressError, type FetchFn } from "@ionosphere/webhook";

const SUBJECT = "A".repeat(26);
const quietLogger = { info: () => {}, warn: () => {}, error: () => {}, debug: () => {}, child: () => quietLogger } as never;

interface Posted {
  url: string;
  body: string;
  headers: Record<string, string>;
}

/**
 * 가짜 fetch — 실제 가드는 `@ionosphere/webhook`이 테스트한다. 여기서는 **가드가 던지면
 * 어떻게 되는가**와 **무엇이 나갔는가**를 본다.
 */
function collector(opts: { blockHosts?: string[] } = {}): { fetch: FetchFn; posted: Posted[] } {
  const posted: Posted[] = [];
  return {
    posted,
    fetch: async (url, init) => {
      if (opts.blockHosts?.some((h) => url.includes(h))) throw new BlockedAddressError("blocked");
      posted.push({ url, body: init.body, headers: init.headers });
      return { status: 200 };
    },
  };
}

async function setup(fetchFn: FetchFn): Promise<{ db: DbDriver; opts: PushModuleOptions; methods: ReturnType<typeof buildPushMethods> }> {
  const db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
  const opts: PushModuleOptions = { db, logger: quietLogger, fetch: fetchFn };
  return { db, opts, methods: buildPushMethods(opts) };
}

const ctx = { accountId: SUBJECT, createdIds: {} } as never;

/** 등록 → 확인 코드 회수 → 확인까지. 코드는 **엔드포인트로 간 것**에서 꺼낸다. */
async function subscribeAndVerify(
  methods: ReturnType<typeof buildPushMethods>,
  posted: Posted[],
  url = "https://push.example.test/endpoint",
): Promise<string> {
  const res = (await methods["PushSubscription/set"]!({ create: { s1: { deviceClientId: "dev-1", url } } }, ctx)) as Record<string, unknown>;
  const id = (res.created as Record<string, { id: string }>).s1!.id;
  const verification = JSON.parse(posted[posted.length - 1]!.body) as { "@type": string; verificationCode: string };
  expect(verification["@type"]).toBe("PushVerification");
  await methods["PushSubscription/set"]!({ update: { [id]: { verificationCode: verification.verificationCode } } }, ctx);
  return id;
}

describe("등록과 확인 (§7.2.2)", () => {
  /** ★등록 직후 나가는 것은 `StateChange`가 아니라 `PushVerification`이다(§7.2.2). */
  test("등록하면 PushVerification이 먼저 나간다", async () => {
    const c = collector();
    const { db, methods } = await setup(c.fetch);
    await methods["PushSubscription/set"]!(
      { create: { s1: { deviceClientId: "dev-1", url: "https://push.example.test/e" } } },
      ctx,
    );
    expect(c.posted).toHaveLength(1);
    const body = JSON.parse(c.posted[0]!.body) as { "@type": string; pushSubscriptionId: string; verificationCode: string };
    expect(body["@type"]).toBe("PushVerification");
    expect(body.pushSubscriptionId).toBeTruthy();
    expect(body.verificationCode).toBeTruthy();
    await db.close();
  });

  test("확인 절차 왕복", async () => {
    const c = collector();
    const { db, opts, methods } = await setup(c.fetch);
    const id = await subscribeAndVerify(methods, c.posted);

    const got = await listPushSubscriptions(db, SUBJECT);
    expect(got).toHaveLength(1);
    expect(got[0]!.verifiedAt).not.toBe(null);
    expect(got[0]!.id).toBe(id);
    void opts;
    await db.close();
  });

  /** ★확인 전에는 아무것도 나가지 않는다 — 이것이 임의 URL POST 도구가 되지 않는 장치다. */
  test("확인 전에는 StateChange를 보내지 않는다", async () => {
    const c = collector();
    const { db, opts, methods } = await setup(c.fetch);
    await methods["PushSubscription/set"]!(
      { create: { s1: { deviceClientId: "dev-1", url: "https://push.example.test/endpoint" } } },
      ctx,
    );
    c.posted.length = 0; // 확인 요청은 이미 나갔다 — 이후를 본다

    const sent = await pushStateChange(opts, SUBJECT, SUBJECT, { Email: "5" });
    expect(sent).toBe(0);
    expect(c.posted).toHaveLength(0);
    await db.close();
  });

  test("확인 뒤에는 StateChange가 나간다", async () => {
    const c = collector();
    const { db, opts, methods } = await setup(c.fetch);
    await subscribeAndVerify(methods, c.posted);
    c.posted.length = 0;

    expect(await pushStateChange(opts, SUBJECT, SUBJECT, { Email: "5" })).toBe(1);
    const payload = JSON.parse(c.posted[0]!.body) as { "@type": string; changed: Record<string, Record<string, string>> };
    expect(payload["@type"]).toBe("StateChange");
    expect(payload.changed[SUBJECT]!.Email).toBe("5");
    await db.close();
  });

  /** ★틀린 코드로는 확인되지 않는다 — 절차가 형식만 남으면 안 된다. */
  test("틀린 확인 코드는 거절", async () => {
    const c = collector();
    const { db, methods } = await setup(c.fetch);
    const res = (await methods["PushSubscription/set"]!(
      { create: { s1: { deviceClientId: "dev-1", url: "https://push.example.test/e" } } },
      ctx,
    )) as Record<string, unknown>;
    const id = (res.created as Record<string, { id: string }>).s1!.id;

    const bad = (await methods["PushSubscription/set"]!({ update: { [id]: { verificationCode: "nope" } } }, ctx)) as Record<string, unknown>;
    expect((bad.notUpdated as Record<string, { type: string }>)[id]?.type).toBe("invalidProperties");
    expect((await listPushSubscriptions(db, SUBJECT))[0]!.verifiedAt).toBe(null);
    await db.close();
  });
});

describe("SSRF 표면", () => {
  /** ★등록 시점에 막는다. 배달 시점만 막으면 사용자는 등록이 성공한 줄 알고 원인을 모른다. */
  test("사설·루프백 주소는 등록되지 않는다", async () => {
    const c = collector();
    const { db, methods } = await setup(c.fetch);
    for (const url of [
      "http://127.0.0.1/x",
      "http://localhost/x",
      "http://10.0.0.1/x",
      "http://[::1]/x",
      "http://169.254.169.254/latest/meta-data",
      "http://[::ffff:a9fe:a9fe]/x",
    ]) {
      const res = (await methods["PushSubscription/set"]!({ create: { s: { deviceClientId: "d", url } } }, ctx)) as Record<string, unknown>;
      const notCreated = res.notCreated as Record<string, { type: string }>;
      expect(notCreated.s?.type).toBe("invalidProperties");
    }
    // 하나도 만들어지지 않았다 = 확인 요청조차 나가지 않았다
    expect(await listPushSubscriptions(db, SUBJECT)).toHaveLength(0);
    expect(c.posted).toHaveLength(0);
    await db.close();
  });

  /**
   * ★등록 뒤에 DNS가 바뀌어 사설로 해석되면 **연결 단계 가드**가 던진다. 그때 푸시는
   * 조용히 실패해야 하고(부가 기능이 상태 갱신을 막으면 안 된다) 상태는 남아야 한다.
   */
  test("배달 시점 차단은 삼키고 나머지는 계속 보낸다", async () => {
    const blocked = { hosts: [] as string[] };
    const posted: Posted[] = [];
    const fetchFn: FetchFn = async (url, init) => {
      if (blocked.hosts.some((h) => url.includes(h))) throw new BlockedAddressError("blocked");
      posted.push({ url, body: init.body, headers: init.headers });
      return { status: 200 };
    };
    const { db, opts, methods } = await setup(fetchFn);

    // 두 구독을 만들고 **둘 다 확인**한다(확인 단계에서는 아직 차단이 없다).
    for (const [dev, host] of [["dev-a", "rebound.example.test"], ["dev-b", "ok.example.test"]] as const) {
      const res = (await methods["PushSubscription/set"]!(
        { create: { s: { deviceClientId: dev, url: `https://${host}/e` } } },
        ctx,
      )) as Record<string, unknown>;
      const id = (res.created as Record<string, { id: string }>).s!.id;
      const code = (JSON.parse(posted[posted.length - 1]!.body) as { verificationCode: string }).verificationCode;
      await methods["PushSubscription/set"]!({ update: { [id]: { verificationCode: code } } }, ctx);
    }
    posted.length = 0;

    // 이제 한쪽이 사설로 해석된다(등록 이후 DNS가 바뀐 상황).
    blocked.hosts.push("rebound.example.test");
    /**
     * ★막힌 쪽은 조용히 실패하고 **나머지는 그대로 간다**. 한 엔드포인트의 실패가 다른
     * 구독자의 알림까지 막으면 안 된다.
     */
    expect(await pushStateChange(opts, SUBJECT, SUBJECT, { Email: "1" })).toBe(1);
    expect(posted).toHaveLength(1);
    expect(posted[0]!.url).toContain("ok.example.test");
    await db.close();
  });
});

describe("조회 (§7.2.1)", () => {
  /** ★확인 코드와 keys는 **절대** 나가지 않는다 — 나가면 확인 절차가 우회된다. */
  test("verificationCode·keys를 돌려주지 않는다", async () => {
    const c = collector();
    const { db, methods } = await setup(c.fetch);
    /**
     * ★**진짜** P-256 공개키를 쓴다. 형식이 맞지 않으면 암호화가 던지고 확인 요청이 아예
     * 나가지 않는다 — 그러면 이 테스트가 검사하려던 자리(응답에 비밀이 없나)에 닿지 못한다.
     */
    const { createECDH } = await import("node:crypto");
    const ec = createECDH("prime256v1");
    ec.generateKeys();
    const b64u = (b: Buffer): string => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    await methods["PushSubscription/set"]!(
      {
        create: {
          s1: {
            deviceClientId: "dev-1",
            url: "https://push.example.test/e",
            keys: { p256dh: b64u(ec.getPublicKey()), auth: b64u(Buffer.alloc(16, 5)) },
          },
        },
      },
      ctx,
    );
    const got = (await methods["PushSubscription/get"]!({ ids: null }, ctx)) as Record<string, unknown>;
    const list = got.list as Record<string, unknown>[];
    expect(list).toHaveLength(1);
    expect(list[0]!.verificationCode).toBe(null);
    expect(list[0]!.keys).toBe(null);
    // ★응답 어디에도 확인 코드가 없다 — 저장된 값을 직접 꺼내 대조한다(본문은 암호문이다).
    const { rows } = await db.query({ sql: "SELECT verification_code FROM push_subscriptions", params: [] });
    expect(JSON.stringify(got)).not.toContain(String(rows[0]!.verification_code));
    await db.close();
  });

  test("모르는 id는 notFound", async () => {
    const c = collector();
    const { db, methods } = await setup(c.fetch);
    const got = (await methods["PushSubscription/get"]!({ ids: ["nope"] }, ctx)) as Record<string, unknown>;
    expect(got.notFound).toEqual(["nope"]);
    await db.close();
  });
});

describe("변경과 삭제", () => {
  /** ★검증된 구독의 목적지를 바꿀 수 있으면 확인 절차를 우회한다. */
  test("url·keys·deviceClientId는 바꿀 수 없다", async () => {
    const c = collector();
    const { db, methods } = await setup(c.fetch);
    const id = await subscribeAndVerify(methods, c.posted);
    for (const patch of [{ url: "https://evil.example.test/x" }, { keys: null }, { deviceClientId: "other" }]) {
      const res = (await methods["PushSubscription/set"]!({ update: { [id]: patch } }, ctx)) as Record<string, unknown>;
      expect((res.notUpdated as Record<string, { type: string }>)[id]?.type).toBe("invalidProperties");
    }
    expect((await listPushSubscriptions(db, SUBJECT))[0]!.url).toBe("https://push.example.test/endpoint");
    await db.close();
  });

  /** ★만료가 없으면 죽은 엔드포인트로 영원히 POST한다 — 상한으로 깎는다(§7.2.1). */
  test("만료는 상한으로 깎인다", async () => {
    const c = collector();
    const { db, methods } = await setup(c.fetch);
    const res = (await methods["PushSubscription/set"]!(
      { create: { s1: { deviceClientId: "d", url: "https://push.example.test/e", expires: "2099-01-01T00:00:00Z" } } },
      ctx,
    )) as Record<string, unknown>;
    const expires = Date.parse((res.created as Record<string, { expires: string }>).s1!.expires);
    expect(expires).toBeLessThan(Date.now() + 8 * 24 * 3600 * 1000);
    await db.close();
  });

  /** ★같은 기기가 다시 등록하면 교체다 — 아니면 죽은 구독이 쌓인다(§7.2.1). */
  test("같은 deviceClientId는 교체된다", async () => {
    const c = collector();
    const { db, methods } = await setup(c.fetch);
    await methods["PushSubscription/set"]!({ create: { a: { deviceClientId: "dev", url: "https://a.example.test/e" } } }, ctx);
    await methods["PushSubscription/set"]!({ create: { b: { deviceClientId: "dev", url: "https://b.example.test/e" } } }, ctx);
    const got = await listPushSubscriptions(db, SUBJECT);
    expect(got).toHaveLength(1);
    expect(got[0]!.url).toBe("https://b.example.test/e");
    await db.close();
  });

  test("삭제된다", async () => {
    const c = collector();
    const { db, methods } = await setup(c.fetch);
    const id = await subscribeAndVerify(methods, c.posted);
    const res = (await methods["PushSubscription/set"]!({ destroy: [id] }, ctx)) as Record<string, unknown>;
    expect(res.destroyed).toEqual([id]);
    expect(await listPushSubscriptions(db, SUBJECT)).toHaveLength(0);
    await db.close();
  });

  test("구독 수 상한", async () => {
    const c = collector();
    const { db, methods } = await setup(c.fetch);
    let overQuota = false;
    for (let i = 0; i < 12; i++) {
      const res = (await methods["PushSubscription/set"]!(
        { create: { s: { deviceClientId: `dev-${i}`, url: `https://p${i}.example.test/e` } } },
        ctx,
      )) as Record<string, unknown>;
      if ((res.notCreated as Record<string, { type: string }>).s?.type === "overQuota") overQuota = true;
    }
    expect(overQuota).toBe(true);
    await db.close();
  });
});

describe("types 필터 (§7.2.1)", () => {
  test("관심 타입만 받는다", async () => {
    const c = collector();
    const { db, opts, methods } = await setup(c.fetch);
    const res = (await methods["PushSubscription/set"]!(
      { create: { s1: { deviceClientId: "d", url: "https://push.example.test/e", types: ["Mailbox"] } } },
      ctx,
    )) as Record<string, unknown>;
    const id = (res.created as Record<string, { id: string }>).s1!.id;
    const code = (JSON.parse(c.posted[0]!.body) as { verificationCode: string }).verificationCode;
    await methods["PushSubscription/set"]!({ update: { [id]: { verificationCode: code } } }, ctx);
    c.posted.length = 0;

    // Email만 바뀌면 아무것도 안 간다
    expect(await pushStateChange(opts, SUBJECT, SUBJECT, { Email: "5" })).toBe(0);
    // Mailbox가 섞이면 그것만 실려 간다
    expect(await pushStateChange(opts, SUBJECT, SUBJECT, { Email: "6", Mailbox: "7" })).toBe(1);
    const payload = JSON.parse(c.posted[0]!.body) as { changed: Record<string, Record<string, string>> };
    expect(Object.keys(payload.changed[SUBJECT]!)).toEqual(["Mailbox"]);
    await db.close();
  });
});

describe("암호화 (RFC 8291)", () => {
  /** keys가 있으면 본문이 암호화된다 — 중계자가 남이라 평문이면 시계열이 그에게 남는다. */
  test("keys가 있으면 aes128gcm으로 나간다", async () => {
    const c = collector();
    const { db, opts, methods } = await setup(c.fetch);
    // 진짜 P-256 공개키가 필요하다 — 형식이 맞지 않으면 암호화가 던진다.
    const { createECDH } = await import("node:crypto");
    const e = createECDH("prime256v1");
    e.generateKeys();
    const b64url = (b: Buffer): string => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const keys = { p256dh: b64url(e.getPublicKey()), auth: b64url(Buffer.alloc(16, 3)) };

    const res = (await methods["PushSubscription/set"]!(
      { create: { s1: { deviceClientId: "d", url: "https://push.example.test/e", keys } } },
      ctx,
    )) as Record<string, unknown>;
    const id = (res.created as Record<string, { id: string }>).s1!.id;
    // 확인 요청부터 암호화돼 나간다
    expect(c.posted[0]!.headers["content-encoding"]).toBe("aes128gcm");

    // 확인 코드는 암호문 안에 있으므로 저장소에서 꺼내 쓴다(테스트 편의).
    const { rows } = await db.query({ sql: "SELECT verification_code FROM push_subscriptions WHERE id = ?", params: [id] });
    await methods["PushSubscription/set"]!({ update: { [id]: { verificationCode: String(rows[0]!.verification_code) } } }, ctx);
    c.posted.length = 0;

    await pushStateChange(opts, SUBJECT, SUBJECT, { Email: "9" });
    expect(c.posted[0]!.headers["content-encoding"]).toBe("aes128gcm");
    // 평문 JSON이 아니다
    expect(c.posted[0]!.body.includes("StateChange")).toBe(false);
    await db.close();
  });
});

describe("PushWatcher", () => {
  /** ★첫 폴은 기준선이다 — 재기동 때마다 모든 구독자가 알림을 받으면 안 된다. */
  test("첫 폴은 알림을 보내지 않는다", async () => {
    const c = collector();
    const { db, methods } = await setup(c.fetch);
    await subscribeAndVerify(methods, c.posted);
    c.posted.length = 0;

    let state = { email: "1", mailbox: "1", thread: "1", submission: "1" };
    const w = new PushWatcher({ db, logger: quietLogger, fetch: c.fetch, store: { jmapState: async () => state } });
    expect(await w.tick()).toBe(0);
    expect(c.posted).toHaveLength(0);

    // 두 번째부터 변화를 본다
    state = { ...state, email: "2" };
    expect(await w.tick()).toBe(1);
    const payload = JSON.parse(c.posted[0]!.body) as { changed: Record<string, Record<string, string>> };
    expect(payload.changed[SUBJECT]!.Email).toBe("2");
    await db.close();
  });

  test("변화가 없으면 아무것도 안 보낸다", async () => {
    const c = collector();
    const { db, methods } = await setup(c.fetch);
    await subscribeAndVerify(methods, c.posted);
    c.posted.length = 0;
    const state = { email: "1", mailbox: "1", thread: "1", submission: "1" };
    const w = new PushWatcher({ db, logger: quietLogger, fetch: c.fetch, store: { jmapState: async () => state } });
    await w.tick();
    expect(await w.tick()).toBe(0);
    expect(c.posted).toHaveLength(0);
    await db.close();
  });

  /** 구독이 없으면 폴링 자체를 하지 않는다 — 이 기능을 안 쓰는 사람이 비용을 내면 안 된다. */
  test("구독이 없으면 상태를 조회하지 않는다", async () => {
    const c = collector();
    const { db } = await setup(c.fetch);
    let calls = 0;
    const w = new PushWatcher({
      db,
      logger: quietLogger,
      fetch: c.fetch,
      store: {
        jmapState: async () => {
          calls += 1;
          return { email: "1", mailbox: "1", thread: "1", submission: "1" };
        },
      },
    });
    await w.tick();
    expect(calls).toBe(0);
    await db.close();
  });
});

describe("Core capability 병합", () => {
  /**
   * ★`PushSubscription`은 Core capability에 얹힌다. 엔진이 모듈을 **메서드 단위로** 합치지
   * 않고 capability 단위로 덮어썼다면 `Core/echo`가 사라진다 — 그러면 이 배선이 다른 기능을
   * 조용히 지운 것이 된다.
   */
  test("Core/echo가 살아 있다", async () => {
    const { JmapEngine, coreModule, CORE_CAPABILITY } = await import("@ionosphere/proto-jmap");
    const c = collector();
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    const engine = new JmapEngine({
      modules: [coreModule, { capability: CORE_CAPABILITY, methods: buildPushMethods({ db, logger: quietLogger, fetch: c.fetch }) }],
      capabilities: [CORE_CAPABILITY],
      sessionState: () => "0",
    });
    // `handle`의 둘째 인자는 컨텍스트가 아니라 **accountId 문자열**이다(엔진이 ctx를 만든다).
    const res = await engine.handle({ using: [CORE_CAPABILITY], methodCalls: [["Core/echo", { hi: 1 }, "c0"]] }, SUBJECT);
    expect((res.methodResponses[0] as [string, Record<string, unknown>, string])[0]).toBe("Core/echo");

    const push = await engine.handle({ using: [CORE_CAPABILITY], methodCalls: [["PushSubscription/get", { ids: null }, "c0"]] }, SUBJECT);
    const r = push.methodResponses[0] as [string, Record<string, unknown>, string];
    if (r[0] === "error") throw new Error(`unexpected error: ${JSON.stringify(r[1])}`);
    expect(r[0]).toBe("PushSubscription/get");
    await db.close();
  });
});
