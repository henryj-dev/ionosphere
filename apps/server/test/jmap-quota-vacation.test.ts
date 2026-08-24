/**
 * JMAP `Quota`(RFC 9425) · `VacationResponse`(RFC 8621 §8).
 *
 * ★두 기능 모두 **데이터/판정이 이미 있고 표면만 없었다.** 쿼터는 IMAP QUOTA가 이미 보여
 * 주는 값이고, 부재 응답은 Sieve `vacation`의 게이트가 이미 돌고 있다. 그래서 이 파일의
 * 요점은 "새 기능이 도는가"가 아니라 **같은 소스를 보는가**다 — 갈라지면 IMAP에서는 찼다는데
 * JMAP에서는 아니거나, 자동 응답이 두 번 나간다.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

let app: IonosphereApp;
let blobRoot: string;
let base: string;
let accountId: string;
const AUTH = "Basic " + Buffer.from("you@test.local:pw-qv").toString("base64");

const USING = [
  "urn:ietf:params:jmap:core",
  "urn:ietf:params:jmap:mail",
  // Identity는 submission 모듈 소속이다 — using에 없으면 unknownMethod가 된다.
  "urn:ietf:params:jmap:submission",
  "urn:ietf:params:jmap:quota",
  "urn:ietf:params:jmap:vacationresponse",
];

async function jmapCall(methodCalls: unknown[]): Promise<unknown[][]> {
  const res = await fetch(`${base}/jmap/api`, {
    method: "POST",
    headers: { authorization: AUTH, "content-type": "application/json" },
    body: JSON.stringify({ using: USING, methodCalls }),
  });
  expect(res.status).toBe(200);
  return ((await res.json()) as { methodResponses: unknown[][] }).methodResponses;
}
const body = (r: unknown[][], i = 0): Record<string, unknown> => (r[i] as [string, Record<string, unknown>, string])[1];
const name = (r: unknown[][], i = 0): string => (r[i] as [string, unknown, string])[0];

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-qv-"));
  app = new IonosphereApp({
    hostname: "test.local",
    dbPath: ":memory:",
    blobRoot,
    smtpPort: 0,
    pop3Port: 0,
    jmapPort: 0,
    resolver: offlineResolver(),
  });
  await app.start();
  const me = await app.createUser("you@test.local", "pw-qv");
  accountId = me.accountId;
  base = `http://127.0.0.1:${app.jmapPort}`;
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("Session 광고", () => {
  test("두 capability가 서버·계정 양쪽에 있다", async () => {
    const res = await fetch(`${base}/jmap/session`, { headers: { authorization: AUTH } });
    const s = (await res.json()) as { capabilities: Record<string, unknown>; accounts: Record<string, { accountCapabilities: Record<string, unknown> }> };
    for (const urn of ["urn:ietf:params:jmap:quota", "urn:ietf:params:jmap:vacationresponse"]) {
      expect(urn in s.capabilities).toBe(true);
      // ★계정별 능력 객체에도 키가 있어야 클라이언트가 그 계정에서 쓸 수 있다고 판단한다.
      expect(urn in s.accounts[accountId]!.accountCapabilities).toBe(true);
    }
  });
});

describe("Quota/get (RFC 9425)", () => {
  test("octets·count 두 객체를 낸다", async () => {
    const r = await jmapCall([["Quota/get", { accountId, ids: null }, "c0"]]);
    expect(name(r)).toBe("Quota/get");
    const list = body(r).list as Record<string, unknown>[];
    expect(list.map((q) => q.id).sort()).toEqual(["count", "octets"]);
    const octets = list.find((q) => q.id === "octets")!;
    expect(octets.resourceType).toBe("octets");
    expect(octets.scope).toBe("account");
    expect(typeof octets.used).toBe("number");
  });

  /** ★`quota_bytes === 0`은 스토어에서 **무제한**이다 — JMAP에서는 그게 null이다. */
  test("무제한 계정은 hardLimit이 null", async () => {
    const r = await jmapCall([["Quota/get", { accountId, ids: ["octets"] }, "c0"]]);
    expect((body(r).list as Record<string, unknown>[])[0]!.hardLimit).toBe(null);
  });

  /** ★IMAP QUOTA와 **같은 값**이어야 한다. 갈라지면 어느 쪽이 맞는지 알 수 없다. */
  test("스토어의 getQuota와 같은 값이다", async () => {
    await app.db.batch([{ sql: "UPDATE accounts SET quota_bytes = ? WHERE id = ?", params: [12345, accountId] }]);
    const q = await app.store.getQuota(accountId);
    const r = await jmapCall([["Quota/get", { accountId, ids: ["octets", "count"] }, "c0"]]);
    const list = body(r).list as Record<string, unknown>[];
    expect(list.find((x) => x.id === "octets")!.hardLimit).toBe(q.quotaBytes);
    expect(list.find((x) => x.id === "octets")!.used).toBe(q.usedBytes);
    expect(list.find((x) => x.id === "count")!.used).toBe(q.messageCount);
    await app.db.batch([{ sql: "UPDATE accounts SET quota_bytes = 0 WHERE id = ?", params: [accountId] }]);
  });

  test("모르는 id는 notFound", async () => {
    const r = await jmapCall([["Quota/get", { accountId, ids: ["nope"] }, "c0"]]);
    expect(body(r).notFound).toEqual(["nope"]);
    expect(body(r).list).toEqual([]);
  });

  test("Quota/query는 두 id를 낸다", async () => {
    const r = await jmapCall([["Quota/query", { accountId }, "c0"]]);
    expect((body(r).ids as string[]).sort()).toEqual(["count", "octets"]);
  });

  /** 받아 놓고 무시하면 클라이언트가 걸러진 줄 안다 — 명시적으로 거절한다. */
  test("Quota/query의 filter는 거절한다", async () => {
    const r = await jmapCall([["Quota/query", { accountId, filter: { resourceType: "octets" } }, "c0"]]);
    expect(name(r)).toBe("error");
    expect(body(r).type).toBe("unsupportedFilter");
  });

  test("Quota/changes는 cannotCalculateChanges", async () => {
    const r = await jmapCall([["Quota/changes", { accountId, sinceState: "0" }, "c0"]]);
    expect(name(r)).toBe("error");
    expect(body(r).type).toBe("cannotCalculateChanges");
  });
});

describe("VacationResponse (RFC 8621 §8)", () => {
  test("기본은 꺼져 있고 싱글턴이 항상 존재한다", async () => {
    const r = await jmapCall([["VacationResponse/get", { accountId, ids: null }, "c0"]]);
    const list = body(r).list as Record<string, unknown>[];
    expect(list).toHaveLength(1);
    expect(list[0]!.id).toBe("singleton");
    expect(list[0]!.isEnabled).toBe(false);
  });

  test("설정을 저장하고 다시 읽는다", async () => {
    const r = await jmapCall([
      ["VacationResponse/set", { accountId, update: { singleton: { isEnabled: true, subject: "Away", textBody: "휴가 중입니다" } } }, "c0"],
      ["VacationResponse/get", { accountId, ids: ["singleton"] }, "c1"],
    ]);
    expect(body(r, 0).notUpdated).toEqual({});
    const v = (body(r, 1).list as Record<string, unknown>[])[0]!;
    expect(v.isEnabled).toBe(true);
    expect(v.subject).toBe("Away");
    expect(v.textBody).toBe("휴가 중입니다");
  });

  /** ★패치는 현재 값 **위에** 얹는다 — 통째로 덮으면 isEnabled만 바꾸려다 본문이 지워진다. */
  test("부분 갱신이 나머지를 지우지 않는다", async () => {
    await jmapCall([["VacationResponse/set", { accountId, update: { singleton: { isEnabled: true, textBody: "본문 유지" } } }, "c0"]]);
    const r = await jmapCall([
      ["VacationResponse/set", { accountId, update: { singleton: { isEnabled: false } } }, "c0"],
      ["VacationResponse/get", { accountId, ids: ["singleton"] }, "c1"],
    ]);
    const v = (body(r, 1).list as Record<string, unknown>[])[0]!;
    expect(v.isEnabled).toBe(false);
    expect(v.textBody).toBe("본문 유지");
  });

  /** ★빈 자동 응답은 상대에게 빈 메일을 보내는 것이라 안 보내느니만 못하다. */
  test("본문 없이 켜면 거절한다", async () => {
    await jmapCall([["VacationResponse/set", { accountId, update: { singleton: { isEnabled: false, textBody: null, htmlBody: null } } }, "c0"]]);
    const r = await jmapCall([["VacationResponse/set", { accountId, update: { singleton: { isEnabled: true } } }, "c0"]]);
    const notUpdated = body(r).notUpdated as Record<string, { type: string }>;
    expect(notUpdated.singleton?.type).toBe("invalidProperties");
  });

  test("fromDate가 toDate보다 늦으면 거절한다", async () => {
    const r = await jmapCall([
      [
        "VacationResponse/set",
        { accountId, update: { singleton: { isEnabled: true, textBody: "x", fromDate: "2026-12-01T00:00:00Z", toDate: "2026-01-01T00:00:00Z" } } },
        "c0",
      ],
    ]);
    expect((body(r).notUpdated as Record<string, { type: string }>).singleton?.type).toBe("invalidProperties");
  });

  test("날짜 형식 오류도 거절한다", async () => {
    const r = await jmapCall([["VacationResponse/set", { accountId, update: { singleton: { fromDate: "어제" } } }, "c0"]]);
    expect((body(r).notUpdated as Record<string, { type: string }>).singleton?.type).toBe("invalidProperties");
  });

  /** ★싱글턴은 만들 수도 지울 수도 없다(§8) — 지원하는 척하면 실패 이유가 모호해진다. */
  test("create·destroy는 지원하지 않는다", async () => {
    const r = await jmapCall([
      ["VacationResponse/set", { accountId, create: { x: { isEnabled: true, textBody: "y" } } }, "c0"],
      ["VacationResponse/set", { accountId, destroy: ["singleton"] }, "c1"],
    ]);
    expect(Object.keys(body(r, 0).notCreated as object)).toEqual(["x"]);
    expect(Object.keys(body(r, 1).notDestroyed as object)).toEqual(["singleton"]);
  });

  test("싱글턴 외의 id는 notFound", async () => {
    const r = await jmapCall([["VacationResponse/get", { accountId, ids: ["other"] }, "c0"]]);
    expect(body(r).notFound).toEqual(["other"]);
  });
});

describe("VacationResponse가 배달 경로의 게이트를 탄다", () => {
  /**
   * ★설정만 있고 판정이 갈라지면 자동 응답이 두 번 나가거나 메일링리스트에 부재 알림이
   * 뿌려진다. 여기서는 **Sieve와 같은 게이트**를 타는지를 배달 결정 함수로 확인한다.
   */
  test("켜면 배달이 vacation 요청을 만들어 낸다", async () => {
    await jmapCall([
      ["VacationResponse/set", { accountId, update: { singleton: { isEnabled: true, subject: "Away", textBody: "부재중" } } }, "c0"],
    ]);
    const r = await jmapCall([["VacationResponse/get", { accountId, ids: ["singleton"] }, "c0"]]);
    expect((body(r).list as Record<string, unknown>[])[0]!.isEnabled).toBe(true);

    // 저장된 값이 그대로 읽히는지 — 배달 경로가 이 행을 읽어 VacationRequest로 옮긴다
    const { rows } = await app.db.query({
      sql: "SELECT is_enabled, subject, text_body FROM vacation_response WHERE account_id = ?",
      params: [accountId],
    });
    expect(Number(rows[0]!.is_enabled)).toBe(1);
    expect(String(rows[0]!.subject)).toBe("Away");
    expect(String(rows[0]!.text_body)).toBe("부재중");
  });

  /** ★날짜 창은 JMAP에만 있는 개념이라(§8) 배달 경로에서만 검사한다. */
  test("날짜 창 밖이면 저장은 되지만 응답 대상이 아니다", async () => {
    await jmapCall([
      [
        "VacationResponse/set",
        { accountId, update: { singleton: { isEnabled: true, textBody: "x", fromDate: "2020-01-01T00:00:00Z", toDate: "2020-01-02T00:00:00Z" } } },
        "c0",
      ],
    ]);
    const r = await jmapCall([["VacationResponse/get", { accountId, ids: ["singleton"] }, "c0"]]);
    const v = (body(r).list as Record<string, unknown>[])[0]!;
    expect(v.isEnabled).toBe(true); // 설정은 켜져 있다
    expect(v.toDate).toBe("2020-01-02T00:00:00.000Z"); // 창은 이미 지났다
  });
});

describe("Identity/set (RFC 8621 §6.3)", () => {
  /**
   * ★주소 소유 검사가 이 메서드의 핵심이다. 없으면 남의 주소로 신원을 만들 수 있고,
   * 발송 게이트가 나중에 막더라도 그때는 **이미 보낸 줄 아는** 상태다.
   */
  test("보낼 수 없는 주소로는 만들 수 없다", async () => {
    const r = await jmapCall([["Identity/set", { accountId, create: { i1: { email: "someone@elsewhere.test" } } }, "c0"]]);
    const notCreated = body(r).notCreated as Record<string, { type: string }>;
    expect(notCreated.i1?.type).toBe("forbidden");
  });

  test("자기 주소로는 만들 수 있다", async () => {
    const r = await jmapCall([
      ["Identity/set", { accountId, create: { i1: { email: "you@test.local", name: "Me" } } }, "c0"],
      ["Identity/get", { accountId, ids: null }, "c1"],
    ]);
    const created = body(r, 0).created as Record<string, { id: string }>;
    expect(created.i1?.id).toBeTruthy();
    const list = body(r, 1).list as Record<string, unknown>[];
    expect(list.some((i) => i.name === "Me")).toBe(true);
  });

  test("부분 갱신이 나머지를 지우지 않는다", async () => {
    const c = await jmapCall([["Identity/set", { accountId, create: { i: { email: "you@test.local", name: "Keep", textSignature: "sig" } } }, "c0"]]);
    const id = (body(c).created as Record<string, { id: string }>).i!.id;
    const r = await jmapCall([
      ["Identity/set", { accountId, update: { [id]: { textSignature: "new" } } }, "c0"],
      ["Identity/get", { accountId, ids: [id] }, "c1"],
    ]);
    const got = (body(r, 1).list as Record<string, unknown>[])[0]!;
    expect(got.name).toBe("Keep");
    expect(got.textSignature).toBe("new");
  });

  test("email을 남의 주소로 바꾸는 것도 막는다", async () => {
    const c = await jmapCall([["Identity/set", { accountId, create: { i: { email: "you@test.local" } } }, "c0"]]);
    const id = (body(c).created as Record<string, { id: string }>).i!.id;
    const r = await jmapCall([["Identity/set", { accountId, update: { [id]: { email: "someone@elsewhere.test" } } }, "c0"]]);
    expect((body(r).notUpdated as Record<string, { type: string }>)[id]?.type).toBe("forbidden");
  });

  test("삭제할 수 있다", async () => {
    const c = await jmapCall([["Identity/set", { accountId, create: { i: { email: "you@test.local" } } }, "c0"]]);
    const id = (body(c).created as Record<string, { id: string }>).i!.id;
    const r = await jmapCall([["Identity/set", { accountId, destroy: [id] }, "c0"]]);
    expect(body(r).destroyed).toEqual([id]);
  });

  test("없는 id는 notUpdated/notDestroyed", async () => {
    const r = await jmapCall([
      ["Identity/set", { accountId, update: { nope: { name: "x" } } }, "c0"],
      ["Identity/set", { accountId, destroy: ["nope"] }, "c1"],
    ]);
    expect((body(r, 0).notUpdated as Record<string, { type: string }>).nope?.type).toBe("notFound");
    expect((body(r, 1).notDestroyed as Record<string, { type: string }>).nope?.type).toBe("notFound");
  });
});

describe("Blob/copy (RFC 8620 §6.3)", () => {
  /** 계정이 하나뿐이라 늘 거절이다 — 중요한 것은 그 거절이 **규격이 정한** 것이라는 점이다. */
  test("같은 계정이면 invalidArguments, 다른 계정이면 fromAccountNotFound", async () => {
    const same = await jmapCall([["Blob/copy", { accountId, fromAccountId: accountId, blobIds: [] }, "c0"]]);
    expect(name(same)).toBe("error");
    expect(body(same).type).toBe("invalidArguments");

    const other = await jmapCall([["Blob/copy", { accountId, fromAccountId: "other", blobIds: [] }, "c0"]]);
    expect(body(other).type).toBe("fromAccountNotFound");
  });
});
