/**
 * 자격증명 표면 스코프 (`credentials.scopes`) — 감사 G1.
 *
 * ★이 컬럼은 저장만 되고 **아무도 읽지 않았다.** `auth.ts`의 옛 주석은 "scope 검사는
 * 호출자(프로토콜별) 몫"이라고 적었는데 그 호출자가 없었다. `api_keys.scopes`가 똑같은
 * 결함을 겪고 단일 관문으로 고쳐진 적이 있는데(`api/server.ts`), 여기는 그 교훈이
 * 적용되지 않은 채 남아 있었다.
 *
 * 이제 관문이 `authenticate`/`scramAuthorize` **안에** 있고 표면이 필수 인자다.
 * 이 파일은 그 관문이 실제로 막는지, 그리고 하위 호환이 유지되는지를 고정한다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import {
  AUTH_SURFACES,
  authenticate,
  createAppPassword,
  createCredential,
  credentialAllowsSurface,
  listCredentials,
  scramAuthorize,
  Store,
} from "@ionosphere/store";

async function setup(): Promise<{ db: DbDriver; accountId: string }> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const store = new Store(db);
  const { tenantId } = await store.createTenant("t");
  const { accountId } = await store.createAccount({ tenantId, email: "u@x.test" });
  await createCredential(db, { accountId, password: "primary-pw" });
  return { db, accountId };
}

describe("credentialAllowsSurface", () => {
  /** ★하위 호환 — 기존 자격증명은 전부 scopes가 null이다. 기본값이 곧 "제한 없음"이어야 한다. */
  test("null·빈 문자열은 제한 없음", () => {
    for (const s of AUTH_SURFACES) {
      expect(credentialAllowsSurface(null, s)).toBe(true);
      expect(credentialAllowsSurface("", s)).toBe(true);
      expect(credentialAllowsSurface("   ", s)).toBe(true);
      expect(credentialAllowsSurface(undefined, s)).toBe(true);
    }
  });

  test("나열한 표면만 허용", () => {
    expect(credentialAllowsSurface("imap", "imap")).toBe(true);
    expect(credentialAllowsSurface("imap", "submission")).toBe(false);
    expect(credentialAllowsSurface("imap,submission", "submission")).toBe(true);
    expect(credentialAllowsSurface("imap submission", "submission")).toBe(true); // 공백 구분도
    expect(credentialAllowsSurface("IMAP", "imap")).toBe(true); // 대소문자 무시
  });

  /**
   * ★fail closed — 오타가 있으면 그 항목은 **아무 표면도 열지 않는다.** 모르는 이름을 무시하고
   * 통과시키면 오타 하나가 제한을 통째로 없앤다.
   */
  test("모르는 이름은 아무것도 열지 않는다", () => {
    expect(credentialAllowsSurface("imapp", "imap")).toBe(false);
    expect(credentialAllowsSurface("nonsense", "jmap")).toBe(false);
    // 아는 이름이 함께 있으면 그것만 열린다
    expect(credentialAllowsSurface("imapp,imap", "imap")).toBe(true);
    expect(credentialAllowsSurface("imapp,imap", "pop3")).toBe(false);
  });
});

describe("authenticate 관문", () => {
  test("스코프 없는 자격증명은 모든 표면에서 통한다", async () => {
    const { db, accountId } = await setup();
    for (const s of AUTH_SURFACES) {
      expect(await authenticate(db, "u@x.test", "primary-pw", s)).toMatchObject({ accountId });
    }
  });

  test("IMAP 전용 앱 비밀번호는 IMAP에서만 통한다", async () => {
    const { db, accountId } = await setup();
    const { password } = await createAppPassword(db, accountId, "readonly client", "imap");
    expect(await authenticate(db, "u@x.test", password, "imap")).toMatchObject({ accountId });
    for (const s of AUTH_SURFACES.filter((x) => x !== "imap")) {
      expect(await authenticate(db, "u@x.test", password, s)).toBeNull();
    }
  });

  test("여러 표면을 지정할 수 있다", async () => {
    const { db, accountId } = await setup();
    const { password } = await createAppPassword(db, accountId, "mail client", "imap,submission");
    expect(await authenticate(db, "u@x.test", password, "imap")).toMatchObject({ accountId });
    expect(await authenticate(db, "u@x.test", password, "submission")).toMatchObject({ accountId });
    expect(await authenticate(db, "u@x.test", password, "pop3")).toBeNull();
  });

  /**
   * ★스코프 거절은 비밀번호 실패와 **같은 `null`**이다. 갈래를 나누면 "비밀번호는 맞고
   * 표면만 틀렸다"가 응답 차이로 새어 나가 자격증명 확인 수단이 된다.
   */
  test("스코프 거절과 비밀번호 실패는 구분되지 않는다", async () => {
    const { db, accountId } = await setup();
    const { password } = await createAppPassword(db, accountId, "imap only", "imap");
    expect(await authenticate(db, "u@x.test", password, "pop3")).toBeNull();
    expect(await authenticate(db, "u@x.test", "totally-wrong", "pop3")).toBeNull();
  });

  /** 쓰이지 않은 자격증명이므로 `last_used_at`도 움직이지 않아야 한다. */
  test("스코프 거절은 last_used_at을 갱신하지 않는다", async () => {
    const { db, accountId } = await setup();
    const { id, password } = await createAppPassword(db, accountId, "imap only", "imap");
    await authenticate(db, "u@x.test", password, "pop3");
    const before = (await listCredentials(db, accountId)).find((c) => c.id === id)!;
    expect(before.lastUsedAt).toBe(null);

    await authenticate(db, "u@x.test", password, "imap");
    const after = (await listCredentials(db, accountId)).find((c) => c.id === id)!;
    expect(after.lastUsedAt).not.toBe(null);
  });

  /** 다른 자격증명은 영향을 받지 않는다 — 앱 비번을 좁혀도 기본 비번은 그대로다. */
  test("한 자격증명의 제한이 다른 것에 번지지 않는다", async () => {
    const { db, accountId } = await setup();
    await createAppPassword(db, accountId, "imap only", "imap");
    expect(await authenticate(db, "u@x.test", "primary-pw", "pop3")).toMatchObject({ accountId });
  });
});

describe("scramAuthorize 관문", () => {
  /**
   * ★SCRAM은 `authenticate`를 **거치지 않는다**(증명은 엔진이 하고 여기는 최종 승인만).
   * 이 검사가 없으면 제한된 기본 비밀번호가 SCRAM 경로에서만 제한 없이 통과한다 —
   * 정지 계정이 SCRAM에서만 새던 것과 같은 부류의 구멍이다.
   */
  test("기본 비밀번호의 스코프를 SCRAM도 지킨다", async () => {
    const db = await openSqlite();
    await migrate(db, allMigrations);
    const store = new Store(db);
    const { tenantId } = await store.createTenant("t");
    const { accountId } = await store.createAccount({ tenantId, email: "s@x.test" });
    await createCredential(db, { accountId, password: "pw", scopes: "imap" });

    expect(await scramAuthorize(db, "s@x.test", "imap")).toMatchObject({ accountId });
    expect(await scramAuthorize(db, "s@x.test", "pop3")).toBe(null);
    expect(await scramAuthorize(db, "s@x.test", "submission")).toBe(null);
  });

  test("스코프 없으면 모든 표면 통과", async () => {
    const { db, accountId } = await setup();
    for (const s of AUTH_SURFACES) {
      expect(await scramAuthorize(db, "u@x.test", s)).toMatchObject({ accountId });
    }
  });

  test("없는 계정은 표면과 무관하게 null", async () => {
    const { db } = await setup();
    expect(await scramAuthorize(db, "ghost@x.test", "imap")).toBe(null);
  });
});

describe("목록에 스코프가 보인다", () => {
  /**
   * 스코프 거절이 인증 실패와 구분되지 않게 나가므로, 운영자가 "비밀번호는 맞는데 왜 안 되지"에
   * 답할 수 있는 자리가 여기뿐이다.
   */
  test("listCredentials가 scopes를 돌려준다", async () => {
    const { db, accountId } = await setup();
    const { id } = await createAppPassword(db, accountId, "imap only", "imap");
    const creds = await listCredentials(db, accountId);
    expect(creds.find((c) => c.id === id)!.scopes).toBe("imap");
    // 기본 비번은 제한 없음
    expect(creds.find((c) => c.id !== id)!.scopes).toBe(null);
  });
});
