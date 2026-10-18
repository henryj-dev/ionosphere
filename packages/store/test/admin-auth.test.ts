/** 관리 콘솔 사람 주체 — 생성·비밀번호·TOTP 등록/검증·세션 수명·철회 (마이그레이션 025). */
import { describe, expect, test } from "@ionosphere/testkit";
import { base32Decode, hotp, totpStep } from "@ionosphere/core";
import { ADMIN_ROLE, ADMIN_STATUS, allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import {
  beginAdminTotpEnrollment,
  confirmAdminTotpEnrollment,
  createAdminSession,
  createAdminUser,
  markAdminSessionMfa,
  resetAdminTotpAndRevokeSessions,
  resolveAdminSession,
  revokeAdminSession,
  revokeAdminSessions,
  setAdminPasswordAndRevokeSessions,
  verifyAdminPassword,
  verifyAdminTotp,
} from "@ionosphere/store";

const KEY = "test-master-key";
const POLICY = { idleMs: 30 * 60_000, absoluteMs: 12 * 3600_000 };

async function setup(): Promise<{ db: DbDriver; id: string }> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const id = (await createAdminUser(db, { username: "Ops@Ionosphere.test", role: ADMIN_ROLE.admin, password: "admin-pw" }))!;
  return { db, id };
}

function codeAt(secret: string, nowMs: number): string {
  return hotp(base32Decode(secret)!, totpStep(nowMs));
}

describe("관리자 생성·비밀번호", () => {
  test("사용자명은 소문자로 정규화되고 중복이면 null", async () => {
    const { db } = await setup();
    expect(await createAdminUser(db, { username: "ops@ionosphere.test", role: ADMIN_ROLE.readonly })).toBeNull();
    expect((await verifyAdminPassword(db, "OPS@ionosphere.test", "admin-pw"))?.username).toBe("ops@ionosphere.test");
  });

  test("틀림·없음·정지·비밀번호 없음은 전부 null", async () => {
    const { db, id } = await setup();
    expect(await verifyAdminPassword(db, "ops@ionosphere.test", "wrong")).toBeNull();
    expect(await verifyAdminPassword(db, "nobody@ionosphere.test", "admin-pw")).toBeNull();
    await createAdminUser(db, { username: "sso-only@ionosphere.test", role: ADMIN_ROLE.admin });
    expect(await verifyAdminPassword(db, "sso-only@ionosphere.test", "")).toBeNull();
    await db.batch([{ sql: "UPDATE admin_users SET status = ? WHERE id = ?", params: [ADMIN_STATUS.suspended, id] }]);
    expect(await verifyAdminPassword(db, "ops@ionosphere.test", "admin-pw")).toBeNull();
  });

  test("비밀번호 교체는 기존 세션을 전부 끊는다", async () => {
    const { db, id } = await setup();
    const s = await createAdminSession(db, id, Date.now());
    expect(await setAdminPasswordAndRevokeSessions(db, id, "new-pw")).toBe(true);
    expect(await resolveAdminSession(db, s.token, POLICY)).toBeNull();
    expect(await verifyAdminPassword(db, "ops@ionosphere.test", "new-pw")).not.toBeNull();
    expect(await verifyAdminPassword(db, "ops@ionosphere.test", "admin-pw")).toBeNull();
  });
});

describe("TOTP 등록·검증", () => {
  test("등록은 코드를 맞혀야 확정되고, 확정 전에는 MFA로 쓰이지 않는다", async () => {
    const { db, id } = await setup();
    const now = 1_800_000_000_000;
    const secret = (await beginAdminTotpEnrollment(db, id, KEY))!;
    expect(await verifyAdminTotp(db, id, codeAt(secret, now), KEY, now)).toBe(false);
    expect(await confirmAdminTotpEnrollment(db, id, "000000", KEY, now)).toBe(false);
    expect(await confirmAdminTotpEnrollment(db, id, codeAt(secret, now), KEY, now)).toBe(true);
    // 저장값은 봉인돼 있다 — 평문 비밀이 DB에 없다.
    const { rows } = await db.query({ sql: "SELECT totp_secret FROM admin_users WHERE id = ?", params: [id] });
    expect(String(rows[0]!.totp_secret)).toStartWith("enc$v1$");
    expect(String(rows[0]!.totp_secret)).not.toContain(secret);
  });

  test("★등록에 쓴 코드와 같은 스텝은 다시 못 쓰고, 다음 스텝은 된다", async () => {
    const { db, id } = await setup();
    const now = 1_800_000_000_000;
    const secret = (await beginAdminTotpEnrollment(db, id, KEY))!;
    await confirmAdminTotpEnrollment(db, id, codeAt(secret, now), KEY, now);
    expect(await verifyAdminTotp(db, id, codeAt(secret, now), KEY, now)).toBe(false);
    const later = now + 30_000;
    expect(await verifyAdminTotp(db, id, codeAt(secret, later), KEY, later)).toBe(true);
    expect(await verifyAdminTotp(db, id, codeAt(secret, later), KEY, later)).toBe(false);
  });

  test("마스터 키가 없으면 TOTP를 다루지 않는다(평문 저장 금지)", async () => {
    const { db, id } = await setup();
    await expect(beginAdminTotpEnrollment(db, id, undefined)).rejects.toThrow(/MASTER_KEY/);
  });

  test("MFA 초기화는 비밀을 지우고 세션을 끊는다", async () => {
    const { db, id } = await setup();
    const now = 1_800_000_000_000;
    const secret = (await beginAdminTotpEnrollment(db, id, KEY))!;
    await confirmAdminTotpEnrollment(db, id, codeAt(secret, now), KEY, now);
    const s = await createAdminSession(db, id, now, now);
    expect(await resetAdminTotpAndRevokeSessions(db, id)).toBe(true);
    expect(await resolveAdminSession(db, s.token, POLICY, now)).toBeNull();
    expect((await verifyAdminPassword(db, "ops@ionosphere.test", "admin-pw"))?.mfaEnrolled).toBe(false);
  });
});

describe("세션", () => {
  test("토큰으로 해석되고, 원문 토큰·CSRF 토큰은 DB에 없다", async () => {
    const { db, id } = await setup();
    const s = await createAdminSession(db, id, null);
    const r = await resolveAdminSession(db, s.token, POLICY);
    expect(r?.user.id).toBe(id);
    expect(r?.mfaAt).toBeNull();
    const { rows } = await db.query({ sql: "SELECT * FROM admin_sessions" });
    const dump = JSON.stringify(rows);
    expect(dump).not.toContain(s.token);
    expect(dump).not.toContain(s.csrfToken);
  });

  test("idle·절대 만료", async () => {
    const { db, id } = await setup();
    const t0 = 1_800_000_000_000;
    const s = await createAdminSession(db, id, t0, t0);
    expect(await resolveAdminSession(db, s.token, POLICY, t0 + POLICY.idleMs + 1)).toBeNull();
    // 활동을 이어 가도 절대 수명은 넘지 못한다.
    const s2 = await createAdminSession(db, id, t0, t0);
    let t = t0;
    while (t < t0 + POLICY.absoluteMs) {
      t += 20 * 60_000;
      const r = await resolveAdminSession(db, s2.token, POLICY, t);
      if (t - t0 > POLICY.absoluteMs) expect(r).toBeNull();
      else expect(r).not.toBeNull();
    }
  });

  test("★로그아웃·정지·역할 하향은 다음 해석부터 반영된다", async () => {
    const { db, id } = await setup();
    const a = await createAdminSession(db, id, Date.now());
    const b = await createAdminSession(db, id, Date.now());
    await revokeAdminSession(db, a.sessionId);
    expect(await resolveAdminSession(db, a.token, POLICY)).toBeNull();
    expect(await resolveAdminSession(db, b.token, POLICY)).not.toBeNull();

    await db.batch([{ sql: "UPDATE admin_users SET role = ? WHERE id = ?", params: [ADMIN_ROLE.readonly, id] }]);
    expect((await resolveAdminSession(db, b.token, POLICY))?.user.role).toBe(ADMIN_ROLE.readonly);

    await db.batch([{ sql: "UPDATE admin_users SET status = ? WHERE id = ?", params: [ADMIN_STATUS.suspended, id] }]);
    expect(await resolveAdminSession(db, b.token, POLICY)).toBeNull();
  });

  test("모든 세션 철회와 MFA 시각 기록", async () => {
    const { db, id } = await setup();
    const a = await createAdminSession(db, id, null);
    await markAdminSessionMfa(db, a.sessionId, 1234);
    expect((await resolveAdminSession(db, a.token, POLICY))?.mfaAt).toBe(1234);
    await createAdminSession(db, id, null);
    expect(await revokeAdminSessions(db, id)).toBe(2);
    expect(await resolveAdminSession(db, a.token, POLICY)).toBeNull();
  });

  test("모르는 역할 값은 세션을 열지 않는다(권한 0이 아니라 없음으로 닫는다)", async () => {
    const { db, id } = await setup();
    const s = await createAdminSession(db, id, Date.now());
    await db.batch([{ sql: "UPDATE admin_users SET role = 9 WHERE id = ?", params: [id] }]);
    expect(await resolveAdminSession(db, s.token, POLICY)).toBeNull();
  });
});
