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
  csrfTokenFor,
  PROVISIONAL_TOTP_LOCK,
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

describe("TOTP 연속 실패 잠금", () => {
  test("★문턱을 넘으면 잠기고, 잠긴 동안은 맞는 코드도 거절하며, 풀린 뒤 성공하면 초기화된다", async () => {
    const { db, id } = await setup();
    const t0 = 1_800_000_000_000;
    const secret = (await beginAdminTotpEnrollment(db, id, KEY))!;
    await confirmAdminTotpEnrollment(db, id, codeAt(secret, t0), KEY, t0);
    let t = t0 + 30_000;
    for (let i = 0; i < PROVISIONAL_TOTP_LOCK.freeFailures; i++) expect(await verifyAdminTotp(db, id, "000000", KEY, t)).toBe(false);
    // 문턱에 닿은 직후부터 잠긴다 — 맞는 코드도 통하지 않는다.
    expect(await verifyAdminTotp(db, id, codeAt(secret, t), KEY, t)).toBe(false);
    const { rows } = await db.query({ sql: "SELECT totp_failures, totp_locked_until FROM admin_users WHERE id = ?", params: [id] });
    expect(Number(rows[0]!.totp_failures)).toBe(PROVISIONAL_TOTP_LOCK.freeFailures);
    expect(Number(rows[0]!.totp_locked_until)).toBeGreaterThan(t);
    t = Number(rows[0]!.totp_locked_until) + 30_000;
    expect(await verifyAdminTotp(db, id, codeAt(secret, t), KEY, t)).toBe(true);
    const after = await db.query({ sql: "SELECT totp_failures, totp_locked_until FROM admin_users WHERE id = ?", params: [id] });
    expect(Number(after.rows[0]!.totp_failures)).toBe(0);
    expect(after.rows[0]!.totp_locked_until).toBeNull();
  });

  test("잠금은 실패할수록 길어진다(상한까지)", async () => {
    const { db, id } = await setup();
    const t0 = 1_800_000_000_000;
    const secret = (await beginAdminTotpEnrollment(db, id, KEY))!;
    await confirmAdminTotpEnrollment(db, id, codeAt(secret, t0), KEY, t0);
    const lengths: number[] = [];
    let t = t0 + 30_000;
    for (let i = 0; i < PROVISIONAL_TOTP_LOCK.freeFailures + 3; i++) {
      await verifyAdminTotp(db, id, "000000", KEY, t);
      const { rows } = await db.query({ sql: "SELECT totp_locked_until FROM admin_users WHERE id = ?", params: [id] });
      if (rows[0]!.totp_locked_until != null) {
        lengths.push(Number(rows[0]!.totp_locked_until) - t);
        t = Number(rows[0]!.totp_locked_until) + 1; // 잠금이 풀린 직후 다시 틀린다
      }
    }
    expect(lengths.length).toBeGreaterThan(2);
    for (let i = 1; i < lengths.length; i++) expect(lengths[i]!).toBeGreaterThan(lengths[i - 1]!);
  });
});

describe("CSRF 토큰 유도", () => {
  test("세션 토큰에서 같은 값을 다시 만들 수 있고, 세션마다 다르다", async () => {
    const { db, id } = await setup();
    const a = await createAdminSession(db, id, null);
    const b = await createAdminSession(db, id, null);
    expect(csrfTokenFor(a.token)).toBe(a.csrfToken);
    expect(a.csrfToken).not.toBe(b.csrfToken);
  });
});

describe("TOTP 동시 추측", () => {
  test("★추측을 한꺼번에 보내도 문턱 수만큼만 계산되고 나머지는 잠금에 막힌다", async () => {
    const { db, id } = await setup();
    const t0 = 1_800_000_000_000;
    const secret = (await beginAdminTotpEnrollment(db, id, KEY))!;
    await confirmAdminTotpEnrollment(db, id, codeAt(secret, t0), KEY, t0);
    const t = t0 + 30_000;
    const guesses = Array.from({ length: 30 }, (_, i) => String(100000 + i));
    await Promise.all(guesses.map((g) => verifyAdminTotp(db, id, g, KEY, t)));
    const { rows } = await db.query({ sql: "SELECT totp_failures, totp_locked_until FROM admin_users WHERE id = ?", params: [id] });
    // 차지에 성공한 시도만 센다 — 문턱(free)을 넘지 않는다.
    expect(Number(rows[0]!.totp_failures)).toBe(PROVISIONAL_TOTP_LOCK.freeFailures);
    expect(Number(rows[0]!.totp_locked_until)).toBeGreaterThan(t);
    expect(await verifyAdminTotp(db, id, codeAt(secret, t), KEY, t)).toBe(false);
  });
});
