/**
 * ARF 파싱 + 신고율 자동 정지 — PLAN.md §8 통제 ④의 "신고율" 절반.
 *
 * ★가장 중요한 계약은 **`not-spam`을 신고로 세지 않는 것**이다(RFC 5965 §7.3).
 * 그건 신고가 아니라 정정이라, 세면 사용자가 "스팸 아님"을 눌렀는데 발신자가 정지되는
 * 정반대 결과가 된다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, MTA_QUEUE_STATUS } from "@ionosphere/db";
import { ulid } from "@ionosphere/core";
import { checkAccountAbuse, recordComplaint } from "../src/abuse.ts";
import { parseArf, isCountableComplaint, FEEDBACK_ID_HEADER } from "../src/arf.ts";

/** 최소 형태의 ARF 리포트. */
function arf(opts: { type: string; queueId?: string }): string {
  return [
    "From: fbl@provider.example",
    "To: abuse@ionosphere.test",
    'Content-Type: multipart/report; report-type=feedback-report; boundary="b"',
    "",
    "--b",
    "Content-Type: message/feedback-report",
    "",
    `Feedback-Type: ${opts.type}`,
    "User-Agent: SomeFBL/1.0",
    "Version: 1",
    "Original-Mail-From: sender@ionosphere.test",
    "",
    "--b",
    "Content-Type: message/rfc822",
    "",
    "From: sender@ionosphere.test",
    ...(opts.queueId ? [`${FEEDBACK_ID_HEADER}: ${opts.queueId}`] : []),
    "Subject: 원문",
    "",
    "본문은 우리가 읽지 않는다",
    "--b--",
  ].join("\r\n");
}

describe("parseArf", () => {
  test("피드백 종류와 우리 발송 식별자를 뽑는다", () => {
    const r = parseArf(arf({ type: "abuse", queueId: "01ABCQUEUE" }));
    expect(r).not.toBeNull();
    expect(r!.feedbackType).toBe("abuse");
    expect(r!.queueId).toBe("01ABCQUEUE");
    expect(r!.originalMailFrom).toBe("sender@ionosphere.test");
  });

  test("식별자가 없으면 null — 상관관계 불가를 조용히 넘기지 않는다", () => {
    expect(parseArf(arf({ type: "abuse" }))!.queueId).toBeNull();
  });

  test("ARF가 아닌 메일은 null (그냥 메일이다)", () => {
    expect(parseArf("From: a@b\r\nSubject: hi\r\n\r\nbody")).toBeNull();
  });

  test("깨진 입력에 던지지 않는다 — 외부 입력이 수신 처리를 멈추면 안 된다", () => {
    for (const bad of ["", "Content-Type: message/feedback-report", "\r\n\r\n"]) {
      expect(() => parseArf(bad)).not.toThrow();
    }
  });

  test("★`not-spam`은 신고가 아니다 — 세면 정반대 결과가 된다", () => {
    expect(isCountableComplaint("abuse")).toBe(true);
    expect(isCountableComplaint("fraud")).toBe(true);
    expect(isCountableComplaint("not-spam")).toBe(false);
    expect(isCountableComplaint("virus")).toBe(false);
    expect(isCountableComplaint("other")).toBe(false);
  });
});

async function seed(sentCount: number): Promise<{ db: Awaited<ReturnType<typeof openSqlite>>; accountId: string; ids: string[] }> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const accountId = ulid();
  const tenantId = ulid();
  const ids: string[] = [];
  const now = Date.now();
  for (let i = 0; i < sentCount; i++) {
    const id = ulid();
    ids.push(id);
    await db.batch([
      {
        sql: `INSERT INTO mta_queue (id, tenant_id, account_id, blob_id, env_from, rcpt, rcpt_domain, status, attempts, next_attempt, created_at)
              VALUES (?, ?, ?, 'b', 'a@x', 'r@y', 'y', ?, 0, 0, ?)`,
        params: [id, tenantId, accountId, MTA_QUEUE_STATUS.done, now],
      },
    ]);
  }
  return { db, accountId, ids };
}

describe("신고율 자동 정지", () => {
  test("★신고가 임계를 넘으면 정지 — 바운스가 0이어도", async () => {
    const { db, accountId, ids } = await seed(100);
    // 기본 임계 0.3% → 100건 중 1건이면 1%로 초과.
    expect(await recordComplaint(db, ids[0]!, Date.now())).toBe(1);
    const v = await checkAccountAbuse(db, accountId);
    expect(v.action).toBe("suspend");
    if (v.action !== "suspend") throw new Error("unreachable");
    expect(v.complained).toBe(1);
    expect(v.bounced).toBe(0);
    expect(v.reason).toContain("complaint rate");
    db.close?.();
  });

  test("임계 이하면 통과한다", async () => {
    const { db, accountId, ids } = await seed(1000);
    await recordComplaint(db, ids[0]!, Date.now()); // 0.1% — 임계(0.3%) 이하
    const v = await checkAccountAbuse(db, accountId);
    expect(v.action).toBe("ok");
    expect(v.complaintRate).toBeLessThan(0.003);
    db.close?.();
  });

  test("★표본이 적으면 판정을 보류한다 — 한 건으로 정지시키지 않는다", async () => {
    const { db, accountId, ids } = await seed(5);
    await recordComplaint(db, ids[0]!, Date.now()); // 20%지만 표본 5 < minSample 20
    expect((await checkAccountAbuse(db, accountId)).action).toBe("ok");
    db.close?.();
  });

  test("★신고 기록은 멱등 — 같은 리포트가 두 번 와도 한 번만 센다", async () => {
    const { db, accountId, ids } = await seed(100);
    expect(await recordComplaint(db, ids[0]!, 1000)).toBe(1);
    // FBL 재전송이 실제로 있다. 두 번째는 아무것도 바꾸지 않아야 한다.
    expect(await recordComplaint(db, ids[0]!, 2000)).toBe(0);
    const v = await checkAccountAbuse(db, accountId);
    expect(v.complained).toBe(1);
    db.close?.();
  });

  test("우리 발송이 아닌 식별자는 아무것도 바꾸지 않는다", async () => {
    const { db, accountId } = await seed(100);
    expect(await recordComplaint(db, "01NOTOURS", Date.now())).toBe(0);
    expect((await checkAccountAbuse(db, accountId)).complained).toBe(0);
    db.close?.();
  });

  test("★신고를 기록해도 status는 그대로 — 분모가 무너지면 신고율이 틀린다", async () => {
    const { db, accountId, ids } = await seed(100);
    await recordComplaint(db, ids[0]!, Date.now());
    const { rows } = await db.query({ sql: "SELECT status FROM mta_queue WHERE id = ?", params: [ids[0]!] });
    expect(Number(rows[0]?.status)).toBe(MTA_QUEUE_STATUS.done);
    // 발송 수(분모)가 100 그대로여야 한다.
    expect((await checkAccountAbuse(db, accountId)).sent).toBe(100);
    db.close?.();
  });
});
