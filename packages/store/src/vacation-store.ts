/**
 * Sieve `vacation` 중복 억제 (RFC 5230 §4.5).
 *
 * ★자동 응답은 "보내는 것"보다 **안 보내는 것**이 어렵다. 같은 사람에게 계속 답하면 그건
 * 자동 응답이 아니라 스팸이고, 상대도 자동 응답이면 둘이 무한히 주고받는다. `:days`(기본 7)
 * 안에는 같은 수신자에게 한 번만 보낸다.
 *
 * ★주소를 **해시로** 저장한다. 이 테이블은 "누가 이 사람에게 메일을 보냈나"의 목록이라
 * 평문으로 두면 그 자체가 열람 대상이 된다. 판정에 필요한 것은 동일성뿐이다
 * (PLAN §8 "운영자는 사용자 메일 내용을 열람하지 않는다"와 같은 취지 — `bayes_tokens`가
 * 토큰을 해시로 두는 것과 같은 규율).
 */
import { sha256hex32 } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";

/** 주소·핸들을 저장 키로. 소문자 정규화 후 해시 — 대소문자만 다른 주소가 두 번 받으면 안 된다. */
function key(value: string): string {
  return sha256hex32(value.trim().toLowerCase());
}

/**
 * 이 (계정, 핸들, 수신자)에 지금 응답해도 되는가 — **되면 기록까지 남기고 true**.
 *
 * ★판정과 기록을 **한 함수로 묶는다.** 나누면 "된다"를 받고 기록 전에 다른 배달이 끼어드는
 * 창이 생기고, 그러면 같은 상대가 두 통을 받는다. 이 저장소의 낙관 잠금 규율(§3-2)을 쓰기엔
 * 과한 자리라 — 최악이 자동 응답 한 통 중복이다 — `insertIgnore`의 영향 행 수로 판정한다.
 * 그 한 문장이 곧 "내가 처음이다"의 증명이다.
 */
export async function claimVacationReply(
  db: DbDriver,
  input: { accountId: string; handle: string; recipient: string; days: number; now?: number },
): Promise<boolean> {
  const now = input.now ?? Date.now();
  const handleHash = key(input.handle);
  const recipientHash = key(input.recipient);
  const expiresAt = now + input.days * 24 * 60 * 60 * 1000;

  // 만료된 기록은 없는 것으로 본다 — 먼저 치워야 아래 insert가 자리를 잡는다.
  await db.batch([
    {
      sql: "DELETE FROM vacation_sent WHERE account_id = ? AND handle_hash = ? AND recipient_hash = ? AND expires_at <= ?",
      params: [input.accountId, handleHash, recipientHash, now],
    },
  ]);

  const [res] = await db.batch([
    {
      sql: db.insertIgnore("vacation_sent", ["account_id", "handle_hash", "recipient_hash", "sent_at", "expires_at"]),
      params: [input.accountId, handleHash, recipientHash, now, expiresAt],
    },
  ]);
  // 영향 행이 1이면 우리가 넣은 것 = 아직 안 보냈다. 0이면 유효한 기록이 이미 있다.
  return (res?.changes ?? 0) === 1;
}

/** 만료된 억제 기록 정리 — 보존 스윕이 부른다. */
export async function sweepVacationSent(db: DbDriver, now: number = Date.now()): Promise<number> {
  const [res] = await db.batch([{ sql: "DELETE FROM vacation_sent WHERE expires_at <= ?", params: [now] }]);
  return res?.changes ?? 0;
}


// ── JMAP VacationResponse (RFC 8621 §8) ───────────────────────────────────────

/** 계정당 하나. 없으면 "꺼짐"과 같다 — 행이 없는 것과 `isEnabled: false`를 구분하지 않는다. */
export interface VacationResponseRow {
  isEnabled: boolean;
  fromDate: number | null;
  toDate: number | null;
  subject: string | null;
  textBody: string | null;
  htmlBody: string | null;
}

const VACATION_RESPONSE_OFF: VacationResponseRow = {
  isEnabled: false,
  fromDate: null,
  toDate: null,
  subject: null,
  textBody: null,
  htmlBody: null,
};

export async function getVacationResponse(db: DbDriver, accountId: string): Promise<VacationResponseRow> {
  const { rows } = await db.query({
    sql: "SELECT is_enabled, from_date, to_date, subject, text_body, html_body FROM vacation_response WHERE account_id = ?",
    params: [accountId],
  });
  const r = rows[0];
  if (!r) return { ...VACATION_RESPONSE_OFF };
  return {
    isEnabled: Number(r.is_enabled) === 1,
    fromDate: r.from_date == null ? null : Number(r.from_date),
    toDate: r.to_date == null ? null : Number(r.to_date),
    subject: r.subject == null ? null : String(r.subject),
    textBody: r.text_body == null ? null : String(r.text_body),
    htmlBody: r.html_body == null ? null : String(r.html_body),
  };
}

/**
 * 통째로 덮어쓴다 — 싱글턴이라 부분 갱신도 결국 전체 상태를 쓰는 것과 같다.
 * 호출자(JMAP `/set`)가 patch를 현재 값 위에 얹어 완성한 뒤 넘긴다.
 */
export async function setVacationResponse(db: DbDriver, accountId: string, v: VacationResponseRow, now: number = Date.now()): Promise<void> {
  await db.batch([
    { sql: "DELETE FROM vacation_response WHERE account_id = ?", params: [accountId] },
    {
      sql: `INSERT INTO vacation_response (account_id, is_enabled, from_date, to_date, subject, text_body, html_body, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      params: [accountId, v.isEnabled ? 1 : 0, v.fromDate, v.toDate, v.subject, v.textBody, v.htmlBody, now],
    },
  ]);
}
