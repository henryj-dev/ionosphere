/**
 * 대외 리포트 집계 — DMARC(RFC 7489 §7.2) · TLS-RPT(RFC 8460) 카운터.
 *
 * ★메시지마다 한 행이 아니라 **조합마다 한 행**이다. 리포트가 (기간, 소스 IP, 판정, 정렬)별
 * 개수이므로 처음부터 그 조합을 PK로 두고 카운터만 올린다 — 하루 수백만 건이 들어와도
 * 행 수는 **실제 조합 수**(정상 도메인이면 수십~수백)로 묶인다.
 *
 * ★증가는 `UPDATE` 먼저, 영향 행이 0이면 `INSERT`다. upsert 문법은 다이얼렉트마다 다르고
 * 이 저장소는 다이얼렉트 분기를 봉인한다(`insertIgnore`가 유일한 탈출구) — 두 문장으로
 * 나누면 어느 방언에서나 같게 돈다.
 *
 * ★두 문장 사이에 다른 프로세스가 같은 행을 넣으면 `INSERT`가 PK 충돌로 실패한다. 그때는
 * **다시 UPDATE**하면 되므로 삼키고 재시도한다 — 리포트 카운터라 최악이 1 차이이고,
 * 그걸 위해 낙관 잠금을 도는 것은 과하다.
 */
import type { DbDriver } from "@ionosphere/db";

/** UTC 자정으로 내림 — 리포트 기간이 하루 단위라 그 경계로 미리 묶는다. */
export function utcDayStart(ms: number): number {
  return Math.floor(ms / 86_400_000) * 86_400_000;
}

export interface DmarcRowKey {
  policyDomain: string;
  headerFrom: string;
  sourceIp: string;
  disposition: string;
  dkimAligned: boolean;
  spfAligned: boolean;
  dkimResult: string;
  spfResult: string;
  dkimDomain?: string | null;
  spfDomain?: string | null;
}

/** 이 조합의 카운터를 1 올린다. 실패해도 던지지 않는다 — 리포트가 배달을 막으면 안 된다. */
export async function recordDmarcRow(db: DbDriver, key: DmarcRowKey, now: number = Date.now()): Promise<void> {
  const day = utcDayStart(now);
  const pk = [
    day,
    key.policyDomain,
    key.headerFrom,
    key.sourceIp,
    key.disposition,
    key.dkimAligned ? 1 : 0,
    key.spfAligned ? 1 : 0,
    key.dkimResult,
    key.spfResult,
  ];
  const where = `day = ? AND policy_domain = ? AND header_from = ? AND source_ip = ? AND disposition = ?
                   AND dkim_aligned = ? AND spf_aligned = ? AND dkim_result = ? AND spf_result = ?`;
  const [res] = await db.batch([
    { sql: `UPDATE dmarc_report_rows SET count = count + 1 WHERE ${where}`, params: pk },
  ]);
  if ((res?.changes ?? 0) > 0) return;
  try {
    await db.batch([
      {
        sql: `INSERT INTO dmarc_report_rows
                (day, policy_domain, header_from, source_ip, disposition, dkim_aligned, spf_aligned,
                 dkim_result, spf_result, dkim_domain, spf_domain, count)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
        params: [...pk, key.dkimDomain ?? null, key.spfDomain ?? null],
      },
    ]);
  } catch {
    // 경합 — 다른 프로세스가 방금 넣었다. 다시 올리면 된다(위 주석).
    await db.batch([{ sql: `UPDATE dmarc_report_rows SET count = count + 1 WHERE ${where}`, params: pk }]);
  }
}

export interface TlsRptRowKey {
  policyDomain: string;
  policyType: string;
  receivingMx: string;
  resultType: string;
}

export async function recordTlsRptRow(db: DbDriver, key: TlsRptRowKey, now: number = Date.now()): Promise<void> {
  const day = utcDayStart(now);
  const pk = [day, key.policyDomain, key.policyType, key.receivingMx, key.resultType];
  const where = "day = ? AND policy_domain = ? AND policy_type = ? AND receiving_mx = ? AND result_type = ?";
  const [res] = await db.batch([{ sql: `UPDATE tlsrpt_report_rows SET count = count + 1 WHERE ${where}`, params: pk }]);
  if ((res?.changes ?? 0) > 0) return;
  try {
    await db.batch([
      {
        sql: `INSERT INTO tlsrpt_report_rows (day, policy_domain, policy_type, receiving_mx, result_type, count)
              VALUES (?, ?, ?, ?, ?, 1)`,
        params: pk,
      },
    ]);
  } catch {
    await db.batch([{ sql: `UPDATE tlsrpt_report_rows SET count = count + 1 WHERE ${where}`, params: pk }]);
  }
}

/** 하루치 DMARC 행을 정책 도메인별로. */
export async function loadDmarcDay(db: DbDriver, day: number): Promise<Map<string, (DmarcRowKey & { count: number })[]>> {
  const { rows } = await db.query({
    sql: `SELECT policy_domain, header_from, source_ip, disposition, dkim_aligned, spf_aligned,
                 dkim_result, spf_result, dkim_domain, spf_domain, count
            FROM dmarc_report_rows WHERE day = ? ORDER BY policy_domain, source_ip`,
    params: [day],
  });
  const out = new Map<string, (DmarcRowKey & { count: number })[]>();
  for (const r of rows) {
    const domain = String(r.policy_domain);
    const list = out.get(domain) ?? [];
    list.push({
      policyDomain: domain,
      headerFrom: String(r.header_from),
      sourceIp: String(r.source_ip),
      disposition: String(r.disposition),
      dkimAligned: Number(r.dkim_aligned) === 1,
      spfAligned: Number(r.spf_aligned) === 1,
      dkimResult: String(r.dkim_result),
      spfResult: String(r.spf_result),
      dkimDomain: r.dkim_domain == null ? null : String(r.dkim_domain),
      spfDomain: r.spf_domain == null ? null : String(r.spf_domain),
      count: Number(r.count),
    });
    out.set(domain, list);
  }
  return out;
}

/** 하루치 TLS-RPT 행을 정책 도메인별로. */
export async function loadTlsRptDay(db: DbDriver, day: number): Promise<Map<string, (TlsRptRowKey & { count: number })[]>> {
  const { rows } = await db.query({
    sql: `SELECT policy_domain, policy_type, receiving_mx, result_type, count
            FROM tlsrpt_report_rows WHERE day = ? ORDER BY policy_domain, receiving_mx`,
    params: [day],
  });
  const out = new Map<string, (TlsRptRowKey & { count: number })[]>();
  for (const r of rows) {
    const domain = String(r.policy_domain);
    const list = out.get(domain) ?? [];
    list.push({
      policyDomain: domain,
      policyType: String(r.policy_type),
      receivingMx: String(r.receiving_mx),
      resultType: String(r.result_type),
      count: Number(r.count),
    });
    out.set(domain, list);
  }
  return out;
}

/**
 * 이 (종류, 날짜, 도메인)의 리포트를 **아직 안 보냈으면** 표시하고 true.
 *
 * ★판정과 기록을 한 함수로 묶는다. 나누면 "안 보냈다"를 받고 표시하기 전에 다른 인스턴스가
 * 끼어들어 **같은 리포트가 두 번** 나간다 — 받는 쪽은 중복으로 세어 통계가 부풀고
 * 우리는 스팸처럼 보인다. `vacation_sent`와 같은 규율이다.
 */
export async function claimReportSend(
  db: DbDriver,
  kind: "dmarc" | "tlsrpt",
  day: number,
  policyDomain: string,
  reportId: string,
  now: number = Date.now(),
): Promise<boolean> {
  const [res] = await db.batch([
    {
      sql: db.insertIgnore("report_sends", ["kind", "day", "policy_domain", "report_id", "sent_at"]),
      params: [kind, day, policyDomain, reportId, now],
    },
  ]);
  return (res?.changes ?? 0) === 1;
}

/** 보낸 뒤 더 필요 없는 집계 행을 지운다. */
export async function purgeReportRows(db: DbDriver, beforeDay: number): Promise<{ dmarc: number; tlsrpt: number; sends: number }> {
  const res = await db.batch([
    { sql: "DELETE FROM dmarc_report_rows WHERE day < ?", params: [beforeDay] },
    { sql: "DELETE FROM tlsrpt_report_rows WHERE day < ?", params: [beforeDay] },
    // 발송 기록은 조금 더 오래 둔다 — 중복 방지 근거라 집계보다 먼저 사라지면 안 된다.
    { sql: "DELETE FROM report_sends WHERE day < ?", params: [beforeDay - 7 * 86_400_000] },
  ]);
  return { dmarc: res[0]?.changes ?? 0, tlsrpt: res[1]?.changes ?? 0, sends: res[2]?.changes ?? 0 };
}
