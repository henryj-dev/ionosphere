/**
 * 대외 리포트 **발송** — DMARC 집계(RFC 7489 §7.2) · TLS-RPT(RFC 8460).
 *
 * ★두 리포트 다 "받기만 하고 내지는 않던" 것이다. 그건 상호운용을 반쪽만 하는 상태다 —
 * 우리는 남의 리포트로 우리 정렬을 고치면서, 우리에게 보내는 쪽에는 같은 근거를 주지 않는다.
 * MTA-STS를 **강제하면서** TLS-RPT를 안 내는 것은 특히 어긋난다(상대는 우리 쪽 강제로
 * 실패하는데 그 사실을 알 방법이 없다).
 *
 * ★하루에 한 번, **어제치**를 보낸다. 오늘치를 보내면 아직 쌓이는 중인 기간을 보고하게 된다.
 */
import { gzipSync } from "node:zlib";
import { ulid, type Logger } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import {
  buildDmarcReportXml,
  dmarcReportFilename,
  isRuaAuthorized,
  parseRua,
  type DnsResolver,
} from "@ionosphere/mail-auth";
import { buildTlsRptJson, parseTlsRptRua, tlsRptFilename, TLSRPT_SUCCESS } from "@ionosphere/mta-sts";
import { claimReportSend, loadDmarcDay, loadTlsRptDay, purgeReportRows, utcDayStart } from "@ionosphere/store";


/** 리포트를 실제로 보내는 통로 — 조립층이 MTA 큐에 넣는 함수를 준다. */
export interface ReportSender {
  send(input: { to: string; subject: string; filename: string; contentType: string; body: Uint8Array }): Promise<void>;
}

export interface ReportOptions {
  db: DbDriver;
  resolver: DnsResolver;
  logger: Logger;
  sender: ReportSender;
  /** `org_name`·파일명의 발신 식별자. 보통 우리 MX 호스트명. */
  reportingDomain: string;
  /** `<email>`·`contact-info`에 적을 주소. */
  contactEmail: string;
  /** 집계 행 보존 기간(일). 기본 7 — 보낸 뒤에는 쓸모가 없다. */
  retentionDays?: number;
  now?: number;
}

/** 하루치 결과 요약 — 리퍼 로그에 그대로 실린다. */
export interface ReportRunResult {
  dmarcSent: number;
  dmarcSkipped: number;
  tlsrptSent: number;
  tlsrptSkipped: number;
  purged: number;
}

/** `_dmarc.<domain>` TXT에서 태그 맵을 뽑는다. 없거나 DMARC1이 아니면 null. */
async function dmarcTags(domain: string, resolver: DnsResolver): Promise<Map<string, string> | null> {
  let txts: string[];
  try {
    txts = await resolver.txt(`_dmarc.${domain}`);
  } catch {
    return null;
  }
  for (const raw of txts) {
    const map = new Map<string, string>();
    for (const seg of raw.split(";")) {
      const eq = seg.indexOf("=");
      if (eq === -1) continue;
      map.set(seg.slice(0, eq).trim().toLowerCase(), seg.slice(eq + 1).trim());
    }
    if (map.get("v")?.toUpperCase() === "DMARC1") return map;
  }
  return null;
}

/**
 * 하루치 리포트를 보낸다.
 *
 * ★실패는 **도메인 단위로** 삼킨다. 한 도메인의 DNS가 죽었다고 나머지 도메인 리포트가
 * 통째로 안 나가면 안 된다 — 리포트는 부가 기능이고, 부가 기능이 서로를 막으면 안 된다.
 */
export async function runReports(opts: ReportOptions): Promise<ReportRunResult> {
  const now = opts.now ?? Date.now();
  // 어제치 — 오늘은 아직 쌓이는 중이다.
  const day = utcDayStart(now) - 86_400_000;
  const beginSec = Math.floor(day / 1000);
  const endSec = Math.floor((day + 86_400_000 - 1) / 1000);
  const result: ReportRunResult = { dmarcSent: 0, dmarcSkipped: 0, tlsrptSent: 0, tlsrptSkipped: 0, purged: 0 };

  // ── DMARC 집계 ──────────────────────────────────────────────────────────────
  for (const [policyDomain, rows] of await loadDmarcDay(opts.db, day)) {
    try {
      const tags = await dmarcTags(policyDomain, opts.resolver);
      const rua = tags?.get("rua");
      if (!tags || !rua) {
        // 정책이 사라졌거나 rua가 없다 — 보낼 곳이 없다는 사실 자체는 오류가 아니다.
        result.dmarcSkipped += 1;
        continue;
      }
      const targets = parseRua(rua);
      if (targets.length === 0) {
        result.dmarcSkipped += 1;
        continue;
      }

      const reportId = ulid();
      const xml = buildDmarcReportXml({
        orgName: opts.reportingDomain,
        orgEmail: opts.contactEmail,
        reportId,
        beginSec,
        endSec,
        policyDomain,
        policy: {
          p: tags.get("p") ?? "none",
          sp: tags.get("sp") ?? null,
          adkim: tags.get("adkim") ?? "r",
          aspf: tags.get("aspf") ?? "r",
          pct: tags.get("pct") != null ? Number(tags.get("pct")) : null,
        },
        rows: rows.map((r) => ({
          sourceIp: r.sourceIp,
          count: r.count,
          disposition: (r.disposition === "quarantine" || r.disposition === "reject" ? r.disposition : "none") as
            | "none"
            | "quarantine"
            | "reject",
          dkimAligned: r.dkimAligned,
          spfAligned: r.spfAligned,
          headerFrom: r.headerFrom,
          dkimResult: r.dkimResult,
          spfResult: r.spfResult,
          dkimDomain: r.dkimDomain ?? null,
          spfDomain: r.spfDomain ?? null,
        })),
      });
      const body = gzipSync(Buffer.from(xml, "utf8"));
      const filename = dmarcReportFilename(opts.reportingDomain, policyDomain, beginSec, endSec);

      /**
       * ★보내기 **전에** 중복 방지를 건다. 보낸 뒤에 걸면 그 사이에 죽었을 때 다음 실행이
       * 같은 리포트를 또 보낸다 — 받는 쪽은 중복으로 세고 우리는 스팸처럼 보인다.
       */
      if (!(await claimReportSend(opts.db, "dmarc", day, policyDomain, reportId, now))) {
        result.dmarcSkipped += 1;
        continue;
      }

      let sent = 0;
      for (const t of targets) {
        /**
         * ★외부 목적지 검증(§7.1). 이게 없으면 누구나 피해자 주소를 `rua`에 적어 두고
         * **전 세계 수신 서버를 증폭기로** 쓴다. 확인 실패는 보내지 않는 쪽으로 수렴시킨다.
         */
        if (!(await isRuaAuthorized(policyDomain, t.email, opts.resolver))) {
          opts.logger.warn("dmarc rua 미승인 — 보내지 않는다", { policyDomain, rua: t.email });
          continue;
        }
        // `!size` 상한을 넘으면 보내지 않는다(§7.2.1) — 받는 쪽이 거부할 것을 보낼 이유가 없다.
        if (t.maxBytes !== null && body.length > t.maxBytes) {
          opts.logger.warn("dmarc 리포트가 rua 크기 상한 초과", { policyDomain, rua: t.email, bytes: body.length });
          continue;
        }
        await opts.sender.send({
          to: t.email,
          subject: `Report Domain: ${policyDomain} Submitter: ${opts.reportingDomain} Report-ID: ${reportId}`,
          filename,
          contentType: "application/gzip",
          body,
        });
        sent += 1;
      }
      if (sent > 0) result.dmarcSent += 1;
      else result.dmarcSkipped += 1;
    } catch (err) {
      opts.logger.warn("dmarc 리포트 실패", { policyDomain, error: err instanceof Error ? err.message : String(err) });
      result.dmarcSkipped += 1;
    }
  }

  // ── TLS-RPT ────────────────────────────────────────────────────────────────
  for (const [policyDomain, rows] of await loadTlsRptDay(opts.db, day)) {
    try {
      let txts: string[];
      try {
        txts = await opts.resolver.txt(`_smtp._tls.${policyDomain}`);
      } catch {
        result.tlsrptSkipped += 1;
        continue;
      }
      const targets = txts.flatMap((t) => parseTlsRptRua(t));
      if (targets.length === 0) {
        result.tlsrptSkipped += 1;
        continue;
      }

      const reportId = `${new Date(day).toISOString().slice(0, 10)}.${policyDomain}@${opts.reportingDomain}`;
      const json = buildTlsRptJson({
        organizationName: opts.reportingDomain,
        startIso: new Date(day).toISOString(),
        endIso: new Date(day + 86_400_000 - 1).toISOString(),
        reportId,
        contactInfo: opts.contactEmail,
        policyDomain,
        rows: rows.map((r) => ({
          policyType: (r.policyType === "sts" || r.policyType === "tlsa" ? r.policyType : "no-policy-found") as
            | "sts"
            | "tlsa"
            | "no-policy-found",
          receivingMx: r.receivingMx,
          resultType: r.resultType,
          count: r.count,
        })),
      });
      const body = gzipSync(Buffer.from(json, "utf8"));

      if (!(await claimReportSend(opts.db, "tlsrpt", day, policyDomain, reportId, now))) {
        result.tlsrptSkipped += 1;
        continue;
      }
      for (const to of targets) {
        await opts.sender.send({
          to,
          // §5.3이 정한 제목 형식 — 받는 쪽이 자동 분류한다.
          subject: `Report Domain: ${policyDomain} Submitter: ${opts.reportingDomain} Report-ID: <${reportId}>`,
          filename: tlsRptFilename(opts.reportingDomain, policyDomain, beginSec, endSec),
          contentType: "application/tlsrpt+gzip",
          body,
        });
      }
      result.tlsrptSent += 1;
    } catch (err) {
      opts.logger.warn("tlsrpt 리포트 실패", { policyDomain, error: err instanceof Error ? err.message : String(err) });
      result.tlsrptSkipped += 1;
    }
  }

  const purged = await purgeReportRows(opts.db, utcDayStart(now) - (opts.retentionDays ?? 7) * 86_400_000);
  result.purged = purged.dmarc + purged.tlsrpt + purged.sends;
  return result;
}

/** 성공 세션 표식 — 기록 쪽이 같은 문자열을 써야 리포트에서 성공으로 센다. */
export { TLSRPT_SUCCESS };
