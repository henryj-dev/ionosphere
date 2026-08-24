/**
 * 대외 리포트 발송 (`runReports`).
 *
 * ★두 가지가 이 파일의 핵심이다:
 *  · **미승인 `rua`로 보내지 않는다** — 이 검사가 없으면 누구나 피해자 주소를 `rua`에 적어
 *    전 세계 수신 서버를 증폭기로 쓴다(RFC 7489 §7.1).
 *  · **같은 리포트를 두 번 보내지 않는다** — 받는 쪽은 중복으로 세어 통계가 부풀고
 *    우리는 스팸처럼 보인다.
 */
import { gunzipSync } from "node:zlib";
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { DnsNotFoundError, type DnsResolver } from "@ionosphere/mail-auth";
import { recordDmarcRow, recordTlsRptRow, utcDayStart } from "@ionosphere/store";
import { runReports, type ReportSender } from "../src/reports.ts";

const NOW = Date.UTC(2026, 7, 24, 12, 0, 0);
const YESTERDAY = utcDayStart(NOW) - 86_400_000;

function resolver(txts: Record<string, string[]>): DnsResolver {
  return {
    txt: async (name: string) => {
      const v = txts[name.toLowerCase()];
      if (!v) throw new DnsNotFoundError(`no TXT: ${name}`);
      return v;
    },
    mx: async () => [],
    a: async () => [],
    aaaa: async () => [],
    ptr: async () => [],
  };
}

interface Sent {
  to: string;
  subject: string;
  filename: string;
  contentType: string;
  body: Uint8Array;
}

function collector(): { sender: ReportSender; sent: Sent[] } {
  const sent: Sent[] = [];
  return { sender: { send: async (m) => void sent.push(m as Sent) }, sent };
}

const quietLogger = { info: () => {}, warn: () => {}, error: () => {}, debug: () => {}, child: () => quietLogger } as never;

async function freshDb(): Promise<DbDriver> {
  const db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
  return db;
}

async function seedDmarc(db: DbDriver): Promise<void> {
  await recordDmarcRow(
    db,
    {
      policyDomain: "sender.test",
      headerFrom: "sender.test",
      sourceIp: "203.0.113.5",
      disposition: "none",
      dkimAligned: true,
      spfAligned: true,
      dkimResult: "pass",
      spfResult: "pass",
      dkimDomain: "sender.test",
      spfDomain: "sender.test",
    },
    YESTERDAY,
  );
}

const opts = (db: DbDriver, r: DnsResolver, sender: ReportSender) => ({
  db,
  resolver: r,
  logger: quietLogger,
  sender,
  reportingDomain: "mx.ionosphere.test",
  contactEmail: "dmarc@ionosphere.test",
  now: NOW,
});

describe("DMARC 집계 리포트 발송", () => {
  test("같은 도메인 rua로 보낸다", async () => {
    const db = await freshDb();
    await seedDmarc(db);
    const { sender, sent } = collector();
    const r = resolver({ "_dmarc.sender.test": ["v=DMARC1; p=reject; rua=mailto:agg@sender.test"] });

    const res = await runReports(opts(db, r, sender));
    expect(res.dmarcSent).toBe(1);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.to).toBe("agg@sender.test");
    expect(sent[0]!.filename).toContain("mx.ionosphere.test!sender.test!");
    expect(sent[0]!.contentType).toBe("application/gzip");
    // gzip을 풀면 우리가 만든 XML이다
    const xml = gunzipSync(Buffer.from(sent[0]!.body)).toString("utf8");
    expect(xml).toContain("<domain>sender.test</domain>");
    expect(xml).toContain("<source_ip>203.0.113.5</source_ip>");
    await db.close();
  });

  /** ★증폭 공격 방어 — 승인 레코드가 없는 외부 주소로는 **보내지 않는다**. */
  test("승인되지 않은 외부 rua로는 보내지 않는다", async () => {
    const db = await freshDb();
    await seedDmarc(db);
    const { sender, sent } = collector();
    // victim.test는 승인 레코드가 없다
    const r = resolver({ "_dmarc.sender.test": ["v=DMARC1; p=reject; rua=mailto:flood@victim.test"] });

    const res = await runReports(opts(db, r, sender));
    expect(sent).toHaveLength(0);
    expect(res.dmarcSent).toBe(0);
    await db.close();
  });

  test("승인 레코드가 있으면 외부 rua로도 보낸다", async () => {
    const db = await freshDb();
    await seedDmarc(db);
    const { sender, sent } = collector();
    const r = resolver({
      "_dmarc.sender.test": ["v=DMARC1; p=reject; rua=mailto:agg@reports.test"],
      "sender.test._report._dmarc.reports.test": ["v=DMARC1"],
    });
    expect((await runReports(opts(db, r, sender))).dmarcSent).toBe(1);
    expect(sent[0]!.to).toBe("agg@reports.test");
    await db.close();
  });

  /** ★같은 리포트를 두 번 보내면 받는 쪽 통계가 부풀고 우리는 스팸처럼 보인다. */
  test("두 번 돌려도 한 번만 보낸다", async () => {
    const db = await freshDb();
    await seedDmarc(db);
    const { sender, sent } = collector();
    const r = resolver({ "_dmarc.sender.test": ["v=DMARC1; p=reject; rua=mailto:agg@sender.test"] });

    await runReports(opts(db, r, sender));
    const second = await runReports(opts(db, r, sender));
    expect(sent).toHaveLength(1);
    expect(second.dmarcSent).toBe(0);
    expect(second.dmarcSkipped).toBe(1);
    await db.close();
  });

  test("rua가 없으면 건너뛴다", async () => {
    const db = await freshDb();
    await seedDmarc(db);
    const { sender, sent } = collector();
    const r = resolver({ "_dmarc.sender.test": ["v=DMARC1; p=reject"] });
    expect((await runReports(opts(db, r, sender))).dmarcSkipped).toBe(1);
    expect(sent).toHaveLength(0);
    await db.close();
  });

  /** 정책이 사라진 도메인 — 보낼 곳이 없다는 사실 자체는 오류가 아니다. */
  test("DMARC 레코드가 없으면 건너뛴다", async () => {
    const db = await freshDb();
    await seedDmarc(db);
    const { sender, sent } = collector();
    expect((await runReports(opts(db, resolver({}), sender))).dmarcSkipped).toBe(1);
    expect(sent).toHaveLength(0);
    await db.close();
  });

  /** `!size` 상한을 넘으면 받는 쪽이 거부할 것을 보낼 이유가 없다. */
  test("rua 크기 상한을 넘으면 보내지 않는다", async () => {
    const db = await freshDb();
    await seedDmarc(db);
    const { sender, sent } = collector();
    const r = resolver({ "_dmarc.sender.test": ["v=DMARC1; p=reject; rua=mailto:agg@sender.test!1"] });
    await runReports(opts(db, r, sender));
    expect(sent).toHaveLength(0);
    await db.close();
  });

  /** ★오늘치는 아직 쌓이는 중이다 — 보내면 반쪽 기간을 보고하게 된다. */
  test("오늘 쌓인 것은 보내지 않는다", async () => {
    const db = await freshDb();
    await recordDmarcRow(
      db,
      {
        policyDomain: "sender.test",
        headerFrom: "sender.test",
        sourceIp: "203.0.113.9",
        disposition: "none",
        dkimAligned: true,
        spfAligned: true,
        dkimResult: "pass",
        spfResult: "pass",
      },
      NOW, // 오늘
    );
    const { sender, sent } = collector();
    const r = resolver({ "_dmarc.sender.test": ["v=DMARC1; p=reject; rua=mailto:agg@sender.test"] });
    await runReports(opts(db, r, sender));
    expect(sent).toHaveLength(0);
    await db.close();
  });
});

describe("TLS-RPT 발송", () => {
  test("_smtp._tls의 rua로 보낸다", async () => {
    const db = await freshDb();
    await recordTlsRptRow(
      db,
      { policyDomain: "peer.test", policyType: "sts", receivingMx: "mx1.peer.test", resultType: "starttls-not-supported" },
      YESTERDAY,
    );
    const { sender, sent } = collector();
    const r = resolver({ "_smtp._tls.peer.test": ["v=TLSRPTv1; rua=mailto:tlsrpt@peer.test"] });

    const res = await runReports(opts(db, r, sender));
    expect(res.tlsrptSent).toBe(1);
    expect(sent[0]!.to).toBe("tlsrpt@peer.test");
    expect(sent[0]!.contentType).toBe("application/tlsrpt+gzip");
    const json = JSON.parse(gunzipSync(Buffer.from(sent[0]!.body)).toString("utf8")) as {
      policies: { "failure-details": { "result-type": string }[] }[];
    };
    expect(json.policies[0]!["failure-details"][0]!["result-type"]).toBe("starttls-not-supported");
    await db.close();
  });

  test("두 번 돌려도 한 번만 보낸다", async () => {
    const db = await freshDb();
    await recordTlsRptRow(db, { policyDomain: "peer.test", policyType: "sts", receivingMx: "mx1.peer.test", resultType: "dane-required" }, YESTERDAY);
    const { sender, sent } = collector();
    const r = resolver({ "_smtp._tls.peer.test": ["v=TLSRPTv1; rua=mailto:tlsrpt@peer.test"] });
    await runReports(opts(db, r, sender));
    await runReports(opts(db, r, sender));
    expect(sent).toHaveLength(1);
    await db.close();
  });

  test("TXT가 없으면 건너뛴다", async () => {
    const db = await freshDb();
    await recordTlsRptRow(db, { policyDomain: "peer.test", policyType: "sts", receivingMx: "mx1.peer.test", resultType: "dane-required" }, YESTERDAY);
    const { sender, sent } = collector();
    expect((await runReports(opts(db, resolver({}), sender))).tlsrptSkipped).toBe(1);
    expect(sent).toHaveLength(0);
    await db.close();
  });
});

describe("집계 카운터", () => {
  /** ★조합마다 한 행이고 개수만 오른다 — 메시지마다 행을 남기면 하루 수백만 행이 된다. */
  test("같은 조합은 한 행에서 카운트가 오른다", async () => {
    const db = await freshDb();
    const key = {
      policyDomain: "sender.test",
      headerFrom: "sender.test",
      sourceIp: "203.0.113.5",
      disposition: "none",
      dkimAligned: true,
      spfAligned: true,
      dkimResult: "pass",
      spfResult: "pass",
    };
    for (let i = 0; i < 5; i++) await recordDmarcRow(db, key, YESTERDAY);
    const { rows } = await db.query({ sql: "SELECT count FROM dmarc_report_rows", params: [] });
    expect(rows).toHaveLength(1);
    expect(Number(rows[0]!.count)).toBe(5);
    await db.close();
  });

  test("다른 조합은 다른 행이다", async () => {
    const db = await freshDb();
    const base = {
      policyDomain: "sender.test",
      headerFrom: "sender.test",
      disposition: "none",
      dkimAligned: true,
      spfAligned: true,
      dkimResult: "pass",
      spfResult: "pass",
    };
    await recordDmarcRow(db, { ...base, sourceIp: "203.0.113.5" }, YESTERDAY);
    await recordDmarcRow(db, { ...base, sourceIp: "203.0.113.9" }, YESTERDAY);
    const { rows } = await db.query({ sql: "SELECT count FROM dmarc_report_rows", params: [] });
    expect(rows).toHaveLength(2);
    await db.close();
  });

  test("보존창 밖 집계는 정리된다", async () => {
    const db = await freshDb();
    await recordDmarcRow(
      db,
      {
        policyDomain: "old.test",
        headerFrom: "old.test",
        sourceIp: "203.0.113.1",
        disposition: "none",
        dkimAligned: true,
        spfAligned: true,
        dkimResult: "pass",
        spfResult: "pass",
      },
      NOW - 30 * 86_400_000,
    );
    const { sender } = collector();
    const res = await runReports({ ...opts(db, resolver({}), sender), retentionDays: 7 });
    expect(res.purged).toBeGreaterThan(0);
    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM dmarc_report_rows", params: [] });
    expect(Number(rows[0]!.n)).toBe(0);
    await db.close();
  });
});
