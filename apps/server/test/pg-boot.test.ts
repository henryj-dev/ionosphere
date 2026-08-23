/**
 * PostgreSQL 배선 e2e — `IonosphereApp`이 SQLite가 아닌 공유 DB로 뜨고, 수신→저장→조회가 도는가.
 *
 * 왜 필요한가: 서버를 역할별로 분리하려면 여러 인스턴스가 **하나의 DB**를 봐야 한다. 그런데
 * `openStorage()`가 `openSqlite`를 하드코딩하고 있어 **다른 DB로 갈 배선 자체가 없었다**.
 * 어댑터(`packages/db/src/postgres.ts`)는 있었지만 조립층에서 쓸 방법이 없었다는 뜻이다.
 *
 * env 게이트: `IONOSPHERE_TEST_PG_URL` 없으면 skip(오프라인 CI 보호).
 * 로컬 실행: `./scripts/dialect-test.sh`가 띄우는 PG를 쓰거나 직접 docker로 띄운다.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDatabase } from "@ionosphere/db";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

const PG_URL = process.env.IONOSPHERE_TEST_PG_URL;
const d = PG_URL ? describe : describe.skip;

/**
 * 전용 스키마 이름 — `IONOSPHERE_TEST_PG_URL`의 `public`을 **직접 지우지 않는다.**
 *
 * ★왜(2026-08-01 실사고, MySQL 쪽과 같은 결함): 예전에는 `DROP SCHEMA public CASCADE`로
 * 공유 DB의 스키마를 통째로 비웠다. 그런데 `apps/server/test/dialect-contract.test.ts`가
 * 같은 env를 읽어 **같은 스키마에서 마이그레이션을 돌린다.** 병렬 실행에서 이쪽 DROP이 저쪽
 * 중간에 끼어들면 `relation "modseq_claims" does not exist` 류로 죽는다(실측: 3회 중 2회 실패).
 *
 * `packages/db/test/postgres.test.ts`는 이미 전용 스키마(`ionosphere_test`)로 격리하고 있었다 —
 * 그 패턴을 여기에도 맞춘다. 이름을 다르게 두는 이유: 이 파일은 **서버를 띄워** DB를 쓰므로
 * postgres.test.ts와 동시에 돌면 둘이 또 겹친다.
 */
const TEST_SCHEMA = "ionosphere_pgboot_test";

/** 서버·마이그레이션이 전용 스키마만 보도록 search_path를 URL에 실어 보낸다. */
function scopedUrl(url: string): string {
  const u = new URL(url);
  u.searchParams.set("options", `-c search_path=${TEST_SCHEMA}`);
  return u.toString();
}

/** 전용 스키마를 재생성해 매 실행을 결정적으로 만든다. */
async function resetSchema(url: string): Promise<void> {
  const db = await openDatabase(url);
  await db.batch([
    { sql: `DROP SCHEMA IF EXISTS ${TEST_SCHEMA} CASCADE` },
    { sql: `CREATE SCHEMA ${TEST_SCHEMA}` },
  ]);
  await db.close();
}

function deliver(port: number, rcpt: string, subject: string): Promise<string> {
  const raw = [`From: s@remote.example`, `To: ${rcpt}`, `Subject: ${subject}`, "", "body"].join("\r\n");
  // QUIT은 넣지 않는다 — 넣으면 마지막 응답이 DATA의 250이 아니라 QUIT의 221이 된다.
  const script = ["EHLO c\r\n", "MAIL FROM:<s@remote.example>\r\n", `RCPT TO:<${rcpt}>\r\n`, "DATA\r\n", raw + "\r\n.\r\n"];
  return new Promise((resolve, reject) => {
    const sock = connect(port, "127.0.0.1");
    sock.setEncoding("utf8");
    let buf = "";
    let step = 0;
    let last = "";
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error("timeout"));
    }, 20_000);
    sock.on("data", (c: string) => {
      buf += c;
      let i: number;
      while ((i = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        // ★SMTP 멀티라인 응답(EHLO의 `250-...`)은 마지막 줄만 "응답 완료"다.
        // 줄마다 다음 명령을 보내면 EHLO 한 번에 스크립트가 통째로 소진된다.
        if (line.length >= 4 && line[3] === "-") continue;
        last = line;
        if (step < script.length) sock.write(script[step++]!);
        else {
          clearTimeout(timer);
          sock.end();
          resolve(last);
          return;
        }
      }
    });
    sock.on("error", (e: Error) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

d("PostgreSQL 배선 — 공유 DB로 기동", () => {
  let app: IonosphereApp;
  let blobRoot: string;
  let accountId: string;

  beforeAll(async () => {
    await resetSchema(PG_URL!);
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-pgboot-"));
    app = new IonosphereApp({
      hostname: "mx.test.local",
      dbPath: "unused-when-dbUrl-set",
      // ★전용 스키마를 보게 한다 — `PG_URL!` 그대로 주면 서버가 `public`에 마이그레이션을
      //   적용해 위 resetSchema와 어긋나고, dialect-contract와 다시 겹친다.
      dbUrl: scopedUrl(PG_URL!),
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      runMtaWorker: false,
      resolver: offlineResolver(),
    });
    await app.start();
    const created = await app.createUser("u@test.local", "pw");
    accountId = created.accountId;
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("SQLite가 아니라 PostgreSQL로 떴다", () => {
    expect(app.db.dialect).toBe("postgres");
  });

  test("마이그레이션이 전부 적용됐다", async () => {
    const { rows } = await app.db.query({ sql: "SELECT COUNT(*) AS n FROM schema_migrations" });
    expect(Number(rows[0]!.n)).toBeGreaterThanOrEqual(4);
  });

  test("수신 → 저장 → 조회가 PG 위에서 동작한다", async () => {
    const resp = await deliver(app.smtpPort, "u@test.local", "pg e2e");
    expect(resp).toStartWith("250");

    const inbox = (await app.store.getMailboxByRole(accountId, "inbox"))!;
    const list = await app.store.listMessages(inbox.id);
    expect(list).toHaveLength(1);
  });

  test("낙관적 락(modseq_claims)이 PG에서도 성립한다 — 동시 append 20건", async () => {
    const inbox = (await app.store.getMailboxByRole(accountId, "inbox"))!;
    const before = (await app.store.listMessages(inbox.id)).length;
    await Promise.all(Array.from({ length: 20 }, (_, i) => deliver(app.smtpPort, "u@test.local", `burst ${i}`)));
    const after = await app.store.listMessages(inbox.id);
    expect(after.length).toBe(before + 20); // 유실·중복 없음

    // change_log의 modseq는 gap 없이 1..N이어야 한다(§3-3 전역 불변식)
    const { rows } = await app.db.query({
      sql: "SELECT DISTINCT modseq FROM change_log WHERE account_id = ? ORDER BY modseq",
      params: [accountId],
    });
    const seqs = rows.map((r) => Number(r.modseq));
    expect(seqs).toEqual(Array.from({ length: seqs.length }, (_, i) => i + 1));
  });
});
