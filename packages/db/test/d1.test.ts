import { describe, expect, test } from "@ionosphere/testkit";
import { BatchConflictError, openD1, type Statement } from "@ionosphere/db";

/**
 * D1은 실제 계정 없이 단위테스트 불가 → fetch를 주입해 요청 URL/바디 조립,
 * 응답 파싱, 에러 매핑, 상한 검사를 검증한다(연결 불필요, 항상 실행).
 */

interface RecordedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

/** 캔드 응답을 순서대로 돌려주며 요청을 기록하는 가짜 fetch. */
function fakeFetch(responses: unknown[]): { fetch: typeof fetch; requests: RecordedRequest[] } {
  const requests: RecordedRequest[] = [];
  let i = 0;
  const fn = (async (url: string | URL | Request, init?: RequestInit) => {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) headers[k] = v;
    requests.push({
      url: String(url),
      method: init?.method ?? "GET",
      headers,
      body: init?.body ? JSON.parse(init.body as string) : undefined,
    });
    const payload = responses[i++] ?? { ok: true, json: { result: [], success: true, errors: [], messages: [] } };
    const p = payload as { ok?: boolean; status?: number; json: unknown };
    return {
      ok: p.ok ?? true,
      status: p.status ?? 200,
      json: async () => p.json,
    } as Response;
  }) as unknown as typeof fetch;
  return { fetch: fn, requests };
}

const opts = (fetchImpl: typeof fetch) => ({
  accountId: "acct123",
  databaseId: "db456",
  apiToken: "tok789",
  fetch: fetchImpl,
});

function okQuery(rows: Record<string, unknown>[]) {
  return { ok: true, json: { result: [{ results: rows, success: true, meta: { changes: 0 } }], success: true, errors: [], messages: [] } };
}
function okBatch(changesList: number[]) {
  return {
    ok: true,
    json: {
      result: changesList.map((c) => ({ results: [], success: true, meta: { changes: c } })),
      success: true,
      errors: [],
      messages: [],
    },
  };
}

describe("D1 어댑터 (fetch 주입 단위테스트)", () => {
  test("query: URL/인증헤더/바디 조립 + 행 파싱", async () => {
    const f = fakeFetch([okQuery([{ id: "T", n: 1 }])]);
    const db = openD1(opts(f.fetch));
    const { rows } = await db.query({ sql: "SELECT * FROM tenants WHERE id = ?", params: ["T"] });

    expect(rows).toEqual([{ id: "T", n: 1 }]);
    const req = f.requests[0]!;
    expect(req.url).toBe("https://api.cloudflare.com/client/v4/accounts/acct123/d1/database/db456/query");
    expect(req.method).toBe("POST");
    expect(req.headers.Authorization).toBe("Bearer tok789");
    expect(req.headers["Content-Type"]).toBe("application/json");
    expect(req.body).toEqual({ sql: "SELECT * FROM tenants WHERE id = ?", params: ["T"] });
    await db.close();
  });

  test("batch: {batch:[...]} 폼 + 문장별 changes 반환", async () => {
    const f = fakeFetch([okBatch([1, 1])]);
    const db = openD1(opts(f.fetch));
    const stmts: Statement[] = [
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: ["A", 1] },
      { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?, ?, 1, 0)", params: ["T", "t1"] },
    ];
    const results = await db.batch(stmts);

    expect(results.map((r) => r.changes)).toEqual([1, 1]);
    expect(f.requests[0]!.body).toEqual({
      batch: [
        { sql: stmts[0]!.sql, params: ["A", 1] },
        { sql: stmts[1]!.sql, params: ["T", "t1"] },
      ],
    });
    await db.close();
  });

  test("제약 위반: 봉투 success:false + UNIQUE 메시지 → BatchConflictError", async () => {
    const f = fakeFetch([
      { ok: true, json: { result: [], success: false, errors: [{ code: 7500, message: "UNIQUE constraint failed: modseq_claims.modseq" }], messages: [] } },
    ]);
    const db = openD1(opts(f.fetch));
    await expect(
      db.batch([{ sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: ["A", 5] }]),
    ).rejects.toBeInstanceOf(BatchConflictError);
    await db.close();
  });

  test("비제약 에러: 일반 Error(메시지 전파)", async () => {
    const f = fakeFetch([
      { ok: false, status: 400, json: { result: [], success: false, errors: [{ code: 1000, message: "no such table: nope" }], messages: [] } },
    ]);
    const db = openD1(opts(f.fetch));
    const err = await db.query({ sql: "SELECT * FROM nope" }).catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err).not.toBeInstanceOf(BatchConflictError);
    expect((err as Error).message).toContain("no such table");
    await db.close();
  });

  test("파라미터 정규화: boolean→1/0, Uint8Array→number[], null 통과", async () => {
    const f = fakeFetch([okQuery([])]);
    const db = openD1(opts(f.fetch));
    await db.query({ sql: "SELECT ?, ?, ?, ?", params: [true, false, new Uint8Array([1, 2, 255]), null] });
    expect(f.requests[0]!.body).toEqual({ sql: "SELECT ?, ?, ?, ?", params: [1, 0, [1, 2, 255], null] });
    await db.close();
  });

  test("상한: SQL 100KB 초과 → 조기 에러(요청 없음)", async () => {
    const f = fakeFetch([]);
    const db = openD1(opts(f.fetch));
    const bigSql = "SELECT '" + "x".repeat(100_001) + "'";
    await expect(db.query({ sql: bigSql })).rejects.toThrow(/100000B를 초과/);
    expect(f.requests.length).toBe(0);
    await db.close();
  });

  test("상한: 파라미터 100개 초과 → 조기 에러", async () => {
    const f = fakeFetch([]);
    const db = openD1(opts(f.fetch));
    const params = Array.from({ length: 101 }, (_, i) => i);
    await expect(db.query({ sql: "SELECT ?", params })).rejects.toThrow(/파라미터/);
    expect(f.requests.length).toBe(0);
    await db.close();
  });

  test("상한: 배치 1000문장 초과 → 조기 에러", async () => {
    const f = fakeFetch([]);
    const db = openD1(opts(f.fetch));
    const stmts = Array.from({ length: 1001 }, () => ({ sql: "SELECT 1" }));
    await expect(db.batch(stmts)).rejects.toThrow(/배치 문장/);
    expect(f.requests.length).toBe(0);
    await db.close();
  });

  test("insertIgnore: INSERT OR IGNORE (SQLite 계열)", () => {
    const db = openD1(opts(fakeFetch([]).fetch));
    expect(db.insertIgnore("blobs", ["id", "size_bytes"])).toBe(
      "INSERT OR IGNORE INTO blobs (id, size_bytes) VALUES (?, ?)",
    );
  });

  test("dialect = d1", () => {
    expect(openD1(opts(fakeFetch([]).fetch)).dialect).toBe("d1");
  });
});
