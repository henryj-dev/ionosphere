/**
 * Sieve 스크립트 저장소 (ManageSieve RFC 5804 / JMAP Sieve).
 *
 * 스크립트 **저장**만 담당한다 — 파싱·실행은 @ionosphere/sieve, 프로토콜은 @ionosphere/proto-managesieve.
 * 이전엔 이 코드가 Store 클래스 안에 있어서, ManageSieve 기능을 손보려면 메일함·메시지 로직이
 * 든 1700줄짜리 파일을 열어야 했다.
 */
import { ulid } from "@ionosphere/core";
import { StoreError } from "./errors.ts";
import type { StoreInternals } from "./internals.ts";

/** 계정의 활성 Sieve 스크립트 내용(배달 필터용). 없으면 null. */
export async function getActiveSieveScript(s: StoreInternals, accountId: string): Promise<string | null> {
  const { rows } = await s.db.query({
    sql: "SELECT content FROM sieve_scripts WHERE account_id = ? AND active = 1 LIMIT 1",
    params: [accountId],
  });
  return rows[0] ? String(rows[0].content) : null;
}

/** 스크립트 저장(upsert — PUTSCRIPT는 덮어쓰기). 신규는 비활성. 검증은 호출자(파서). */
export async function putSieveScript(s: StoreInternals, accountId: string, name: string, content: string): Promise<void> {
  return s.writer.run(accountId, () =>
    s.withRetry(async () => {
      const { rows } = await s.db.query({ sql: "SELECT id FROM sieve_scripts WHERE account_id = ? AND name = ?", params: [accountId, name] });
      if (rows[0]) {
        await s.db.batch([{ sql: "UPDATE sieve_scripts SET content = ? WHERE id = ?", params: [content, String(rows[0].id)] }]);
      } else {
        await s.db.batch([
          { sql: "INSERT INTO sieve_scripts (id, account_id, name, content, active, created_at) VALUES (?, ?, ?, ?, 0, ?)", params: [ulid(), accountId, name, content, Date.now()] },
        ]);
      }
    }),
  );
}

export async function listSieveScripts(s: StoreInternals, accountId: string): Promise<{ name: string; active: boolean }[]> {
  const { rows } = await s.db.query({ sql: "SELECT name, active FROM sieve_scripts WHERE account_id = ? ORDER BY name", params: [accountId] });
  return rows.map((r) => ({ name: String(r.name), active: Number(r.active) === 1 }));
}

export async function getSieveScript(s: StoreInternals, accountId: string, name: string): Promise<string | null> {
  const { rows } = await s.db.query({ sql: "SELECT content FROM sieve_scripts WHERE account_id = ? AND name = ?", params: [accountId, name] });
  return rows[0] ? String(rows[0].content) : null;
}

/** 삭제. 활성 스크립트는 삭제 불가(RFC 5804 §2.10) → StoreError. */
export async function deleteSieveScript(s: StoreInternals, accountId: string, name: string): Promise<void> {
  return s.writer.run(accountId, () =>
    s.withRetry(async () => {
      const { rows } = await s.db.query({ sql: "SELECT id, active FROM sieve_scripts WHERE account_id = ? AND name = ?", params: [accountId, name] });
      if (!rows[0]) throw new StoreError(`script not found: ${name}`);
      if (Number(rows[0].active) === 1) throw new StoreError("cannot delete active script");
      await s.db.batch([{ sql: "DELETE FROM sieve_scripts WHERE id = ?", params: [String(rows[0].id)] }]);
    }),
  );
}

/** 활성 스크립트 지정. name=""이면 전체 비활성(RFC 5804 §2.8). */
export async function setActiveSieveScript(s: StoreInternals, accountId: string, name: string): Promise<void> {
  return s.writer.run(accountId, () =>
    s.withRetry(async () => {
      if (name !== "") {
        const { rows } = await s.db.query({ sql: "SELECT id FROM sieve_scripts WHERE account_id = ? AND name = ?", params: [accountId, name] });
        if (!rows[0]) throw new StoreError(`script not found: ${name}`);
      }
      await s.db.batch([
        { sql: "UPDATE sieve_scripts SET active = 0 WHERE account_id = ?", params: [accountId] },
        ...(name !== "" ? [{ sql: "UPDATE sieve_scripts SET active = 1 WHERE account_id = ? AND name = ?", params: [accountId, name] }] : []),
      ]);
    }),
  );
}

/** 이름 변경(RFC 5804 §2.11). active 상태 유지. */
export async function renameSieveScript(s: StoreInternals, accountId: string, from: string, to: string): Promise<void> {
  return s.writer.run(accountId, () =>
    s.withRetry(async () => {
      const { rows } = await s.db.query({ sql: "SELECT id FROM sieve_scripts WHERE account_id = ? AND name = ?", params: [accountId, from] });
      if (!rows[0]) throw new StoreError(`script not found: ${from}`);
      const { rows: dup } = await s.db.query({ sql: "SELECT id FROM sieve_scripts WHERE account_id = ? AND name = ?", params: [accountId, to] });
      if (dup[0]) throw new StoreError(`script already exists: ${to}`);
      await s.db.batch([{ sql: "UPDATE sieve_scripts SET name = ? WHERE id = ?", params: [to, String(rows[0].id)] }]);
    }),
  );
}
