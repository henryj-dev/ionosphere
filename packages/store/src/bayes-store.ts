/**
 * 베이즈 토큰 저장소 — `@ionosphere/spam`의 `BayesStore` 구현.
 *
 * ★계정 경계를 지키는 것이 이 파일의 책임이다. 모든 질의에 `account_id`가 들어가고,
 * 분류기는 계정 id를 넘길 뿐 다른 계정을 볼 방법이 없다.
 */
import type { BayesStore, TokenCounts } from "@ionosphere/spam";
import type { DbDriver } from "@ionosphere/db";
import { chunk, MAX_PARAMS_PER_STATEMENT, queryInChunks } from "./chunk.ts";

/**
 * 쓰기 경로의 토큰 청크 크기.
 *
 * ★예전엔 이 파일이 `CHUNK = 90`과 자체 `chunk()`를 들고 있었다. 값도 헬퍼도 `chunk.ts`의
 * 복제였고, 그러면 소유자 쪽 한도를 조정해도 여기가 옛 값을 계속 쓴다. 읽기 경로는
 * `queryInChunks`가 알아서 나누고, 쓰기 경로만 한도에서 유도한다(토큰 1 + 카운트 2 + 계정 1).
 */
const WRITE_CHUNK = Math.floor(MAX_PARAMS_PER_STATEMENT / 4);

export function createBayesStore(db: DbDriver): BayesStore {
  return {
    async counts(accountId: string, tokens: readonly string[]): Promise<Map<string, TokenCounts>> {
      const map = new Map<string, TokenCounts>();
      const rows = await queryInChunks(
        db,
        tokens,
        (ph) => `SELECT token, spam_count, ham_count FROM bayes_tokens WHERE account_id = ? AND token IN (${ph})`,
        [accountId],
      );
      for (const r of rows) {
        map.set(String(r.token), { spam: Number(r.spam_count ?? 0), ham: Number(r.ham_count ?? 0) });
      }
      return map;
    },

    async train(accountId: string, tokens: readonly string[], kind: "spam" | "ham"): Promise<void> {
      const col = kind === "spam" ? "spam_count" : "ham_count";
      const totalCol = kind === "spam" ? "spam_msgs" : "ham_msgs";
      /**
       * ★upsert를 **한 배치**로 묶는다. 이 저장소의 규약이 "한 논리 연산 = db.batch() 한 번"이고
       * (CLAUDE.md), 토큰마다 왕복하면 메일 한 통 학습에 수백 번이 된다.
       *
       * `insertIgnore` + `UPDATE`로 나눈 이유: 다이얼렉트마다 upsert 문법이 갈리는데
       * (`ON CONFLICT` vs `ON DUPLICATE KEY`), 그 분기는 `@ionosphere/db` 밖으로 나오면 안 된다
       * (다이얼렉트 봉인 규약). 두 문장이면 네 방언에서 같은 SQL로 성립한다.
       */
      for (const part of chunk([...tokens], WRITE_CHUNK)) {
        const stmts = [];
        for (const t of part) {
          // ★`insertIgnore()`는 다이얼렉트 봉인 규약이 명시한 **유일한 탈출구**다
          //   (CLAUDE.md). 여기서 `ON CONFLICT`를 직접 쓰면 그 규약이 깨진다.
          stmts.push({
            sql: db.insertIgnore("bayes_tokens", ["account_id", "token", "spam_count", "ham_count"]),
            params: [accountId, t, 0, 0],
          });
          stmts.push({
            sql: `UPDATE bayes_tokens SET ${col} = ${col} + 1 WHERE account_id = ? AND token = ?`,
            params: [accountId, t],
          });
        }
        await db.batch(stmts);
      }
      await db.batch([
        {
          sql: db.insertIgnore("bayes_totals", ["account_id", "spam_msgs", "ham_msgs"]),
          params: [accountId, 0, 0],
        },
        { sql: `UPDATE bayes_totals SET ${totalCol} = ${totalCol} + 1 WHERE account_id = ?`, params: [accountId] },
      ]);
    },

    async totals(accountId: string): Promise<{ spam: number; ham: number }> {
      const { rows } = await db.query({
        sql: "SELECT spam_msgs, ham_msgs FROM bayes_totals WHERE account_id = ?",
        params: [accountId],
      });
      return { spam: Number(rows[0]?.spam_msgs ?? 0), ham: Number(rows[0]?.ham_msgs ?? 0) };
    },
  };
}
