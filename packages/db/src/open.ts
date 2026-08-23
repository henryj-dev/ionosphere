/**
 * 연결 문자열 → 드라이버 선택. **다이얼렉트 분기의 유일한 승인 지점**(SCHEMA.md §1-5 정신).
 *
 * 왜 필요한가: 조립층(apps/server)이 `openSqlite`를 직접 부르고 있어서 **다른 DB로 갈 배선 자체가
 * 없었다**. 서버를 역할별로 분리하려면 여러 인스턴스가 하나의 DB를 봐야 하는데, SQLite는 로컬
 * 파일이라 그게 불가능하다. 여기서 스킴으로 갈라주면 조립층은 계속 `dialect`를 모른 채로 있을 수 있다.
 *
 * ⚠ SQLite를 **여러 프로세스가 동시에** 쓰는 구성은 지원하지 않는다. `sqlite.ts`가 `busy_timeout`을
 * 걸지 않고 `SQLITE_BUSY`를 제약 위반으로 분류하지도 않아, 스토어의 재시도 루프가 그 오류를 잡지 못한다.
 * 멀티 인스턴스는 PostgreSQL(또는 MySQL)로 가야 한다.
 *
 * ★PG/MySQL 드라이버는 **동적 import**한다(정적 import 금지). SQLite는 런타임 빌트인이라
 * (`bun:sqlite`/`node:sqlite`) 의존성이 없는데, 정적으로 끌어오면 `pg`·`mysql2`가 설치돼 있지
 * 않은 환경에서 **모듈 해석 단계에서 죽는다** — SQLite만 쓰려는 사용자가 쓰지도 않을 드라이버
 * 두 개를 설치해야 했다(실측: `Cannot find package 'pg'`). 오픈소스 배포에서 "SQLite만으로
 * 완전히 동작"이 성립해야 하므로 실제 쓰는 방언만 로드한다.
 */
import { openSqlite } from "./sqlite.ts";
import type { DbDriver } from "./types.ts";

/**
 * 연결 문자열로 드라이버를 연다.
 *  - `postgres://…` / `postgresql://…` → PostgreSQL
 *  - `mysql://…`                        → MySQL
 *  - `sqlite:<경로>` / `file:<경로>`    → SQLite
 *  - 스킴이 없으면 **파일 경로로 간주**해 SQLite (기존 `dbPath` 동작과 호환)
 *
 * D1은 계정/토큰 등 URL로 표현하기 어색한 설정이 필요해 여기서 다루지 않는다 — `openD1`을 직접 쓴다.
 */
/**
 * 연결 문자열을 **로그·화면에 찍어도 되는 형태**로. 자격증명만 지운다.
 *
 * ★정본을 여기 두는 이유: 이 문자열의 형식을 아는 곳이 `openDatabase`다. 예전엔 `cli.ts`와
 * `scripts/migrate-to-sql.ts`가 같은 정규식을 각자 들고 있었고, 마스킹을 잊은 세 번째 자리가
 * 생기면 그때 비밀번호가 로그로 나간다 — 되돌릴 수 없는 종류의 실수다.
 *
 * 파일 경로(스킴 없음)는 그대로 돌려준다. 감출 것이 없고, 감추면 "어느 DB를 보는가"라는
 * 질문에 답하지 못한다.
 */
export function describeDbSpec(spec: string): string {
  /**
   * ★authority 구간(`//` ~ 다음 `/`)**만** 잘라 그 안의 `user:pass@`를 지운다.
   *
   * 예전 정규식 `\/\/[^@/]*@`은 비밀번호에 `/`가 있으면 **마스킹에 실패했다** —
   * `[^@/]*`가 `/`에서 멈춰 `@`에 닿지 못한다. `postgres://user:p/w@host/db`가 그대로 로그에
   * 찍힌다는 뜻이다. URL 규격상 비밀번호의 `/`는 인코딩해야 하지만, **인코딩하지 않은 값이
   * 들어왔을 때 조용히 새는 쪽**이 이 함수가 막아야 할 사고다(fail closed).
   *
   * 반대로 authority 밖의 `@`(경로에 든 것)는 건드리지 않는다 — 감출 것이 아니고,
   * 지우면 "어느 DB를 보는가"에 답하지 못한다.
   */
  const at = spec.indexOf("//");
  if (at < 0) return spec;
  const start = at + 2;
  /**
   * `//` 뒤 **마지막** `@`까지를 자격증명으로 본다.
   *
   * ★왜 "첫" 이 아니라 "마지막"인가: 인코딩하지 않은 `@`가 비밀번호에 들어오면
   * (`p@ss@host`) 첫 `@`에서 자르는 순간 `ss`가 남아 **비밀번호 일부가 그대로 새어 나간다.**
   * 마지막을 쓰면 호스트가 통째로 가려질 수는 있어도 비밀번호는 남지 않는다 —
   * 진단 정보를 조금 잃는 쪽이 자격증명을 흘리는 쪽보다 낫다(fail closed).
   *
   * 같은 이유로 authority 경계(`/`)를 먼저 찾지 않는다. 비밀번호에 `/`가 들어오면
   * (`p/w@host`) 경계 판정이 무너져 `@`에 닿지 못하고, 그러면 **아무것도 가려지지 않는다** —
   * 예전 정규식 `\/\/[^@/]*@`이 정확히 그렇게 실패했다.
   */
  const cred = spec.lastIndexOf("@");
  if (cred < start) return spec;
  return `${spec.slice(0, start)}<자격증명>${spec.slice(cred)}`;
}

export async function openDatabase(spec: string): Promise<DbDriver> {
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(spec)?.[1]?.toLowerCase();
  switch (scheme) {
    case "postgres":
    case "postgresql":
      return (await import("./postgres.ts")).openPostgres(spec);
    case "mysql":
      return (await import("./mysql.ts")).openMysql(spec);
    case "sqlite":
    case "file":
      // `sqlite::memory:` 같은 형태도 받도록 스킴만 벗겨 넘긴다.
      return openSqlite(spec.slice(scheme.length + 1) || ":memory:");
    case undefined:
      return openSqlite(spec); // 스킴 없음 = 파일 경로(레거시 dbPath)
    default:
      throw new Error(`지원하지 않는 DB 스킴: ${scheme} (postgres|mysql|sqlite|file 또는 파일 경로)`);
  }
}
