import { BatchConflictError, type DbDriver } from "./types.ts";

/**
 * 마이그레이션 규율 (SCHEMA.md §9-4):
 * - D1은 트랜잭셔널 DDL이 없으므로 문장 단위 멱등(IF NOT EXISTS 등)으로 작성하고,
 *   러너는 실패 지점부터 재개한다 (버전 기록은 해당 버전의 전 문장 성공 후).
 * - 버전은 단조 증가 정수. 적용된 버전의 statements는 절대 수정 금지 — 새 버전 추가만.
 */
export interface Migration {
  version: number;
  name: string;
  statements: readonly string[];
}

const MIGRATIONS_TABLE = `CREATE TABLE IF NOT EXISTS schema_migrations (
  version    BIGINT PRIMARY KEY,
  name       VARCHAR(190) NOT NULL,
  applied_at BIGINT NOT NULL
)`;

/**
 * 마이그레이션 배타 락 테이블.
 *
 * 왜 필요한가: 러너에 락이 없으면 **두 서버가 동시에 부팅할 때 둘 다 pending을 보고 DDL을 돌린다.**
 * 003처럼 `CREATE TABLE …_rebuild` → `INSERT SELECT` → `DROP TABLE` → `RENAME` 패턴이 겹치면
 * 한쪽이 원본을 DROP한 사이 다른 쪽이 그 원본을 읽어 **데이터가 사라질 수 있다**.
 * 서버를 역할별로 분리하는 순간 동시 부팅은 예외가 아니라 기본값이 된다.
 *
 * PostgreSQL의 advisory lock 같은 방언 전용 기능을 쓰지 않는 이유: 이 저장소는 SQLite/PG/MySQL/D1을
 * 같은 코드로 지원하고, 다이얼렉트 분기는 봉인 대상이다. PK 충돌은 네 방언 모두에서 동일하게 원자적이다.
 */
const LOCK_TABLE = `CREATE TABLE IF NOT EXISTS schema_lock (
  id          VARCHAR(16) PRIMARY KEY,
  owner       VARCHAR(64) NOT NULL,
  acquired_at BIGINT NOT NULL
)`;

const LOCK_ID = "migrate";

export interface MigrateOptions {
  /** 락 소유자 식별자(진단·해제 가드용). 기본: 임의 문자열. */
  owner?: string;
  /** 락 대기 상한(ms). 초과 시 예외 — 무한 대기로 부팅이 매달리는 것보다 낫다. 기본 60초. */
  waitMs?: number;
  /** 이 시간이 지난 락은 죽은 프로세스의 것으로 보고 뺏는다(ms). 기본 5분. */
  staleMs?: number;
  /** 대기 폴링 간격(ms). 기본 250. */
  pollMs?: number;
}

const DEFAULT_WAIT_MS = 60_000;
/** 마이그레이션이 이보다 오래 걸리면 락을 뺏긴다 — 대형 재빌드가 있으면 늘릴 것. */
const DEFAULT_STALE_MS = 5 * 60_000;
const DEFAULT_POLL_MS = 250;

/**
 * `CREATE TABLE IF NOT EXISTS`를 **동시 실행 안전하게** 수행한다.
 *
 * ⚠ PostgreSQL에서 `IF NOT EXISTS`는 동시성 안전이 아니다 — 두 세션이 동시에 존재 검사를 통과한 뒤
 * 한쪽이 `pg_type_typname_nsp_index` 유니크 위반(23505)으로 실패한다. 공식 문서도 이 경합을 인정한다.
 * 실측(PG 16, 커넥션 4개 동시 부팅): **3개가 여기서 터져 기동 실패**했다. 락을 잡기도 전이라
 * 락으로는 막을 수 없다.
 *
 * 제약 위반을 삼켜도 되는 이유: 이 함수의 사후조건은 "테이블이 존재한다"인데, 경합에서 졌다는 건
 * **상대가 만들었다는 뜻**이라 사후조건이 이미 성립한다. 다른 종류의 오류는 그대로 던진다.
 */
async function ensureTable(db: DbDriver, sql: string): Promise<void> {
  try {
    await db.batch([{ sql }]);
  } catch (err) {
    if (!(err instanceof BatchConflictError)) throw err;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function randomOwner(): string {
  return `${process.pid}-${Math.floor(Date.now() % 1e6)}-${Math.floor(Math.random() * 1e6)}`;
}

/**
 * 락 획득 시도 — 성공 시 true.
 *
 * 두 갈래 모두 **단일 문장 check-and-set**이라 프로세스 간 원자적이다:
 *  ① 락 행이 없으면 INSERT (PK 충돌 = 패배)
 *  ② 있으면 stale일 때만 뺏는 가드된 UPDATE (영향 행 수 = 승인 신호, §9-4 규율)
 */
async function tryAcquire(db: DbDriver, owner: string, now: number, staleMs: number): Promise<boolean> {
  try {
    await db.batch([
      { sql: "INSERT INTO schema_lock (id, owner, acquired_at) VALUES (?, ?, ?)", params: [LOCK_ID, owner, now] },
    ]);
    return true;
  } catch (err) {
    if (!(err instanceof BatchConflictError)) throw err;
  }
  const [res] = await db.batch([
    {
      sql: "UPDATE schema_lock SET owner = ?, acquired_at = ? WHERE id = ? AND acquired_at < ?",
      params: [owner, now, LOCK_ID, now - staleMs],
    },
  ]);
  return (res?.changes ?? 0) === 1;
}

/** 락 해제 — **자기가 잡은 락만** 푼다(뺏긴 뒤에 푸는 사고 방지). */
async function release(db: DbDriver, owner: string): Promise<void> {
  await db.batch([{ sql: "DELETE FROM schema_lock WHERE id = ? AND owner = ?", params: [LOCK_ID, owner] }]);
}

/**
 * 리스 갱신 — **자기 락일 때만** acquired_at을 밀어 준다. 영향 행 수 0이면 이미 뺏긴 것이다.
 *
 * 왜 필요한가: staleMs(기본 5분)는 "죽은 프로세스의 락을 뺏는" 장치인데, 갱신이 없으면
 * **살아서 마이그레이션을 돌리는 중인 프로세스의 락도 5분이 지나면 뺏긴다.** 그러면 락이
 * 막으려던 바로 그 상황(동시 DDL)이 벌어진다 — 003·006처럼 `DROP` + `RENAME`을 쓰는
 * 재빌드가 겹치면 한쪽이 원본을 DROP한 사이 다른 쪽이 그 원본을 읽어 **데이터가 사라진다.**
 * 대형 재빌드일수록 위험이 커지는 구조라 시간이 아니라 생존 신호로 판정해야 한다.
 */
async function renew(db: DbDriver, owner: string, now: number): Promise<boolean> {
  const [res] = await db.batch([
    { sql: "UPDATE schema_lock SET acquired_at = ? WHERE id = ? AND owner = ?", params: [now, LOCK_ID, owner] },
  ]);
  return (res?.changes ?? 0) === 1;
}

/** 아직 적용되지 않은 마이그레이션 목록(버전 순). */
async function pendingOf(db: DbDriver, migrations: readonly Migration[]): Promise<Migration[]> {
  const { rows } = await db.query({ sql: "SELECT version FROM schema_migrations" });
  const applied = new Set(rows.map((r) => Number(r.version)));
  return [...migrations].sort((a, b) => a.version - b.version).filter((m) => !applied.has(m.version));
}

/**
 * 적용된 버전 수를 반환. **배타 락 아래에서 실행**되므로 여러 인스턴스가 동시에 불러도 안전하다.
 *
 * 대기 측은 락을 얻은 뒤 pending을 **다시 읽는다** — 그 사이 승자가 전부 적용했다면 0을 반환한다.
 * (락을 기다리는 동안 자기가 처음 읽은 pending 목록은 이미 낡았다는 뜻이다.)
 */
export async function migrate(
  db: DbDriver,
  migrations: readonly Migration[],
  opts: MigrateOptions = {},
): Promise<number> {
  await ensureTable(db, MIGRATIONS_TABLE);
  await ensureTable(db, LOCK_TABLE);

  // 적용할 게 없으면 락을 잡지 않는다 — 정상 재기동(대부분의 부팅)이 서로를 기다리지 않게 한다.
  if ((await pendingOf(db, migrations)).length === 0) return 0;

  const owner = opts.owner ?? randomOwner();
  const waitMs = opts.waitMs ?? DEFAULT_WAIT_MS;
  const staleMs = opts.staleMs ?? DEFAULT_STALE_MS;
  const pollMs = opts.pollMs ?? DEFAULT_POLL_MS;

  const deadline = Date.now() + waitMs;
  let acquired = false;
  for (;;) {
    acquired = await tryAcquire(db, owner, Date.now(), staleMs);
    if (acquired) break;
    if (Date.now() >= deadline) {
      throw new Error(
        `마이그레이션 락 획득 실패(${waitMs}ms 대기) — 다른 인스턴스가 적용 중이거나 락이 남아 있다. ` +
          `schema_lock 테이블을 확인할 것.`,
      );
    }
    await sleep(pollMs);
  }

  /**
   * 리스 하트비트 — staleMs의 1/3 주기로 갱신한다(한두 번 놓쳐도 뺏기지 않을 여유).
   * 타이머는 호출자(여기)가 소유하고 finally에서 반드시 끈다.
   *
   * ⚠ 한계: 타이머는 이벤트 루프가 돌아야 뛴다. **SQLite 드라이버는 동기**라 오래 걸리는 DDL
   * 하나가 루프를 통째로 막으면 그동안 갱신이 안 된다. 다만 SQLite는 애초에 다중 프로세스
   * 구성을 지원하지 않으므로(open.ts) 락 경합 자체가 없다 — 이 하트비트가 실제로 필요한
   * PostgreSQL·MySQL은 드라이버가 비동기라 정상 동작한다.
   */
  const renewEvery = Math.max(50, Math.floor(staleMs / 3));
  const heartbeat = setInterval(() => {
    void renew(db, owner, Date.now()).then(
      (held) => {
        if (!held) {
          // 이미 뺏겼다 — 여기서 할 수 있는 건 흔적을 남기는 것뿐이다(진행 중 DDL은 못 되돌린다).
          process.stderr.write("[db:migrate] ⚠ 마이그레이션 락을 잃었다 — 다른 인스턴스와 동시 실행 중일 수 있다\n");
        }
      },
      () => {
        /* 일시적 DB 오류 — 다음 주기에 다시 시도 */
      },
    );
  }, renewEvery);
  heartbeat.unref?.();

  try {
    // 락을 기다리는 사이 승자가 적용했을 수 있으므로 반드시 다시 읽는다.
    const pending = await pendingOf(db, migrations);
    for (const m of pending) {
      for (const sql of m.statements) {
        await db.batch([{ sql }]); // 문장 단위 — 멱등 DDL 전제
      }
      await db.batch([
        {
          sql: "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
          params: [m.version, m.name, Date.now()],
        },
      ]);
    }
    return pending.length;
  } finally {
    clearInterval(heartbeat);
    await release(db, owner);
  }
}
