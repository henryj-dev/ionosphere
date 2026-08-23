/** 알리아스 CLI(add-alias/list-aliases/remove-alias) — 서브프로세스로 부트스트랩부터 검증. */
import { spawnSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ulid } from "@ionosphere/core";
import { openSqlite } from "@ionosphere/db";

const here = dirname(fileURLToPath(import.meta.url));
const cli = join(here, "../src/cli.ts");
let dir: string;
let dbPath: string;

function run(...cliArgs: string[]): { stdout: string; stderr: string; code: number } {
  // ★`process.execPath`로 실행한다 — 러너와 **같은 node 바이너리**여야 버전 차이로 갈라지지
  // 않는다. 예전엔 `["bun", cli, ...]`로 bun을 직접 불렀는데, bun을 지운 뒤에는 그 자체가
  // 없는 명령이 된다. CLI는 `.ts`라 node 24+의 타입 스트리핑으로 그대로 실행된다.
  const p = spawnSync(process.execPath, [cli, ...cliArgs], {
    env: { ...process.env, IONOSPHERE_DB: dbPath, IONOSPHERE_BLOBS: join(dir, "blobs") },
  });
  // node spawnSync는 status/stdout/stderr를 쓴다. 스폰 실패 시 null일 수 있어 방어한다.
  return { stdout: p.stdout?.toString() ?? "", stderr: p.stderr?.toString() ?? "", code: p.status ?? 0 };
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "ionosphere-cli-"));
  dbPath = join(dir, "cli.db");
  // 부트스트랩: 계정 + 도메인
  expect(run("create-user", "u@d.test", "pw123").code).toBe(0);
  expect(run("add-domain", "d.test").code).toBe(0);
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("알리아스 CLI", () => {
  test("add-alias: 로컬 계정 대상 → account 알리아스", () => {
    const r = run("add-alias", "info@d.test", "u@d.test");
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("계정 u@d.test");
  });

  test("add-alias: 외부 주소 대상 → forward_to", () => {
    const r = run("add-alias", "fwd@d.test", "ext@remote.test");
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("포워딩 ext@remote.test");
  });

  test("list-aliases: 둘 다 노출(account/forward 구분)", () => {
    const r = run("list-aliases", "d.test");
    expect(r.stdout).toContain("info@d.test\taccount:u@d.test");
    expect(r.stdout).toContain("fwd@d.test\tforward:ext@remote.test");
  });

  test("add-alias: 로컬 계정 여러 개 → 팬아웃(한 주소가 계정 N개를 가리킨다)", () => {
    expect(run("create-user", "u2@d.test", "pw123").code).toBe(0);
    const r = run("add-alias", "team@d.test", "u@d.test", "u2@d.test");
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("계정 u@d.test, u2@d.test");

    const listed = run("list-aliases", "d.test").stdout;
    expect(listed).toContain("team@d.test\taccount:u2@d.test,u@d.test"); // 목록은 이메일 정렬
  });

  test("add-alias: 로컬 + 외부를 섞으면 둘 다 대상이 된다", () => {
    const r = run("add-alias", "both@d.test", "u@d.test", "ext2@remote.test");
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("계정 u@d.test");
    expect(r.stdout).toContain("포워딩 ext2@remote.test");
  });

  test("중복 알리아스 → 실패(비0 종료)", () => {
    expect(run("add-alias", "info@d.test", "u@d.test").code).not.toBe(0);
  });

  /**
   * 배달 경로는 MAX_RELAY_TARGETS 초과 시 fail closed로 **아무것도** 릴레이하지 않는다.
   * 생성 시 막지 않으면 설정은 받아들여졌는데 그 주소로 온 메일이 영구 451 루프에 빠진다.
   */
  test("add-alias: 포워딩 대상이 상한을 넘으면 거절(배달 시점 무음 실패 방지)", () => {
    const r = run("add-alias", "many@d.test", "a@x.test", "b@x.test", "c@x.test", "d@x.test", "e@x.test");
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain("포워딩 대상은 최대");
  });

  /**
   * getAccountByEmail은 전역 조회다. REST(createAlias)는 대상마다 tenant_id를 대조하는데
   * CLI에만 그 검사가 없어서, 오타 하나로 타 테넌트 계정에 배달되는 알리아스가 만들어졌다.
   */
  test("add-alias: 타 테넌트 계정을 대상으로 지정하면 거절", async () => {
    // CLI create-user는 공용 기본 테넌트를 쓰므로(defaultTenantId) 다른 테넌트 계정은
    // 직접 심어야 재현된다 — 멀티테넌트 배포에서 REST로 만들어진 계정에 해당한다.
    const db = await openSqlite(dbPath);
    try {
      const now = Date.now();
      const otherTenant = ulid();
      await db.batch([
        { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?, 'other', 1, ?)", params: [otherTenant, now] },
        {
          sql: "INSERT INTO accounts (id, tenant_id, email, status, uidvalidity_last, created_at) VALUES (?, ?, 'other@other.test', 1, 1, ?)",
          params: [ulid(), otherTenant, now],
        },
      ]);
    } finally {
      await db.close();
    }

    const r = run("add-alias", "x@d.test", "other@other.test");
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain("테넌트 소속이 아니다");
  });

  test("미등록 도메인 → 실패", () => {
    expect(run("add-alias", "x@nope.test", "u@d.test").code).not.toBe(0);
  });

  test("remove-alias: 삭제 후 list에서 사라짐", () => {
    expect(run("remove-alias", "fwd@d.test").stdout).toContain("삭제됨");
    expect(run("list-aliases", "d.test").stdout).not.toContain("fwd@d.test");
    // 없는 알리아스 삭제 → 대상 없음
    expect(run("remove-alias", "ghost@d.test").stdout).toContain("대상 없음");
  });
});
