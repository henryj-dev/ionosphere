/**
 * 콘솔 관리자 CLI — 첫 관리자 부트스트랩(docs/OPERATIONS.md §8) 절차를 서브프로세스로 고정한다.
 *
 * 지키는 것: 관리자 비밀번호는 **stdin/env로만** 들어간다(argv는 `ps`·셸 히스토리에 남는다).
 * 출력 어디에도 원문이 나오지 않고, 저장은 해시다.
 */
import { spawnSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { openSqlite } from "@ionosphere/db";

const here = dirname(fileURLToPath(import.meta.url));
const cli = join(here, "../src/cli.ts");
const PASSWORD = "bootstrap-admin-password";

let dir: string;
let dbPath: string;

function run(cliArgs: string[], stdin?: string): { stdout: string; stderr: string; code: number } {
  const p = spawnSync(process.execPath, [cli, ...cliArgs], {
    env: { ...process.env, IONOSPHERE_DB: dbPath, IONOSPHERE_BLOBS: join(dir, "blobs"), IONOSPHERE_CLI_SECRET: "" },
    ...(stdin !== undefined ? { input: stdin } : {}),
  });
  return { stdout: p.stdout?.toString() ?? "", stderr: p.stderr?.toString() ?? "", code: p.status ?? 0 };
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "ionosphere-admin-cli-"));
  dbPath = join(dir, "cli.db");
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("admin-user-create (CLI)", () => {
  test("비밀번호를 stdin으로 받아 첫 운영자를 만들고, 원문은 출력·DB 어디에도 없다", async () => {
    const res = run(["admin-user-create", "--username=Ops@ionosphere.test", "--role=owner"], PASSWORD + "\n");
    expect(res.code).toBe(0);
    expect(res.stdout).toContain("관리자 생성됨: ops@ionosphere.test");
    expect(res.stdout + res.stderr).not.toContain(PASSWORD);
    // 일회용 등록 코드가 한 번 출력된다 — 운영자가 본인에게 따로 전달한다.
    expect(res.stdout).toContain("TOTP 등록 코드");
    expect(res.stdout).toMatch(/[a-z]{4}-[a-z]{4}-[a-z]{4}-[a-z]{4}/);

    const db = await openSqlite(dbPath);
    const { rows } = await db.query({ sql: "SELECT username, role, tenant_id, password_hash FROM admin_users" });
    await db.close();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.username).toBe("ops@ionosphere.test");
    expect(rows[0]!.tenant_id).toBeNull();
    expect(String(rows[0]!.password_hash)).toStartWith("scrypt$");
    expect(String(rows[0]!.password_hash)).not.toContain(PASSWORD);
  });

  test("argv로 넘긴 비밀번호는 받되 경고한다(ps·히스토리 노출)", () => {
    const res = run(["admin-user-create", "--username=argv@ionosphere.test", "--role=admin", `--password=${PASSWORD}`]);
    expect(res.code).toBe(0);
    expect(res.stderr).toContain("argv로 받았다");
  });

  test("도움말은 비밀번호가 stdin 전용이라고 실제 동작대로 안내한다", () => {
    const res = run(["help", "admin-user-create"]);
    expect(res.stdout + res.stderr).toContain("--password\t비밀번호 (필수) ※ stdin 또는 환경변수로만 받는다");
  });
});
