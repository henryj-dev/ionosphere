/**
 * 스마트호스트 CLI(set/list/remove) — 서브프로세스로 부트스트랩부터 검증.
 *
 * 여기서 지키는 것은 **비밀 취급**이다: 토큰은 stdin/env로만 들어가고, 저장은 봉인된 형태이며,
 * 출력 어디에도 원문이 나오지 않아야 한다. 릴레이 토큰은 그 자체로 임의 발신 권한이라
 * 한 번 로그·스크롤백에 남으면 회수 전까지 계속 유효하다.
 */
import { spawnSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { open } from "@ionosphere/core";
import { openSqlite, SMARTHOST_TENANT_DEFAULT, SMARTHOST_TLS } from "@ionosphere/db";

const here = dirname(fileURLToPath(import.meta.url));
const cli = join(here, "../src/cli.ts");
const MASTER_KEY = "cli-master-key";
const TOKEN = "cfut_TESTONLY_not_a_real_token";

let dir: string;
let dbPath: string;

function run(cliArgs: string[], opts?: { stdin?: string; env?: Record<string, string> }): { stdout: string; stderr: string; code: number } {
  // ★`process.execPath`로 실행한다 — 러너와 **같은 node 바이너리**여야 버전 차이로 갈라지지
  // 않는다. 예전엔 `["bun", cli, ...]`로 bun을 직접 불렀는데, bun을 지운 뒤에는 그 자체가
  // 없는 명령이 된다. CLI는 `.ts`라 node 24+의 타입 스트리핑으로 그대로 실행된다.
  const p = spawnSync(process.execPath, [cli, ...cliArgs], {
    env: { ...process.env, IONOSPHERE_DB: dbPath, IONOSPHERE_BLOBS: join(dir, "blobs"), IONOSPHERE_MASTER_KEY: MASTER_KEY, ...opts?.env },
    // node는 stdin이 아니라 `input`으로 준다(string | Buffer).
    ...(opts?.stdin ? { input: opts.stdin } : {}),
  });
  return { stdout: p.stdout?.toString() ?? "", stderr: p.stderr?.toString() ?? "", code: p.status ?? 0 };
}

async function rows(): Promise<Record<string, unknown>[]> {
  const db = await openSqlite(dbPath);
  const { rows: r } = await db.query({ sql: "SELECT * FROM smarthosts ORDER BY domain", params: [] });
  await db.close();
  return r;
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "ionosphere-smarthost-cli-"));
  dbPath = join(dir, "cli.db");
  expect(run(["create-user", "u@ionosphere.test", "pw123"]).code).toBe(0);
  expect(run(["add-domain", "ionosphere.test"]).code).toBe(0);
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("set-smarthost", () => {
  test("--preset=cloudflare가 접속 파라미터를 채우고 토큰은 stdin으로 받는다", async () => {
    const res = run(["set-smarthost", "--preset=cloudflare", "--domain=ionosphere.test"], { stdin: TOKEN + "\n" });
    expect(res.code).toBe(0);

    const [row] = await rows();
    expect(row).toBeDefined();
    expect(row!.host).toBe("smtp.mx.cloudflare.net");
    expect(Number(row!.port)).toBe(465);
    expect(Number(row!.tls_mode)).toBe(SMARTHOST_TLS.implicit);
    expect(row!.username).toBe("api_token");
    expect(Number(row!.max_rcpts)).toBe(50);
    // 도메인 지정은 **그 도메인을 소유한 테넌트**에 붙어야 한다 — 아니면 해석기가 못 찾는다
    expect(row!.domain).toBe("ionosphere.test");
  });

  test("토큰은 봉인돼 저장되고 출력 어디에도 원문이 나오지 않는다", async () => {
    const res = run(["set-smarthost", "--preset=cloudflare", "--domain=ionosphere.test"], { stdin: TOKEN + "\n" });
    expect(res.stdout).not.toContain(TOKEN);
    expect(res.stderr).not.toContain(TOKEN);

    const [row] = await rows();
    const stored = String(row!.secret);
    expect(stored).not.toContain(TOKEN);
    // 봉인은 되돌릴 수 있어야 한다 — 저장만 하고 못 읽으면 발송이 통째로 막힌다
    expect(open(stored, MASTER_KEY)).toBe(TOKEN);
  });

  test("stdin의 개행은 토큰의 일부가 아니다 — 파이프로 넘길 때 조용히 인증이 깨지던 자리", async () => {
    run(["set-smarthost", "--preset=cloudflare", "--domain=ionosphere.test"], { stdin: `  ${TOKEN}\n` });
    const [row] = await rows();
    expect(open(String(row!.secret), MASTER_KEY)).toBe(TOKEN);
  });

  test("IONOSPHERE_SMARTHOST_SECRET 환경변수로도 받는다", async () => {
    const res = run(["set-smarthost", "--preset=cloudflare", "--domain=ionosphere.test"], { env: { IONOSPHERE_SMARTHOST_SECRET: TOKEN } });
    expect(res.code).toBe(0);
    const [row] = await rows();
    expect(open(String(row!.secret), MASTER_KEY)).toBe(TOKEN);
  });

  test("등록되지 않은 도메인은 거절한다 — 엉뚱한 테넌트에 붙는 것을 막는다", () => {
    const res = run(["set-smarthost", "--preset=cloudflare", "--domain=nope.test"], { stdin: TOKEN });
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("등록되지 않은 도메인");
  });

  test("알 수 없는 preset·tls는 거절한다", () => {
    expect(run(["set-smarthost", "--preset=sendgrid"], { stdin: TOKEN }).code).toBe(1);
    expect(run(["set-smarthost", "--host=h.test", "--tls=maybe"], { stdin: TOKEN }).code).toBe(1);
  });

  test("--domain 없이 부르면 테넌트 기본 범위로 들어간다", async () => {
    const res = run(["set-smarthost", "--host=relay.internal", "--tls=required", "--port=587"]);
    expect(res.code).toBe(0);
    const all = await rows();
    const def = all.find((r) => String(r.domain) === SMARTHOST_TENANT_DEFAULT);
    expect(def).toBeDefined();
    expect(def!.host).toBe("relay.internal");
    // 사용자명이 없으면 비밀도 없다 — stdin을 읽으려 멈춰서도 안 된다
    expect(def!.secret).toBeNull();
  });

  test("같은 범위에 다시 설정하면 덮어쓴다(범위당 하나)", async () => {
    run(["set-smarthost", "--host=first.test", "--tls=required"]);
    run(["set-smarthost", "--host=second.test", "--tls=required"]);
    const all = await rows();
    const defs = all.filter((r) => String(r.domain) === SMARTHOST_TENANT_DEFAULT);
    expect(defs).toHaveLength(1);
    expect(defs[0]!.host).toBe("second.test");
  });
});

describe("list-smarthosts / remove-smarthost", () => {
  test("목록은 비밀 존재 여부만 보여준다", () => {
    run(["set-smarthost", "--preset=cloudflare", "--domain=ionosphere.test"], { stdin: TOKEN });
    const res = run(["list-smarthosts"]);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain("smtp.mx.cloudflare.net:465");
    expect(res.stdout).toContain("secret=설정됨");
    expect(res.stdout).not.toContain(TOKEN);
  });

  test("remove는 지정 범위만 지운다", async () => {
    run(["set-smarthost", "--preset=cloudflare", "--domain=ionosphere.test"], { stdin: TOKEN });
    run(["set-smarthost", "--host=relay.internal", "--tls=required"]);

    expect(run(["remove-smarthost", "--domain=ionosphere.test"]).stdout).toContain("삭제됨");
    const all = await rows();
    expect(all.map((r) => r.domain)).toEqual([SMARTHOST_TENANT_DEFAULT]);

    expect(run(["remove-smarthost"]).stdout).toContain("삭제됨");
    expect(await rows()).toHaveLength(0);
    expect(run(["remove-smarthost"]).stdout).toContain("설정이 없습니다");
  });
});

/**
 * 마스터키 대조 — 틀린 키로 봉인해도 **쓰기는 성공하고**, 깨지는 건 나중에 서버가 열 때다.
 * 그때 증상이 "아웃바운드 전부 지연"이라 원인을 거슬러 올라가기 어렵다. 쓰기 전에 잡는다.
 * (릴레이 토큰을 IONOSPHERE_MASTER_KEY 자리에 넣는 실제 사고에서 나온 검사다.)
 */
describe("마스터키 대조", () => {
  test("이 DB의 DKIM 키를 못 여는 마스터키면 거부한다 — 봉인 후에는 늦다", async () => {
    const before = await rows();
    const res = run(["set-smarthost", "--preset=cloudflare", "--domain=ionosphere.test"], {
      stdin: TOKEN,
      env: { IONOSPHERE_MASTER_KEY: "cfut_wrong_key_looks_like_a_token" },
    });
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("IONOSPHERE_MASTER_KEY가 이 DB의 것과 다릅니다");
    // 힌트가 실제 실수(토큰을 마스터키 자리에 넣음)를 짚어야 한다
    expect(res.stderr).toContain("stdin");
    // 거부했으면 아무것도 쓰지 않았어야 한다
    expect(await rows()).toEqual(before);
  });

  test("올바른 마스터키는 그대로 통과한다", async () => {
    expect(run(["set-smarthost", "--preset=cloudflare", "--domain=ionosphere.test"], { stdin: TOKEN }).code).toBe(0);
  });
});

describe("도메인 오류 메시지", () => {
  test("어느 DB를 봤는지 알려 준다 — IONOSPHERE_DB가 다른 DB를 가리켜 생긴 혼선이 있었다", () => {
    const res = run(["set-smarthost", "--preset=cloudflare", "--domain=nope.test"], { stdin: TOKEN });
    expect(res.code).toBe(1);
    expect(res.stderr).toContain(dbPath);
    expect(res.stderr).toContain("IONOSPHERE_DB");
  });
});
