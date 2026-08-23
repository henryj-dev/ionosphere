/**
 * 관리 콘솔 — **무상태 스키마 구동**이 실제로 성립하는지.
 *
 * 여기서 지키려는 것은 하나다: **명령을 추가하면 화면이 따라온다.** 그 반대 상태가 이 저장소의
 * 반복 사고였다 — API에 기능이 생겨도 화면은 하드코딩이라 뒤처졌고, 계정 정지가 자동 집행에는
 * 있는데 사람이 쓸 입구는 없던 것이 그 결과다(콘솔이 "정지를 쓰세요(현재 콘솔에는 정지 버튼이
 * 없습니다)"라고 스스로 적어 두고 있었다).
 *
 * ★브라우저 없이 확인하는 방법: 콘솔이 그리는 근거는 `/v1/commands`의 서술뿐이므로, **서술이
 * 화면에 필요한 것을 다 담고 있는지**를 검사하면 렌더링 결과를 검사한 것과 같은 값을 얻는다.
 * (실제 렌더링은 개발 중 브라우저로 확인했지만, 그건 재현되지 않으므로 테스트가 아니다.)
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { Store } from "@ionosphere/store";
import { AdminApiServer } from "../src/server.ts";

const ROOT = "root-console-test-token";

let servers: AdminApiServer[] = [];
let dbs: DbDriver[] = [];
afterEach(async () => {
  await Promise.all(servers.map((s) => s.close()));
  await Promise.all(dbs.map((d) => d.close()));
  servers = [];
  dbs = [];
});

async function setup(): Promise<{ baseUrl: string }> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  dbs.push(db);
  const server = new AdminApiServer({
    db,
    store: new Store(db),
    resolveTxt: async () => [],
    resolveMx: async () => [],
    rootToken: ROOT,
  });
  servers.push(server);
  const port = await server.listen(0, "127.0.0.1");
  return { baseUrl: `http://127.0.0.1:${port}` };
}

const auth = { authorization: `Bearer ${ROOT}`, "content-type": "application/json" };

interface Spec {
  name: string;
  group: string;
  label: string;
  summary: string;
  readOnly: boolean;
  destructive?: boolean;
  irreversible?: boolean;
  rootOnly?: boolean;
  args: { name: string; label: string; type: string; required: boolean; choices?: { value: string }[] }[];
  fields?: { key: string; label: string }[];
}

async function commands(baseUrl: string): Promise<Spec[]> {
  const res = await fetch(`${baseUrl}/v1/commands`, { headers: auth });
  expect(res.status).toBe(200);
  return ((await res.json()) as { commands: Spec[] }).commands;
}

async function call(baseUrl: string, name: string, args: Record<string, unknown>): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(`${baseUrl}/v1/commands/${encodeURIComponent(name)}`, {
    method: "POST",
    headers: auth,
    body: JSON.stringify(args),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe("관리 콘솔 — 스키마 구동", () => {
  test("★화면은 명령 목록·인코딩 말고는 아무것도 하드코딩하지 않는다", async () => {
    const { baseUrl } = await setup();
    const html = await (await fetch(`${baseUrl}/admin`)).text();
    const script = html.slice(html.indexOf("<script>") + 8, html.lastIndexOf("</script>"));

    // 서술을 받아 오는 배선과, 명령을 이름으로 부르는 입구.
    expect(script).toContain('api("GET", "/v1/commands")');
    expect(script).toContain('"/v1/commands/" + encodeURIComponent(name)');

    /**
     * ★탭·컬럼·명령 이름이 화면에 박혀 있으면 안 된다. 박히는 순간 "서버에는 있는데 화면에는
     * 없는" 갈래가 다시 생긴다. 대표적인 것들이 없는지 본다(전수 검사는 과하고 깨지기 쉽다).
     *
     * **주석은 제외하고 검사한다** — 설계 의도를 적으면서 예시로 명령 이름을 드는 것은
     * 하드코딩이 아니다. 지우게 하면 "왜 이렇게 만들었는지"가 사라져 더 나쁜 거래가 된다.
     */
    const code = script.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
    for (const hardcoded of ["account-suspend", "domain-release", "queue-retry", "smarthost-set"]) {
      expect(code.includes(hardcoded)).toBe(false);
    }
  });

  test("★모든 명령이 화면을 그릴 만큼 자기를 서술한다", async () => {
    const { baseUrl } = await setup();
    const list = await commands(baseUrl);
    expect(list.length).toBeGreaterThan(20);

    for (const c of list) {
      // 라벨·요약이 없으면 화면에 이름(영문 슬러그)이 그대로 노출된다.
      expect(c.label.length).toBeGreaterThan(0);
      expect(c.summary.length).toBeGreaterThan(0);
      expect(c.group.length).toBeGreaterThan(0);
      for (const a of c.args) {
        expect(a.label.length).toBeGreaterThan(0);
        // enum은 선택지가 있어야 select를 그린다 — 없으면 자유 입력이 되어 오타가 통과한다.
        if (a.type === "enum") expect((a.choices ?? []).length).toBeGreaterThan(0);
      }
      // 조회 명령은 컬럼 서술이 있어야 표가 사람이 읽는 형태로 그려진다(단일 객체 결과는 예외).
      if (c.readOnly && !["usage", "tls-status"].includes(c.name)) {
        expect((c.fields ?? []).length).toBeGreaterThan(0);
      }
    }
  });

  test("★파괴적 명령은 그렇게 표시된다 — 화면의 2단계 확인이 여기서 나온다", async () => {
    const { baseUrl } = await setup();
    const byName = new Map((await commands(baseUrl)).map((c) => [c.name, c]));

    // 되돌릴 수 없는 것들은 둘 다 표시돼야 한다(화면이 빨간 버튼 + 경고문을 그린다).
    for (const name of ["account-delete", "domain-release", "credential-revoke", "api-key-revoke"]) {
      expect(byName.get(name)?.destructive).toBe(true);
      expect(byName.get(name)?.irreversible).toBe(true);
    }
    /**
     * ★정지는 파괴적이지만 **되돌릴 수 있다**. 이 구분이 화면에 드러나야 운영자가
     * "잠시 막기"와 "삭제"를 혼동하지 않는다 — 예전 콘솔이 0(정지)을 "대기", 2(삭제 드레인)를
     * "비활성"으로 표시해 되돌릴 수 없는 삭제를 누르게 하던 사고가 정확히 그 혼동이었다.
     */
    expect(byName.get("account-suspend")?.destructive).toBe(true);
    expect(byName.get("account-suspend")?.irreversible).toBeUndefined();
    // 재활성은 파괴적이지 않다 — 확인 단계 없이 바로 눌러야 한다(복구는 급한 일이다).
    expect(byName.get("account-activate")?.destructive).toBeUndefined();
  });

  test("★행 버튼이 자동으로 생긴다 — 인자 1개짜리 변경 명령 + 표 컬럼", async () => {
    const { baseUrl } = await setup();
    const list = await commands(baseUrl);

    /**
     * 화면 규칙: 같은 그룹의 변경 명령 중 **인자가 하나**이고 그 값을 행에서 채울 수 있으면
     * 행 버튼이 된다. 그 규칙이 성립하는지를 서술만으로 확인한다 — 계정 표의 `email`/`id`가
     * `account` 인자를 채울 수 있어야 정지·삭제 버튼이 나타난다.
     */
    const accountList = list.find((c) => c.name === "account-list")!;
    const cols = new Set((accountList.fields ?? []).map((f) => f.key));
    expect(cols.has("email")).toBe(true);
    expect(cols.has("id")).toBe(true);

    const rowCmds = list.filter((c) => c.group === "계정" && !c.readOnly && c.args.length === 1);
    const names = rowCmds.map((c) => c.name);
    expect(names).toContain("account-suspend");
    expect(names).toContain("account-activate");
    expect(names).toContain("account-delete");
    // 그 유일한 인자는 `account` — 화면이 행의 email/id로 채운다.
    expect(rowCmds.find((c) => c.name === "account-suspend")?.args[0]?.name).toBe("account");
  });

  test("★평문 시크릿은 일반 결과와 분리돼 온다 — 표에 섞이면 안 된다", async () => {
    const { baseUrl } = await setup();
    const { body: t } = await call(baseUrl, "tenant-create", { name: "console-demo" });
    const tenantId = (t.data as { tenantId: string }).tenantId;

    const key = await call(baseUrl, "api-key-create", { tenantId, label: "gui" });
    expect(key.status).toBe(200);
    /**
     * 서버는 해시만 보관하므로 이 응답이 유일한 노출 지점이다. `data`에 섞으면 화면이 그것을
     * 일반 값처럼 표에 찍고, 로그·감사에서 걸러낼 수도 없다.
     */
    const secret = key.body.__secret as { label: string; value: string };
    expect(secret.value.startsWith("amk_")).toBe(true);
    expect(JSON.stringify(key.body.data)).not.toContain(secret.value);
  });

  test("★조회는 rows, 변경은 data — 화면이 결과 모양을 추측하지 않는다", async () => {
    const { baseUrl } = await setup();
    const { body: t } = await call(baseUrl, "tenant-create", { name: "shape-demo" });
    const tenantId = (t.data as { tenantId: string }).tenantId;

    const listed = await call(baseUrl, "account-list", { tenantId });
    expect(Array.isArray(listed.body.rows)).toBe(true);

    const added = await call(baseUrl, "domain-add", { tenantId, name: "shape.test", preVerified: "true" });
    expect(added.status).toBe(200);
    expect(added.body.data).toBeDefined();
    expect(added.body.message).toBeTruthy(); // 화면이 토스트로 띄운다
  });

  test("★새 기능이 화면에 나타난다 — 이전에 API에도 없던 것들", async () => {
    const { baseUrl } = await setup();
    const names = (await commands(baseUrl)).map((c) => c.name);
    /**
     * 이것들이 목록에 있다는 것은 **콘솔에도 있다는 뜻**이다(화면은 이 목록으로 그린다).
     * 전부 예전에는 API에도 없어서 DB를 직접 만지거나 SSH가 필요하던 것들이다.
     */
    for (const added of [
      "account-suspend", // 되돌릴 수 없는 삭제뿐이던 자리
      "account-activate",
      "domain-disable", // DOMAIN_STATUS.disabled를 세팅하는 코드가 0건이었다
      "domain-enable",
      "queue-retry", // 큐는 조회만 가능했다
      "queue-cancel",
      "smarthost-set", // CLI에만 있었다
      "smarthost-list",
      "smarthost-remove",
      "tenant-list", // 생성만 있고 조회가 없었다
      "oauth-token-create", // CLI에만 있었다
    ]) {
      expect(names).toContain(added);
    }
  });

  test("계정 정지 → 재활성 왕복이 명령 입구로 동작한다", async () => {
    const { baseUrl } = await setup();
    const { body: t } = await call(baseUrl, "tenant-create", { name: "cycle-demo" });
    const tenantId = (t.data as { tenantId: string }).tenantId;
    await call(baseUrl, "domain-add", { tenantId, name: "cycle.test", preVerified: "true" });
    await call(baseUrl, "account-create", { tenantId, email: "bob@cycle.test", password: "pw123456" });

    const suspended = await call(baseUrl, "account-suspend", { tenantId, account: "bob@cycle.test" });
    expect(suspended.status).toBe(200);
    expect((suspended.body.data as { status: number }).status).toBe(0); // ACCOUNT_STATUS.suspended

    const activated = await call(baseUrl, "account-activate", { tenantId, account: "bob@cycle.test" });
    expect(activated.status).toBe(200);
    expect((activated.body.data as { status: number }).status).toBe(1);

    /**
     * ★삭제된 계정은 되살릴 수 없다 — 화면이 "정지"와 "삭제"를 혼동하게 두면 안 되는 이유다.
     * 삭제 드레인은 편도이고 리퍼가 이미 메일함·자격증명을 지웠다.
     */
    await call(baseUrl, "account-delete", { tenantId, account: "bob@cycle.test" });
    const revive = await call(baseUrl, "account-activate", { tenantId, account: "bob@cycle.test" });
    expect(revive.status).toBe(409);
  });
});
