/**
 * 관리 CLI — **명령 계층(@ionosphere/admin-cmd) 위의 얇은 argv 어댑터.**
 *
 * 사용법:
 *   node apps/server/src/cli.ts <명령> [--key=value ...]
 *   node apps/server/src/cli.ts help            # 전체 명령 목록
 *   node apps/server/src/cli.ts help <명령>      # 그 명령의 인자
 *
 * 환경: IONOSPHERE_DB_URL(연결 문자열, 우선) 또는 IONOSPHERE_DB(파일 경로, 기본 ionosphere.db),
 *       IONOSPHERE_MASTER_KEY(DKIM·릴레이 비밀 봉인 — 미설정 시 평문 경고),
 *       IONOSPHERE_TENANT(대상 테넌트 id — 미지정 시 'default' 테넌트를 쓰거나 만든다)
 *
 * ★이 파일이 하는 일은 넷뿐이다: ① argv 파싱 ② 비밀값을 stdin/env로 받기 ③ 명령 호출
 * ④ 사람이 읽는 출력. **DB를 직접 만지지 않는다.**
 *
 * 왜 이렇게 바뀌었나: 예전에는 여기에 15개 명령의 SQL이 직접 있었고 REST API에도 같은 일을
 * 하는 핸들러가 따로 있었다. 그래서 둘이 갈라졌다 — CLI로 만든 도메인은 `verify_token`이
 * 없어 나중에 API로 재검증할 수 없었고(옛 주석이 증언한다), 알리아스 생성의 테넌트 사슬
 * 검사는 REST에만 있어 CLI로는 **타 테넌트 계정에 배달되는 알리아스**를 만들 수 있었다.
 * 이제 두 표면이 같은 명령을 부르므로 그런 비대칭이 생길 자리가 없다.
 *
 * ★DB 선택은 **서버(main.ts)와 같은 규칙**이다: IONOSPHERE_DB_URL이 있으면 그것, 없으면 IONOSPHERE_DB.
 * 예전엔 CLI만 `openSqlite`를 직접 불러서, PG로 운영하면 연결 문자열을 SQLite 파일 이름으로
 * 열려다 죽었다. 두 곳이 다른 규칙을 쓰면 운영자가 "서버는 PG를 보는데 CLI는 빈 SQLite를 본다"를
 * 눈치채지 못한다 — `list-users`가 조용히 "계정 없음"을 찍는 것이 그 증상이다.
 *
 * 주의: SQLite는 단일 라이터 전제(SCHEMA §3-3) — 서버 실행 중엔 쓰기 명령을 피할 것.
 * (PG/MySQL은 해당 없음 — 서버와 동시 사용이 정상이다.)
 */
import {
  CommandError,
  createRegistry,
  labelFor,
  runCommand,
  usageOf,
  type CommandContext,
  type CommandSpec,
  type FieldSpec,
} from "@ionosphere/admin-cmd";
import { allMigrations, describeDbSpec, migrate, openDatabase } from "@ionosphere/db";
import { SMARTHOST_PRESETS } from "./smarthost.ts";
import { Store } from "@ionosphere/store";
import { applyLegacyEnvAliases } from "@ionosphere/core";
// ★구 `IONOSPHERE_*` env를 새 이름으로 넘긴다 — env를 처음 읽기 전에(packages/core/src/env-legacy.ts).
applyLegacyEnvAliases();

/** 서버와 동일한 우선순위 — URL이 있으면 그것, 없으면 파일 경로(레거시). */
const dbSpec = process.env.IONOSPHERE_DB_URL ?? process.env.IONOSPHERE_DB ?? "ionosphere.db";
/** 진단 메시지용 표시값 — 마스킹 정본은 `@ionosphere/db`가 소유한다(형식을 아는 곳이 거기다). */
const dbPath = describeDbSpec(dbSpec);
const [cmdName, ...argv] = process.argv.slice(2);

const registry = createRegistry();

/**
 * 옛 명령 이름 → 새 이름.
 *
 * ★이름을 그냥 바꾸면 **운영 문서와 라이브 절차가 전부 깨진다.** README·docs/STATUS.md의
 * 복붙 가능한 명령들, `scripts/imaptest-local.sh`, 그리고 사람의 손에 익은 것들이 여기 걸린다.
 * 이 리팩터링은 내부 구조 변경이므로 밖에서 보이는 것이 바뀌면 안 된다 — REST 경로를 그대로
 * 둔 것과 같은 이유다.
 *
 * 새 이름을 쓰는 쪽이 정본이고(그룹-동사 규칙: `account-create`), 옛 이름은 계속 동작한다.
 */
const ALIASES: Readonly<Record<string, string>> = {
  "create-user": "account-create",
  "list-users": "account-list",
  "add-domain": "domain-add",
  "add-alias": "alias-add",
  "list-aliases": "alias-list",
  "remove-alias": "alias-remove",
  "add-app-password": "app-password-create",
  "list-app-passwords": "app-password-list",
  "revoke-app-password": "credential-revoke",
  "revoke-credential": "credential-revoke",
  "add-oauth-token": "oauth-token-create",
  "list-oauth-tokens": "oauth-token-list",
  "set-smarthost": "smarthost-set",
  "list-smarthosts": "smarthost-list",
  "remove-smarthost": "smarthost-remove",
};

/**
 * **argv로 절대 받지 않는** 인자 이름.
 *
 * argv는 같은 호스트의 다른 사용자에게 `ps`로 보이고 셸 히스토리에도 남는다. 여기 있는 값들은
 * 그 자체로 권한이고(릴레이 토큰 = 임의 발신, TLS 개인키 = 신원 위장) 한 번 노출되면 회수
 * 전까지 유효하다. 반면 계정 비밀번호는 원래 CLI가 argv로 받아 왔고 README·스크립트가 그
 * 형태라 여기 넣지 않는다 — **위험의 크기가 다르므로 규칙도 다르다.**
 */
const STDIN_ONLY: Readonly<Record<string, readonly string[]>> = {
  "smarthost-set": ["password"], // 릴레이 토큰
  "tls-upload": ["key"], // TLS 개인키
};
const stdinOnly = (command: string, arg: string): boolean => (STDIN_ONLY[command] ?? []).includes(arg);

/** `--k=v` 형태 플래그 파싱 — 값에 `=`가 들어갈 수 있으므로 첫 `=`만 자른다. */
function parseFlags(args: readonly string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const a of args) {
    if (!a.startsWith("--")) continue;
    const eq = a.indexOf("=");
    if (eq < 0) {
      out[a.slice(2)] = "true"; // `--preVerified` 같은 불리언 플래그
      continue;
    }
    out[a.slice(2, eq)] = a.slice(eq + 1);
  }
  return out;
}

/** `--`로 시작하지 않는 인자들 — 순서대로 필수 인자에 채운다(예: `create-user a@b pw`). */
function positional(args: readonly string[]): string[] {
  return args.filter((a) => !a.startsWith("--"));
}

/**
 * 비밀값을 읽는다 — **argv로는 받지 않는다.**
 *
 * argv는 같은 호스트의 다른 사용자에게 `ps`로 그대로 보이고 셸 히스토리 파일에도 남는다.
 * 릴레이 토큰·비밀번호는 그 자체로 권한이라 한 번 노출되면 회수 전까지 계속 유효하다.
 * env 또는 stdin만 받는다.
 */
async function readSecret(argName: string): Promise<string> {
  const fromEnv = process.env.IONOSPHERE_SMARTHOST_SECRET ?? process.env.IONOSPHERE_CLI_SECRET;
  if (fromEnv) return fromEnv;
  // 대화형이면 왜 멈춰 있는지 알려 준다 — 안내가 없으면 그냥 먹통으로 보인다.
  if (process.stdin.isTTY) console.error(`${argName}을(를) 입력하고 Ctrl-D를 누르십시오(화면에 표시되지 않습니다):`);
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(Buffer.from(c));
  // 파이프로 넘길 때 붙는 개행을 떼지 않으면 그대로 비밀번호의 일부가 된다.
  return Buffer.concat(chunks).toString("utf8").trim();
}

function printUsage(spec: CommandSpec): void {
  console.error(`사용법: ${usageOf(spec)}`);
  console.error(`  ${spec.summary}`);
  for (const a of spec.args) {
    const req = a.required ? "필수" : "선택";
    const extra = a.type === "secret" ? " ※ stdin 또는 환경변수로만 받는다" : "";
    console.error(`  --${a.name}\t${a.label} (${req})${extra}`);
    if (a.help) console.error(`      ${a.help}`);
    if (a.choices) console.error(`      가능: ${a.choices.map((c) => c.value).join(" | ")}`);
  }
}

function printHelp(): void {
  console.error("사용법: cli.ts <명령> [--key=value ...]\n");
  let group = "";
  for (const c of registry.list()) {
    if (c.spec.group !== group) {
      group = c.spec.group;
      console.error(`\n[${group}]`);
    }
    const mark = c.spec.irreversible ? " ⚠되돌릴 수 없음" : c.spec.destructive ? " ⚠파괴적" : "";
    console.error(`  ${c.spec.name.padEnd(22)} ${c.spec.summary}${mark}`);
  }
  console.error("\n자세히: cli.ts help <명령>");
}

if (!cmdName || cmdName === "help" || cmdName === "--help" || cmdName === "-h") {
  const target = argv[0] ?? positional(argv)[0];
  const spec = target ? registry.get(target)?.spec : undefined;
  if (spec) printUsage(spec);
  else printHelp();
  process.exit(cmdName ? 0 : 1);
}

/** 옛 이름으로 불렀으면 새 이름으로 옮긴다(위 ALIASES 주석). */
const resolvedName = ALIASES[cmdName] ?? cmdName;
const cmd = registry.get(resolvedName);
if (!cmd) {
  console.error(`알 수 없는 명령: ${cmdName}`);
  printHelp();
  process.exit(1);
}

const db = await openDatabase(dbSpec);
await migrate(db, allMigrations);
const store = new Store(db);

/**
 * 대상 테넌트 — `IONOSPHERE_TENANT`가 있으면 그것, 없으면 'default'(없으면 만든다).
 *
 * CLI는 단일 운영자 도구라 매번 테넌트 id를 적게 하면 실사용이 어렵다. 반면 REST는 root가
 * 반드시 명시해야 한다 — 그쪽은 여러 테넌트를 가로지르는 주체이기 때문이다. **같은 규칙을
 * 두 표면에 강요하지 않는 것**이 여기서는 옳다(위험이 다르다).
 */
async function defaultTenantId(): Promise<string> {
  const fromEnv = process.env.IONOSPHERE_TENANT;
  if (fromEnv) return fromEnv;
  const { rows } = await db.query({ sql: "SELECT id FROM tenants WHERE name = 'default' LIMIT 1" });
  if (rows[0]) return String(rows[0].id);
  const { tenantId } = await store.createTenant("default");
  return tenantId;
}

/** 인자 수집: 위치 인자 → 필수 인자 순서대로, `--k=v`가 이긴다. */
async function collectArgs(): Promise<Record<string, string | undefined>> {
  const flags = parseFlags(argv);
  const pos = positional(argv);
  const out: Record<string, string | undefined> = {};

  /**
   * 위치 인자는 **필수 인자 순서대로** 채운다 — `create-user a@b.com pw`가 그대로 동작하게.
   *
   * ★계정 비밀번호는 위치 인자로 받는다(`STDIN_ONLY_SECRETS`에 없다). 원래 CLI가 그랬고
   * README·`scripts/imaptest-local.sh`가 그 형태다. 반면 **릴레이 토큰과 TLS 개인키는
   * stdin/env로만** 받는다 — 그쪽은 그 자체로 임의 발신 권한이고 한 번 노출되면 회수 전까지
   * 계속 유효해서, `ps`·셸 히스토리 노출의 대가가 다르다(readSecret 주석).
   */
  const required = cmd!.spec.args.filter((a) => a.required && !stdinOnly(resolvedName, a.name));
  let consumed = 0;
  for (const a of required) {
    if (a.variadic) {
      /**
       * ★가변 인자는 **남은 위치 인자를 전부** 가져간다(`add-alias info@d a@d b@d`).
       * 이 갈래가 없으면 첫 대상만 반영되고 나머지가 조용히 사라져, 팬아웃 알리아스가
       * 반쪽으로 만들어진다 — 설정은 성공했는데 일부 수신자에게만 배달되는 형태다.
       */
      const rest = pos.slice(consumed);
      if (rest.length > 0) out[a.name] = rest.join(",");
      consumed = pos.length;
      continue;
    }
    const v = pos[consumed];
    if (v !== undefined) out[a.name] = v;
    consumed += 1;
  }
  // 남은 위치 인자는 마지막 선택 인자로(예: `add-app-password <email> <label...>`).
  const rest = pos.slice(consumed);
  if (rest.length > 0) {
    const optional = cmd!.spec.args.find((a) => !a.required && a.type === "string");
    if (optional) out[optional.name] = rest.join(" ");
  }
  Object.assign(out, flags);

  /**
   * 옛 CLI의 플래그 방언을 새 인자 이름으로 옮긴다 — **어댑터의 일이다.**
   * 명령 계층은 하나의 이름만 알고, argv가 어떤 모양으로 들어오는지는 여기서 흡수한다.
   * (`--user`/`--max-rcpts`는 문서·라이브 절차에 그대로 적혀 있다.)
   */
  /**
   * ★CLI의 `add-domain`은 **검증을 생략한다**(기존 동작). 로컬 셸 접근이 곧 서버 소유라
   * 자사 도메인 전제이고, 라이브 절차(`docs/STATUS.md`)가 "add-domain 하면 바로 쓸 수 있다"에
   * 기대고 있다. REST는 반대로 항상 검증을 요구한다 — 그쪽은 남의 도메인을 주장할 수 있는
   * 표면이기 때문이다. **같은 명령이지만 표면에 따라 기본값이 다른 것이 옳다**(위험이 다르다).
   * `--preVerified=false`로 명시하면 REST와 같은 검증 흐름을 탈 수 있다.
   */
  if (resolvedName === "domain-add" && out.preVerified === undefined) out.preVerified = "true";

  /**
   * 같은 이유로 CLI의 `create-user`는 도메인 검증을 요구하지 않는다(기존 동작).
   * README의 첫 사용 흐름과 `scripts/imaptest-local.sh`가 계정을 도메인보다 먼저 만든다.
   * REST는 완화하지 않는다 — 근거는 `accounts.ts`의 게이트 주석(선점 DoS·라우팅 폴백).
   */
  if (resolvedName === "account-create" && out.allowUnverifiedDomain === undefined) {
    out.allowUnverifiedDomain = "true";
  }

  if (flags.user !== undefined && out.username === undefined) out.username = flags.user;
  if (flags["max-rcpts"] !== undefined && out.maxRcpts === undefined) out.maxRcpts = flags["max-rcpts"];
  if (flags["pre-verified"] !== undefined && out.preVerified === undefined) out.preVerified = flags["pre-verified"];

  /**
   * `--preset=cloudflare` — 접속 파라미터를 사람이 매번 옮겨 적지 않게 한다.
   *
   * ★포트와 TLS 모드는 **짝**이다(465는 implicit, 587은 STARTTLS). 한쪽만 맞으면 연결이
   * 성립하지 않거나 최악의 경우 자격증명이 평문으로 나간다. 그래서 프리셋이 둘을 함께 준다.
   * 명시 플래그가 프리셋을 이긴다 — 운영자가 적은 값이 항상 우선이어야 한다.
   */
  const presetName = flags.preset;
  if (presetName !== undefined) {
    const preset = SMARTHOST_PRESETS[presetName];
    if (!preset) {
      throw new CommandError(
        "invalid",
        `알 수 없는 preset: ${presetName}`,
        `가능: ${Object.keys(SMARTHOST_PRESETS).join(", ")}`,
      );
    }
    out.host ??= preset.host;
    out.port ??= String(preset.port);
    out.tls ??= preset.tls;
    if (preset.username) out.username ??= preset.username;
    if (preset.maxRcptsPerSession) out.maxRcpts ??= String(preset.maxRcptsPerSession);
    if (process.stdin.isTTY) console.error(`preset ${presetName}의 비밀번호: ${preset.secretHint}`);
  }

  /**
   * stdin 전용 시크릿을 읽는다 — 이미 플래그로 들어온 값은 그대로 둔다.
   *
   * ★"필요한가"를 `required`만으로 판정하면 안 된다. `smarthost-set`의 비밀번호는 스펙상
   * 선택이지만 **사용자명을 지정하면 필수**다(인증 없는 릴레이도 있어서 무조건 필수로 둘 수 없다).
   * 이 조건을 놓치면 stdin을 읽지 않고 "비밀번호가 필요합니다"로 끝난다 — 파이프로 토큰을
   * 넘기는 라이브 절차가 통째로 깨지는 자리다.
   */
  const needsSecret = (name: string): boolean => {
    if (resolvedName === "smarthost-set" && name === "password") return (out.username ?? "") !== "";
    return true;
  };
  for (const a of cmd!.spec.args) {
    if (!stdinOnly(resolvedName, a.name)) continue;
    if (out[a.name] !== undefined) continue;
    if (!a.required && !flags[a.name] && !needsSecret(a.name)) continue;
    const fromFlag = flags[a.name];
    if (fromFlag !== undefined) {
      console.error(`⚠ --${a.name}을(를) argv로 받았다 — ps·셸 히스토리에 남는다. stdin/env를 쓸 것.`);
      out[a.name] = fromFlag;
      continue;
    }
    out[a.name] = await readSecret(a.label);
  }
  return out;
}

/** 표를 사람이 읽게 — 탭 구분(기존 CLI 출력 형식과 같다: `cut`·`awk`로 파이프 가능). */
function printRows(rows: readonly Record<string, unknown>[], spec: CommandSpec): void {
  if (rows.length === 0) {
    console.log("(없음)");
    return;
  }
  // 서술이 없으면 키를 그대로 컬럼으로 쓴다(형식·인코딩 정보 없음).
  const cols: readonly FieldSpec[] = spec.fields ?? Object.keys(rows[0]!).map((k) => ({ key: k, label: k }));
  for (const r of rows) {
    console.log(
      cols
        .map((c) => {
          const v = r[c.key];
          if (v === null || v === undefined) return "-";
          // 시각은 ISO로 — 사람이 로그와 대조할 수 있어야 한다.
          if (c.format === "time" && typeof v === "number") return new Date(v).toISOString();
          /**
           * ★상태 정수를 사람 말로 옮긴다 — **GUI와 같은 인코딩을 쓴다**(labelFor).
           * 예전엔 CLI가 `status=0`을 그대로 찍어서, 같은 계정을 화면에서는 "정지"로 보고
           * 터미널에서는 `0`으로 보게 됐다. 표면마다 다르게 읽히면 그 자체가 오독의 원인이다.
           */
          if (c.encoding) return labelFor(c.encoding, v);
          return String(v);
        })
        .join("\t"),
    );
  }
}

const ctx: CommandContext = {
  db,
  store,
  tenantId: await defaultTenantId(),
  // CLI는 로컬 셸 접근이 전제라 전권이다 — root 전용 명령(테넌트 목록·TLS)도 쓸 수 있어야 한다.
  isRoot: true,
  masterKey: process.env.IONOSPHERE_MASTER_KEY,
};

try {
  const args = await collectArgs();
  const result = await runCommand(registry, ctx, resolvedName, args);

  if (result.rows) printRows(result.rows, cmd.spec);
  if (result.message) console.log(result.message);
  /**
   * 평문 시크릿은 **마지막에, 눈에 띄게** 찍는다. 서버는 해시만 보관하므로 이 출력을 놓치면
   * 복구할 수 없다 — 표 사이에 섞여 스크롤로 지나가면 안 된다.
   */
  if (result.secret) {
    console.log(`\n${result.secret.label}:`);
    console.log(`  ${result.secret.value}`);
    console.log(`  ⚠ 이 값은 다시 볼 수 없습니다. 서버에는 해시만 저장됩니다.${result.secret.hint ? ` ${result.secret.hint}` : ""}`);
  }
  /**
   * DNS 안내 — **이걸 못 보면 관리자가 레코드를 넣을 수 없다.** 도메인을 만든 직후가 유일하게
   * 자연스러운 출력 지점이라(다시 보려면 API를 따로 불러야 한다) 여기서 표로 찍는다.
   */
  const dns = result.data?.dnsInstructions;
  if (Array.isArray(dns) && dns.length > 0) {
    console.log("\nDNS에 추가할 레코드:");
    for (const r of dns as { name: string; type: string; value: string; purpose: string }[]) {
      console.log(`  ${r.name}  ${r.type}  "${r.value}"   # ${r.purpose}`);
    }
  }
  // rows도 message도 secret도 없으면 구조화 결과를 그대로 낸다(스크립트가 파싱할 수 있게).
  if (!result.rows && !result.message && !result.secret && result.data) {
    console.log(JSON.stringify(result.data, null, 2));
  }

  /**
   * ★포워딩 대상이 있으면 **SRS가 실제로 활성인지** 알려준다.
   *
   * 조건만 알려주고 현재 상태를 알려주지 않으면, 운영자는 만들었다고 믿는데 그 주소로 온
   * 메일은 `550 no such user`로 거절된다(`backend.ts`의 `forwardable`이 srsSecret을 요구한다).
   * 2026-08-03 라이브에서 정확히 그랬다: `/etc/ionosphere.env`에 `IONOSPHERE_SRS_SECRET=`이 **값 없이**
   * 키만 있어 빈 문자열이 되고 falsy로 떨어졌다 — `grep -c`로는 줄이 1개라 "설정됨"으로 보였다.
   * **키가 있는 것과 값이 있는 것은 다른 사실이다.**
   *
   * CLI는 서버 프로세스가 아니므로 같은 env를 본다는 보장이 없다. 그래서 단정하지 않고
   * "이 CLI가 보는 값"임을 밝힌다 — 틀린 확신을 주는 것이 침묵보다 나쁘다.
   */
  /**
   * 판정은 **명령이 실제로 외부 포워딩을 만들었는지**로 한다. 인자에 `@`가 있는지로 보면
   * 로컬 계정을 이메일로 지목한 흔한 경우(`alias-add info@d alice@d`)에 헛경고가 뜬다 —
   * 매번 뜨는 경고는 곧 무시되고, 진짜 필요한 순간에도 읽히지 않는다.
   */
  if (resolvedName === "alias-add" && result.data?.hasForward === true) {
    const srs = process.env.IONOSPHERE_SRS_SECRET;
    if (srs === undefined || srs.trim() === "") {
      console.warn(
        `⚠ 포워딩이 비활성이다 — IONOSPHERE_SRS_SECRET이 ${srs === undefined ? "미설정" : "빈 값"}이다(이 CLI가 보는 env 기준).\n` +
          `  이 상태로는 해당 주소 수신이 550 "no such user"로 거절된다. 서버의 env에 값을 넣고 재시작할 것.\n` +
          `  생성 예: openssl rand -base64 32`,
      );
    }
  }
} catch (err) {
  if (err instanceof CommandError) {
    console.error(err.message);
    if (err.hint) console.error(`  ${err.hint}`);
    // DB를 잘못 가리켜서 "없다"가 나오는 경우가 잦아, notFound에는 대상 DB를 함께 보여준다.
    /**
     * ★"없다"는 진단은 **어느 DB를 봤는지**와 함께여야 쓸모가 있다. IONOSPHERE_DB/IONOSPHERE_DB_URL이
     * 라이브가 아닌 곳을 가리켜 "계정 없음"이 나오던 혼선이 실제로 있었다(파일 머리말 주석).
     */
    if (err.kind === "notFound") {
      console.error(`  (이 CLI가 본 DB: ${dbPath} — IONOSPHERE_DB_URL/IONOSPHERE_DB 확인)`);
    }
    if (err.kind === "invalid") printUsage(cmd.spec);
    await db.close();
    process.exit(1);
  }
  await db.close();
  throw err;
}

await db.close();
