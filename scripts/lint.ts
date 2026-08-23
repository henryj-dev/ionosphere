/**
 * 규약 린터 — 의존성 0(node:fs만). `bun scripts/lint.ts` / `node scripts/lint.ts` 둘 다 동작.
 *
 * tsconfig가 타입 레벨(strict·erasableSyntaxOnly·exactOptionalPropertyTypes)을 강제하는 반면,
 * 아래 규약들은 그동안 사람 기억에만 의존했다. 실제로 "기계가 강제하는 영역은 지켜지고,
 * 아닌 영역만 갈라졌다"는 패턴이 코드 검수에서 관측됐다(SASL 4중 구현, 도메인 INSERT 갈라짐 등).
 *
 * 검사 항목:
 *  1. 상대 import는 `.ts` 확장자 필수 (node의 .ts 직접 실행 요건)
 *  2. npm import 화이트리스트 (node: 빌트인 + pg + mysql2)
 *  3. 금지 구문 (enum / namespace — erasableSyntaxOnly 보강, 에러 메시지를 규약 언어로)
 *  4. 소스 내 리터럴 제어문자(NUL·SOH) — 이 저장소에서 반복 발생한 사고. escape로 쓸 것
 *  5. @ionosphere/* 패키지 간 순환 의존
 *  6. 프로토콜 엔진이 바이트를 누적하면 @ionosphere/core 소유의 라인 상한을 참조할 것
 *  7. 블록 주석 안에서 별표 두 개 뒤에 슬래시가 오는 시퀀스 — 주석을 조기 종료시킨다
 *  8. 배달·라우팅 패키지에서 `domains`를 원시 SQL로 조회 금지 — 판정 정본은 @ionosphere/db
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
const ALLOWED_NPM = new Set(["pg", "mysql2", "mysql2/promise"]);

interface Violation {
  file: string;
  line: number;
  rule: string;
  message: string;
}

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === ".git" || entry === "dist") continue;
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (entry.endsWith(".ts")) out.push(p);
  }
  return out;
}

/** 코드에서 소스 파일 목록(테스트 포함 — 규약은 테스트에도 적용). */
function sourceFiles(): string[] {
  const dirs = [join(ROOT, "packages"), join(ROOT, "apps"), join(ROOT, "scripts")];
  return dirs.flatMap((d) => {
    try {
      return walk(d);
    } catch {
      return [];
    }
  });
}

const violations: Violation[] = [];
const rel = (f: string): string => f.slice(ROOT.length);

/**
 * 라인 상한 상수의 소유자는 `@ionosphere/core/limits.ts` 하나다(CLAUDE.md 소유권 표).
 * 프로토콜별로 값이 달라야 하면 limits.ts에 각각 이름을 준다.
 */
const LINE_LIMIT_NAMES = ["MAX_COMMAND_LINE", "MAX_IMAP_LINE_BYTES"];

/**
 * 규칙 6 — "바이트를 누적하는 프로토콜 엔진은 라인 상한을 가진다".
 *
 * 왜 기계로 강제하는가: SMTP는 개행 없는 바이트 스트림에 프로세스가 죽는 사고를 겪고 상한을
 * 넣었는데, **그 교훈이 POP3로 전파되지 않아 같은 결함이 그대로 남아 있었다**(2026-07-30 감사
 * H-2, 300MB 투입에 RSS 1836MB 실측). 값이 프로토콜마다 흩어져 소유자가 없으면 새 프로토콜을
 * 추가할 때 또 빠진다. 정확한 AST 분석 대신 "버퍼를 들고 있으면 core의 상한을 참조한다"는
 * 실용적 휴리스틱으로 검사한다 — 상한을 **어디서** 검사하는지까지는 못 보지만, 상한이
 * **존재조차 하지 않는** 상태(실제로 일어난 일)는 확실히 잡는다.
 */
function checkEngineBufferLimit(file: string, text: string): void {
  const path = rel(file).split("\\").join("/");
  if (!/^packages\/proto-[^/]+\/src\/(engine|reader)\.ts$/.test(path)) return;
  if (!/\bthis\.buffer\b/.test(text)) return; // 버퍼를 안 들고 있으면(리더에 위임) 해당 없음

  const imported = new Set(
    [...text.matchAll(/import\s*(?:type\s*)?\{([^}]*)\}\s*from\s*"@ionosphere\/core"/g)].flatMap((m) =>
      (m[1] ?? "").split(",").map((s) => s.trim().split(/\s+/).pop() ?? ""),
    ),
  );
  const ok = LINE_LIMIT_NAMES.some(
    (name) => imported.has(name) && (text.match(new RegExp(`\\b${name}\\b`, "g")) ?? []).length >= 2,
  );
  if (ok) return;

  violations.push({
    file,
    line: 0,
    rule: "engine-buffer-limit",
    message:
      `버퍼를 누적하는 프로토콜 엔진에 라인 상한이 없다 — @ionosphere/core에서 ` +
      `${LINE_LIMIT_NAMES.join(" 또는 ")}를 import해 사용할 것 ` +
      `(개행 없는 스트림 하나로 프로세스가 죽는다 — proto-smtp guardDataBuffer 주석 참조)`,
  });
}

/**
 * 런타임 전용 전역 API 금지 — `Bun.serve`·`Bun.file` 등(CLAUDE.md 의존성).
 *
 * 왜 기계로 강제하는가: 이 저장소는 두 런타임에서 다 돌아야 하는데, `Bun.*`는 **bun으로 개발하는
 * 동안 아무 증상이 없다.** node로 띄우는 순간에야 `Bun is not defined`로 죽고, 그 시점이 배포일 수
 * 있다. 실측으로 현재 소스에 실사용 0건(주석 2건뿐)이라 지금 고정하면 비용이 0이다.
 *
 * `bun:sqlite`처럼 **import 형태**로 쓰는 것은 이 규칙의 대상이 아니다 — `sqlite.ts`가 node와
 * bun 양쪽을 동적으로 갈라 쓰고 있고, 그건 듀얼 런타임을 지키는 방식이다.
 */
function checkNoRuntimeGlobals(file: string, text: string): void {
  const path = rel(file).split("\\").join("/");
  if (!/^(packages|apps)\/[^/]+\/(src|test)\//.test(path)) return;

  for (const m of text.matchAll(/(?<![\w.$])Bun\s*\.\s*[A-Za-z_$]/g)) {
    const before = text.slice(0, m.index ?? 0);
    const line = before.split("\n").length;
    const lineText = text.split("\n")[line - 1] ?? "";
    // 주석에 "Bun.serve 금지"처럼 규약을 적어 둔 것은 위반이 아니다.
    if (/^\s*(\*|\/\/|\/\*)/.test(lineText)) continue;
    violations.push({
      file,
      line,
      rule: "no-runtime-global",
      message:
        "런타임 전용 전역(Bun.*) 사용 금지 — node:http/node:net/node:tls로 작성할 것. " +
        "bun으로 개발하는 동안은 증상이 없고 node로 띄울 때 'Bun is not defined'로 죽는다(듀얼 런타임)",
    });
  }
}

/**
 * 프로토콜 엔진은 I/O를 import하지 않는다 — "순수 엔진 + 얇은 어댑터"(CLAUDE.md 아키텍처).
 *
 * 왜 기계로 강제하는가: 이 성질 덕분에 프로토콜 동작이 소켓 없이 테스트되고, 비동기 확인이
 * 필요한 지점이 액션 emit으로 드러난다. 그런데 엔진에 `node:net` 한 줄을 넣는 것은 **아무
 * 경고 없이 통과한다** — 타입도 테스트도 막지 않고, 오히려 그 자리에서 짜는 게 편해 보인다.
 * 한 번 뚫리면 상태머신과 소켓이 엉켜 되돌리기가 비싸진다. 실측으로 현재 6개 엔진 전부
 * 0건이므로, 지금 고정해 두면 비용이 0이다(README에 공개적으로 적은 성질이기도 하다).
 *
 * `node:crypto`·`node:buffer` 같은 순수 계산 모듈은 허용한다 — 막으려는 것은 **바깥과
 * 이야기하는 능력**(소켓·파일·프로세스)이다.
 */
const ENGINE_FORBIDDEN_MODULES = ["net", "tls", "http", "http2", "https", "fs", "fs/promises", "dns", "dns/promises", "dgram", "child_process", "worker_threads", "cluster"];

function checkEnginePurity(file: string, text: string): void {
  const path = rel(file).split("\\").join("/");
  if (!/^packages\/proto-[^/]+\/src\/engine\.ts$/.test(path)) return;

  for (const m of text.matchAll(/^\s*(?:import|export)\s[^;]*?from\s*"node:([a-z_/]+)"/gm)) {
    const mod = m[1] ?? "";
    if (!ENGINE_FORBIDDEN_MODULES.includes(mod)) continue;
    violations.push({
      file,
      line: text.slice(0, m.index ?? 0).split("\n").length,
      rule: "engine-purity",
      message:
        `프로토콜 엔진이 node:${mod}를 import한다 — 엔진은 I/O import 0개인 순수 상태머신이어야 ` +
        "하고 소켓은 server.ts가 담당한다. 비동기 확인이 필요하면 액션을 emit하고 멈춘 뒤 " +
        "xxxResult()로 재개할 것(CLAUDE.md 아키텍처). 엉키면 프로토콜 동작을 소켓 없이 테스트할 수 없다",
    });
  }
}

/**
 * 규칙 7 — 블록 주석 안에서 별표 두 개 뒤에 슬래시가 오면 거기서 주석이 닫힌다.
 *
 * 이 저장소는 주석이 길고 한국어 마크다운 강조를 많이 쓴다. 강조 닫는 별표 바로 뒤에 경로나
 * 프리픽스의 슬래시가 오면(IPv6 프리픽스, 절대경로, 글롭 등) 의도치 않게 주석이 종료되고
 * 나머지 텍스트가 코드로 파싱된다. **파일 하나가 아니라 그 파일을 import하는 패키지 전체의
 * 테스트가 로드 단계에서 죽는다** — 2026-07-31에 실제로 저장소 빌드가 이걸로 멈췄다.
 * CLAUDE.md의 "리터럴 제어문자 금지"와 같은 계열: **툴체인을 깨뜨리는 문자 시퀀스** 규칙이다.
 *
 * 문자열 리터럴은 건너뛴다 — 글롭 패턴에 같은 시퀀스가 정당하게 등장하기 때문이다.
 * 그래서 정규식이 아니라 주석/문자열 상태를 추적하는 스캐너로 짰다.
 */
function checkCommentTerminator(file: string, text: string): void {
  const EARLY_CLOSE = `**${"/"}`; // 소스에 리터럴로 쓰면 이 파일 자신의 주석이 닫힌다
  let i = 0;
  let line = 1;
  let inBlock = false;
  while (i < text.length) {
    const c = text[i];
    if (c === "\n") {
      line += 1;
      i += 1;
      continue;
    }
    if (inBlock) {
      if (text.startsWith(EARLY_CLOSE, i)) {
        violations.push({
          file,
          line,
          rule: "no-early-comment-close",
          message:
            "블록 주석 안에서 별표 두 개 뒤에 슬래시가 오면 거기서 주석이 종료된다 — " +
            "경로·프리픽스는 백틱으로 감쌀 것(`/64`, `/etc/ionosphere.env`). 주석을 닫으려면 별표 하나 + 슬래시",
        });
      }
      if (text.startsWith("*/", i)) {
        inBlock = false;
        i += 2;
        continue;
      }
      i += 1;
      continue;
    }
    // ── 주석 밖 ──
    if (text.startsWith("/*", i)) {
      inBlock = true;
      i += 2;
      continue;
    }
    if (text.startsWith("//", i)) {
      while (i < text.length && text[i] !== "\n") i += 1;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      // 문자열 건너뛰기 — 이스케이프만 처리하면 충분하다(글롭 오탐 방지가 목적).
      const quote = c;
      i += 1;
      while (i < text.length) {
        if (text[i] === "\\") {
          i += 2;
          continue;
        }
        if (text[i] === quote) break;
        if (text[i] === "\n") {
          line += 1;
          if (quote !== "`") break; // 홑/겹따옴표는 줄을 넘지 않는다(미닫힘 방어)
        }
        i += 1;
      }
      i += 1;
      continue;
    }
    i += 1;
  }
}

/**
 * 배달·라우팅 경로에서 `domains` 테이블을 원시 SQL로 조회하지 못하게 한다.
 *
 * ★왜 규칙으로 만들었나(감사 5차 H-4): 같은 판정("이 도메인이 우리 것인가")을 세 곳이 각자
 * 원시 SQL로 하다가 **두 곳이 `status`를 빠뜨렸다**. `domains.name`에는 UNIQUE 제약이 없어
 * 아무 테넌트나 미검증 행을 만들 수 있으므로, 그 행 하나가 타 테넌트의 발송 경로를 뒤집었다.
 *
 * 판정 정본은 `@ionosphere/db`의 `lookupDomainRouting`/`isLocallyRoutableDomain`이다. 관리 API처럼
 * 도메인 자체를 CRUD하는 곳은 원시 SQL이 정상이므로, **배달·라우팅을 담당하는 패키지에만**
 * 건다. 검사 대상을 넓히는 것보다 "여기서는 반드시 정본을 쓴다"를 좁고 확실하게 거는 편이
 * 오탐 없이 오래 간다.
 */
const DOMAIN_SQL_SEALED_PATHS = ["packages/mta/src/", "packages/store/src/"];

function checkDomainLookupOwnership(file: string, lines: readonly string[]): void {
  const normalized = file.replaceAll("\\", "/");
  if (!DOMAIN_SQL_SEALED_PATHS.some((p) => normalized.includes(p))) return;
  lines.forEach((line, i) => {
    if (line.trimStart().startsWith("*") || line.trimStart().startsWith("//")) return; // 주석은 제외
    // `FROM domains`만 본다 — domains가 **판정의 주체**인 질의다. `JOIN domains`는 주소 소유
    // 확인처럼 domains를 차원으로만 쓰는 다른 질의라 정본으로 대체할 대상이 아니다.
    if (!/\bFROM\s+domains\b/i.test(line)) return;
    violations.push({
      file,
      line: i + 1,
      rule: "domain-lookup-owner",
      message:
        "domains를 원시 SQL로 조회하지 말 것 — 판정 정본은 @ionosphere/db의 lookupDomainRouting/" +
        "isLocallyRoutableDomain이다. status를 빠뜨린 조회가 타 테넌트의 라우팅을 뒤집은 사고(감사 H-4)",
    });
  });
}

/**
 * 공유 테스트 DB를 파괴적으로 비우는 테스트를 막는다.
 *
 * 왜(2026-08-01, 두 방언에서 각각 발생): `IONOSPHERE_TEST_PG_URL`·`IONOSPHERE_TEST_MYSQL_URL`은 여러
 * 테스트 파일이 함께 읽는다. 그중 일부가 그 DB의 스키마를 **통째로 비우면**(`DROP SCHEMA public
 * CASCADE`, 전 테이블 DROP) 병렬 실행에서 다른 파일의 마이그레이션 중간에 끼어들어 깨진다.
 *   - MySQL: `Unknown column 'ad.account_id'` (006이 그 컬럼을 지우는 마이그레이션이다)
 *   - PG:    `relation "modseq_claims" does not exist`
 * 로컬 재현: 수정 전 MySQL 5/5 실패, PG 3회 중 2회 실패.
 *
 * 특히 나쁜 것은 **간헐적**이라는 점이다. 같은 커밋에서 CI 워크플로는 통과하고 Deploy의 verify
 * 잡은 실패했다 — 러너 부하에 따라 순서가 달라진다. 그래서 사람 눈으로는 "가끔 깨지는 테스트"로
 * 보이고, 실제로 배포 게이트를 조용히 막고 있었다.
 *
 * 규칙: 테스트 파일이 파괴적 DDL을 쓰면 **전용 스키마/DB로 스코프**해야 한다. 판정은
 * `search_path=`(PG) 또는 `CREATE DATABASE`(MySQL)의 존재로 한다 — 둘 중 하나가 있으면
 * env가 준 DB를 직접 비우는 것이 아니라 자기 것을 만들어 쓴다는 뜻이다.
 */
const DESTRUCTIVE_DDL = /\bDROP\s+(SCHEMA|DATABASE|TABLE)\b/i;

function checkSharedTestDbIsolation(file: string, lines: readonly string[]): void {
  const normalized = file.replaceAll("\\", "/");
  if (!normalized.endsWith(".test.ts")) return;
  const text = lines.join("\n");
  if (!/IONOSPHERE_TEST_(PG|MYSQL)_URL/.test(text)) return;
  // 전용 스코프를 만들고 있으면 통과 — 그게 이 규칙이 요구하는 것이다.
  if (/search_path=/.test(text) || /CREATE\s+DATABASE/i.test(text)) return;

  lines.forEach((line, i) => {
    const t = line.trimStart();
    if (t.startsWith("*") || t.startsWith("//")) return; // 주석의 설명은 위반이 아니다
    if (!DESTRUCTIVE_DDL.test(line)) return;
    violations.push({
      file,
      line: i + 1,
      rule: "shared-test-db-isolation",
      message:
        "공유 테스트 DB(IONOSPHERE_TEST_*_URL)를 파괴적으로 비우지 말 것 — 전용 스키마/DB를 만들어 쓸 것" +
        "(PG는 search_path, MySQL은 CREATE DATABASE). 병렬 실행에서 다른 테스트의 마이그레이션을 깨뜨려 " +
        "배포 게이트가 간헐적으로 막힌 사고(2026-08-01)",
    });
  });
}

/**
 * DKIM/ARC 크립토 프리미티브의 소유자를 강제한다 — `packages/mail-auth/src/crypto.ts`.
 *
 * 왜(2026-08-01 실사고): 서명·검증·공개키 임포트 분기가 `sign.ts`·`verify.ts`·`arc.ts`에 **세 벌**
 * 복제돼 있었고, 그래서 RFC 8463 §3 위반이 세 곳에 동시에 존재했다. ed25519-sha256은 정규화된
 * 원문이 아니라 그 **SHA-256 다이제스트**를 서명해야 하는데 원문을 서명하고 있었다.
 * 검증 쪽도 같은 방식이라 자체 라운드트립 테스트는 전부 통과했고(뮤테이션으로 확인: 결함 상태에서
 * 기존 28건 전부 pass) 외부 검증자만 실패했다 — 라이브 발송 메일 전체의 우리 서명이 무효였다.
 *
 * 호출부 정규식(`cryptoSign(null,`)이 아니라 **import 지정자**를 보는 이유: 호출부는 변수명·별칭·
 * 줄바꿈에 취약하지만 import는 한 줄이고 모호하지 않다. `createHash`(bh 계산)는 허용한다 —
 * 해시는 정규화 결과를 요약하는 것이지 서명 정책이 아니다.
 *
 * 스코프를 `packages/mail-auth/src/`로 좁히는 이유: 전역으로 걸면 `packages/tls/`의 JWS·CSR·X.509
 * 서명(ACME)이 전부 정당한 위반으로 잡힌다. `domain-lookup-owner`와 같은 좁은 스코프 전략이다.
 */
const DKIM_CRYPTO_OWNER = "packages/mail-auth/src/crypto.ts";
const DKIM_CRYPTO_FORBIDDEN = ["sign", "verify", "createPublicKey", "createPrivateKey"];

function checkDkimCryptoOwner(file: string, text: string): void {
  const normalized = file.replaceAll("\\", "/");
  if (!normalized.includes("packages/mail-auth/src/")) return;
  if (normalized.endsWith(DKIM_CRYPTO_OWNER)) return; // 정본 자신은 예외

  for (const m of text.matchAll(/import\s*\{([^}]*)\}\s*from\s*"node:crypto"/g)) {
    const specifiers = (m[1] ?? "").split(",").map((s) => s.trim());
    for (const spec of specifiers) {
      if (spec.startsWith("type ")) continue; // `type KeyObject`는 값이 아니라 타입이다
      // `sign as cryptoSign` 형태에서 원래 이름을 본다.
      const original = (spec.split(/\s+as\s+/)[0] ?? "").trim();
      if (!DKIM_CRYPTO_FORBIDDEN.includes(original)) continue;
      const before = text.slice(0, m.index ?? 0);
      violations.push({
        file,
        line: before.split("\n").length,
        rule: "dkim-crypto-owner",
        message:
          `node:crypto의 ${original}을 직접 가져오지 말 것 — DKIM 서명·검증·키 임포트의 정본은 ` +
          "crypto.ts다(signDkimData/verifyDkimData/ed25519PublicKeyFromRaw). 같은 분기가 3곳에 " +
          "복제돼 RFC 8463 §3 위반이 동시에 존재했다(2026-08-01). createHash는 허용",
      });
    }
  }
}

/**
 * SQLite 단독 운영이 npm 드라이버 없이 성립해야 한다 — 오픈소스 자립성.
 *
 * SQLite는 런타임 빌트인(`bun:sqlite`/`node:sqlite`)이라 의존성이 0인데, `postgres.ts`·`mysql.ts`를
 * **정적으로** import하면 모듈 해석 단계에서 `pg`·`mysql2`를 찾는다. 그래서 SQLite만 쓰려는
 * 사용자도 쓰지도 않을 드라이버 두 개를 설치해야 했다(실측: 두 패키지가 없는 환경에서
 * `Cannot find package 'pg'`로 패키지 진입점 로드 자체가 실패).
 *
 * 지금은 `index.ts`·`open.ts`가 `await import(…)`로 지연 로드한다. 그런데 이건 **정적 import 한 줄이
 * 들어오면 조용히 깨지는** 성질이다 — 타입체크도 테스트도 통과하고, `pg`가 설치된 개발 환경에서는
 * 아무 증상이 없다. 그래서 기계로 막는다.
 *
 * 드라이버 파일 자신(`postgres.ts`/`mysql.ts`)은 당연히 예외다.
 */
const DB_DRIVER_FILES = ["packages/db/src/postgres.ts", "packages/db/src/mysql.ts"];

function checkLazyDbDrivers(file: string, text: string): void {
  const normalized = file.replaceAll("\\", "/");
  if (!normalized.includes("packages/db/src/")) return;
  if (DB_DRIVER_FILES.some((f) => normalized.endsWith(f))) return;

  for (const m of text.matchAll(/^\s*import\s[^;]*?from\s*"\.\/(postgres|mysql)\.ts"/gm)) {
    violations.push({
      file,
      line: text.slice(0, m.index ?? 0).split("\n").length,
      rule: "lazy-db-drivers",
      message:
        `./${m[1]}.ts를 정적 import하지 말 것 — \`await import()\`로 지연 로드해야 한다. ` +
        "정적이면 pg·mysql2가 없는 환경에서 패키지 진입점 로드가 실패해 **SQLite 단독 운영이 깨진다** " +
        "(오픈소스 자립성). pg가 설치된 개발 환경에서는 증상이 없어 조용히 회귀한다",
    });
  }
}

function check(file: string): void {
  const text = readFileSync(file, "utf8");
  const lines = text.split("\n");
  checkEngineBufferLimit(file, text);
  checkEnginePurity(file, text);
  checkNoRuntimeGlobals(file, text);
  checkCommentTerminator(file, text);
  checkDomainLookupOwnership(file, lines);
  checkSharedTestDbIsolation(file, lines);
  checkDkimCryptoOwner(file, text);
  checkLazyDbDrivers(file, text);

  lines.forEach((line, i) => {
    const lineNo = i + 1;

    // ── 1·2. import 대상 검사 ──────────────────────────────────────
    /**
     * 문자열 리터럴 **안에 있는** `from "`은 import가 아니다.
     *
     * 오탐 사례: 테스트가 헤더 이름을 문자열로 비교할 때(예: indexOf로 두 헤더의 순서를 확인할 때)
     * 문자열 안의 `from` + 공백 + 따옴표가 import 구문처럼 보여, 뒤따르는 코드 조각을 모듈 이름으로
     * 읽고 npm-allowlist 위반을 냈다. 코드를 비틀어 피하면 같은 함정이 남으므로 도구를 고친다.
     *
     * 판정: 키워드 앞의 따옴표 개수가 홀수면 문자열 안이다. import 문의 지정자 자체는 문자열이라
     * 통째로 지울 수 없어(그러면 검사 대상이 사라진다) 이 방식을 쓴다.
     */
    const specs = [...line.matchAll(/(?:from|import)\s+"([^"]+)"/g)]
      .filter((m) => (line.slice(0, m.index).split('"').length - 1) % 2 === 0)
      .map((m) => m[1]!);
    for (const spec of specs) {
      if (spec.startsWith(".")) {
        if (!spec.endsWith(".ts")) {
          violations.push({
            file,
            line: lineNo,
            rule: "relative-import-ext",
            message: `상대 import는 .ts 확장자 필수: "${spec}"`,
          });
        }
        continue;
      }
      // ★`bun:` 면제를 뺐다(2026-08-02 node 전용 전환). 이제 `bun:test`·`bun:sqlite`를 다시
      // 들이면 npm-allowlist 위반으로 잡힌다 — 러너를 옮긴 뒤 조용히 되돌아오는 것을 막는다.
      if (spec.startsWith("node:") || spec.startsWith("@ionosphere/")) continue;
      if (!ALLOWED_NPM.has(spec)) {
        violations.push({
          file,
          line: lineNo,
          rule: "npm-allowlist",
          message: `허용되지 않은 npm 의존: "${spec}" (허용: ${[...ALLOWED_NPM].join(", ")})`,
        });
      }
    }

    // ── 3. 금지 구문 ──────────────────────────────────────────────
    if (/^\s*(?:export\s+)?(?:const\s+)?enum\s+\w/.test(line)) {
      violations.push({ file, line: lineNo, rule: "no-enum", message: "enum 금지(erasableSyntaxOnly) — as const 객체 + 유니온 타입 사용" });
    }
    if (/^\s*(?:export\s+)?namespace\s+\w/.test(line)) {
      violations.push({ file, line: lineNo, rule: "no-namespace", message: "namespace 금지(erasableSyntaxOnly) — 모듈 사용" });
    }

    // ── 4. 리터럴 제어문자 ────────────────────────────────────────
    // NUL(0x00)·SOH(0x01)는 SASL 등에서 자주 쓰이는데, 소스에 리터럴로 들어가면
    // diff·grep·툴 체인이 깨진다. "" escape 또는 String.fromCharCode(0)로 쓸 것.
    const ctrl = line.match(/[\u0000\u0001]/);
    if (ctrl) {
      const code = ctrl[0].charCodeAt(0).toString(16).padStart(4, "0");
      violations.push({
        file,
        line: lineNo,
        rule: "no-literal-control-char",
        message: `리터럴 제어문자 U+${code.toUpperCase()} — "\\u${code}" escape 또는 String.fromCharCode()로 쓸 것`,
      });
    }
  });
}

/** package.json 의존을 읽어 @ionosphere/* 그래프를 만들고 순환을 찾는다. */
function checkCycles(): void {
  const pkgDir = join(ROOT, "packages");
  const graph = new Map<string, string[]>();
  let entries: string[];
  try {
    entries = readdirSync(pkgDir);
  } catch {
    return;
  }
  for (const name of entries) {
    const manifest = join(pkgDir, name, "package.json");
    let json: { name?: string; dependencies?: Record<string, string> };
    try {
      json = JSON.parse(readFileSync(manifest, "utf8")) as typeof json;
    } catch {
      continue;
    }
    if (!json.name) continue;
    graph.set(
      json.name,
      Object.keys(json.dependencies ?? {}).filter((d) => d.startsWith("@ionosphere/")),
    );
  }

  const state = new Map<string, "visiting" | "done">();
  const stack: string[] = [];
  const walkNode = (node: string): void => {
    if (state.get(node) === "done") return;
    if (state.get(node) === "visiting") {
      const cycle = [...stack.slice(stack.indexOf(node)), node].join(" → ");
      violations.push({ file: join(ROOT, "packages"), line: 0, rule: "no-package-cycle", message: `패키지 순환 의존: ${cycle}` });
      return;
    }
    state.set(node, "visiting");
    stack.push(node);
    for (const dep of graph.get(node) ?? []) walkNode(dep);
    stack.pop();
    state.set(node, "done");
  };
  for (const node of graph.keys()) walkNode(node);
}

for (const f of sourceFiles()) check(f);
checkCycles();

if (violations.length === 0) {
  console.log("LINT OK — 규약 위반 없음");
  process.exit(0);
}

const byRule = new Map<string, Violation[]>();
for (const v of violations) {
  const list = byRule.get(v.rule);
  if (list) list.push(v);
  else byRule.set(v.rule, [v]);
}
for (const [rule, list] of byRule) {
  console.error(`\n[${rule}] ${list.length}건`);
  for (const v of list.slice(0, 20)) {
    console.error(`  ${rel(v.file)}${v.line ? `:${v.line}` : ""}  ${v.message}`);
  }
  if (list.length > 20) console.error(`  ... 외 ${list.length - 20}건`);
}
console.error(`\n총 ${violations.length}건 위반`);
process.exit(1);
