/**
 * 기동 게이트 — 잘못된 보안 설정을 **부팅 시점에** 막는지 서브프로세스로 검증한다(감사 H-1·M-8).
 *
 * 왜 서브프로세스인가: 이 검사들의 값어치는 전부 "언제 터지느냐"에 있다. 함수 단위로 부르면
 * 순서가 증명되지 않는다. 여기서 확인하는 것은 리스너가 하나도 뜨기 전에 프로세스가 죽는다는
 * 사실이다 — 평문으로 개인키를 한 번이라도 페치한 뒤에 알아차리면 이미 늦었다.
 */
import { spawnSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const entry = join(here, "../src/main.ts");
let dir: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "ionosphere-boot-guard-"));
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** 최소 env로 기동 시도 — 개발자 셸의 IONOSPHERE_* 잔재가 결과를 흔들지 않게 통째로 교체한다. */
function boot(env: Record<string, string>): { code: number; stderr: string; output: string } {
  const p = spawnSync(process.execPath, [entry], {
    env: {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? "",
      IONOSPHERE_DB: join(dir, "boot.db"),
      IONOSPHERE_BLOBS: join(dir, "blobs"),
      IONOSPHERE_SMTP_PORT: "off",
      IONOSPHERE_POP3_PORT: "off",
      ...env,
    },
  });
  // node spawnSync는 status/stdout/stderr를 쓴다(bun의 exitCode와 다르다).
  // 스폰 자체가 실패하면 stdout/stderr가 null일 수 있어 방어한다.
  const stderr = p.stderr?.toString() ?? "";
  // 경고는 로거를 타고 stdout으로 나가므로 둘을 합쳐 본다.
  return { code: p.status ?? 0, stderr, output: stderr + (p.stdout?.toString() ?? "") };
}

/**
 * 평문 http: cert URL은 **기동을 막지 않는다**(운영 결정, 2026-07-31) — 라이브 cert-api가
 * 관리 VPC 주소라 거부하면 배포가 통째로 막히기 때문이다. 대신 **기동 시 1회 + 매 페치마다**
 * 경고를 남긴다. 여기서 고정하는 계약은 "리스너가 뜨기 전에 경고가 반드시 나온다"는 것이다 —
 * 조용히 지나가면 감사 H-1(개인키·Bearer 토큰 평문 전송)이 그대로 되돌아온다.
 *
 * 프로세스를 끝내려고 뒤에 반드시 실패하는 값을 함께 넣는다(게이트를 지나갔음을 결정적으로 관측).
 */
describe("TLS URL 평문 경고 (H-1)", () => {
  test("IONOSPHERE_TLS_MODE=url + http:// 는 기동하되 경고를 남긴다", () => {
    const r = boot({
      IONOSPHERE_MASTER_KEY: "k",
      IONOSPHERE_BLOB_GC: "bogus",
      IONOSPHERE_TLS_MODE: "url",
      IONOSPHERE_TLS_URL_CERT: "http://10.253.192.10:8080/cert-api/v1/certs/node-01/fullchain.pem",
      IONOSPHERE_TLS_URL_KEY: "http://10.253.192.10:8080/cert-api/v1/certs/node-01/privkey.pem",
    });
    expect(r.output).toContain("평문 http:");
    // 경고 문구는 왜 위험한지까지 말해야 한다 — "경고가 있었다"만으로는 아무도 안 고친다.
    expect(r.output).toContain("Bearer");
  });

  test("https: 구성은 경고를 남기지 않는다(정상 구성은 조용하다)", () => {
    const r = boot({
      IONOSPHERE_MASTER_KEY: "k",
      IONOSPHERE_BLOB_GC: "bogus",
      IONOSPHERE_TLS_MODE: "url",
      IONOSPHERE_TLS_URL_CERT: "https://vault.internal/cert",
      IONOSPHERE_TLS_URL_KEY: "https://vault.internal/key",
    });
    expect(r.output).not.toContain("평문 http:");
  });

  test("IONOSPHERE_TLS_ACME_DIRECTORY가 http:여도 기동하되 경고를 남긴다", () => {
    const r = boot({
      IONOSPHERE_MASTER_KEY: "k",
      IONOSPHERE_BLOB_GC: "bogus",
      IONOSPHERE_TLS_MODE: "acme",
      IONOSPHERE_CF_DNS_TOKEN: "t",
      IONOSPHERE_TLS_ACME_DIRECTORY: "http://acme.internal/directory",
    });
    expect(r.output).toContain("평문 http:");
  });
});

describe("비밀 저장 기동 게이트 (M-8)", () => {
  test("IONOSPHERE_MASTER_KEY 미설정이면 기동 거부", () => {
    const r = boot({});
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain("IONOSPHERE_MASTER_KEY");
  });

  test("IONOSPHERE_ALLOW_PLAINTEXT_SECRETS=1이면 게이트를 통과(다음 단계에서 멈춘다)", () => {
    // 뒤이어 반드시 실패할 값을 넣어 "게이트를 지나갔다"를 결정적으로 관측한다.
    const r = boot({ IONOSPHERE_ALLOW_PLAINTEXT_SECRETS: "1", IONOSPHERE_BLOB_GC: "bogus" });
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain("IONOSPHERE_BLOB_GC");
    expect(r.stderr).not.toContain("IONOSPHERE_MASTER_KEY 미설정 —");
  });
});

/**
 * 리스너 포트의 `off` 토큰 — **모든 리스너에서** 통해야 한다.
 *
 * ★왜 이 테스트가 있나(2026-08-02 사고): `off`는 `IONOSPHERE_SMTP_PORT`·`IONOSPHERE_POP3_PORT`
 * 두 곳에서만 처리되고 나머지는 `Number(env)`로 직접 변환했다. 역할 분리 문서가
 * `IONOSPHERE_IMAP_PORT=off`를 안내했는데 그 값이 **NaN**이 되어 `ERR_SOCKET_BAD_PORT`로
 * **크래시루프**에 빠졌다(라이브 node-01 축소 중 NRestarts=10, 즉시 롤백).
 *
 * 토큰의 의미는 리스너마다 같아야 한다. 한 곳만 다르면 그 사실은 **배포 때** 드러난다.
 */
describe("리스너 포트 off 토큰", () => {
  const OFFABLE = [
    "IONOSPHERE_IMAP_PORT",
    "IONOSPHERE_IMAPS_PORT",
    "IONOSPHERE_POP3S_PORT",
    "IONOSPHERE_SMTPS_PORT",
    "IONOSPHERE_SUBMISSION_PORT",
    "IONOSPHERE_MANAGESIEVE_PORT",
    "IONOSPHERE_JMAP_PORT",
    "IONOSPHERE_LMTP_PORT",
    "IONOSPHERE_ADMIN_PORT",
    "IONOSPHERE_AUTOCONFIG_PORT",
    "IONOSPHERE_HTTPS_FRONT_PORT",
    "IONOSPHERE_HTTP_REDIRECT_PORT",
    "IONOSPHERE_METRICS_PORT",
  ];

  test("★off를 준 리스너가 있어도 기동한다 (NaN 크래시 회귀)", () => {
    const env: Record<string, string> = { IONOSPHERE_MASTER_KEY: "0".repeat(64) };
    for (const k of OFFABLE) env[k] = "off";
    const r = boot(env);
    // 기동 자체가 성공해야 한다 — 예전엔 여기서 ERR_SOCKET_BAD_PORT로 죽었다.
    expect(r.output).not.toContain("ERR_SOCKET_BAD_PORT");
    expect(r.output).not.toContain("NaN");
  });

  test("숫자가 아닌 값은 기동 실패로 드러난다 (조용히 NaN을 흘리지 않는다)", () => {
    const r = boot({ IONOSPHERE_MASTER_KEY: "0".repeat(64), IONOSPHERE_IMAP_PORT: "nonsense" });
    expect(r.code).not.toBe(0);
    expect(r.output).toContain("포트 값이 잘못됨");
  });
});

/**
 * 80을 두 주인이 다투는 구성 — **기동 시점에** 막아야 한다.
 *
 * ★왜 중요한가: ACME http-01 챌린지 서버는 발급이 필요할 때만 80을 연다. 리다이렉트가
 * 그 포트를 상시 점유하면 `listen()`이 EADDRINUSE로 실패하는데, 그 순간이 **인증서 갱신
 * 시점**이다. 즉 설정 실수가 90일 뒤에 인증서 만료로 드러난다 — MTA-STS enforce에서는
 * 곧 수신 장애다. 기동 때 죽는 편이 훨씬 낫다.
 */
describe("80 포트 충돌 가드", () => {
  const BASE = { IONOSPHERE_MASTER_KEY: "0".repeat(64), IONOSPHERE_HTTP_REDIRECT_PORT: "80" };

  test("★리다이렉트 + ACME http-01이 같은 포트면 기동을 세운다", () => {
    const r = boot({ ...BASE, IONOSPHERE_TLS_MODE: "acme", IONOSPHERE_TLS_ACME_CHALLENGE: "http-01" });
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain("IONOSPHERE_HTTP_REDIRECT_PORT");
    // 원인과 해법이 메시지에 있어야 한다 — 90일 뒤가 아니라 지금 고치라는 뜻이다.
    expect(r.stderr).toContain("갱신");
  });

  test("챌린지 포트를 옮기면 공존을 허용한다", () => {
    const r = boot({
      ...BASE,
      IONOSPHERE_TLS_MODE: "acme",
      IONOSPHERE_TLS_ACME_CHALLENGE: "http-01",
      IONOSPHERE_TLS_ACME_HTTP_PORT: "8080",
    });
    expect(r.stderr).not.toContain("IONOSPHERE_HTTP_REDIRECT_PORT=80가 ACME");
  });

  test("dns-01이면 80을 다투지 않는다", () => {
    const r = boot({ ...BASE, IONOSPHERE_TLS_MODE: "acme", IONOSPHERE_TLS_ACME_CHALLENGE: "dns-01" });
    expect(r.stderr).not.toContain("IONOSPHERE_HTTP_REDIRECT_PORT=80가 ACME");
  });

  test("acme를 안 쓰면 다툴 상대가 없다 (라이브 구성: IONOSPHERE_TLS_MODE=url)", () => {
    const r = boot({ ...BASE, IONOSPHERE_TLS_MODE: "url" });
    expect(r.stderr).not.toContain("IONOSPHERE_HTTP_REDIRECT_PORT=80가 ACME");
  });
});
