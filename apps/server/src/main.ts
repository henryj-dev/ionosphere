/**
 * ionosphere 서버 엔트리.
 * 로그: IONOSPHERE_LOG_LEVEL(debug|info|warn|error, 기본 info),
 *       IONOSPHERE_LOG_FORMAT(pretty|json, 기본 TTY면 pretty 아니면 json)
 * (STARTTLS가 node에서만 동작하던 시절의 주의는 걷어냈다 — 2026-08-02부터 node 전용이다.)
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { applyLegacyEnvAliases, createLogger, type LogLevel } from "@ionosphere/core";
import type { SmarthostOptions, TlsMode } from "@ionosphere/mta";
import { listenersFromEnv } from "./listeners.ts";
import { RecursiveResolver } from "@ionosphere/dns";
import { createCertSource, httpChallengeServer, type AcmeChallenge, type CertSource } from "@ionosphere/tls";
import { cloudflareDnsProvider } from "./cf-dns.ts";
import { FsBlobStore, isBlobGcMode, S3BlobStore, type BlobGcMode, type BlobStore } from "@ionosphere/store";
import { HTTP_SERVICES, IonosphereApp, type AppAuditOptions, type HttpServiceName, type ServiceHosts, type TlsListenerName } from "./app.ts";

// ★구 `IONOSPHERE_*` env를 새 이름으로 넘긴다 — 반드시 env를 처음 읽기 **전에**.
// 코드 배포와 `/etc/*.env` 교체를 따로 할 수 있게 하는 전환 장치다(packages/core/src/env-legacy.ts).
const legacyEnv = applyLegacyEnvAliases();
if (legacyEnv.length > 0) {
  process.emitWarning(
    `구 이름 env ${legacyEnv.length}개를 IONOSPHERE_*로 넘겼다(${legacyEnv.slice(0, 3).join(", ")}${legacyEnv.length > 3 ? " 외" : ""}). ` +
      "env 파일을 새 이름으로 바꾼 뒤 이 경고가 사라지는지 확인할 것.",
  );
}

/**
 * 리스너 포트 파싱 — `off`면 그 리스너를 아예 띄우지 않는다(역할별 서버 분리).
 *
 * 왜 `0`을 "끔"으로 쓰지 않는가: 이 저장소에서 `0`은 이미 "임시 포트"(테스트가 포트 충돌을
 * 피하려고 쓰는 관례)다. 의미를 겹치면 테스트가 조용히 리스너 없이 돌게 된다.
 */
function optionalPort(key: "smtpPort" | "pop3Port", raw: string | undefined, fallback: number): Record<string, number> {
  const v = (raw ?? "").trim().toLowerCase();
  if (v === "off") return {};
  const n = raw === undefined || raw === "" ? fallback : Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > 65535) throw new Error(`포트 값이 잘못됨: ${key}=${raw}`);
  return { [key]: n };
}

/**
 * 기본값이 **없는** 리스너의 포트 파싱 — 지정하면 그 포트, `off`면 안 띄운다, 없으면 안 띄운다.
 *
 * ★왜 필요한가(2026-08-02 사고): 이 포트들은 `Number(process.env.X)`로 직접 변환하고 있었다.
 * 역할 분리 문서(`docs/SPLIT.md`)가 `IONOSPHERE_IMAP_PORT=off`를 쓰라고 안내했는데, 그 값이
 * `Number("off")` → **NaN**이 되어 `ERR_SOCKET_BAD_PORT`로 **크래시루프**에 빠졌다
 * (node-01 축소 중 NRestarts=10, 즉시 롤백). `off`가 두 포트에서만 통하는 것을
 * 나머지가 모르고 있었던 셈이다 — 토큰의 의미는 리스너마다 같아야 한다.
 *
 * 잘못된 값은 **기동 실패**로 만든다(NaN을 조용히 흘리지 않는다). 설정 실수는 기동 시점에
 * 드러나야 하고, 그게 이 저장소가 `IONOSPHERE_LISTEN_*`에서 이미 쓰는 규율이다.
 */
function namedPort<K extends string>(key: K, raw: string | undefined): Record<K, number> | Record<string, never> {
  if (raw === undefined || raw.trim() === "") return {};
  const v = raw.trim().toLowerCase();
  if (v === "off" || v === "false" || v === "no" || v === "disabled") return {};
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > 65535) throw new Error(`포트 값이 잘못됨: ${key}=${raw} (숫자 또는 off)`);
  return { [key]: n } as Record<K, number>;
}

/**
 * 블롭 저장소 선택 — S3 설정이 **완전할 때만** S3를 쓴다.
 *
 * 왜 부분 설정을 기동 실패로 만드는가: 일부만 채워진 걸 조용히 무시하고 로컬 FS로 떨어지면,
 * 여러 서버가 각자 자기 디스크에 쓰면서 "왜 다른 노드에서 본문이 안 보이지"를 며칠 뒤에야
 * 알게 된다. 설정 실수는 기동 시점에 드러나야 한다.
 */
function buildBlobStore(): BlobStore | undefined {
  const keys = ["IONOSPHERE_S3_ENDPOINT", "IONOSPHERE_S3_BUCKET", "IONOSPHERE_S3_ACCESS_KEY", "IONOSPHERE_S3_SECRET_KEY"] as const;
  const present = keys.filter((k) => process.env[k]);
  if (present.length === 0) return undefined; // 로컬 FS(기존 동작)
  if (present.length !== keys.length) {
    const missing = keys.filter((k) => !process.env[k]);
    throw new Error(`S3 블롭 저장소 설정이 불완전하다 — 누락: ${missing.join(", ")}`);
  }
  const s3 = new S3BlobStore({
    endpoint: process.env.IONOSPHERE_S3_ENDPOINT!,
    region: process.env.IONOSPHERE_S3_REGION ?? "us-east-1",
    bucket: process.env.IONOSPHERE_S3_BUCKET!,
    accessKeyId: process.env.IONOSPHERE_S3_ACCESS_KEY!,
    secretAccessKey: process.env.IONOSPHERE_S3_SECRET_KEY!,
    ...(process.env.IONOSPHERE_S3_PREFIX ? { prefix: process.env.IONOSPHERE_S3_PREFIX } : {}),
    // Vultr·MinIO는 path-style이 필요하다. 틀리면 404/SignatureDoesNotMatch로 나온다.
    ...(process.env.IONOSPHERE_S3_PATH_STYLE === "1" ? { forcePathStyle: true } : {}),
    ...(process.env.IONOSPHERE_S3_TIMEOUT_MS ? { timeoutMs: Number(process.env.IONOSPHERE_S3_TIMEOUT_MS) } : {}),
  });
  return s3;
}

/** 양의 정수 env — 지정 시 값 검증, 미지정 시 빈 객체(기본값은 소비자가 갖는다). */
function positiveIntEnv<K extends string>(key: K, envName: string): Record<K, number> | Record<string, never> {
  const raw = process.env[envName];
  if (raw === undefined || raw.trim() === "") return {};
  const n = Number(raw);
  // ★NaN을 조용히 흘리지 않는다. `Number("1h")`는 NaN이고, 그게 flush 간격에 들어가면
  //   `setInterval(fn, NaN)`이 1ms 간격으로 돌아 감사 로그가 CPU를 태운다(2026-08-02 포트 사고와
  //   같은 부류 — 잘못된 값은 기동 시점에 드러나야 한다).
  if (!Number.isInteger(n) || n <= 0) throw new Error(`${envName} 값이 잘못됨: ${raw} (양의 정수)`);
  return { [key]: n } as Record<K, number>;
}

/**
 * 접근 감사 로그 설정 — `IONOSPHERE_AUDIT=1`이 아니면 `undefined`(완전 비활성).
 *
 * 이관 대상 버킷은 **블롭 버킷과 분리한다**(`IONOSPHERE_AUDIT_S3_*`). 같은 버킷을 쓰면 감사 기록의
 * 접근권한·보존기간을 메일 본문과 따로 걸 수 없고, 블롭 자격증명이 새면 감사 기록까지 함께
 * 지워질 수 있다 — 그건 감사 로그의 존재 이유를 무너뜨린다.
 *
 * `buildBlobStore`와 같은 규율로 **부분 설정을 기동 실패**로 만든다: 조용히 로컬 전용으로
 * 떨어지면 파일이 쌓이다 보존기간이 지나 버려지고, 그 사실을 몇 주 뒤 감사 요청이 왔을 때 안다.
 */
function buildAuditOptions(hostname: string): AppAuditOptions | undefined {
  if (process.env.IONOSPHERE_AUDIT !== "1") return undefined;
  const keys = ["IONOSPHERE_AUDIT_S3_ENDPOINT", "IONOSPHERE_AUDIT_S3_BUCKET", "IONOSPHERE_AUDIT_S3_ACCESS_KEY", "IONOSPHERE_AUDIT_S3_SECRET_KEY"] as const;
  const present = keys.filter((k) => process.env[k]);
  if (present.length !== 0 && present.length !== keys.length) {
    const missing = keys.filter((k) => !process.env[k]);
    throw new Error(`감사 로그 S3 설정이 불완전하다 — 누락: ${missing.join(", ")}`);
  }
  return {
    dir: process.env.IONOSPHERE_AUDIT_DIR ?? "/var/lib/ionosphere/audit",
    ...positiveIntEnv("flushIntervalMs", "IONOSPHERE_AUDIT_FLUSH_MS"),
    ...positiveIntEnv("shipIntervalMs", "IONOSPHERE_AUDIT_SHIP_INTERVAL_MS"),
    ...positiveIntEnv("localRetainDays", "IONOSPHERE_AUDIT_LOCAL_RETAIN_DAYS"),
    // 이관 키에 들어간다 — 세 인스턴스가 같은 버킷에 쓰므로 서로 달라야 한다(덮어쓰기 방지).
    shipHost: process.env.IONOSPHERE_AUDIT_SHIP_HOST ?? hostname,
    ...(present.length === keys.length
      ? {
          s3: {
            endpoint: process.env.IONOSPHERE_AUDIT_S3_ENDPOINT!,
            bucket: process.env.IONOSPHERE_AUDIT_S3_BUCKET!,
            accessKeyId: process.env.IONOSPHERE_AUDIT_S3_ACCESS_KEY!,
            secretAccessKey: process.env.IONOSPHERE_AUDIT_S3_SECRET_KEY!,
            region: process.env.IONOSPHERE_AUDIT_S3_REGION ?? "us-east-1",
            ...(process.env.IONOSPHERE_AUDIT_S3_PREFIX ? { prefix: process.env.IONOSPHERE_AUDIT_S3_PREFIX } : {}),
            // MinIO·Vultr는 path-style이 필요하다. 틀리면 404/SignatureDoesNotMatch로 나온다.
            ...(process.env.IONOSPHERE_AUDIT_S3_PATH_STYLE === "1" ? { forcePathStyle: true } : {}),
          },
        }
      : {}),
  };
}

/** IONOSPHERE_BLOB_GC 파싱 — 오타를 기본값으로 흘리지 않고 기동 실패로 만든다. */
function parseBlobGcMode(v: string): BlobGcMode {
  if (!isBlobGcMode(v)) throw new Error(`IONOSPHERE_BLOB_GC 값이 잘못됨: ${v} (off|mark|sweep)`);
  return v;
}

const LE_PROD = "https://acme-v02.api.letsencrypt.org/directory";

/** 필수 env — 없으면 `undefined`를 URL·경로 자리에 흘려보내지 않고 기동을 막는다. */
function requiredEnv(key: string): string {
  const v = process.env[key];
  if (!v) throw new Error(`${key}가 필요하다 (IONOSPHERE_TLS_MODE=${process.env.IONOSPHERE_TLS_MODE})`);
  return v;
}

/**
 * TLS 인증서 소스 env 파싱 — IONOSPHERE_TLS_MODE(none|selfsigned|file|url|acme). 미설정 시 undefined
 * (레거시 IONOSPHERE_IMAPS_TLS_* 경로 유지). dir 기본 /var/lib/ionosphere/tls.
 *   selfsigned: IONOSPHERE_TLS_CN(기본 hostname)·IONOSPHERE_TLS_SANS(콤마)
 *   file:       IONOSPHERE_IMAPS_TLS_KEY·IONOSPHERE_IMAPS_TLS_CERT
 *   url:        IONOSPHERE_TLS_URL_CERT·IONOSPHERE_TLS_URL_KEY·IONOSPHERE_TLS_URL_AUTH(선택 Bearer)
 *   acme:       IONOSPHERE_TLS_ACME_DOMAINS(콤마)·IONOSPHERE_TLS_ACME_EMAIL·IONOSPHERE_TLS_ACME_DIRECTORY(기본 LE)
 *               + IONOSPHERE_TLS_ACME_CHALLENGE=http-01(기본)|dns-01
 *                 http-01: IONOSPHERE_TLS_ACME_HTTP_PORT(기본 80) — 외부 서비스 불필요
 *                 dns-01 : IONOSPHERE_CF_DNS_TOKEN(필수)·IONOSPHERE_CF_ZONE_ID(선택) — Cloudflare DNS 전용
 *
 * ⚠ url·acme에 평문 `http:`를 쓰면 **개인키와 Bearer 토큰이 네트워크에 그대로 노출된다**
 *   (감사 H-1). 기동을 막지는 않지만 **기동 시 1회 + 페치할 때마다 매번** 경고를 남긴다 —
 *   라이브 cert-api가 관리 VPC 주소라 거부하면 배포가 통째로 막히기 때문이다. 로그가 계속
 *   쌓이는 것이 "아직 https로 안 바꿨다"는 지속 신호다.
 */
/** 로거는 certSource 생성보다 **먼저** 만든다 — url/acme 소스가 기동 시점에 평문 경고를 낸다. */
const logger = createLogger({
  level: (process.env.IONOSPHERE_LOG_LEVEL as LogLevel | undefined) ?? "info",
  ...(process.env.IONOSPHERE_LOG_FORMAT === "json" || process.env.IONOSPHERE_LOG_FORMAT === "pretty"
    ? { format: process.env.IONOSPHERE_LOG_FORMAT }
    : {}),
});

/**
 * ACME 챌린지 선택 — `IONOSPHERE_TLS_ACME_CHALLENGE=http-01|dns-01`.
 *
 * ★기본이 http-01인 이유(오픈소스 자립성): dns-01은 `DnsProvider` 구현이 필요하고 이 저장소에
 * 있는 건 Cloudflare용 하나뿐이다. 다른 DNS를 쓰는 사용자는 `IONOSPHERE_TLS_MODE=acme`를 아예
 * 쓸 수 없었다. http-01은 80포트만 있으면 외부 서비스 계정 없이 성립한다.
 *
 * env 미지정인데 CF 토큰이 있으면 dns-01로 간다 — 기존 배포가 토큰만 넣어 두었기 때문이고,
 * 기본값 변경으로 **조용히 챌린지가 바뀌면** 갱신이 몇 주 뒤에 만료로 드러난다.
 */
function acmeChallengeFromEnv(): AcmeChallenge {
  const want = process.env.IONOSPHERE_TLS_ACME_CHALLENGE?.trim().toLowerCase();
  const cfToken = process.env.IONOSPHERE_CF_DNS_TOKEN;
  const kind = want ?? (cfToken ? "dns-01" : "http-01");
  if (kind === "dns-01") {
    if (!cfToken) throw new Error("IONOSPHERE_TLS_ACME_CHALLENGE=dns-01엔 IONOSPHERE_CF_DNS_TOKEN 필요 (또는 http-01을 쓸 것)");
    return {
      type: "dns-01",
      dns: cloudflareDnsProvider({ apiToken: cfToken, ...(process.env.IONOSPHERE_CF_ZONE_ID ? { zoneId: process.env.IONOSPHERE_CF_ZONE_ID } : {}) }),
    };
  }
  if (kind !== "http-01") throw new Error(`알 수 없는 IONOSPHERE_TLS_ACME_CHALLENGE: ${kind} (http-01|dns-01)`);
  const portRaw = process.env.IONOSPHERE_TLS_ACME_HTTP_PORT;
  const port = portRaw === undefined || portRaw === "" ? 80 : Number(portRaw);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`포트 값이 잘못됨: IONOSPHERE_TLS_ACME_HTTP_PORT=${portRaw}`);
  // 리스너는 발급 동안만 연다 — 80포트를 상시 점유하면 같은 호스트의 웹서버와 충돌한다.
  const server = httpChallengeServer({ port, logger });
  return { type: "http-01", http: server, open: () => server.listen(), close: () => server.close() };
}

/**
 * 인증서 소스 하나를 env에서 만든다.
 *
 * @param prefix env 접두어. 기본 소스는 `IONOSPHERE_TLS_`, 리스너별은 `IONOSPHERE_TLS_<LISTENER>_`.
 * @param cacheSub 캐시 하위 디렉터리 — **리스너별로 반드시 달라야 한다**(아래 ★).
 */
function certSourceFrom(prefix: string, hostname: string, cacheSub?: string): CertSource | undefined {
  const env = (k: string): string | undefined => process.env[`${prefix}${k}`];
  const mode = env("MODE");
  if (!mode) return undefined;
  const baseDir = process.env.IONOSPHERE_TLS_DIR ?? "/var/lib/ionosphere/tls";
  /**
   * ★url 소스의 캐시 파일명은 고정(`url-cert.pem`/`url-key.pem`)이라, 여러 소스가 같은 디렉터리를
   * 쓰면 **서로의 캐시를 덮어쓴다.** 그러면 원격 페치 실패 시 폴백이 엉뚱한 이름의 인증서가 되고,
   * 그 포트는 조용히 잘못된 인증서를 제시한다(폴백은 원격이 죽었을 때만 쓰이므로 평소엔 안 드러난다).
   * acme/selfsigned도 같은 디렉터리에 계정키·인증서를 두므로 같은 이유로 나눈다.
   */
  const dir = cacheSub ? join(baseDir, cacheSub) : baseDir;
  const sans = env("SANS")?.split(",").map((s) => s.trim()).filter(Boolean);
  const cn = env("CN") ?? hostname;
  switch (mode) {
    case "none":
      return createCertSource({ mode: "none" });
    case "selfsigned":
      return createCertSource({ mode: "selfsigned", commonName: cn, ...(sans && sans.length ? { sans } : {}), dir });
    case "file":
      // 레거시 키 이름은 기본 소스에서만 인정한다 — 리스너별은 접두어 규칙을 따른다.
      return createCertSource({
        mode: "file",
        keyPath: env("KEY") ?? requiredEnv(prefix === "IONOSPHERE_TLS_" ? "IONOSPHERE_IMAPS_TLS_KEY" : `${prefix}KEY`),
        certPath: env("CERT") ?? requiredEnv(prefix === "IONOSPHERE_TLS_" ? "IONOSPHERE_IMAPS_TLS_CERT" : `${prefix}CERT`),
      });
    case "url": {
      const auth = env("URL_AUTH") ?? process.env.IONOSPHERE_TLS_URL_AUTH;
      /**
       * 원격이 준 인증서가 **우리 호스트용인지** 대조할 기준. 이게 없으면 침해된 cert 엔드포인트가
       * 자기가 가진 아무 인증서(+짝 맞는 키)나 밀어넣어도 그대로 설치된다. 광고 호스트를 그대로 쓴다 —
       * 클라이언트가 실제로 검증할 이름이 그것이기 때문(와일드카드 SAN은 checkHost가 처리한다).
       */
      const expectedHosts = [...new Set([cn, ...(sans ?? [])])].filter(Boolean);
      return createCertSource({
        mode: "url",
        certUrl: requiredEnv(`${prefix}URL_CERT`),
        keyUrl: requiredEnv(`${prefix}URL_KEY`),
        ...(auth ? { headers: { authorization: auth } } : {}),
        ...(expectedHosts.length ? { expectedHosts } : {}),
        logger,
        cacheDir: dir,
      });
    }
    case "acme": {
      const domains = (env("ACME_DOMAINS") ?? hostname).split(",").map((s) => s.trim()).filter(Boolean);
      const email = env("ACME_EMAIL") ?? process.env.IONOSPHERE_TLS_ACME_EMAIL;
      return createCertSource({
        mode: "acme",
        domains,
        directoryUrl: env("ACME_DIRECTORY") ?? process.env.IONOSPHERE_TLS_ACME_DIRECTORY ?? LE_PROD,
        challenge: acmeChallengeFromEnv(),
        dir,
        ...(email ? { contactEmail: email } : {}),
        logger,
      });
    }
    default:
      throw new Error(`알 수 없는 ${prefix}MODE: ${mode}`);
  }
}

const tlsCertSource = certSourceFrom("IONOSPHERE_TLS_", process.env.IONOSPHERE_HOSTNAME ?? "localhost");

/**
 * 리스너별 인증서 소스 — `IONOSPHERE_TLS_<LISTENER>_MODE`가 있는 리스너만 만든다.
 *
 * 예) 25번만 다른 인증서:
 *   IONOSPHERE_TLS_SMTP_MODE=url
 *   IONOSPHERE_TLS_SMTP_URL_CERT=https://…/mx/fullchain.pem
 *   IONOSPHERE_TLS_SMTP_URL_KEY=https://…/mx/privkey.pem
 *   IONOSPHERE_TLS_SMTP_CN=mx.example.com        # SAN 대조 기준(생략 시 IONOSPHERE_HOSTNAME)
 *   # URL_AUTH·ACME_EMAIL·ACME_DIRECTORY는 생략 시 전역(IONOSPHERE_TLS_*) 값을 물려받는다
 *
 * ★`IONOSPHERE_TLS_<L>_CN`을 꼭 줄 것: 생략하면 SAN 대조 기준이 `IONOSPHERE_HOSTNAME`이 되는데,
 * 리스너별로 인증서를 나누는 이유가 **이름이 다르기 때문**이라 그 기본값은 거의 항상 틀리다.
 * 틀리면 `assertUsableCert`가 거부해 그 포트만 TLS 없이 남는다(fail closed — 조용히 통과하지 않는다).
 */
const TLS_LISTENER_ENV: ReadonlyArray<readonly [TlsListenerName, string]> = [
  ["smtp", "SMTP"],
  ["submission", "SUBMISSION"],
  ["smtps", "SMTPS"],
  ["imap", "IMAP"],
  ["imaps", "IMAPS"],
  ["pop3", "POP3"],
  ["pop3s", "POP3S"],
  ["manageSieve", "MANAGESIEVE"],
  ["httpsFront", "HTTPS_FRONT"],
  ["adminTls", "ADMIN_TLS"],
];

function listenerCertSources(hostname: string): Partial<Record<TlsListenerName, CertSource>> {
  const out: Partial<Record<TlsListenerName, CertSource>> = {};
  for (const [name, envName] of TLS_LISTENER_ENV) {
    // 캐시 하위 디렉터리는 리스너 이름으로 나눈다(위 ★ 캐시 충돌 방지).
    const src = certSourceFrom(`IONOSPHERE_TLS_${envName}_`, hostname, name);
    if (src) out[name] = src;
  }
  return out;
}

const tlsListenerSources = listenerCertSources(process.env.IONOSPHERE_HOSTNAME ?? "localhost");

/**
 * 스마트호스트(587 릴레이) env 파싱 — IONOSPHERE_SMARTHOST(호스트), IONOSPHERE_SMARTHOST_PORT(기본 587),
 * IONOSPHERE_SMARTHOST_USER/PASS(SASL), IONOSPHERE_SMARTHOST_TLS(required|opportunistic|implicit|never, 기본 required).
 * 아웃바운드 25 차단 환경(Vultr 승인 대기 등)에서 실발송 경로로 사용 — docs/STATUS.md §9.
 */
function smarthostFromEnv(): SmarthostOptions | undefined {
  const host = process.env.IONOSPHERE_SMARTHOST;
  if (!host) return undefined;
  const user = process.env.IONOSPHERE_SMARTHOST_USER;
  const pass = process.env.IONOSPHERE_SMARTHOST_PASS;
  const tlsEnv = process.env.IONOSPHERE_SMARTHOST_TLS;
  const tlsModes: TlsMode[] = ["required", "opportunistic", "implicit", "never"];
  return {
    host,
    ...(process.env.IONOSPHERE_SMARTHOST_PORT ? { port: Number(process.env.IONOSPHERE_SMARTHOST_PORT) } : {}),
    ...(user && pass ? { auth: { user, pass } } : {}),
    ...(tlsEnv && (tlsModes as string[]).includes(tlsEnv) ? { tls: tlsEnv as TlsMode } : {}),
  };
}

const smarthost = smarthostFromEnv();

/** 레이트리밋 env(§8 ③) — 지정한 축만 오버라이드, 나머지는 DEFAULT_RATE_LIMIT. */
function rateLimitFromEnv(): { perMinute?: number; perHour?: number; perDay?: number } | undefined {
  const perMinute = Number(process.env.IONOSPHERE_RATE_PER_MINUTE);
  const perHour = Number(process.env.IONOSPHERE_RATE_PER_HOUR);
  const perDay = Number(process.env.IONOSPHERE_RATE_PER_DAY);
  const out = {
    ...(Number.isFinite(perMinute) && perMinute > 0 ? { perMinute } : {}),
    ...(Number.isFinite(perHour) && perHour > 0 ? { perHour } : {}),
    ...(Number.isFinite(perDay) && perDay > 0 ? { perDay } : {}),
  };
  return Object.keys(out).length > 0 ? out : undefined;
}

const rateLimit = rateLimitFromEnv();

/**
 * 재귀 DNS 리졸버 opt-in(IONOSPHERE_RECURSIVE_DNS=1). DNSBL 신뢰 조회를 위해 퍼블릭 리졸버
 * 차단을 회피하는 자체 리졸버(루트힌트→authoritative iterative)를 주입한다. 기본값은
 * 하위호환을 위해 NodeDnsResolver(OS 리졸버) 유지 — app.ts가 미지정 시 그것을 쓴다.
 */
const recursiveResolver = process.env.IONOSPHERE_RECURSIVE_DNS === "1" ? new RecursiveResolver() : undefined;

/**
 * 비밀 저장 게이트 — IONOSPHERE_MASTER_KEY가 없으면 DKIM 개인키와 스마트호스트 릴레이 비밀번호가
 * `plain$` **평문**으로 DB에 들어간다. 그러면 DB 백업 타르볼 하나가 곧 도메인 서명 권한이다.
 *
 * 왜 기동 거부인가: 지금까지 이 조건은 부팅 시 경고조차 없이 통과했고, 경고는 **키를 쓰는 시점**
 * (도메인 생성 등)에만 나와서 로그를 보고 있지 않으면 아무도 모른 채 몇 달이 지난다. 같은 파일에
 * 대조군이 있다 — acme 모드에 CF 토큰이 없으면 여기서 기동을 막는다. 같은 강도로 맞춘다.
 *
 * 다만 이미 평문으로 돌고 있는 배포를 배포 즉시 죽이면 안 되므로, 의도적 선택임을 표명하는
 * IONOSPHERE_ALLOW_PLAINTEXT_SECRETS=1 경로를 남긴다(그 경우 매 부팅 경고).
 */
/**
 * 걷어낸 env 키가 남아 있으면 **경고한다**(2026-08-06, 8443 제거).
 *
 * ★왜 조용히 무시하면 안 되는가: `listenersFromEnv`는 아는 이름만 읽으므로 남은 키가 기동을
 * 깨뜨리지는 않는다. 그래서 더 위험하다 — 운영자는 `IONOSPHERE_ADMIN_TLS_PORT=8443`이 env에
 * 있으니 관리 표면이 떠 있다고 믿는데 실제로는 아무것도 리슨하지 않는다. 이 저장소가 이미
 * 겪은 상태다(`IONOSPHERE_ADMIN_TLS_PORT`가 셋 다 있는데 `IONOSPHERE_ADMIN_PORT`가 없어 두 대가
 * 조용히 꺼져 있었다). **에러가 아니라 경고인 이유**는 반대 방향이 더 나쁘기 때문이다:
 * 배포 시점에 세 대가 동시에 기동 실패하면 그게 곧 장애다.
 */
function warnRemovedEnv(): void {
  for (const key of ["IONOSPHERE_ADMIN_TLS_PORT", "IONOSPHERE_LISTEN_ADMIN_TLS", "IONOSPHERE_ADMIN_HOST_PREFIX"]) {
    if (process.env[key] === undefined) continue;
    logger.warn(`${key}는 더 이상 쓰이지 않는다 — 관리 콘솔 이름은 IONOSPHERE_HOST_ADMIN으로 지정한다`, {
      component: "app",
      key,
    });
  }
}

/**
 * 80을 두 주인이 다투지 않게 한다 — 상시 리다이렉트 vs 발급 순간의 ACME http-01.
 *
 * ★왜 기동 시점에 막는가: 챌린지 서버는 발급이 필요할 때만 80을 연다(`http-challenge.ts`).
 * 리다이렉트가 80을 상시 점유하면 그 `listen()`이 EADDRINUSE로 실패하는데, 그 순간은
 * **인증서 갱신 시점**이다. 즉 설정 실수가 90일 뒤에, 그것도 인증서 만료라는 최악의 형태로
 * 드러난다(MTA-STS enforce에서는 곧 수신 장애다). 이 저장소의 규율대로 설정 실수는
 * 기동 시점에 드러나야 한다.
 *
 * 포트가 서로 다르면 공존을 허용한다 — `IONOSPHERE_TLS_ACME_HTTP_PORT`로 챌린지를 옮겨 두고
 * 앞단에서 그 경로만 넘기는 구성이 가능하기 때문이다. 겹칠 때만 막는다.
 */
function assertNoPort80Conflict(): void {
  const redirect = process.env.IONOSPHERE_HTTP_REDIRECT_PORT;
  if (redirect === undefined || redirect.trim() === "") return;
  if (process.env.IONOSPHERE_TLS_MODE !== "acme") return;
  const challenge = (process.env.IONOSPHERE_TLS_ACME_CHALLENGE ?? "http-01").trim().toLowerCase();
  if (challenge !== "http-01") return;
  const acmePort = process.env.IONOSPHERE_TLS_ACME_HTTP_PORT?.trim() || "80";
  if (acmePort !== redirect.trim()) return;
  throw new Error(
    `IONOSPHERE_HTTP_REDIRECT_PORT=${redirect}가 ACME http-01 챌린지 포트와 겹친다. ` +
      "리다이렉트가 그 포트를 상시 점유하면 **인증서 갱신이 실패한다**(90일 뒤에 드러난다). " +
      "IONOSPHERE_TLS_ACME_HTTP_PORT로 챌린지를 다른 포트로 옮기거나, dns-01을 쓰거나, 리다이렉트를 끌 것.",
  );
}

/**
 * 서비스별 Host 화이트리스트를 env에서 읽는다 — `IONOSPHERE_HOST_<서비스>`(콤마 구분).
 *
 * 예) `IONOSPHERE_HOST_MTA_STS=mta-sts.ionosphere.test,mta-sts.example.com`
 *
 * ★**콤마 목록인 이유**: `mta-sts.`·`autoconfig.`는 호스팅하는 **도메인마다** 이름이 다르다.
 * 값을 하나만 받게 하면 테넌트를 추가하는 순간 그 도메인의 정책 서빙이 조용히 404가 되고,
 * MTA-STS enforce에서는 그 테넌트의 **수신이 막힌다**. 화이트리스트의 비용은 "테넌트를
 * 늘릴 때 목록도 늘린다"이지 "하나만 쓴다"가 아니다.
 *
 * 미지정 서비스는 `{서비스}.localhost` 하나만 받는다(app.ts `hostsFor`). 즉 아무 것도 안
 * 넣으면 실서비스 이름은 전부 404다 — 의도한 fail closed이고, 그래서 **env가 배포보다
 * 먼저** 들어가야 한다.
 */
function serviceHostsFromEnv(): ServiceHosts {
  const out: Record<string, string[]> = {};
  for (const [name, spec] of Object.entries(HTTP_SERVICES)) {
    const raw = process.env[`IONOSPHERE_HOST_${spec.env}`];
    if (raw === undefined || raw.trim() === "") continue;
    const hosts = raw
      .split(",")
      .map((h) => h.trim().toLowerCase())
      .filter((h) => h.length > 0);
    // 값이 있는데 전부 걸러졌다면(콤마만 있는 등) 조용히 기본값으로 떨어지면 안 된다 —
    // 운영자는 지정했다고 믿는데 실제로는 `.localhost`만 받는 상태가 된다.
    if (hosts.length === 0) throw new Error(`IONOSPHERE_HOST_${spec.env} 값이 비었다: ${raw}`);
    out[name] = hosts;
  }
  return out as ServiceHosts;
}

function assertSecretsAtRest(): void {
  if (process.env.IONOSPHERE_MASTER_KEY) return;
  if (process.env.IONOSPHERE_ALLOW_PLAINTEXT_SECRETS === "1") {
    logger.warn("IONOSPHERE_MASTER_KEY 미설정 — DKIM 개인키·릴레이 비밀번호가 평문(plain$)으로 저장된다", { component: "app" });
    return;
  }
  throw new Error(
    "IONOSPHERE_MASTER_KEY 미설정 — DKIM 개인키와 스마트호스트 비밀번호가 평문(plain$)으로 DB에 저장된다. " +
      "키를 설정하거나, 평문 저장을 의도한 경우에만 IONOSPHERE_ALLOW_PLAINTEXT_SECRETS=1로 명시하라.",
  );
}

assertSecretsAtRest();
assertNoPort80Conflict();
warnRemovedEnv();

const hostname = process.env.IONOSPHERE_HOSTNAME ?? "localhost";

const app = new IonosphereApp({
  hostname,
  dbPath: process.env.IONOSPHERE_DB ?? "ionosphere.db",
  blobRoot: process.env.IONOSPHERE_BLOBS ?? "blobs",
  // DB 연결 문자열 — 여러 서버가 상태를 공유하려면 postgres://…를 쓴다.
  // 미지정 시 IONOSPHERE_DB(파일 경로) 그대로 = SQLite 단일 인스턴스(기존 동작).
  ...(process.env.IONOSPHERE_DB_URL ? { dbUrl: process.env.IONOSPHERE_DB_URL } : {}),
  // 공유 블롭 저장소(S3 호환). 미설정 시 로컬 FS — 서버를 분리하면 반드시 설정해야 한다.
  ...((): { blobs?: BlobStore; blobsFallback?: BlobStore } => {
    const blobs = buildBlobStore();
    if (!blobs) return {};
    // 전환기: 이미 로컬 디스크에 쌓인 블롭을 계속 읽어야 한다(읽기 폴백 + 양쪽 삭제).
    // 지표 ionosphere_blob_fallback_reads_total이 0으로 수렴하면 이 env를 빼서 래퍼를 벗긴다.
    // ⚠ 지표를 안 보고 벗기면 **옛 메일의 본문만 조용히 사라진다**.
    return process.env.IONOSPHERE_S3_MIGRATE_FROM_FS === "1"
      ? { blobs, blobsFallback: new FsBlobStore(process.env.IONOSPHERE_BLOBS ?? "blobs") }
      : { blobs };
  })(),
  // 역할별 분리를 위해 리스너를 끌 수 있다: `off`(대소문자 무시)면 그 리스너를 띄우지 않는다.
  // `0`은 "끔"이 아니라 임시 포트(테스트 관례)라 별도 토큰이 필요하다.
  ...optionalPort("smtpPort", process.env.IONOSPHERE_SMTP_PORT, 2525),
  ...optionalPort("pop3Port", process.env.IONOSPHERE_POP3_PORT, 1110),
  // IMAP(143/993) — 포트 지정 시에만 리슨 (Phase 3). 993은 전용 인증서 파일 경로 필요.
  ...namedPort("imapPort", process.env.IONOSPHERE_IMAP_PORT),
  ...namedPort("imapsPort", process.env.IONOSPHERE_IMAPS_PORT),
  // POP3S(암시적 TLS). 110 평문 인증은 인증서가 있으면 자동 차단되므로, 쓰려면 이 포트가 필요하다.
  ...namedPort("pop3sPort", process.env.IONOSPHERE_POP3S_PORT),
  ...namedPort("lmtpPort", process.env.IONOSPHERE_LMTP_PORT),
  // TLS 모드 지정 시 certSource, 아니면 레거시 imapsTls 경로(하위호환)
  ...(tlsCertSource ? { certSource: tlsCertSource } : {}),
  // 리스너별 인증서 — 지정한 포트만 위 기본 소스 대신 자기 소스를 쓴다.
  ...(Object.keys(tlsListenerSources).length ? { certSources: tlsListenerSources } : {}),
  ...(!tlsCertSource && process.env.IONOSPHERE_IMAPS_TLS_KEY && process.env.IONOSPHERE_IMAPS_TLS_CERT
    ? {
        imapsTls: {
          key: readFileSync(process.env.IONOSPHERE_IMAPS_TLS_KEY),
          cert: readFileSync(process.env.IONOSPHERE_IMAPS_TLS_CERT),
        },
      }
    : {}),
  // submission(587)은 포트 지정 시에만 리슨 — MTA 워커도 함께 기동됨 (app.ts)
  ...namedPort("submissionPort", process.env.IONOSPHERE_SUBMISSION_PORT),
  // 465 암시적 TLS submission — 인증서는 IONOSPHERE_IMAPS_TLS_*(암시적 TLS 공유) 재사용
  ...namedPort("smtpsPort", process.env.IONOSPHERE_SMTPS_PORT),
  ...(process.env.IONOSPHERE_MASTER_KEY ? { masterKey: process.env.IONOSPHERE_MASTER_KEY } : {}),
  // 587 릴레이(스마트호스트) — 지정 시 MX 직접 발송 대신 전량 릴레이
  ...(smarthost ? { smarthost } : {}),
  ...(rateLimit ? { rateLimit } : {}),
  // ManageSieve(4190, Phase 4) — Sieve 스크립트 관리
  ...namedPort("manageSievePort", process.env.IONOSPHERE_MANAGESIEVE_PORT),
  // JMAP HTTP(Phase 4) — 포트 지정 시에만 리슨. 외부 URL은 Session 생성용(리버스 프록시 뒤)
  ...namedPort("jmapPort", process.env.IONOSPHERE_JMAP_PORT),
  ...(process.env.IONOSPHERE_JMAP_BASE_URL ? { jmapBaseUrl: process.env.IONOSPHERE_JMAP_BASE_URL } : {}),
  // 관리 API — 포트 지정 시에만 리슨
  ...namedPort("adminPort", process.env.IONOSPHERE_ADMIN_PORT),
  ...(process.env.IONOSPHERE_ADMIN_TOKEN ? { adminRootToken: process.env.IONOSPHERE_ADMIN_TOKEN } : {}),
  /**
   * 관리 콘솔을 얹을 Host 접두사(예: `admin.`). **미지정 시 관리 콘솔에 원격으로 닿을 수 없다**
   * — 평문 `IONOSPHERE_ADMIN_PORT`는 항상 루프백에만 붙는다. (예전의 8443은 걷어냈다.)
   *
   * 이 vhost는 내부 인터페이스로 착지한 연결만 받는다(`exposure: "internal"`). 그 위에 토큰.
   * 인증서는 `IONOSPHERE_TLS_ADMIN_TLS_*` 소스의 것을 SNI로 제시하므로 **`IONOSPHERE_TLS_ADMIN_TLS_CN`을
   * 반드시 그 이름으로 줄 것** — 생략하면 SAN 대조 기준이 `IONOSPHERE_HOSTNAME`이 되어 자료 적재가
   * 거부되고(fail closed) 443의 admin 이름만 기본 인증서를 제시하다 이름 불일치로 깨진다.
   *
   * 소문자로 정규화한다: 라우트 매칭이 Host 헤더를 소문자로 낮춰 비교하므로(https-front.ts),
   * 대문자로 적으면 **아무것도 매칭되지 않는 채 조용히 켜진 것처럼 보인다**.
   */
  serviceHosts: serviceHostsFromEnv(),
  // 클라이언트 자동설정 — 포트 지정 시에만 리슨(평문 HTTP, TLS 프록시 뒤 권장)
  ...namedPort("autoconfigPort", process.env.IONOSPHERE_AUTOCONFIG_PORT),
  ...(process.env.IONOSPHERE_AUTOCONFIG_BRAND ? { autoconfigBrand: process.env.IONOSPHERE_AUTOCONFIG_BRAND } : {}),
  // 역할별 호스트(클라이언트 광고용). 미지정 시 IONOSPHERE_HOSTNAME.
  ...(process.env.IONOSPHERE_IMAP_HOST ? { imapHost: process.env.IONOSPHERE_IMAP_HOST } : {}),
  ...(process.env.IONOSPHERE_SUBMISSION_HOST ? { submissionHost: process.env.IONOSPHERE_SUBMISSION_HOST } : {}),
  // POP3는 **호스트를 명시할 때만** 자동설정에 실린다(다른 둘과 달리 hostname 폴백이 없다) —
  // 995를 연 것과 클라이언트에 권하는 것은 다른 결정이고, 폴백하면 전자가 후자를 강제한다.
  ...(process.env.IONOSPHERE_POP3_HOST ? { pop3Host: process.env.IONOSPHERE_POP3_HOST } : {}),
  // ⚠ MTA-STS mx — MX 레코드가 가리키는 호스트. 위 둘과 같이 바꾸면 enforce에서 수신이 죽는다.
  ...(process.env.IONOSPHERE_MX_HOST ? { mxHost: process.env.IONOSPHERE_MX_HOST } : {}),
  // MTA-STS 정책 서빙 모드(enforce|testing|none) — autoconfig 서버가 /.well-known/mta-sts.txt 응답
  ...(process.env.IONOSPHERE_MTA_STS_MODE === "enforce" || process.env.IONOSPHERE_MTA_STS_MODE === "testing" || process.env.IONOSPHERE_MTA_STS_MODE === "none"
    ? { mtaStsMode: process.env.IONOSPHERE_MTA_STS_MODE }
    : {}),
  // MTA-STS 발신측 강제(발송 시 수신 도메인 정책 준수)
  ...(process.env.IONOSPHERE_MTA_STS_ENFORCE === "1" ? { mtaStsEnforce: true } : {}),
  // DANE 발신측(RFC 7672) — TLSA를 DNSSEC 검증해 조회하고 인증서를 고정한다.
  ...(process.env.IONOSPHERE_DANE === "1" ? { dane: true } : {}),
  // SMTP STARTTLS(25/587) — MTA-STS enforce의 전제. 런타임 미지원 시 자동 비활성.
  ...(process.env.IONOSPHERE_SMTP_STARTTLS === "1" ? { smtpStartTls: true } : {}),
  /**
   * 신뢰 릴레이 CIDR(쉼표 구분) — 우리가 운영하는 MTA의 접속 대역. 예: `10.0.82.134/32`.
   *
   * 역할을 여러 대로 나누면(docs/SPLIT.md) 로컬 도메인 메일이 MSA → MX로 한 홉을 더 타는데,
   * MX가 보는 접속 IP가 사설 주소라 SPF가 **구조적으로 fail**한다. 그 fail은 발신자에 대한
   * 사실이 아니라 우리 배치에 대한 사실이라, 여기에 그 대역을 적어 검사 대상에서 뺀다.
   * 무엇이 꺼지고 무엇이 안 꺼지는지는 `IonosphereSmtpBackendOptions.trustedRelays` 주석에 있다.
   *
   * ⚠ 잘못 적으면 **기동에 실패한다**(파싱 시 throw). 조용히 빈 목록이 되는 것보다 낫다 —
   * 신뢰 목록이 오타로 비면 운영자는 예외가 걸린 줄 알고 계속 fail을 본다.
   */
  ...((): { trustedRelays?: string[] } => {
    const raw = process.env.IONOSPHERE_TRUSTED_RELAYS;
    if (!raw || raw.trim() === "") return {};
    return { trustedRelays: raw.split(",").map((s) => s.trim()).filter((s) => s !== "") };
  })(),
  // HTTPS 프론트(443 종단) — 지정 시 JMAP/autoconfig 앞단 TLS 종단 + Host 리버스 프록시
  ...namedPort("httpsFrontPort", process.env.IONOSPHERE_HTTPS_FRONT_PORT),
  /**
   * 80 → 443 리다이렉트(보통 `80`). 443 프론트가 뜰 때만 함께 얹힌다.
   *
   * ⚠ ACME http-01과 **같은 포트를 다툰다** — 아래 `assertNoPort80Conflict`가 막는다.
   */
  ...namedPort("httpRedirectPort", process.env.IONOSPHERE_HTTP_REDIRECT_PORT),
  // 관측성 — 포트 지정 시에만 계측·노출(평문 HTTP, 내부망 전용)
  ...namedPort("metricsPort", process.env.IONOSPHERE_METRICS_PORT),
  // 기본은 127.0.0.1 — 원격 스크레이프가 필요할 때만 명시 지정(예: 0.0.0.0). app.ts 주석 참조.
  ...(process.env.IONOSPHERE_METRICS_HOST ? { metricsHost: process.env.IONOSPHERE_METRICS_HOST } : {}),
  /**
   * 서비스별 리스너 오버라이드 — `IONOSPHERE_LISTEN_<SERVICE>=<host>:<port>` / `off`.
   * 예) IONOSPHERE_LISTEN_ADMIN=0.0.0.0:8080, IONOSPHERE_LISTEN_METRICS=off
   * 지정하지 않은 서비스는 종전 동작 그대로다(listeners.ts).
   */
  listeners: listenersFromEnv(),
  // 블롭 GC: 기본 "mark"(참조 해제·doomed 표시만, 파일 삭제 없음). 지표를 보고 "sweep"으로 올린다.
  // 잘못된 값은 조용히 기본값으로 흘리지 않고 기동을 막는다 — "off"를 오타로 적어 GC가 도는 것도,
  // "sweep"을 오타로 적어 안 도는 것도 둘 다 나중에야 드러나기 때문.
  // 접근 감사 로그 — IONOSPHERE_AUDIT=1일 때만. 부분 S3 설정은 기동 실패(buildAuditOptions 주석).
  ...((): { audit?: AppAuditOptions } => {
    const audit = buildAuditOptions(hostname);
    return audit ? { audit } : {};
  })(),
  ...(process.env.IONOSPHERE_BLOB_GC ? { blobGcMode: parseBlobGcMode(process.env.IONOSPHERE_BLOB_GC) } : {}),
  ...(process.env.IONOSPHERE_BLOB_GC_GRACE_MS ? { blobGcGraceMs: Number(process.env.IONOSPHERE_BLOB_GC_GRACE_MS) } : {}),
  ...(process.env.IONOSPHERE_BLOB_UPLOAD_TTL_MS ? { blobUploadTtlMs: Number(process.env.IONOSPHERE_BLOB_UPLOAD_TTL_MS) } : {}),
  // SRS 포워딩 — 비밀키 지정 시에만 forward_to 포워딩·바운스 reverse 활성
  ...(process.env.IONOSPHERE_SRS_SECRET ? { srsSecret: process.env.IONOSPHERE_SRS_SECRET } : {}),
  // 포워딩·redirect·바운스 relay의 테넌트별 시간당 총량 상한(기본 1000) — 계정 축 레이트리밋이
  // 걸리지 않는 갈래라 여기가 유일한 상한이다.
  ...(Number.isFinite(Number(process.env.IONOSPHERE_RELAY_PER_HOUR)) && Number(process.env.IONOSPHERE_RELAY_PER_HOUR) > 0
    ? { relayPerHour: Number(process.env.IONOSPHERE_RELAY_PER_HOUR) }
    : {}),
  // 내부 전용: 호스팅하지 않는 도메인으로의 발송을 즉시 거절한다(아웃바운드 25 차단 + 스마트호스트 없음).
  // 안 켜면 사용자는 "보냈다"고 믿은 채 몇 시간 뒤에야 바운스를 받는다.
  ...(process.env.IONOSPHERE_LOCAL_ONLY === "1" ? { localOnly: true } : {}),
  // 발신자 사칭 차단(테넌트 내부) — **기본 on**. 알리아스가 아닌 방식으로 대리 발송을 구현한
  // 배포만 끈다. 끄면 같은 테넌트의 다른 계정을 사칭해 보낼 수 있다.
  ...(process.env.IONOSPHERE_REQUIRE_SENDER_OWNERSHIP === "0" ? { requireSenderOwnership: false } : {}),
  // 배경 워커 on/off — 역할별 서버 분리 시 어느 인스턴스가 무엇을 돌릴지 정한다.
  // 옵션은 예전부터 있었는데 여기서 읽지 않아 **프로덕션에서 켜고 끌 방법이 없었다**.
  // 리스·클레임 가드가 있어 여러 대가 돌려도 정확성은 깨지지 않지만, 중복 작업은 낭비다.
  ...(process.env.IONOSPHERE_RUN_MTA_WORKER ? { runMtaWorker: process.env.IONOSPHERE_RUN_MTA_WORKER === "1" } : {}),
  ...(process.env.IONOSPHERE_RUN_WEBHOOK_WORKER ? { runWebhookWorker: process.env.IONOSPHERE_RUN_WEBHOOK_WORKER === "1" } : {}),
  ...(process.env.IONOSPHERE_RUN_REAPER ? { runReaper: process.env.IONOSPHERE_RUN_REAPER === "1" } : {}),
  // IONOSPHERE_RECURSIVE_DNS=1 시 자체 재귀 리졸버 주입(DNSBL 신뢰 조회). 미설정 시 app.ts 기본값.
  ...(recursiveResolver ? { resolver: recursiveResolver } : {}),
  logger,
});

await app.start();

/**
 * 프로세스 레벨 가드 — 올인원 배포에서는 리스너 전부가 한 프로세스에 있어서,
 * 어느 한 갈래의 처리되지 않은 오류가 **메일 서버 전체**를 내린다.
 *
 * 둘을 다르게 다루는 이유:
 *  - unhandledRejection: 대개 fire-and-forget 비동기 한 갈래의 문제다. 나머지 연결까지 죽일
 *    이유가 없으므로 크게 남기고 계속 돈다(Node 기본은 종료 — 여기서 의도적으로 바꾼다).
 *  - uncaughtException: 동기 스택이 깨진 것이라 상태가 오염됐을 수 있다. 그대로 서빙하면
 *    조용히 잘못된 결과를 낼 수 있으므로 정리 후 종료하고 supervisor가 재시작하게 한다.
 */
process.on("unhandledRejection", (reason: unknown) => {
  logger.error("unhandled rejection — 계속 진행", {
    component: "app",
    error: reason instanceof Error ? reason.message : String(reason),
    ...(reason instanceof Error && reason.stack ? { stack: reason.stack } : {}),
  });
});

process.on("uncaughtException", (err: Error) => {
  logger.error("uncaught exception — 상태 오염 가능, 종료한다", {
    component: "app",
    error: err.message,
    ...(err.stack ? { stack: err.stack } : {}),
  });
  void app
    .stop()
    .catch(() => undefined)
    .then(() => process.exit(1));
});

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    logger.info("shutting down", { component: "app", signal: sig });
    void app.stop().then(() => process.exit(0));
  });
}
