/**
 * 감사 로그 이관 수동 구동 — `AuditShipper.tick()`을 한 번 돈다.
 *
 * 왜 필요한가: 워커는 1시간 간격으로만 돌고(`audit-shipper.ts` `DEFAULT_INTERVAL_MS`),
 * 첫 tick도 기동 후 1시간 뒤다. 그래서
 *   - **이관이 실제로 되는지 확인**하려면 한 시간을 기다려야 하고,
 *   - 서비스 종료(인스턴스 교체·장기 정지) 직전에 남은 파일을 밀어 넣을 방법이 없다.
 * 둘 다 "설정은 넣었는데 이관이 되는지는 모른다"로 끝나는 경로다 — 그 상태를 없애려고 만들었다.
 *
 * ★서버 프로세스와 **별개 프로세스**로 돈다. 같은 디렉터리를 보지만 오늘 파일은 양쪽 모두
 * 건드리지 않으므로(`tick()`이 오늘 날짜를 제외한다) 경합이 없다. 어제 이전 파일은 서버가
 * 이관하든 이 스크립트가 이관하든 결과가 같고, 둘이 겹쳐도 업로드는 멱등(같은 키에 같은 내용)
 * 이며 삭제는 실패해도 다음 tick에 재시도된다.
 *
 * 사용(서버에서):
 *   sudo -u ionosphere node --experimental-strip-types scripts/audit-ship.ts
 *   sudo -u ionosphere node --experimental-strip-types scripts/audit-ship.ts --dry-run
 *
 * env는 서버와 같은 것을 읽는다(`/etc/ionosphere.env`를 소싱하거나 systemd 환경에서 실행).
 */
import { AuditShipper } from "../apps/server/src/audit-shipper.ts";
import { createLogger } from "../packages/core/src/log.ts";
import { applyLegacyEnvAliases } from "../packages/core/src/env-legacy.ts";
// ★구 `IONOSPHERE_*` env를 새 이름으로 넘긴다 — env를 처음 읽기 전에(packages/core/src/env-legacy.ts).
applyLegacyEnvAliases();

const dryRun = process.argv.includes("--dry-run");
const log = createLogger({ format: "pretty" });

const dir = process.env.IONOSPHERE_AUDIT_DIR ?? "/var/lib/ionosphere/audit";
const host = process.env.IONOSPHERE_AUDIT_SHIP_HOST ?? process.env.IONOSPHERE_HOSTNAME ?? "unknown";

// 부분 설정을 조용히 로컬 전용으로 떨어뜨리지 않는다 — main.ts `buildAuditOptions`와 같은 규율.
// 여기서 조용히 넘어가면 "이관을 돌렸다"는 출력이 거짓이 된다.
const endpoint = process.env.IONOSPHERE_AUDIT_S3_ENDPOINT;
const bucket = process.env.IONOSPHERE_AUDIT_S3_BUCKET;
const accessKeyId = process.env.IONOSPHERE_AUDIT_S3_ACCESS_KEY;
const secretAccessKey = process.env.IONOSPHERE_AUDIT_S3_SECRET_KEY;
if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) {
  console.error(
    "IONOSPHERE_AUDIT_S3_ENDPOINT/_BUCKET/_ACCESS_KEY/_SECRET_KEY가 모두 필요하다(이관 대상 미설정).",
  );
  process.exit(2);
}

if (host === "unknown") {
  // 호스트가 키에 들어간다 — 세 인스턴스가 같은 버킷을 쓰므로 이게 없으면 서로 덮어쓴다.
  console.error("IONOSPHERE_HOSTNAME(또는 IONOSPHERE_AUDIT_SHIP_HOST)이 필요하다 — 키 충돌 방지용.");
  process.exit(2);
}

const shipper = new AuditShipper({
  dir,
  host,
  logger: log,
  target: {
    endpoint,
    bucket,
    accessKeyId,
    secretAccessKey,
    region: process.env.IONOSPHERE_AUDIT_S3_REGION ?? "us-east-1",
    ...(process.env.IONOSPHERE_AUDIT_S3_PREFIX ? { prefix: process.env.IONOSPHERE_AUDIT_S3_PREFIX } : {}),
    ...(process.env.IONOSPHERE_AUDIT_S3_PATH_STYLE === "1" ? { forcePathStyle: true } : {}),
    // --dry-run은 **네트워크에 나가지 않는다**: fetch를 가로채 성공을 흉내내지 않고
    // 실패로 돌려 삭제 경로를 막는다. 확인용 실행이 파일을 지우면 안 된다.
    ...(dryRun ? { fetch: (async () => new Response("dry-run", { status: 599 })) as typeof fetch } : {}),
  },
});

const r = await shipper.tick();
console.log(
  `${dryRun ? "[dry-run] " : ""}dir=${dir} host=${host} bucket=${bucket} → shipped=${r.shipped} failed=${r.failed} dropped=${r.dropped}`,
);
if (dryRun) console.log("[dry-run] 업로드를 일부러 실패시켰다 — failed 건수가 곧 '이관 대상 파일 수'다.");
// 실패가 있으면 0이 아닌 코드로 — 크론/수동 확인에서 성공처럼 읽히지 않게.
process.exit(!dryRun && r.failed > 0 ? 1 : 0);
