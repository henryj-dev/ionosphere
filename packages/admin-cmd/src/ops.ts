/**
 * 운영 명령군 — 큐·차단목록·사용량·API 키·테넌트·스마트호스트·TLS.
 *
 * 이 파일에 **저장소에 없던 기능이 여럿 새로 생긴다**:
 *  - 큐 재시도·취소: 조회만 가능해서 멈춘 메일을 손보려면 DB를 직접 UPDATE해야 했다.
 *  - 스마트호스트 CRUD: CLI에만 있었다(SSH 없이는 릴레이를 못 바꿨다).
 *  - 테넌트 목록: 생성만 있고 조회가 없어 root가 자기가 만든 테넌트 id를 되찾을 방법이 없었다.
 */
import { randomBytes } from "node:crypto";
import { open, seal, sha256hex, ulid } from "@ionosphere/core";
import {
  isMtaQueueStatus,
  isSmarthostTls,
  MTA_QUEUE_STATUS,
  SMARTHOST_TENANT_DEFAULT,
  SMARTHOST_TLS,
  type DbDriver,
} from "@ionosphere/db";
import { CommandError, type Command, type CommandContext } from "./types.ts";

function requireTenant(ctx: CommandContext): string {
  if (ctx.tenantId === undefined || ctx.tenantId === "") {
    throw new CommandError("invalid", "tenantId가 필요합니다", "root 토큰으로 호출할 때는 tenantId를 지정하십시오");
  }
  return ctx.tenantId;
}

/** API 키 스코프 — 모르는 값을 저장하면 오타가 곧 권한 0인 키가 된다(조용히 위험). */
const KNOWN_SCOPES = new Set(["admin", "read", "write"]);

const QUEUE_STATUS_CHOICES = Object.entries(MTA_QUEUE_STATUS).map(([k, v]) => ({ value: String(v), label: k }));

/**
 * TLS 모드 — **정본은 `@ionosphere/db`의 `SMARTHOST_TLS`다.** 여기서 새로 적지 않는다.
 *
 * ⚠ 한때 이 파일이 자기 사본(`{never:0, opportunistic:1, required:2, implicit:3}`)을 들고 있었고
 * 정본(`{required:0, opportunistic:1, implicit:2, never:3}`)과 **완전히 달랐다.** 그대로 두면
 * `--tls=implicit`으로 설정한 릴레이가 DB에 `never`(평문 고정)로 저장된다 — 465 릴레이가
 * 평문으로 붙으려다 실패하거나, 최악의 경우 자격증명이 평문으로 나간다.
 * DB 컬럼 인코딩은 스키마 소유 패키지가 갖는다는 규약(CLAUDE.md 소유권 표)이 정확히 이것을 막는다.
 */
const TLS_MODE_NAME: Record<number, string> = Object.fromEntries(
  Object.entries(SMARTHOST_TLS).map(([name, code]) => [code, name]),
);
/** 사람이 읽는 설명은 여기 붙인다 — 이름 자체는 정본이 준다. */
const TLS_HINTS: Record<string, string> = {
  required: "required (STARTTLS 필수)",
  opportunistic: "opportunistic (되면 쓰고 안 되면 평문)",
  implicit: "implicit (465 암시적 TLS)",
  never: "never (평문 고정 — 루프백 외 사용 금지)",
};
const TLS_CHOICES = Object.keys(SMARTHOST_TLS).map((name) => ({ value: name, label: TLS_HINTS[name] ?? name }));

/** 스마트호스트 범위의 테넌트를 정한다 — `--domain`을 주면 **그 도메인을 소유한 테넌트**다. */
async function smarthostScope(ctx: CommandContext, db: DbDriver, domain: string): Promise<string> {
  if (domain === SMARTHOST_TENANT_DEFAULT) return requireTenant(ctx);
  const { rows } = await db.query({ sql: "SELECT tenant_id FROM domains WHERE name = ? LIMIT 1", params: [domain] });
  const owner = rows[0];
  if (!owner) {
    throw new CommandError("notFound", `등록되지 않은 도메인: ${domain}`, "먼저 domain-add로 등록하십시오");
  }
  const ownerTenant = String(owner.tenant_id);
  // 남의 도메인에 릴레이를 붙이면 그 도메인 발신이 이쪽 릴레이를 타게 된다 — 테넌트 경계 위반.
  if (!ctx.isRoot && ctx.tenantId !== undefined && ownerTenant !== ctx.tenantId) {
    throw new CommandError("denied", `이 테넌트가 소유하지 않은 도메인입니다: ${domain}`);
  }
  return ownerTenant;
}

export const opsCommands: readonly Command[] = [
  // ── 큐 ───────────────────────────────────────────────────────────────
  {
    spec: {
      name: "queue-list",
      group: "큐",
      label: "큐 조회",
      summary: "발송 대기·실패 건을 조회한다.",
      readOnly: true,
      args: [{ name: "status", label: "상태", type: "enum", required: false, choices: QUEUE_STATUS_CHOICES }],
      fields: [
        { key: "rcpt", label: "수신자" },
        { key: "status", label: "상태", encoding: "queueStatus" },
        { key: "attempts", label: "시도", format: "number" },
        { key: "nextAttempt", label: "다음 시도", format: "time" },
        { key: "lastError", label: "오류" },
        { key: "id", label: "id" },
      ],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      let statusFilter: number | null = null;
      if (args.status !== undefined) {
        const n = Number(args.status);
        // 외부 입력이라 유효한 status만 받는다 — 예전엔 Number()로 NaN이 그대로 들어갔다.
        if (!Number.isInteger(n) || !isMtaQueueStatus(n)) throw new CommandError("invalid", `잘못된 상태: ${args.status}`);
        statusFilter = n;
      }
      const sql =
        statusFilter !== null
          ? "SELECT id, rcpt, status, attempts, next_attempt, last_error FROM mta_queue WHERE tenant_id = ? AND status = ? ORDER BY created_at"
          : "SELECT id, rcpt, status, attempts, next_attempt, last_error FROM mta_queue WHERE tenant_id = ? ORDER BY created_at";
      const { rows } = await ctx.db.query({ sql, params: statusFilter !== null ? [tenantId, statusFilter] : [tenantId] });
      return {
        rows: rows.map((r) => ({
          id: String(r.id),
          rcpt: String(r.rcpt),
          status: Number(r.status),
          attempts: Number(r.attempts),
          nextAttempt: Number(r.next_attempt),
          lastError: r.last_error == null ? null : String(r.last_error),
        })),
      };
    },
  },
  {
    /**
     * ★재시도 — 저장소에 없던 명령. 조회만 가능해서 멈춘 메일을 손보려면 DB를 직접 UPDATE해야 했다.
     *
     * `inFlight`는 건드리지 않는다. 워커가 그 행을 잡고 있는 중이라 상태를 되돌리면 **같은 메일이
     * 두 번 발송된다** — 큐에서 가장 조심해야 할 사고다. 지연·바운스만 되살린다.
     */
    spec: {
      name: "queue-retry",
      group: "큐",
      label: "큐 재시도",
      summary: "지연·바운스된 건을 즉시 재시도 대상으로 되돌린다(발송 중인 건은 제외).",
      readOnly: false,
      args: [
        { name: "id", label: "큐 id", type: "string", required: false, help: "비우면 지연·바운스 전체를 되살립니다." },
      ],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const now = Date.now();
      const retryable = [MTA_QUEUE_STATUS.deferred, MTA_QUEUE_STATUS.bounced];
      const results = args.id
        ? await ctx.db.batch([
            {
              sql: `UPDATE mta_queue SET status = ?, next_attempt = ?, last_error = NULL
                    WHERE id = ? AND tenant_id = ? AND status IN (?, ?)`,
              params: [MTA_QUEUE_STATUS.queued, now, args.id, tenantId, retryable[0], retryable[1]],
            },
          ])
        : await ctx.db.batch([
            {
              sql: `UPDATE mta_queue SET status = ?, next_attempt = ?, last_error = NULL
                    WHERE tenant_id = ? AND status IN (?, ?)`,
              params: [MTA_QUEUE_STATUS.queued, now, tenantId, retryable[0], retryable[1]],
            },
          ]);
      const changed = results[0]!.changes;
      if (changed === 0) {
        throw new CommandError(
          "notFound",
          args.id ? `재시도할 수 없는 건입니다: ${args.id}` : "재시도 대상이 없습니다",
          "발송 중(inFlight)·완료된 건은 재시도할 수 없습니다",
        );
      }
      return { data: { retried: changed }, message: `${changed}건을 재시도 큐에 넣었습니다` };
    },
  },
  {
    /**
     * 취소 — 행을 지우지 않고 `canceled`로 표시한다. 지우면 "왜 안 갔나"에 답할 근거가 사라진다.
     * `inFlight`를 제외하는 이유는 재시도와 같다(워커가 잡고 있는 행을 건드리지 않는다).
     */
    spec: {
      name: "queue-cancel",
      group: "큐",
      label: "큐 취소",
      summary: "대기·지연 중인 발송을 취소한다. 되돌릴 수 없다.",
      readOnly: false,
      destructive: true,
      irreversible: true,
      args: [{ name: "id", label: "큐 id", type: "string", required: true }],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const results = await ctx.db.batch([
        {
          sql: `UPDATE mta_queue SET status = ?, last_error = ?
                WHERE id = ? AND tenant_id = ? AND status IN (?, ?, ?)`,
          params: [
            MTA_QUEUE_STATUS.canceled,
            "관리자가 취소함",
            args.id!,
            tenantId,
            MTA_QUEUE_STATUS.queued,
            MTA_QUEUE_STATUS.deferred,
            MTA_QUEUE_STATUS.bounced,
          ],
        },
      ]);
      if (results[0]!.changes === 0) {
        throw new CommandError("notFound", `취소할 수 없는 건입니다: ${args.id}`, "발송 중(inFlight)·완료된 건은 취소할 수 없습니다");
      }
      return { data: { canceled: true }, message: `취소됨: ${args.id}` };
    },
  },
  // ── 차단 목록 ────────────────────────────────────────────────────────
  {
    spec: {
      name: "suppression-list",
      group: "차단목록",
      label: "차단 목록",
      summary: "바운스·재시도 소진으로 발송이 막힌 수신자를 조회한다.",
      readOnly: true,
      args: [],
      fields: [
        { key: "email", label: "주소" },
        { key: "reason", label: "사유", encoding: "suppressionReason" },
        { key: "source", label: "출처" },
        { key: "createdAt", label: "등록", format: "time" },
        { key: "expiresAt", label: "만료", format: "time" },
        { key: "active", label: "차단 중" },
      ],
    },
    async run(ctx) {
      const tenantId = requireTenant(ctx);
      const { rows } = await ctx.db.query({
        sql: "SELECT email, reason, source, created_at, expires_at FROM suppressions WHERE tenant_id = ? ORDER BY created_at DESC",
        params: [tenantId],
      });
      /**
       * 만료된 행도 감추지 않는다 — 왜 한 번 막혔는지가 운영 정보고, 반복해서 걸리는 주소는
       * 목록에 남아 있어야 알아볼 수 있다. 대신 지금 실제로 막고 있는지를 `active`로 명시한다.
       */
      const now = Date.now();
      return {
        rows: rows.map((r) => {
          const expiresAt = r.expires_at == null ? null : Number(r.expires_at);
          return {
            email: String(r.email),
            reason: Number(r.reason),
            source: r.source == null ? null : String(r.source),
            createdAt: Number(r.created_at),
            expiresAt,
            active: expiresAt === null || expiresAt > now,
          };
        }),
      };
    },
  },
  {
    spec: {
      name: "suppression-remove",
      group: "차단목록",
      label: "차단 해제",
      summary: "해제하면 다음 발송부터 다시 시도한다. 왜 막혔는지의 기록도 함께 사라진다.",
      readOnly: false,
      destructive: true,
      irreversible: true,
      args: [{ name: "email", label: "주소", type: "string", required: true }],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const results = await ctx.db.batch([
        { sql: "DELETE FROM suppressions WHERE tenant_id = ? AND email = ?", params: [tenantId, args.email!.toLowerCase()] },
      ]);
      if (results[0]!.changes === 0) throw new CommandError("notFound", `차단 목록에 없습니다: ${args.email}`);
      return { data: { deleted: true }, message: `차단 해제됨: ${args.email}` };
    },
  },
  // ── 사용량 ───────────────────────────────────────────────────────────
  {
    spec: {
      name: "usage",
      group: "사용량",
      label: "사용량",
      summary: "저장 용량·계정 수와 최근 발송 집계를 본다.",
      readOnly: true,
      args: [{ name: "windowDays", label: "집계 창(일)", type: "number", required: false, placeholder: "30" }],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const d = args.windowDays === undefined ? NaN : Number(args.windowDays);
      const windowMs = Number.isFinite(d) && d > 0 ? d * 86_400_000 : undefined;
      const usage = await ctx.store.tenantUsage(tenantId, windowMs !== undefined ? { windowMs } : {});
      return { data: usage as unknown as Record<string, unknown> };
    },
  },
  // ── 테넌트 ───────────────────────────────────────────────────────────
  {
    spec: {
      name: "tenant-list",
      group: "테넌트",
      label: "테넌트 목록",
      summary: "전체 테넌트를 조회한다(root 전용).",
      readOnly: true,
      rootOnly: true,
      args: [],
      fields: [
        { key: "name", label: "이름" },
        { key: "id", label: "id" },
        { key: "createdAt", label: "생성", format: "time" },
      ],
    },
    async run(ctx) {
      // 생성만 있고 조회가 없어서, root가 자기가 만든 테넌트 id를 되찾을 방법이 DB 직접 조회뿐이었다.
      const { rows } = await ctx.db.query({ sql: "SELECT id, name, created_at FROM tenants ORDER BY created_at" });
      return {
        rows: rows.map((r) => ({ id: String(r.id), name: String(r.name), createdAt: Number(r.created_at) })),
      };
    },
  },
  {
    spec: {
      name: "tenant-create",
      group: "테넌트",
      label: "테넌트 생성",
      summary: "새 테넌트를 만든다(root 전용).",
      readOnly: false,
      rootOnly: true,
      args: [{ name: "name", label: "이름", type: "string", required: true }],
    },
    async run(ctx, args) {
      const { tenantId } = await ctx.store.createTenant(args.name!);
      return { data: { tenantId }, message: `테넌트 생성됨: ${args.name} (${tenantId})` };
    },
  },
  // ── API 키 ───────────────────────────────────────────────────────────
  {
    spec: {
      name: "api-key-list",
      group: "API 키",
      label: "API 키 목록",
      summary: "발급된 키를 조회한다. 평문은 저장되지 않아 볼 수 없다.",
      readOnly: true,
      args: [],
      fields: [
        { key: "label", label: "라벨" },
        { key: "scopes", label: "권한" },
        { key: "createdAt", label: "발급", format: "time" },
        { key: "revokedAt", label: "폐기", format: "time" },
        { key: "id", label: "id" },
      ],
    },
    async run(ctx) {
      const tenantId = requireTenant(ctx);
      /**
       * 폐기된 키를 숨기지 않는다 — 사고 조사 때 "이 키가 언제 끊겼나"가 감사 로그의 `apiKeyId`와
       * 맞춰 볼 유일한 값이다. 숨기면 로그의 id가 어디에도 매칭되지 않는 고아가 된다.
       */
      const { rows } = await ctx.db.query({
        sql: "SELECT id, label, scopes, created_at, revoked_at FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC",
        params: [tenantId],
      });
      return {
        rows: rows.map((r) => ({
          id: String(r.id),
          label: r.label == null ? null : String(r.label),
          scopes: String(r.scopes),
          createdAt: Number(r.created_at),
          revokedAt: r.revoked_at == null ? null : Number(r.revoked_at),
        })),
      };
    },
  },
  {
    spec: {
      name: "api-key-create",
      group: "API 키",
      label: "API 키 발급",
      summary: "관리 API용 키를 발급한다. 평문은 이때 한 번만 볼 수 있다.",
      readOnly: false,
      args: [
        { name: "label", label: "라벨", type: "string", required: false, placeholder: "ops-laptop" },
        {
          name: "scopes",
          label: "권한",
          type: "enum",
          required: false,
          choices: [
            { value: "admin", label: "admin (전권)" },
            { value: "read", label: "read (조회만)" },
            { value: "write", label: "write (변경)" },
            { value: "read write", label: "read write" },
          ],
          help: "미지정 시 admin입니다.",
        },
      ],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const scopes = args.scopes?.trim() || "admin";
      // 모르는 스코프는 거부한다 — 예전엔 아무 문자열이나 저장했고 검사도 없어서 오타("read-only")가
      // 전권 키로 발급됐다. 지금은 검사가 있어 오타면 권한이 0인데, 그건 더 조용히 위험하다.
      const unknown = scopes
        .split(/[,\s]+/)
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
        .filter((s) => !KNOWN_SCOPES.has(s));
      if (unknown.length > 0) {
        throw new CommandError("invalid", `알 수 없는 권한: ${unknown.join(", ")}`, "admin | read | write 중에서 고르십시오");
      }
      const id = ulid();
      // "amk_" 접두 + 32바이트 CSPRNG hex. 저장은 sha256 해시뿐이다(§4 api_keys.key_hash).
      // 접두사는 유출된 문자열을 보고 "이게 우리 관리 키다"를 즉시 알아보게 하는 값이라 계약이다.
      const key = `amk_${randomBytes(32).toString("hex")}`;
      await ctx.db.batch([
        {
          sql: "INSERT INTO api_keys (id, tenant_id, label, key_hash, scopes, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, NULL)",
          params: [id, tenantId, args.label ?? null, sha256hex(key), scopes, Date.now()],
        },
      ]);
      return {
        data: { id, scopes },
        secret: { label: "API 키", value: key, hint: `id=${id} scopes=${scopes}` },
        message: `API 키 발급됨: ${args.label ?? "(무명)"} (${id})`,
      };
    },
  },
  {
    spec: {
      name: "api-key-revoke",
      group: "API 키",
      label: "API 키 폐기",
      summary: "즉시 반영되며 되돌릴 수 없다. 지금 쓰는 키도 폐기할 수 있다(유출 대응).",
      readOnly: false,
      destructive: true,
      irreversible: true,
      args: [{ name: "id", label: "키 id", type: "string", required: true }],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      /**
       * 행을 지우지 않고 `revoked_at`을 찍는다(인증 질의가 `revoked_at IS NULL`을 본다).
       * 이미 폐기된 키를 다시 폐기해도 시점이 밀리지 않게 `revoked_at IS NULL`을 조건에 둔다.
       */
      const results = await ctx.db.batch([
        {
          sql: "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND tenant_id = ? AND revoked_at IS NULL",
          params: [Date.now(), args.id!, tenantId],
        },
      ]);
      // 존재하지 않는 키와 남의 테넌트 키를 같은 404로 뭉갠다 — id 존재 여부가 새면 열거가 된다.
      if (results[0]!.changes === 0) throw new CommandError("notFound", `키가 없거나 이미 폐기됨: ${args.id}`);
      return { data: { revoked: true, keyId: args.id! }, message: `폐기됨: ${args.id}` };
    },
  },
  // ── 스마트호스트(아웃바운드 릴레이) ──────────────────────────────────
  {
    spec: {
      name: "smarthost-list",
      group: "릴레이",
      label: "릴레이 목록",
      summary: "테넌트·발신 도메인별 아웃바운드 릴레이 설정을 본다.",
      readOnly: true,
      args: [],
      fields: [
        { key: "scope", label: "범위" },
        { key: "endpoint", label: "호스트:포트" },
        { key: "tls", label: "TLS" },
        { key: "username", label: "사용자" },
        { key: "hasSecret", label: "비밀번호" },
        { key: "maxRcpts", label: "RCPT 상한" },
      ],
    },
    async run(ctx) {
      const tenantId = requireTenant(ctx);
      const { rows } = await ctx.db.query({
        sql: `SELECT tenant_id, domain, host, port, tls_mode, username, secret, max_rcpts
              FROM smarthosts WHERE tenant_id = ? ORDER BY domain`,
        params: [tenantId],
      });
      return {
        rows: rows.map((r) => {
          const code = Number(r.tls_mode);
          return {
            scope: String(r.domain) === SMARTHOST_TENANT_DEFAULT ? "(테넌트 기본)" : String(r.domain),
            domain: String(r.domain),
            // `host:port`를 한 칸에 둔다 — 둘은 짝이라(465=implicit, 587=STARTTLS) 따로 읽으면
            // 짝이 어긋난 설정을 눈으로 잡기 어렵다. 기존 CLI 출력 형식이기도 하다.
            endpoint: `${String(r.host)}:${String(r.port)}`,
            host: String(r.host),
            port: Number(r.port),
            tls: `tls=${isSmarthostTls(code) ? TLS_MODE_NAME[code] : `?${code}`}`,
            username: `user=${r.username == null ? "-" : String(r.username)}`,
            // 비밀번호는 **존재 여부만** — 복호화해서 찍으면 터미널 스크롤백·로그·감사에 남는다.
            hasSecret: `secret=${r.secret ? "설정됨" : "-"}`,
            maxRcpts: `max_rcpts=${r.max_rcpts == null ? "-" : String(r.max_rcpts)}`,
          };
        }),
      };
    },
  },
  {
    spec: {
      name: "smarthost-set",
      group: "릴레이",
      label: "릴레이 설정",
      summary: "아웃바운드 릴레이를 지정한다. 범위가 좁을수록(발신 도메인) 우선한다.",
      readOnly: false,
      args: [
        { name: "host", label: "호스트", type: "string", required: true, placeholder: "smtp.example.net" },
        {
          name: "tls",
          label: "TLS",
          type: "enum",
          required: true,
          // 선택지도 정본에서 만든다 — 손으로 적으면 인코딩이 늘 때 여기만 뒤처진다.
          choices: TLS_CHOICES,
          help: "포트와 짝입니다: 465는 implicit, 587은 required.",
        },
        { name: "port", label: "포트", type: "number", required: false, placeholder: "587" },
        { name: "domain", label: "발신 도메인", type: "string", required: false, help: "비우면 테넌트 기본값이 됩니다." },
        { name: "username", label: "사용자명", type: "string", required: false },
        { name: "password", label: "비밀번호", type: "secret", required: false, help: "사용자명을 지정했다면 필요합니다." },
        { name: "maxRcpts", label: "세션당 RCPT 상한", type: "number", required: false },
      ],
    },
    async run(ctx, args) {
      const domain = args.domain ? args.domain.toLowerCase() : SMARTHOST_TENANT_DEFAULT;
      const tenantId = await smarthostScope(ctx, ctx.db, domain);
      const tlsName = args.tls!;
      if (!(tlsName in SMARTHOST_TLS)) throw new CommandError("invalid", `알 수 없는 TLS 모드: ${tlsName}`);
      const tlsMode = SMARTHOST_TLS[tlsName as keyof typeof SMARTHOST_TLS];
      // 인코딩이 @ionosphere/mta와 갈리면 여기서 즉시 드러난다(저장 후 배달 시점에 터지지 않게).
      if (!isSmarthostTls(tlsMode)) throw new CommandError("invalid", `이 배포가 지원하지 않는 TLS 모드: ${tlsName}`);

      const port = args.port === undefined ? 587 : Number(args.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new CommandError("invalid", `잘못된 포트: ${args.port}`);
      const maxRcpts = args.maxRcpts === undefined ? null : Number(args.maxRcpts);
      if (maxRcpts !== null && (!Number.isInteger(maxRcpts) || maxRcpts < 1)) {
        throw new CommandError("invalid", `잘못된 RCPT 상한: ${args.maxRcpts}`);
      }

      const username = args.username ?? "";
      let secretColumn: string | null = null;
      if (username) {
        const secret = args.password;
        if (!secret) {
          throw new CommandError("invalid", "사용자명을 지정하면 비밀번호가 필요합니다", "CLI에서는 stdin 또는 IONOSPHERE_SMARTHOST_SECRET으로 넣습니다");
        }
        /**
         * 이 DB가 봉인에 쓰던 마스터키와 지금 키가 같은지 대조한다. **틀린 키로 봉인해도 쓰기는
         * 성공한다** — 깨지는 건 나중에 서버가 열 때고, 그때 증상은 "아웃바운드가 전부 지연됨"이라
         * 원인까지 거슬러 올라가기 어렵다. 실제로 릴레이 토큰을 마스터키 자리에 넣은 사고가 있었다.
         */
        const { rows } = await ctx.db.query({ sql: "SELECT private_key FROM dkim_keys LIMIT 1" });
        const sample = rows[0]?.private_key;
        if (sample != null) {
          try {
            open(String(sample), ctx.masterKey);
          } catch {
            throw new CommandError(
              "invalid",
              "IONOSPHERE_MASTER_KEY가 이 DB의 것과 다릅니다 — 기존 DKIM 개인키를 복호하지 못합니다",
              "이 키로 봉인하면 서버가 열지 못해 아웃바운드가 전부 지연됩니다. 릴레이 토큰은 IONOSPHERE_MASTER_KEY가 아니라 stdin(또는 IONOSPHERE_SMARTHOST_SECRET)으로 넣습니다.",
            );
          }
        }
        secretColumn = seal(secret, ctx.masterKey).value;
      }

      // 범위당 하나(PK)라 갱신은 지우고 다시 넣는다 — dialect별 UPSERT 문법 분기를 만들지 않는다.
      await ctx.db.batch([
        { sql: "DELETE FROM smarthosts WHERE tenant_id = ? AND domain = ?", params: [tenantId, domain] },
        {
          sql: `INSERT INTO smarthosts (tenant_id, domain, host, port, tls_mode, username, secret, max_rcpts, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          params: [tenantId, domain, args.host!, port, tlsMode, username || null, secretColumn, maxRcpts, Date.now()],
        },
      ]);
      const scope = domain === SMARTHOST_TENANT_DEFAULT ? `테넌트 기본(${tenantId})` : `발신 도메인 ${domain}`;
      return {
        data: { tenantId, domain, host: args.host!, port, tls: tlsName },
        message: `릴레이 설정됨: ${scope} → ${args.host}:${port} tls=${tlsName}${username ? ` user=${username}` : " (인증 없음)"}`,
      };
    },
  },
  {
    spec: {
      name: "smarthost-remove",
      group: "릴레이",
      label: "릴레이 삭제",
      summary: "설정을 지운다. 이후 그 범위는 MX 직송으로 돌아간다.",
      readOnly: false,
      destructive: true,
      args: [{ name: "domain", label: "발신 도메인", type: "string", required: false, help: "비우면 테넌트 기본 설정을 지웁니다." }],
    },
    async run(ctx, args) {
      const domain = args.domain ? args.domain.toLowerCase() : SMARTHOST_TENANT_DEFAULT;
      const tenantId = await smarthostScope(ctx, ctx.db, domain);
      const results = await ctx.db.batch([
        { sql: "DELETE FROM smarthosts WHERE tenant_id = ? AND domain = ?", params: [tenantId, domain] },
      ]);
      /**
       * 없는 설정을 지우는 것은 오류가 아니다(알리아스 삭제와 같은 규율) — 운영자가 "지웠나?"
       * 하고 다시 부르는 것이 정상 흐름이고, 그때 비0 종료로 스크립트를 깨뜨릴 이유가 없다.
       */
      if (results[0]!.changes === 0) return { data: { deleted: false }, message: "해당 범위에 설정이 없습니다" };
      return { data: { deleted: true }, message: "삭제됨 (이 범위는 MX 직송으로 돌아갑니다)" };
    },
  },
  // ── TLS(서버 전역) ───────────────────────────────────────────────────
  {
    spec: {
      name: "tls-status",
      group: "TLS",
      label: "TLS 상태",
      summary: "인증서 주체·SAN·만료를 본다(root 전용).",
      readOnly: true,
      rootOnly: true,
      args: [],
    },
    async run(ctx) {
      if (!ctx.tls) throw new CommandError("unavailable", "이 배포에는 TLS 관리가 구성되지 않았습니다");
      return { data: await ctx.tls.status() };
    },
  },
  {
    spec: {
      name: "tls-refresh",
      group: "TLS",
      label: "인증서 갱신",
      summary: "재취득·갱신 후 리스너를 무중단 교체한다(root 전용).",
      readOnly: false,
      rootOnly: true,
      args: [],
    },
    async run(ctx) {
      if (!ctx.tls) throw new CommandError("unavailable", "이 배포에는 TLS 관리가 구성되지 않았습니다");
      return { data: await ctx.tls.refresh(), message: "인증서를 갱신하고 리스너를 교체했습니다" };
    },
  },
  {
    spec: {
      name: "tls-upload",
      group: "TLS",
      label: "인증서 업로드",
      summary: "cert/key를 올린다. 개인키는 마스터키로 봉인 저장된다(root 전용, sealed 모드).",
      readOnly: false,
      rootOnly: true,
      args: [
        { name: "cert", label: "인증서 PEM", type: "string", required: true, placeholder: "-----BEGIN CERTIFICATE-----" },
        { name: "key", label: "개인키 PEM", type: "secret", required: true, placeholder: "-----BEGIN PRIVATE KEY-----" },
      ],
    },
    async run(ctx, args) {
      if (!ctx.tls?.upload) throw new CommandError("unavailable", "인증서 업로드가 불가합니다(sealed 모드 필요)");
      return { data: await ctx.tls.upload(args.cert!, args.key!), message: "인증서를 교체했습니다" };
    },
  },
];
