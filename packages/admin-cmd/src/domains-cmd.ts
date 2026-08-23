/**
 * 도메인·알리아스 명령군.
 *
 * 여기 담긴 SQL은 **원자성 계약**을 지고 있다(각 명령 주석 참조). 세 어댑터가 이 한 벌만
 * 부르게 된 것이 이 계층의 요점이다 — 예전에는 CLI의 `add-domain`과 API의 `createDomain`이
 * 각자 INSERT를 조립해 컬럼 목록이 갈라졌고, CLI로 만든 도메인은 `verify_token`이 없어
 * 나중에 API로 재검증할 수 없었다.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { MAX_ALIAS_TARGETS, MAX_RELAY_TARGETS, ulid } from "@ionosphere/core";
import { ACCOUNT_STATUS, BatchConflictError, DOMAIN_STATUS } from "@ionosphere/db";
import { assertDomainNameAvailable, LEGACY_OWNERSHIP_TXT_PREFIX, OWNERSHIP_TXT_PREFIX, provisionDomain } from "./domains.ts";
import { CommandError, type Command, type CommandContext } from "./types.ts";

function requireTenant(ctx: CommandContext): string {
  if (ctx.tenantId === undefined || ctx.tenantId === "") {
    throw new CommandError("invalid", "tenantId가 필요합니다", "root 토큰으로 호출할 때는 tenantId를 지정하십시오");
  }
  return ctx.tenantId;
}

/**
 * 시크릿 비교 — 양쪽을 sha256(32바이트 고정)으로 만든 뒤 비교한다.
 * 길이가 달라도 `timingSafeEqual`이 던지지 않고, 길이 자체도 흘리지 않는다.
 */
function secretEquals(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  return timingSafeEqual(ha, hb);
}

/** DNS 조회 실패를 "레코드 없음"으로 수렴시킨다 — 조회 실패와 미게시를 가르면 검증이 불안정해진다. */
async function safeTxt(ctx: CommandContext, name: string): Promise<string[]> {
  if (!ctx.resolveTxt) return [];
  try {
    return await ctx.resolveTxt(name);
  } catch {
    return [];
  }
}
async function safeMx(ctx: CommandContext, name: string): Promise<{ exchange: string; preference: number }[]> {
  if (!ctx.resolveMx) return [];
  try {
    return await ctx.resolveMx(name);
  } catch {
    return [];
  }
}

/** `forwardTo`는 콤마·공백으로 여러 대상을 받는다 — 개수 상한을 생성 시점에 재는 근거. */
export function splitForwardTargets(forwardTo: string): string[] {
  return forwardTo
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export const domainCommands: readonly Command[] = [
  {
    spec: {
      name: "domain-list",
      group: "도메인",
      label: "도메인 목록",
      summary: "이 테넌트의 도메인과 검증 상태를 조회한다.",
      readOnly: true,
      args: [],
      fields: [
        { key: "name", label: "도메인" },
        { key: "status", label: "상태", encoding: "domainStatus" },
        { key: "verifyToken", label: "검증 토큰" },
        { key: "id", label: "id" },
      ],
    },
    async run(ctx) {
      const tenantId = requireTenant(ctx);
      const { rows } = await ctx.db.query({
        sql: "SELECT id, name, status, verify_token FROM domains WHERE tenant_id = ? ORDER BY created_at",
        params: [tenantId],
      });
      return {
        rows: rows.map((r) => ({
          id: String(r.id),
          name: String(r.name),
          status: Number(r.status),
          verifyToken: r.verify_token == null ? null : String(r.verify_token),
        })),
      };
    },
  },
  {
    spec: {
      name: "domain-add",
      group: "도메인",
      label: "도메인 추가",
      summary: "도메인을 등록하고 DKIM 키·DNS 안내를 만든다. 검증 전에는 발송할 수 없다.",
      readOnly: false,
      args: [
        { name: "name", label: "도메인", type: "string", required: true, placeholder: "example.com" },
        {
          name: "preVerified",
          label: "검증 생략(자사 도메인)",
          type: "boolean",
          required: false,
          help: "DNS 검증 없이 즉시 활성화합니다. 소유가 확실한 자사 도메인에만 쓰십시오.",
        },
      ],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const name = args.name!.trim().toLowerCase();
      /**
       * 이름이 이미 남의 것인지 **DKIM 키를 만들기 전에** 본다. 통과해도 최종 관문은 verify의
       * `domain_name_claims` PK다(경합에 안전한 쪽). 형식·예약어 검사는 provisionDomain 안에 있다.
       */
      await assertDomainNameAvailable(ctx.db, tenantId, name);
      const domainId = ulid();
      const preVerified = args.preVerified === "true";
      const prov = provisionDomain({
        domainId,
        tenantId,
        name,
        masterKey: ctx.masterKey,
        ...(preVerified ? { preVerified: true } : {}),
      });
      try {
        await ctx.db.batch(prov.statements);
      } catch (err) {
        if (err instanceof BatchConflictError) throw new CommandError("conflict", `이미 등록된 도메인: ${name}`);
        throw err;
      }
      return {
        data: { domainId, verifyToken: prov.verifyToken, dnsInstructions: prov.dnsRecords, sealed: prov.sealed },
        message: prov.sealed
          ? `도메인 추가됨: ${name} (${domainId})`
          : `도메인 추가됨: ${name} (${domainId}) — ⚠ IONOSPHERE_MASTER_KEY 미설정으로 DKIM 개인키가 평문 저장됨`,
      };
    },
  },
  {
    spec: {
      name: "domain-verify",
      group: "도메인",
      label: "도메인 검증",
      summary: "TXT 토큰·MX·SPF 3종을 확인하고 통과하면 활성화한다.",
      readOnly: false,
      args: [{ name: "domain", label: "도메인(이름 또는 id)", type: "string", required: true }],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const { rows } = await ctx.db.query({
        sql: "SELECT id, name, status, verify_token FROM domains WHERE (id = ? OR name = ?) AND tenant_id = ?",
        params: [args.domain!, args.domain!.toLowerCase(), tenantId],
      });
      const row = rows[0];
      if (!row) throw new CommandError("notFound", `도메인을 찾을 수 없습니다: ${args.domain}`);
      if (Number(row.status) === DOMAIN_STATUS.active) {
        return { data: { status: "active" }, message: "이미 활성 상태입니다" }; // 재검증 idempotent
      }
      const domainId = String(row.id);
      const name = String(row.name);
      const token = String(row.verify_token);

      // 새 이름을 먼저 보고, 없으면 개명 전 이름도 본다 — 이미 게시된 레코드를 무효로 만들지 않는다.
      const txtToken = await safeTxt(ctx, `${OWNERSHIP_TXT_PREFIX}.${name}`);
      const legacyTxtToken = await safeTxt(ctx, `${LEGACY_OWNERSHIP_TXT_PREFIX}.${name}`);
      const tokenOk = [...txtToken, ...legacyTxtToken].some((v) => secretEquals(v.trim(), token));
      const mxOk = (await safeMx(ctx, name)).length > 0;
      const spfOk = (await safeTxt(ctx, name)).some((v) => v.trim().toLowerCase().startsWith("v=spf1"));

      if (!(tokenOk && mxOk && spfOk)) {
        return {
          data: { status: "failed", checks: { token: tokenOk, mx: mxOk, spf: spfOk } },
          message: `검증 실패 — token:${tokenOk ? "ok" : "x"} mx:${mxOk ? "ok" : "x"} spf:${spfOk ? "ok" : "x"}`,
        };
      }
      try {
        await ctx.db.batch([
          { sql: "UPDATE domains SET status = ? WHERE id = ?", params: [DOMAIN_STATUS.active, domainId] },
          { sql: "INSERT INTO domain_name_claims (name, domain_id) VALUES (?, ?)", params: [name, domainId] },
        ]);
      } catch (err) {
        if (err instanceof BatchConflictError) {
          throw new CommandError("conflict", `이 이름은 다른 도메인에서 이미 활성 상태입니다: ${name}`);
        }
        throw err;
      }
      return { data: { status: "active" }, message: `검증 통과 — ${name} 활성화됨` };
    },
  },
  {
    /**
     * ★가역적 차단 — 계정의 suspend와 같은 자리를 도메인에 만든다.
     *
     * `DOMAIN_STATUS.disabled`는 인코딩에 있었지만 이걸 세팅하는 코드가 저장소에 0건이었다.
     * 그래서 도메인을 잠시 멈추려면 **해제(삭제)뿐**이었고, 해제는 계정·알리아스를 먼저 전부
     * 지우라고 요구한다 — 즉 "잠깐 멈춤"의 대가가 사실상 전체 철거였다.
     */
    spec: {
      name: "domain-disable",
      group: "도메인",
      label: "도메인 비활성화",
      summary: "발송·수신을 멈춘다. 데이터는 그대로이며 domain-enable로 되돌린다.",
      readOnly: false,
      destructive: true,
      args: [{ name: "domain", label: "도메인(이름 또는 id)", type: "string", required: true }],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const results = await ctx.db.batch([
        {
          sql: "UPDATE domains SET status = ? WHERE (id = ? OR name = ?) AND tenant_id = ?",
          params: [DOMAIN_STATUS.disabled, args.domain!, args.domain!.toLowerCase(), tenantId],
        },
      ]);
      if (results[0]!.changes === 0) throw new CommandError("notFound", `도메인을 찾을 수 없습니다: ${args.domain}`);
      return { data: { status: DOMAIN_STATUS.disabled }, message: `비활성화됨: ${args.domain} (domain-enable로 해제)` };
    },
  },
  {
    spec: {
      name: "domain-enable",
      group: "도메인",
      label: "도메인 활성화",
      summary: "비활성화된 도메인을 다시 활성 상태로 되돌린다.",
      readOnly: false,
      args: [{ name: "domain", label: "도메인(이름 또는 id)", type: "string", required: true }],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const { rows } = await ctx.db.query({
        sql: "SELECT id, name, status FROM domains WHERE (id = ? OR name = ?) AND tenant_id = ?",
        params: [args.domain!, args.domain!.toLowerCase(), tenantId],
      });
      const row = rows[0];
      if (!row) throw new CommandError("notFound", `도메인을 찾을 수 없습니다: ${args.domain}`);
      if (Number(row.status) === DOMAIN_STATUS.unverified) {
        // 미검증을 여기서 활성으로 올리면 소유권 검증(PLAN §8 통제 ①)을 우회하는 뒷문이 된다.
        throw new CommandError("invalid", `아직 검증되지 않은 도메인입니다: ${row.name}`, "domain-verify를 먼저 실행하십시오");
      }
      await ctx.db.batch([
        { sql: "UPDATE domains SET status = ? WHERE id = ? AND tenant_id = ?", params: [DOMAIN_STATUS.active, String(row.id), tenantId] },
      ]);
      return { data: { status: DOMAIN_STATUS.active }, message: `활성화됨: ${row.name}` };
    },
  },
  {
    /**
     * 도메인 해제. 검증은 한때 **영구**였고 해제 코드가 0건이었다(감사 5차 L-7) — 한 번 검증된
     * 이름이 `domain_name_claims`(PK)에 영원히 묶여 다른 테넌트가 같은 이름을 영영 검증할 수
     * 없었다. 도메인을 실제로 넘기거나 오타로 잡은 이름을 되돌릴 방법이 없었다는 뜻이다.
     */
    spec: {
      name: "domain-release",
      group: "도메인",
      label: "도메인 해제",
      summary: "도메인 소유권과 DKIM 키를 제거한다. 계정·알리아스가 남아 있으면 거부한다.",
      readOnly: false,
      destructive: true,
      irreversible: true,
      args: [{ name: "domain", label: "도메인(이름 또는 id)", type: "string", required: true }],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const { rows } = await ctx.db.query({
        sql: "SELECT id, name FROM domains WHERE (id = ? OR name = ?) AND tenant_id = ?",
        params: [args.domain!, args.domain!.toLowerCase(), tenantId],
      });
      const row = rows[0];
      if (!row) throw new CommandError("notFound", `도메인을 찾을 수 없습니다: ${args.domain}`);
      const domainId = String(row.id);
      const name = String(row.name);
      /**
       * `%@name` 접미 일치. name은 `assertUsableDomainName`을 통과한 LDH 문자열이라 LIKE
       * 와일드카드(`%`/`_`)가 들어올 수 없다. 옛 행에 이상한 문자가 있다면 과다 일치해서
       * 해제가 막힐 뿐이라(fail closed) 안전한 방향이다.
       */
      const emailSuffix = `%@${name}`;

      const { rows: aliasRows } = await ctx.db.query({ sql: "SELECT id FROM addresses WHERE domain_id = ?", params: [domainId] });
      const { rows: accountRows } = await ctx.db.query({
        sql: "SELECT id FROM accounts WHERE tenant_id = ? AND email LIKE ?",
        params: [tenantId, emailSuffix],
      });
      if (aliasRows.length > 0 || accountRows.length > 0) {
        throw new CommandError(
          "conflict",
          `아직 사용 중인 도메인입니다: ${name} (알리아스 ${aliasRows.length}개, 계정 ${accountRows.length}개)`,
          "먼저 해당 알리아스·계정을 정리하십시오",
        );
      }
      /**
       * 한 배치. 순서와 조건이 서로를 붙잡는다: 도메인 삭제에만 "자원 없음" 가드를 걸고,
       * 뒤따르는 두 정리는 **도메인 행이 실제로 사라졌을 때만** 걸리도록 `NOT EXISTS(domains)`를
       * 조건으로 쓴다. 경합으로 첫 문장이 0행이 되면 나머지도 0행이라, DKIM 키만 지워지고
       * 도메인이 남는 반쪽 상태가 없다.
       */
      const results = await ctx.db.batch([
        {
          sql: `DELETE FROM domains WHERE id = ? AND tenant_id = ?
                  AND NOT EXISTS (SELECT 1 FROM addresses WHERE domain_id = ?)
                  AND NOT EXISTS (SELECT 1 FROM accounts WHERE tenant_id = ? AND email LIKE ?)`,
          params: [domainId, tenantId, domainId, tenantId, emailSuffix],
        },
        {
          sql: "DELETE FROM dkim_keys WHERE domain_id = ? AND NOT EXISTS (SELECT 1 FROM domains WHERE id = ?)",
          params: [domainId, domainId],
        },
        {
          // 앵커는 domain_id까지 맞을 때만 지운다 — 이름만 보고 지우면 그 사이 다른 테넌트가
          // 검증해 새로 잡은 앵커를 빼앗아 오게 된다.
          sql: `DELETE FROM domain_name_claims WHERE name = ? AND domain_id = ?
                  AND NOT EXISTS (SELECT 1 FROM domains WHERE id = ?)`,
          params: [name, domainId, domainId],
        },
      ]);
      if (results[0]!.changes === 0) throw new CommandError("conflict", `아직 사용 중인 도메인입니다: ${name}`);
      return { data: { released: true }, message: `해제됨: ${name}` };
    },
  },
  {
    spec: {
      name: "alias-list",
      group: "알리아스",
      label: "알리아스 목록",
      summary: "수신 주소 라우팅을 조회한다.",
      readOnly: true,
      args: [{ name: "domain", label: "도메인 필터", type: "string", required: false }],
      fields: [
        { key: "address", label: "주소" },
        { key: "target", label: "대상" },
        { key: "id", label: "id" },
      ],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const filter = args.domain?.toLowerCase();
      const { rows } = await ctx.db.query({
        sql: `SELECT a.id, a.localpart, d.name AS domain, a.forward_to
              FROM addresses a JOIN domains d ON d.id = a.domain_id
              WHERE a.tenant_id = ?${filter ? " AND d.name = ?" : ""} ORDER BY d.name, a.localpart`,
        params: filter ? [tenantId, filter] : [tenantId],
      });
      /**
       * 목적지는 별도 조회 후 메모리에서 묶는다 — 조인하면 팬아웃 수만큼 알리아스 행이 중복된다.
       * **이메일까지 가져오는 이유**는 화면·CLI가 사람이 읽을 것을 보여줘야 하기 때문이다
       * (ULID만 찍으면 운영자가 그게 누구인지 다시 조회해야 한다). 정렬도 이메일 기준이다.
       */
      const { rows: targetRows } = await ctx.db.query({
        sql: `SELECT t.address_id, t.account_id, acc.email FROM address_targets t
              JOIN addresses a ON a.id = t.address_id
              JOIN accounts acc ON acc.id = t.account_id
              WHERE a.tenant_id = ? ORDER BY acc.email`,
        params: [tenantId],
      });
      const idsByAddress = new Map<string, string[]>();
      const emailsByAddress = new Map<string, string[]>();
      for (const t of targetRows) {
        const key = String(t.address_id);
        (idsByAddress.get(key) ?? idsByAddress.set(key, []).get(key)!).push(String(t.account_id));
        (emailsByAddress.get(key) ?? emailsByAddress.set(key, []).get(key)!).push(String(t.email));
      }
      return {
        rows: rows.map((r) => {
          const key = String(r.id);
          const accountIds = idsByAddress.get(key) ?? [];
          const emails = emailsByAddress.get(key) ?? [];
          const forwardTo = r.forward_to == null ? null : String(r.forward_to);
          const parts: string[] = [];
          if (emails.length > 0) parts.push(`account:${emails.join(",")}`);
          if (forwardTo) parts.push(`forward:${forwardTo}`);
          return {
            id: key,
            address: `${String(r.localpart)}@${String(r.domain)}`,
            accountIds,
            // 대상이 1개일 때만 채워지는 읽기 전용 호환 필드(기존 REST 계약).
            accountId: accountIds.length === 1 ? accountIds[0]! : null,
            forwardTo,
            target: parts.join(" ") || "(목적지 없음)",
          };
        }),
      };
    },
  },
  {
    spec: {
      name: "alias-add",
      group: "알리아스",
      label: "알리아스 추가",
      summary: "주소를 로컬 계정(여럿 가능) 또는 외부 주소로 라우팅한다. localpart '*'는 캐치올.",
      readOnly: false,
      args: [
        { name: "address", label: "주소", type: "string", required: true, placeholder: "info@example.com" },
        {
          name: "target",
          label: "대상",
          type: "string",
          required: true,
          variadic: true,
          placeholder: "user@example.com 또는 계정 id (콤마로 여럿)",
          help: "로컬 계정의 주소/id면 계정 배달, 외부 주소면 포워딩입니다. 섞으면 둘 다 일어납니다.",
        },
      ],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const address = args.address!.trim().toLowerCase();
      const at = address.lastIndexOf("@");
      if (at <= 0 || at === address.length - 1) throw new CommandError("invalid", "주소는 localpart@domain 형식이어야 합니다");
      const localpart = address.slice(0, at);
      const domainName = address.slice(at + 1);

      const { rows: dr } = await ctx.db.query({
        sql: "SELECT id, status FROM domains WHERE name = ? AND tenant_id = ?",
        params: [domainName, tenantId],
      });
      const domainRow = dr[0];
      // 404/409의 근거는 accounts.ts의 같은 게이트 주석 참조(열거 차단 vs 상태 불일치).
      if (!domainRow) throw new CommandError("notFound", `이 테넌트가 소유하지 않은 도메인입니다: ${domainName}`);
      if (Number(domainRow.status) !== DOMAIN_STATUS.active) {
        throw new CommandError("conflict", `아직 검증되지 않은 도메인입니다(not verified): ${domainName}`, "domain-verify를 먼저 실행하십시오");
      }
      const domainId = String(domainRow.id);

      /**
       * 대상을 로컬/외부로 가른다. **로컬 계정은 주소로도 id로도 지목할 수 있다** — 사람은
       * 이메일로 말하고 GUI는 id를 들고 있다. 여기서 한 번에 받아 주지 않으면 CLI 사용자가
       * ULID를 손으로 옮겨 적게 된다.
       */
      const localIds: string[] = [];
      const localEmails: string[] = [];
      const forwards: string[] = [];
      for (const raw of splitForwardTargets(args.target!)) {
        const t = raw.toLowerCase();
        const { rows: ar } = await ctx.db.query({
          sql: "SELECT id, email, status FROM accounts WHERE (id = ? OR email = ?) AND tenant_id = ?",
          params: [raw, t, tenantId],
        });
        const acc = ar[0];
        if (acc) {
          // status=1까지 본다 — 비활성 계정을 목적지로 걸면 라우팅이 걸러내 조용한 no-op이 되고,
          // 대상이 그것뿐이면 알리아스 전체가 죽은 주소가 된다. 즉시 실패로 알린다.
          if (Number(acc.status) !== ACCOUNT_STATUS.active) {
            // 404로 뭉갠다 — "있지만 비활성"과 "없음"을 가르면 계정 존재 여부가 새고,
            // 호출자가 할 일은 어느 쪽이든 "쓸 수 있는 대상을 지정하라"로 같다.
            throw new CommandError("notFound", `계정이 없거나 비활성입니다: ${raw}`);
          }
          localIds.push(String(acc.id));
          localEmails.push(String(acc.email));
        } else if (t.includes("@")) {
          /**
           * ★로컬 계정이 아닌 주소는 외부 포워딩이 된다. 그런데 **우리 도메인의 주소인데
           * 이 테넌트 소유가 아닌 경우**는 오타이지 포워딩 의도가 아니다 — 그대로 두면
           * 남의 계정 주소로 메일을 릴레이하는 알리아스가 조용히 만들어진다.
           * (기존 CLI가 "테넌트 소속이 아니다"로 거절하던 자리이고, REST에는 그 검사가 있었다.)
           */
          const { rows: foreign } = await ctx.db.query({
            sql: "SELECT tenant_id FROM accounts WHERE email = ?",
            params: [t],
          });
          if (foreign[0] && String(foreign[0].tenant_id) !== tenantId) {
            throw new CommandError("denied", `대상 계정이 이 도메인의 테넌트 소속이 아니다: ${raw}`);
          }
          forwards.push(t);
        } else {
          throw new CommandError("notFound", `계정을 찾을 수 없습니다: ${raw}`, "외부 포워딩이라면 완전한 이메일 주소로 적으십시오");
        }
      }
      if (localIds.length === 0 && forwards.length === 0) {
        throw new CommandError("invalid", "대상이 필요합니다(로컬 계정 또는 외부 주소)");
      }
      if (localIds.length > MAX_ALIAS_TARGETS) {
        throw new CommandError("invalid", `팬아웃 대상은 최대 ${MAX_ALIAS_TARGETS}개 (요청: ${localIds.length})`);
      }
      /**
       * 외부 포워딩 대상 수도 **생성 시점에** 막는다. 배달 경로는 초과 시 fail closed로 아무것도
       * 릴레이하지 않으므로, 여기서 통과시키면 설정은 받아들여졌는데 그 주소로 온 메일이 영구
       * 451 루프에 빠진다(로컬 목적지도 없으면 "수신자 없음"이 된다).
       */
      if (forwards.length > MAX_RELAY_TARGETS) {
        throw new CommandError("invalid", `포워딩 대상은 최대 ${MAX_RELAY_TARGETS}개 (요청: ${forwards.length})`);
      }

      const id = ulid();
      try {
        // 주소 행과 목적지를 **한 배치**로 — 주소만 남고 목적지가 없는 중간 상태가 보이면
        // 그 사이 도착한 메일이 조용히 버려진다(라우팅은 목적지 0개를 "수신자 없음"으로 본다).
        await ctx.db.batch([
          {
            sql: `INSERT INTO addresses (id, tenant_id, domain_id, localpart, forward_to, created_at)
                  VALUES (?, ?, ?, ?, ?, ?)`,
            params: [id, tenantId, domainId, localpart, forwards.length > 0 ? forwards.join(",") : null, Date.now()],
          },
          ...localIds.map((accountId) => ({
            sql: "INSERT INTO address_targets (address_id, account_id) VALUES (?, ?)",
            params: [id, accountId],
          })),
        ]);
      } catch (err) {
        if (err instanceof BatchConflictError) throw new CommandError("conflict", `이미 존재하는 알리아스: ${address}`);
        throw err;
      }
      /**
       * `hasForward`는 어댑터를 위한 값이다 — CLI가 SRS 비활성 경고를 **실제로 외부 포워딩을
       * 만들었을 때만** 띄우게 한다(인자에 @가 있는지로 보면 로컬 계정 지정에도 헛경고가 뜬다).
       */
      /**
       * 메시지에 **대상을 사람이 읽는 형태로** 적는다(`계정 a@b, c@d + 포워딩 x@y`).
       * id만 찍으면 운영자가 방금 무엇을 연결했는지 확인하려고 다시 조회해야 한다.
       */
      const parts: string[] = [];
      if (localEmails.length > 0) parts.push(`계정 ${localEmails.join(", ")}`);
      if (forwards.length > 0) parts.push(`포워딩 ${forwards.join(",")}`);
      return {
        // `hasForward`는 어댑터를 위한 값 — CLI가 SRS 비활성 경고를 **실제로 외부 포워딩을
        // 만들었을 때만** 띄우게 한다(인자에 @가 있는지로 보면 로컬 계정 지정에도 헛경고가 뜬다).
        data: { aliasId: id, hasForward: forwards.length > 0 },
        message: `알리아스 추가: ${address} → ${parts.join(" + ")}`,
      };
    },
  },
  {
    spec: {
      name: "alias-remove",
      group: "알리아스",
      label: "알리아스 삭제",
      summary: "삭제하면 그 주소로 오는 메일은 즉시 거부된다.",
      readOnly: false,
      destructive: true,
      irreversible: true,
      args: [{ name: "alias", label: "알리아스(주소 또는 id)", type: "string", required: true }],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      // 주소 문자열로도 지울 수 있게 id를 먼저 해석한다 — 사람은 주소로 말한다.
      const raw = args.alias!;
      const at = raw.lastIndexOf("@");
      let aliasId = raw;
      if (at > 0) {
        const { rows } = await ctx.db.query({
          sql: `SELECT a.id FROM addresses a JOIN domains d ON d.id = a.domain_id
                WHERE a.localpart = ? AND d.name = ? AND a.tenant_id = ?`,
          params: [raw.slice(0, at).toLowerCase(), raw.slice(at + 1).toLowerCase(), tenantId],
        });
        const row = rows[0];
        /**
         * ★없는 알리아스를 지우는 것은 **오류가 아니다**(멱등). 운영자가 "이거 지웠나?" 하고
         * 다시 부르는 것이 정상 흐름이고, 그때 비0 종료로 스크립트를 깨뜨릴 이유가 없다.
         * 지웠는지 아닌지는 `deleted`로 구분해 돌려준다 — 결과를 감추지 않으면서 실패도 아니다.
         */
        if (!row) return { data: { deleted: false }, message: `대상 없음: ${raw}` };
        aliasId = String(row.id);
      }
      // 목적지를 먼저 지운다 — 주소 행만 사라지고 address_targets가 남으면 고아 행이 쌓인다
      // (FK 미사용 정책이라 DB가 대신 정리해 주지 않는다). 한 배치라 중간 상태는 보이지 않는다.
      const results = await ctx.db.batch([
        {
          sql: "DELETE FROM address_targets WHERE address_id IN (SELECT id FROM addresses WHERE id = ? AND tenant_id = ?)",
          params: [aliasId, tenantId],
        },
        { sql: "DELETE FROM addresses WHERE id = ? AND tenant_id = ?", params: [aliasId, tenantId] },
      ]);
      if (results[1]!.changes === 0) return { data: { deleted: false }, message: `대상 없음: ${raw}` };
      return { data: { deleted: true }, message: `삭제됨: ${raw}` };
    },
  },
];
