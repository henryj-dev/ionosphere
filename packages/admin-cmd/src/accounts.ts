/**
 * 계정 명령군 — 생성·목록·정지·재활성·삭제, 앱 비밀번호·OAuth 토큰.
 *
 * ★여기서 **정지(suspend)가 처음 사람 손에 들어온다.** 인코딩(`ACCOUNT_STATUS.suspended`)과
 * 자동 집행(`mta/abuse.ts`의 신고율 초과 정지)은 진작 있었는데 운영자가 쓸 입구가 API에도 CLI에도
 * 없었다. 그래서 "잠시 막아 두기"의 유일한 방법이 **되돌릴 수 없는 삭제**였다 — 관리 콘솔이
 * "정지를 쓰세요(현재 콘솔에는 정지 버튼이 없습니다)"라고 스스로 적어 둔 상태였다.
 * 마이그레이션 006이 인덱스로 의도를 증언하는데 정리 코드가 없던 것과 같은 모양의 구멍이다.
 */
import { CREDENTIAL_KIND, ACCOUNT_STATUS, type DbDriver } from "@ionosphere/db";
import { AUTH_SURFACES, createAppPassword, createCredential, createOAuthToken, listCredentials, revokeCredential } from "@ionosphere/store";
import { CommandError, type Command, type CommandContext } from "./types.ts";

/** 이 명령이 작용할 테넌트. root가 지정하지 않으면 대상이 정해지지 않는다 — 추측하지 않는다. */
function requireTenant(ctx: CommandContext): string {
  if (ctx.tenantId === undefined || ctx.tenantId === "") {
    throw new CommandError("invalid", "tenantId가 필요합니다", "root 토큰으로 호출할 때는 tenantId를 지정하십시오");
  }
  return ctx.tenantId;
}

/**
 * 계정이 이 테넌트 소유인지 확인하고 id를 돌려준다. **입력은 id 또는 이메일 둘 다 받는다** —
 * GUI는 id를 들고 있지만 사람은 이메일로 말한다(CLI에서 ULID를 손으로 옮겨 적게 하면 안 된다).
 *
 * 없을 때 403이 아니라 404인 이유: 남의 테넌트에 그 계정이 **있다는 사실 자체**를 흘리지 않는다.
 */
async function resolveAccount(db: DbDriver, tenantId: string, idOrEmail: string): Promise<{ id: string; email: string; status: number }> {
  const { rows } = await db.query({
    sql: "SELECT id, email, status FROM accounts WHERE (id = ? OR email = ?) AND tenant_id = ?",
    params: [idOrEmail, idOrEmail.toLowerCase(), tenantId],
  });
  const row = rows[0];
  if (!row) throw new CommandError("notFound", `계정을 찾을 수 없습니다: ${idOrEmail}`);
  return { id: String(row.id), email: String(row.email), status: Number(row.status) };
}

/**
 * 계정 주소의 도메인이 이 테넌트 소유이며 검증됐는지.
 *
 * 이 게이트가 없으면 남의 도메인으로 계정을 만들 수 있고, 그 계정은 그 도메인에서 오는 메일을
 * 받게 된다 — SaaS에서 도메인 소유권 검증(PLAN §8 통제 ①)의 의미가 사라지는 자리다.
 */
async function requireOwnedVerifiedDomain(db: DbDriver, tenantId: string, email: string): Promise<void> {
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) {
    throw new CommandError("invalid", "이메일은 localpart@domain 형식이어야 합니다");
  }
  const domain = email.slice(at + 1);
  const { rows } = await db.query({
    sql: "SELECT status FROM domains WHERE name = ? AND tenant_id = ?",
    params: [domain, tenantId],
  });
  const row = rows[0];
  /**
   * ★소유하지 않은 도메인은 **404**다(403이 아니다). 403은 "그건 있는데 네 것이 아니다"를
   * 뜻해서, 남의 테넌트가 어떤 도메인을 갖고 있는지 열거하는 통로가 된다.
   * 미검증은 **409** — 자원은 있는데 상태가 아직 아니라는 뜻이고, 운영자가 할 일(검증)이 다르다.
   */
  if (!row) {
    throw new CommandError("notFound", `이 테넌트가 소유하지 않은 도메인입니다: ${domain}`, "먼저 domain-add로 등록하고 domain-verify를 통과시키십시오");
  }
  if (Number(row.status) !== 1) {
    throw new CommandError("conflict", `아직 검증되지 않은 도메인입니다(not verified): ${domain}`, "domain-verify를 실행하십시오");
  }
}

const accountFields = [
  { key: "email", label: "주소" },
  { key: "status", label: "상태", encoding: "accountStatus" },
  { key: "messageCount", label: "메시지", format: "number" as const },
  { key: "usedBytes", label: "사용량", format: "bytes" as const },
  { key: "id", label: "id" },
];

/**
 * 표면 목록 정규화·검증 — 빈 값이면 `undefined`(제한 없음).
 *
 * ★모르는 이름은 **거절한다.** `credentialAllowsSurface`는 모르는 이름을 "아무 표면도 열지
 * 않음"으로 다루므로(fail closed), 오타가 있는 채로 발급되면 그 자격증명은 어디서도 로그인이
 * 안 되는데 화면에는 성공으로 보인다. 만들 때 막는 편이 그 혼란을 없앤다.
 */
function normalizeSurfaces(raw: string | undefined): string | undefined {
  const parts = (raw ?? "")
    .split(/[,\s]+/)
    .map((x) => x.trim().toLowerCase())
    .filter((x) => x.length > 0);
  if (parts.length === 0) return undefined;
  const known: readonly string[] = AUTH_SURFACES;
  const unknown = parts.filter((x) => !known.includes(x));
  if (unknown.length > 0) {
    throw new CommandError("invalid", `알 수 없는 표면: ${unknown.join(", ")} (가능: ${AUTH_SURFACES.join(", ")})`);
  }
  return [...new Set(parts)].join(",");
}

export const accountCommands: readonly Command[] = [
  {
    spec: {
      name: "account-list",
      group: "계정",
      label: "계정 목록",
      summary: "이 테넌트의 계정과 사용량을 조회한다.",
      readOnly: true,
      args: [],
      fields: accountFields,
    },
    async run(ctx) {
      const tenantId = requireTenant(ctx);
      const { rows } = await ctx.db.query({
        sql: "SELECT id, email, status, message_count, used_bytes FROM accounts WHERE tenant_id = ? ORDER BY created_at",
        params: [tenantId],
      });
      return {
        rows: rows.map((r) => ({
          id: String(r.id),
          email: String(r.email),
          status: Number(r.status),
          messageCount: Number(r.message_count),
          usedBytes: Number(r.used_bytes),
        })),
      };
    },
  },
  {
    spec: {
      name: "account-create",
      group: "계정",
      label: "계정 생성",
      summary: "메일 계정을 만든다(INBOX 포함). 도메인이 검증돼 있어야 한다.",
      readOnly: false,
      args: [
        { name: "email", label: "주소", type: "string", required: true, placeholder: "user@example.com" },
        { name: "password", label: "비밀번호", type: "secret", required: true, help: "IMAP/POP3/SMTP 로그인에 쓰입니다." },
        {
          name: "allowUnverifiedDomain",
          label: "도메인 검증 생략",
          type: "boolean",
          required: false,
          help: "도메인이 아직 등록·검증되지 않아도 계정을 만듭니다. 로컬 셸(CLI) 전용입니다.",
        },
      ],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const email = args.email!.trim().toLowerCase();
      /**
       * ★도메인 게이트를 **표면에 따라 다르게** 건다.
       *
       * REST는 항상 검증을 요구한다 — 남의 검증된 도메인으로 계정을 만들면 두 가지가 동시에
       * 터진다: `accounts.email`이 전역 UNIQUE라 진짜 소유자가 그 주소를 영영 못 만들고(선점 DoS),
       * 수신 라우팅 폴백이 그 계정으로 배달한다. 그래서 그쪽은 완화할 수 없다.
       *
       * CLI는 로컬 셸 접근이 곧 서버 소유라 위험이 다르고, 무엇보다 **첫 사용 흐름이 여기 걸린다** —
       * README와 `scripts/imaptest-local.sh`가 `create-user`를 도메인보다 먼저 부른다.
       * 옵션을 명령에 두고 어댑터가 켜게 한 이유는, 이 완화가 **어디서 오는지 코드에 드러나야**
       * 하기 때문이다(CLI가 몰래 다른 SQL을 쓰는 것이 아니라, 같은 명령의 명시된 인자다).
       */
      if (args.allowUnverifiedDomain !== "true") {
        await requireOwnedVerifiedDomain(ctx.db, tenantId, email);
      }
      if (await ctx.store.getAccountByEmail(email)) {
        throw new CommandError("conflict", `이미 존재하는 계정: ${email}`);
      }
      const { accountId } = await ctx.store.createAccount({ tenantId, email });
      await createCredential(ctx.db, { accountId, password: args.password! });
      return { data: { accountId }, message: `계정 생성됨: ${email} (${accountId})` };
    },
  },
  {
    /**
     * ★가역적 차단 — 이 저장소에 오래 없던 명령.
     *
     * `suspended`(0)는 데이터를 그대로 두고 로그인·수신만 막는다. 반대편의 `deleting`(2)은
     * 편도라 리퍼가 메일함·자격증명을 드레인한다. 조사·대응 중에 쓰라고 만든 것이 이쪽인데
     * 입구가 없어서 운영자가 삭제를 쓰게 되어 있었다.
     */
    spec: {
      name: "account-suspend",
      group: "계정",
      label: "계정 정지",
      summary: "로그인·수신을 막는다. 데이터는 보존되며 account-activate로 되돌릴 수 있다.",
      readOnly: false,
      destructive: true,
      args: [{ name: "account", label: "계정(주소 또는 id)", type: "string", required: true }],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const acc = await resolveAccount(ctx.db, tenantId, args.account!);
      if (acc.status === ACCOUNT_STATUS.deleting) {
        // 삭제 드레인은 편도다 — 정지로 되돌린 것처럼 보이게 두면 운영자가 복구됐다고 오해한다.
        throw new CommandError("conflict", `삭제 중인 계정은 정지할 수 없습니다: ${acc.email}`, "삭제는 되돌릴 수 없습니다");
      }
      await ctx.db.batch([
        { sql: "UPDATE accounts SET status = ? WHERE id = ? AND tenant_id = ?", params: [ACCOUNT_STATUS.suspended, acc.id, tenantId] },
      ]);
      return { data: { accountId: acc.id, status: ACCOUNT_STATUS.suspended }, message: `정지됨: ${acc.email} (account-activate로 해제)` };
    },
  },
  {
    spec: {
      name: "account-activate",
      group: "계정",
      label: "계정 재활성",
      summary: "정지된 계정을 되살린다. 신고율 자동 정지를 해제할 때도 쓴다.",
      readOnly: false,
      args: [{ name: "account", label: "계정(주소 또는 id)", type: "string", required: true }],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const acc = await resolveAccount(ctx.db, tenantId, args.account!);
      if (acc.status === ACCOUNT_STATUS.deleting) {
        throw new CommandError("conflict", `삭제 중인 계정은 되살릴 수 없습니다: ${acc.email}`, "리퍼가 이미 메일함·자격증명을 드레인했습니다");
      }
      await ctx.db.batch([
        { sql: "UPDATE accounts SET status = ? WHERE id = ? AND tenant_id = ?", params: [ACCOUNT_STATUS.active, acc.id, tenantId] },
      ]);
      return { data: { accountId: acc.id, status: ACCOUNT_STATUS.active }, message: `활성화됨: ${acc.email}` };
    },
  },
  {
    spec: {
      name: "account-delete",
      group: "계정",
      label: "계정 삭제",
      summary: "삭제 드레인을 시작한다. 되돌릴 수 없다 — 잠시 막으려면 account-suspend를 쓸 것.",
      readOnly: false,
      destructive: true,
      irreversible: true,
      args: [{ name: "account", label: "계정(주소 또는 id)", type: "string", required: true }],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const acc = await resolveAccount(ctx.db, tenantId, args.account!);
      /**
       * 이 계정을 가리키던 알리아스 목적지도 함께 지운다. 남겨 두면 그 알리아스로 온 메일이
       * 죽은 계정에 배달을 시도하고, `listAliases`가 존재하지 않는 대상을 계속 보여준다.
       * FK 미사용 정책(SCHEMA §1-4)이라 DB가 대신 지워 주지 않는다. 한 배치라 중간 상태가 안 보인다.
       */
      const results = await ctx.db.batch([
        { sql: "UPDATE accounts SET status = ? WHERE id = ? AND tenant_id = ?", params: [ACCOUNT_STATUS.deleting, acc.id, tenantId] },
        {
          // 테넌트 사슬을 타 남의 계정 목적지를 지우지 않게 한다(accountId만으로 지우면 인가가 샌다).
          sql: `DELETE FROM address_targets WHERE account_id IN
                  (SELECT id FROM accounts WHERE id = ? AND tenant_id = ?)`,
          params: [acc.id, tenantId],
        },
      ]);
      if (results[0]!.changes === 0) throw new CommandError("notFound", `계정을 찾을 수 없습니다: ${args.account}`);
      return { data: { ok: true }, message: `삭제 드레인 시작: ${acc.email}` };
    },
  },
  {
    spec: {
      name: "app-password-list",
      group: "계정",
      label: "앱 비밀번호 목록",
      summary: "계정의 앱 비밀번호를 조회한다(평문·해시 모두 응답에 없다).",
      readOnly: true,
      args: [{ name: "account", label: "계정(주소 또는 id)", type: "string", required: true }],
      fields: [
        { key: "label", label: "라벨" },
        // ★스코프를 보여 준다 — 스코프 거절은 인증 실패와 구분되지 않게 나가므로(자격증명
        //   확인 수단이 되지 않게), 운영자가 "비밀번호는 맞는데 왜 안 되지"에 답할 자리가 여기뿐이다.
        { key: "scopes", label: "허용 표면" },
        { key: "createdAt", label: "생성", format: "time" },
        { key: "lastUsedAt", label: "최근 사용", format: "time" },
        { key: "id", label: "id" },
      ],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const acc = await resolveAccount(ctx.db, tenantId, args.account!);
      const creds = await listCredentials(ctx.db, acc.id, CREDENTIAL_KIND.appPassword);
      return {
        rows: creds.map((c) => ({
          id: c.id,
          label: c.label,
          scopes: c.scopes ?? "(제한 없음)",
          createdAt: c.createdAt,
          lastUsedAt: c.lastUsedAt,
        })),
      };
    },
  },
  {
    spec: {
      name: "app-password-create",
      group: "계정",
      label: "앱 비밀번호 발급",
      summary: "클라이언트용 앱 비밀번호를 발급한다. 평문은 이때 한 번만 볼 수 있다.",
      readOnly: false,
      args: [
        { name: "account", label: "계정(주소 또는 id)", type: "string", required: true },
        { name: "label", label: "라벨", type: "string", required: false, placeholder: "iPhone Mail" },
        {
          name: "scopes",
          label: "허용 표면",
          type: "string",
          required: false,
          placeholder: AUTH_SURFACES.join(","),
        },
      ],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const acc = await resolveAccount(ctx.db, tenantId, args.account!);
      const label = args.label?.trim() || "app";
      const scopes = normalizeSurfaces(args.scopes);
      const { id, password } = await createAppPassword(ctx.db, acc.id, label, ...(scopes ? [scopes] : []));
      return {
        data: { id, label, scopes: scopes ?? null },
        // 저장은 해시뿐이라 이 화면을 벗어나면 복구할 수 없다 — 그래서 일반 data와 나눠 둔다.
        secret: { label: `앱 비밀번호 (${label})`, value: password, hint: "하이픈/공백은 무시되므로 그대로 붙여넣어도 됩니다." },
        message: `앱 비밀번호 발급됨: ${acc.email} (${label}, id=${id}${scopes ? `, 표면=${scopes}` : ""})`,
      };
    },
  },
  {
    spec: {
      name: "oauth-token-list",
      group: "계정",
      label: "OAuth 토큰 목록",
      summary: "XOAUTH2/OAUTHBEARER용 베어러 토큰을 조회한다.",
      readOnly: true,
      args: [{ name: "account", label: "계정(주소 또는 id)", type: "string", required: true }],
      fields: [
        { key: "label", label: "라벨" },
        { key: "createdAt", label: "생성", format: "time" },
        { key: "lastUsedAt", label: "최근 사용", format: "time" },
        { key: "id", label: "id" },
      ],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const acc = await resolveAccount(ctx.db, tenantId, args.account!);
      const creds = await listCredentials(ctx.db, acc.id, CREDENTIAL_KIND.oauthToken);
      return { rows: creds.map((c) => ({ id: c.id, label: c.label, createdAt: c.createdAt, lastUsedAt: c.lastUsedAt })) };
    },
  },
  {
    // CLI에만 있던 명령 — 이제 세 표면 전부에 생긴다.
    spec: {
      name: "oauth-token-create",
      group: "계정",
      label: "OAuth 토큰 발급",
      summary: "XOAUTH2/OAUTHBEARER의 access token으로 쓸 값을 발급한다.",
      readOnly: false,
      args: [
        { name: "account", label: "계정(주소 또는 id)", type: "string", required: true },
        { name: "label", label: "라벨", type: "string", required: false },
      ],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const acc = await resolveAccount(ctx.db, tenantId, args.account!);
      const label = args.label?.trim() || "oauth";
      const { id, token } = await createOAuthToken(ctx.db, acc.id, label);
      return {
        data: { id, label },
        secret: { label: `OAuth 토큰 (${label})`, value: token, hint: "XOAUTH2/OAUTHBEARER의 access token으로 사용합니다." },
        message: `OAuth 토큰 발급됨: ${acc.email} (${label}, id=${id})`,
      };
    },
  },
  {
    spec: {
      name: "credential-revoke",
      group: "계정",
      label: "자격증명 폐기",
      summary: "앱 비밀번호·OAuth 토큰을 폐기한다. 즉시 반영되며 되돌릴 수 없다.",
      readOnly: false,
      destructive: true,
      irreversible: true,
      args: [{ name: "credentialId", label: "자격증명 id", type: "string", required: true }],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      /**
       * 경로에 계정이 없으므로 credentials→accounts 조인으로 테넌트 사슬을 확인한다 —
       * 다른 테넌트의 자격증명 id를 찍어 폐기하는 것을 막는 유일한 방어선이다.
       */
      const { rows } = await ctx.db.query({
        sql: `SELECT c.account_id FROM credentials c JOIN accounts a ON a.id = c.account_id
              WHERE c.id = ? AND a.tenant_id = ?`,
        params: [args.credentialId!, tenantId],
      });
      const row = rows[0];
      if (!row) throw new CommandError("notFound", `자격증명을 찾을 수 없습니다: ${args.credentialId}`);
      // store의 revokeCredential은 kind=0(기본 비밀번호)을 지우지 않는다 — 계정 잠금 방지.
      const ok = await revokeCredential(ctx.db, String(row.account_id), args.credentialId!);
      if (!ok) throw new CommandError("invalid", "기본 비밀번호(kind=0)는 폐기할 수 없습니다", "계정 자체를 막으려면 account-suspend를 쓰십시오");
      return { data: { revoked: true }, message: `폐기됨: ${args.credentialId}` };
    },
  },
];
