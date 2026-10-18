/**
 * 관리자(콘솔 사람 주체) 명령군 — 생성·목록·정지·재활성·역할·MFA 초기화·세션 철회 (회원 정책 E1).
 *
 * ★전부 `rootOnly`다. 관리자를 만드는 것은 테넌트를 관리하는 것보다 한 단계 위의 권한이라,
 * 부를 수 있는 주체를 rootToken(부트스트랩)·호스트 CLI(비상 경로)·운영자 owner 세션으로 좁힌다.
 * 테넌트 관리자가 자기 테넌트에 관리자를 늘리는 기능은 아직 없다(필요하면 별도로 연다).
 *
 * 첫 관리자는 CLI(`admin-user-create`)나 rootToken으로 만든다. 그 뒤 rootToken은 쓰지 않는다(결정 D4).
 */
import { ADMIN_ROLE, ADMIN_STATUS, isAdminRole, type AdminRole } from "@ionosphere/db";
import { createAdminUser, resetAdminTotpAndRevokeSessions, revokeAdminSessions, setAdminPasswordAndRevokeSessions } from "@ionosphere/store";
import { CommandError, type Command, type CommandContext } from "./types.ts";

const ROLE_NAMES = Object.keys(ADMIN_ROLE) as (keyof typeof ADMIN_ROLE)[];

function parseRole(raw: string | undefined): AdminRole {
  const name = (raw ?? "").trim().toLowerCase();
  const found = ROLE_NAMES.find((n) => n.toLowerCase() === name);
  if (!found) throw new CommandError("invalid", `알 수 없는 역할: ${raw ?? ""} (가능: ${ROLE_NAMES.join(", ")})`);
  return ADMIN_ROLE[found];
}

/** id 또는 사용자명으로 찾는다. 없으면 notFound. */
async function resolveAdmin(ctx: CommandContext, idOrName: string): Promise<{ id: string; username: string; role: AdminRole; status: number; tenantId: string | null }> {
  const { rows } = await ctx.db.query({
    sql: "SELECT id, username, role, status, tenant_id FROM admin_users WHERE id = ? OR username = ?",
    params: [idOrName, idOrName.trim().toLowerCase()],
  });
  const r = rows[0];
  if (!r) throw new CommandError("notFound", `관리자를 찾을 수 없습니다: ${idOrName}`);
  const role = Number(r.role);
  if (!isAdminRole(role)) throw new CommandError("conflict", `저장된 역할 값이 올바르지 않습니다: ${role}`);
  return { id: String(r.id), username: String(r.username), role, status: Number(r.status), tenantId: r.tenant_id == null ? null : String(r.tenant_id) };
}

/**
 * ★마지막 활성 운영자 owner를 정지·강등하지 못하게 막는다. 막지 않으면 사람 로그인으로는 되돌릴 수 없고,
 * 남는 길이 비상 경로(호스트 CLI)뿐이 된다 — 그 경로가 있다고 해서 일상 실수로 거기까지 가게 두지 않는다.
 *
 * 확인을 UPDATE의 조건으로 넣는다(조회 뒤 쓰기가 아니라). 두 owner를 동시에 정지하면 조회 방식은 둘 다
 * "다른 owner가 있다"를 보고 통과한다. 파생 테이블로 감싼 이유: MySQL은 UPDATE 대상 테이블을 같은 문장의
 * 서브쿼리에서 직접 읽지 못한다(ER_UPDATE_TABLE_USED).
 * ⚠ 남는 틈: 격리 수준이 READ COMMITTED이면 두 트랜잭션이 서로의 커밋 전 상태를 보고 함께 통과할 수 있다.
 * 관리자 수가 적고 사람 손으로 하는 작업이라 그 창은 좁다 — 닫으려면 잠금 행이 필요하다.
 */
const OTHER_OPERATOR_OWNER = `EXISTS (SELECT 1 FROM (SELECT id FROM admin_users WHERE role = ? AND status = ? AND tenant_id IS NULL AND id != ?) AS other_owners)`;

async function updateKeepingAnOwner(ctx: CommandContext, set: string, setParams: unknown[], id: string): Promise<void> {
  const r = await ctx.db.batch([
    {
      sql: `UPDATE admin_users SET ${set}, updated_at = ? WHERE id = ? AND ${OTHER_OPERATOR_OWNER}`,
      params: [...setParams, Date.now(), id, ADMIN_ROLE.owner, ADMIN_STATUS.active, id],
    },
  ]);
  if ((r[0]?.changes ?? 0) === 0) {
    throw new CommandError("conflict", "마지막 활성 운영자 owner입니다", "다른 운영자 owner를 먼저 만드십시오");
  }
}

/**
 * 사용자명 형식 — 길이와 문자 집합을 화이트리스트로 좁힌다. 제어문자·공백이 들어가면 감사 로그와 화면에서
 * 다른 이름처럼 보이고(`ops` vs `ops\u200b`), 로그 줄을 깨뜨릴 수 있다.
 */
const USERNAME_PATTERN = /^[a-z0-9._%+@-]{3,254}$/;

const adminFields = [
  { key: "username", label: "사용자명" },
  { key: "role", label: "역할", encoding: "adminRole" },
  { key: "status", label: "상태", encoding: "adminStatus" },
  { key: "tenantId", label: "테넌트" },
  { key: "mfa", label: "MFA" },
  { key: "id", label: "id" },
];

const accountArg = { name: "admin", label: "관리자(사용자명 또는 id)", type: "string", required: true } as const;

export const adminUserCommands: readonly Command[] = [
  {
    spec: { name: "admin-user-list", group: "관리자", label: "관리자 목록", summary: "콘솔 관리자와 MFA 등록 여부를 조회한다.", readOnly: true, rootOnly: true, args: [], fields: adminFields },
    async run(ctx) {
      const { rows } = await ctx.db.query({ sql: "SELECT id, username, role, status, tenant_id, totp_secret FROM admin_users ORDER BY created_at" });
      return {
        rows: rows.map((r) => ({
          id: String(r.id),
          username: String(r.username),
          role: Number(r.role),
          status: Number(r.status),
          tenantId: r.tenant_id == null ? "(운영자)" : String(r.tenant_id),
          mfa: r.totp_secret == null ? "미등록" : "등록",
        })),
      };
    },
  },
  {
    spec: {
      name: "admin-user-create", sensitive: true,
      group: "관리자",
      label: "관리자 생성",
      summary: "콘솔 관리자를 만든다. 첫 로그인에서 TOTP를 등록해야 다른 화면을 쓸 수 있다.",
      readOnly: false,
      rootOnly: true,
      args: [
        { name: "username", label: "사용자명", type: "string", required: true, placeholder: "ops@ionosphere.test" },
        { name: "password", label: "비밀번호", type: "secret", required: true },
        { name: "role", label: "역할", type: "string", required: true, placeholder: ROLE_NAMES.join(" | ") },
        { name: "adminTenantId", label: "테넌트 id(비우면 운영자)", type: "string", required: false },
      ],
    },
    async run(ctx, args) {
      const role = parseRole(args.role);
      const username = (args.username ?? "").trim().toLowerCase();
      if (!USERNAME_PATTERN.test(username)) {
        throw new CommandError("invalid", "사용자명은 3~254자의 영소문자·숫자와 . _ % + @ - 만 쓸 수 있습니다");
      }
      const password = args.password ?? "";
      if (password.length === 0) throw new CommandError("invalid", "비밀번호가 비어 있습니다");
      const tenantId = args.adminTenantId?.trim() || undefined;
      if (tenantId) {
        const t = await ctx.db.query({ sql: "SELECT id FROM tenants WHERE id = ?", params: [tenantId] });
        if (t.rows.length === 0) throw new CommandError("notFound", `테넌트를 찾을 수 없습니다: ${tenantId}`);
      }
      const id = await createAdminUser(ctx.db, { username, password, role, ...(tenantId ? { tenantId } : {}) });
      if (id === null) throw new CommandError("conflict", `이미 있는 사용자명: ${username}`);
      return { data: { adminUserId: id }, message: `관리자 생성됨: ${username} (${id}) — 첫 로그인에서 TOTP를 등록하십시오` };
    },
  },
  {
    spec: { name: "admin-user-suspend", group: "관리자", label: "관리자 정지", summary: "로그인과 열린 세션을 막는다(다음 요청부터). 되돌릴 수 있다.", readOnly: false, rootOnly: true, destructive: true, args: [accountArg] },
    async run(ctx, args) {
      const a = await resolveAdmin(ctx, args.admin!);
      if (a.role === ADMIN_ROLE.owner && a.tenantId === null) await updateKeepingAnOwner(ctx, "status = ?", [ADMIN_STATUS.suspended], a.id);
      else await ctx.db.batch([{ sql: "UPDATE admin_users SET status = ?, updated_at = ? WHERE id = ?", params: [ADMIN_STATUS.suspended, Date.now(), a.id] }]);
      // 세션 해석이 status를 매번 보므로 철회가 없어도 막히지만, 세션 행까지 닫아 두면 재활성 때 옛 세션이 살아나지 않는다.
      await revokeAdminSessions(ctx.db, a.id);
      return { data: { adminUserId: a.id }, message: `정지됨: ${a.username}` };
    },
  },
  {
    spec: { name: "admin-user-activate", sensitive: true, group: "관리자", label: "관리자 재활성", summary: "정지된 관리자를 되살린다. 옛 세션은 살아나지 않는다.", readOnly: false, rootOnly: true, args: [accountArg] },
    async run(ctx, args) {
      const a = await resolveAdmin(ctx, args.admin!);
      await ctx.db.batch([{ sql: "UPDATE admin_users SET status = ?, updated_at = ? WHERE id = ?", params: [ADMIN_STATUS.active, Date.now(), a.id] }]);
      return { data: { adminUserId: a.id }, message: `활성화됨: ${a.username}` };
    },
  },
  {
    spec: {
      name: "admin-user-role-set",
      group: "관리자",
      label: "관리자 역할 변경",
      summary: "역할을 바꾼다. 하향은 열린 세션의 다음 요청부터 반영된다.",
      readOnly: false,
      rootOnly: true,
      destructive: true,
      args: [accountArg, { name: "role", label: "역할", type: "string", required: true, placeholder: ROLE_NAMES.join(" | ") }],
    },
    async run(ctx, args) {
      const a = await resolveAdmin(ctx, args.admin!);
      const role = parseRole(args.role);
      if (a.role === ADMIN_ROLE.owner && role !== ADMIN_ROLE.owner && a.tenantId === null) await updateKeepingAnOwner(ctx, "role = ?", [role], a.id);
      else await ctx.db.batch([{ sql: "UPDATE admin_users SET role = ?, updated_at = ? WHERE id = ?", params: [role, Date.now(), a.id] }]);
      return { data: { adminUserId: a.id, role }, message: `역할 변경됨: ${a.username}` };
    },
  },
  {
    spec: {
      name: "admin-user-password-set",
      group: "관리자",
      label: "관리자 비밀번호 변경",
      summary: "비밀번호를 바꾸고 그 관리자의 세션을 모두 끊는다.",
      readOnly: false,
      rootOnly: true,
      destructive: true,
      args: [accountArg, { name: "password", label: "새 비밀번호", type: "secret", required: true }],
    },
    async run(ctx, args) {
      const a = await resolveAdmin(ctx, args.admin!);
      if ((args.password ?? "").length === 0) throw new CommandError("invalid", "새 비밀번호가 비어 있습니다");
      await setAdminPasswordAndRevokeSessions(ctx.db, a.id, args.password!);
      return { data: { adminUserId: a.id }, message: `비밀번호 변경됨: ${a.username} (세션 전부 종료)` };
    },
  },
  {
    spec: {
      name: "admin-user-mfa-reset",
      group: "관리자",
      label: "관리자 MFA 초기화",
      summary: "TOTP를 지우고 세션을 끊는다. 다음 로그인에서 다시 등록해야 한다(분실 복구용).",
      readOnly: false,
      rootOnly: true,
      destructive: true,
      args: [accountArg],
    },
    async run(ctx, args) {
      const a = await resolveAdmin(ctx, args.admin!);
      await resetAdminTotpAndRevokeSessions(ctx.db, a.id);
      return { data: { adminUserId: a.id }, message: `MFA 초기화됨: ${a.username} — 다음 로그인에서 재등록` };
    },
  },
  {
    spec: { name: "admin-user-sessions-revoke", group: "관리자", label: "관리자 세션 전부 종료", summary: "모든 기기에서 로그아웃시킨다.", readOnly: false, rootOnly: true, destructive: true, args: [accountArg] },
    async run(ctx, args) {
      const a = await resolveAdmin(ctx, args.admin!);
      const n = await revokeAdminSessions(ctx.db, a.id);
      return { data: { adminUserId: a.id, revoked: n }, message: `세션 ${n}개 종료: ${a.username}` };
    },
  },
];
