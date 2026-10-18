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
import { createAdminUser, issueAdminEnrollCode, resetAdminTotpAndRevokeSessions, revokeAdminSessions, setAdminPasswordAndRevokeSessions } from "@ionosphere/store";
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
 * ★두 단계를 한 배치(트랜잭션)로 한다.
 *  1) 운영자 owner 행을 **전부 먼저 갱신해 잠근다.** 동시에 온 다른 요청은 여기서 앞 트랜잭션이 끝나기를 기다린다.
 *  2) 그다음 "나 말고 활성 운영자 owner가 있다"를 조건으로 대상 행을 바꾼다.
 * 1이 없으면 PG(READ COMMITTED)·MySQL(InnoDB 비잠금 읽기)에서 owner A·B를 동시에 정지할 때 두 트랜잭션이
 * 서로를 아직 활성으로 보고 둘 다 통과한다 — 활성 운영자 owner가 0명이 된다(2026-10-18 검토, 사용자 결정으로 #46에서 수정).
 * 1 덕분에 뒤 트랜잭션의 2는 앞 트랜잭션이 커밋한 상태를 본다(PG는 문장마다 새 스냅숏, MySQL은 첫 일관 읽기가 2라서).
 * SQLite는 쓰기가 하나씩만 돌아 처음부터 해당 없다. 동시성은 `admin-owner-race.test.ts`가 실DB로 확인한다.
 * 두 트랜잭션이 owner 행을 다른 순서로 잠그면 교착이 날 수 있다 — DB가 한쪽을 되돌리고 그 요청은 500을 받는다.
 * 안전한 쪽(아무것도 바뀌지 않음)으로 실패하므로 막지 않는다. 다시 시도하면 된다.
 *
 * 집계(COUNT) 파생 테이블로 감싼 이유: MySQL은 UPDATE 대상 테이블을 같은 문장의 서브쿼리에서 직접 읽지 못하고
 * (ER_UPDATE_TABLE_USED), 단순 파생 테이블은 옵티마이저가 바깥으로 합쳐 같은 오류가 난다. 집계는 합쳐지지 않는다.
 */
const OTHER_OPERATOR_OWNER_COUNT = `(SELECT n FROM (SELECT COUNT(*) AS n FROM admin_users WHERE role = ? AND status = ? AND tenant_id IS NULL AND id != ?) AS other_owners)`;

function isActiveOperatorOwner(a: { role: AdminRole; status: number; tenantId: string | null }): boolean {
  return a.role === ADMIN_ROLE.owner && a.status === ADMIN_STATUS.active && a.tenantId === null;
}

async function updateKeepingAnOwner(ctx: CommandContext, set: string, setParams: unknown[], id: string): Promise<void> {
  const now = Date.now();
  const r = await ctx.db.batch([
    { sql: "UPDATE admin_users SET updated_at = ? WHERE role = ? AND tenant_id IS NULL", params: [now, ADMIN_ROLE.owner] },
    {
      sql: `UPDATE admin_users SET ${set}, updated_at = ? WHERE id = ? AND ${OTHER_OPERATOR_OWNER_COUNT} > 0`,
      params: [...setParams, now, id, ADMIN_ROLE.owner, ADMIN_STATUS.active, id],
    },
  ]);
  if ((r[1]?.changes ?? 0) === 0) {
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
      const enrollCode = await issueAdminEnrollCode(ctx.db, id);
      if (enrollCode === null) throw new CommandError("conflict", "등록 코드를 발급하지 못했습니다");
      return {
        data: { adminUserId: id },
        // 등록 코드는 비밀이다 — data에 섞지 않고 secret으로 따로 싣는다(화면·CLI가 한 번만 보여 준다).
        secret: { label: `TOTP 등록 코드 (${username})`, value: enrollCode, hint: "본인에게 따로 전달하십시오. 24시간 안에 한 번만 쓸 수 있습니다." },
        message: `관리자 생성됨: ${username} (${id}) — 첫 로그인에서 등록 코드로 TOTP를 등록하십시오`,
      };
    },
  },
  {
    spec: { name: "admin-user-suspend", group: "관리자", label: "관리자 정지", summary: "로그인과 열린 세션을 막는다(다음 요청부터). 되돌릴 수 있다.", readOnly: false, rootOnly: true, destructive: true, args: [accountArg] },
    async run(ctx, args) {
      const a = await resolveAdmin(ctx, args.admin!);
      // 보호는 대상이 **지금 활성인 운영자 owner**일 때만 건다. 이미 정지된 행에 걸면 MySQL은 바뀐 행이 없어
      // changes=0을 돌려주고, 그것이 "마지막 owner" 거절로 잘못 읽힌다.
      if (isActiveOperatorOwner(a)) await updateKeepingAnOwner(ctx, "status = ?", [ADMIN_STATUS.suspended], a.id);
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
      if (isActiveOperatorOwner(a) && role !== ADMIN_ROLE.owner) await updateKeepingAnOwner(ctx, "role = ?", [role], a.id);
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
      summary: "TOTP·복구 코드를 지우고 세션을 끊고 새 등록 코드를 발급한다(본인이 복구 코드도 잃었을 때의 보조 경로).",
      readOnly: false,
      rootOnly: true,
      destructive: true,
      args: [accountArg],
    },
    async run(ctx, args) {
      const a = await resolveAdmin(ctx, args.admin!);
      const enrollCode = await resetAdminTotpAndRevokeSessions(ctx.db, a.id);
      if (enrollCode === null) throw new CommandError("notFound", `관리자를 찾을 수 없습니다: ${args.admin}`);
      return {
        data: { adminUserId: a.id },
        secret: { label: `TOTP 등록 코드 (${a.username})`, value: enrollCode, hint: "본인에게 따로 전달하십시오. 24시간 안에 한 번만 쓸 수 있습니다." },
        message: `MFA 초기화됨: ${a.username} — 복구 코드도 폐기됐습니다. 다음 로그인에서 등록 코드로 재등록`,
      };
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
