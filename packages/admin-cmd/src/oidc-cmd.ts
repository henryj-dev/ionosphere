/**
 * 외부 OIDC 신원 연결 명령 (회원 정책 E3). 연결은 **관리자가 명시적으로** 한다 — 자동 연결·JIT 없음(공통 기준 1).
 *
 * 키는 (공급자 설정 id, sub)다. IdP의 이메일·이름으로 찾지 않는다. sub는 IdP 관리 화면이나 첫 로그인 실패의
 * 감사 기록(`oidcUnlinkedSub`)에서 확인해 넣는다.
 */
import { linkAccountOidcIdentity, linkAdminIdentity, listAdminIdentities, unlinkAccountOidcIdentity, unlinkAdminIdentity } from "@ionosphere/store";
import { CommandError, type Command, type CommandContext } from "./types.ts";

const PROVIDER_PATTERN = /^[a-z0-9._-]{1,32}$/;

function provider(raw: string | undefined): string {
  const p = (raw ?? "").trim().toLowerCase();
  if (!PROVIDER_PATTERN.test(p)) throw new CommandError("invalid", "공급자 id는 1~32자의 영소문자·숫자·._- 입니다");
  return p;
}
function subject(raw: string | undefined): string {
  const s = (raw ?? "").trim();
  if (s === "" || s.length > 255) throw new CommandError("invalid", "sub가 비었거나 너무 깁니다(255자 이하)");
  return s;
}
function requireTenant(ctx: CommandContext): string {
  if (!ctx.tenantId) throw new CommandError("invalid", "tenantId가 필요합니다");
  return ctx.tenantId;
}
async function adminId(ctx: CommandContext, idOrName: string): Promise<string> {
  const { rows } = await ctx.db.query({ sql: "SELECT id FROM admin_users WHERE id = ? OR username = ?", params: [idOrName, idOrName.trim().toLowerCase()] });
  if (!rows[0]) throw new CommandError("notFound", `관리자를 찾을 수 없습니다: ${idOrName}`);
  return String(rows[0].id);
}
async function accountId(ctx: CommandContext, tenantId: string, idOrEmail: string): Promise<string> {
  const { rows } = await ctx.db.query({ sql: "SELECT id FROM accounts WHERE (id = ? OR email = ?) AND tenant_id = ?", params: [idOrEmail, idOrEmail.trim().toLowerCase(), tenantId] });
  if (!rows[0]) throw new CommandError("notFound", `계정을 찾을 수 없습니다: ${idOrEmail}`);
  return String(rows[0].id);
}

const providerArg = { name: "provider", label: "OIDC 공급자 id", type: "string", required: true } as const;
const subjectArg = { name: "subject", label: "외부 sub", type: "string", required: true } as const;

export const oidcCommands: readonly Command[] = [
  {
    spec: {
      name: "admin-identity-list",
      group: "관리자",
      label: "관리자 외부 신원 목록",
      summary: "관리자에 연결된 OIDC 신원(공급자·sub)을 조회한다.",
      readOnly: true,
      rootOnly: true,
      args: [],
      fields: [
        { key: "provider", label: "공급자" },
        { key: "subject", label: "sub" },
        { key: "adminUserId", label: "관리자 id" },
        { key: "createdAt", label: "연결", format: "time" },
      ],
    },
    async run(ctx) {
      return { rows: await listAdminIdentities(ctx.db) };
    },
  },
  {
    spec: {
      name: "admin-identity-link",
      group: "관리자",
      label: "관리자 외부 신원 연결",
      summary: "OIDC 신원(공급자·sub)을 관리자에 연결한다. 그 뒤 그 IdP로 로그인할 수 있다(로컬 TOTP는 계약에 따라 요구).",
      readOnly: false,
      rootOnly: true,
      sensitive: true,
      args: [{ name: "admin", label: "관리자(사용자명 또는 id)", type: "string", required: true }, providerArg, subjectArg],
    },
    async run(ctx, args) {
      const id = await adminId(ctx, args.admin!);
      const p = provider(args.provider);
      // 설정된 공급자만 — 아무 이름으로나 행을 만들면 쓰레기 행이 생기고 conflict 검사를 우회한다(2026-10-18 검토).
      if (!(ctx.oidcAdminProviders ?? []).includes(p)) throw new CommandError("invalid", `설정된 관리자 OIDC 공급자가 아닙니다: ${p}`);
      const r = await linkAdminIdentity(ctx.db, p, subject(args.subject), id);
      if (r === "conflict") throw new CommandError("conflict", "그 sub가 이미 연결돼 있거나, 이 관리자가 같은 공급자의 다른 sub에 연결돼 있습니다");
      return { data: { adminUserId: id }, message: `연결됨: ${args.admin} ← ${args.provider}` };
    },
  },
  {
    spec: {
      name: "admin-identity-unlink",
      group: "관리자",
      label: "관리자 외부 신원 해제",
      summary: "관리자의 그 공급자 연결을 끊는다. 이미 열린 세션은 끊지 않는다(필요하면 세션 전부 종료를 함께 쓸 것).",
      readOnly: false,
      rootOnly: true,
      destructive: true,
      args: [{ name: "admin", label: "관리자(사용자명 또는 id)", type: "string", required: true }, providerArg],
    },
    async run(ctx, args) {
      const id = await adminId(ctx, args.admin!);
      if (!(await unlinkAdminIdentity(ctx.db, provider(args.provider), id))) throw new CommandError("notFound", "연결이 없습니다");
      return { data: { adminUserId: id }, message: `해제됨: ${args.admin} ← ${args.provider}` };
    },
  },
  {
    spec: {
      name: "oidc-identity-link",
      group: "계정",
      label: "계정 외부 신원 연결",
      summary: "OIDC 신원(공급자·sub)을 메일 계정에 연결한다(셀프서비스 SSO 로그인용).",
      readOnly: false,
      sensitive: true,
      args: [{ name: "account", label: "계정(주소 또는 id)", type: "string", required: true }, providerArg, subjectArg],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      const p = provider(args.provider);
      // 이 테넌트에 설정된 메일 계정 영역 공급자만 받는다(다른 테넌트의 공급자 이름으로 행을 만들지 못하게).
      if (!(ctx.oidcAccountProviders ?? []).some((x) => x.id === p && x.tenantId === tenantId)) {
        throw new CommandError("invalid", `이 테넌트에 설정된 OIDC 공급자가 아닙니다: ${p}`);
      }
      const acc = await accountId(ctx, tenantId, args.account!);
      const r = await linkAccountOidcIdentity(ctx.db, tenantId, p, subject(args.subject), acc);
      if (r === "no_account") throw new CommandError("conflict", "활성 계정이 아닙니다");
      if (r === "conflict") throw new CommandError("conflict", "그 sub가 이미 연결돼 있거나, 이 계정이 같은 공급자의 다른 sub에 연결돼 있습니다");
      return { data: { accountId: acc }, message: `연결됨: ${args.account} ← ${args.provider}` };
    },
  },
  {
    spec: {
      name: "oidc-identity-unlink",
      group: "계정",
      label: "계정 외부 신원 해제",
      summary: "그 공급자·sub 연결을 끊는다. 열린 셀프서비스 세션은 끊지 않는다.",
      readOnly: false,
      destructive: true,
      args: [providerArg, subjectArg],
    },
    async run(ctx, args) {
      const tenantId = requireTenant(ctx);
      if (!(await unlinkAccountOidcIdentity(ctx.db, tenantId, provider(args.provider), subject(args.subject)))) throw new CommandError("notFound", "연결이 없습니다");
      return { data: { ok: true }, message: `해제됨: ${args.provider}/${args.subject}` };
    },
  },
];
