import { CommandError, type Command, type CommandContext } from "./types.ts";

function tenantId(ctx: CommandContext): string {
  if (!ctx.tenantId) throw new CommandError("invalid", "tenantId가 필요합니다");
  return ctx.tenantId;
}

function port(ctx: CommandContext): NonNullable<CommandContext["sharedMailbox"]> {
  if (!ctx.sharedMailbox) throw new CommandError("unavailable", "shared mailbox 관리 포트가 연결되지 않았습니다");
  return ctx.sharedMailbox;
}

export const sharedMailboxCommands: readonly Command[] = [
  {
    spec: { name: "shared-account-list", group: "공유 메일함", label: "공유 계정 목록", summary: "이 테넌트의 shared account를 조회한다.", readOnly: true, args: [], fields: [{ key: "id", label: "id" }, { key: "email", label: "주소" }, { key: "status", label: "상태" }] },
    async run(ctx) {
      const scope = tenantId(ctx);
      const result = await ctx.db.query({ sql: "SELECT id, email, status FROM accounts WHERE tenant_id = ? AND kind = 1 ORDER BY created_at", params: [scope] });
      return { rows: result.rows.map((row) => ({ id: String(row.id), email: String(row.email), status: Number(row.status) })) };
    },
  },
  {
    spec: { name: "mailbox-acl-list", group: "공유 메일함", label: "메일함 ACL 조회", summary: "메일함의 ACL을 조회한다.", readOnly: true, args: [{ name: "mailboxId", label: "메일함 id", type: "string", required: true }], fields: [{ key: "principalId", label: "주체 id" }, { key: "rights", label: "권한" }, { key: "negative", label: "negative" }] },
    async run(ctx, args) {
      const scope = tenantId(ctx);
      const result = await ctx.db.query({ sql: `SELECT acl.principal_id, acl.rights, acl.negative FROM mailbox_acl acl JOIN mailboxes m ON m.id = acl.mailbox_id JOIN accounts a ON a.id = m.account_id WHERE acl.mailbox_id = ? AND a.tenant_id = ? ORDER BY acl.principal_id`, params: [args.mailboxId, scope] });
      return { rows: result.rows.map((row) => ({ principalId: String(row.principal_id), rights: String(row.rights), negative: Number(row.negative) === 1 })) };
    },
  },
  {
    spec: { name: "directory-sync", group: "공유 메일함", label: "디렉터리 동기화", summary: "구성된 LDAP/AD snapshot을 동기화한다.", readOnly: false, destructive: true, args: [{ name: "provider", label: "provider", type: "string", required: true }] },
    async run(ctx, args) { return await port(ctx).sync(tenantId(ctx), args.provider!); },
  },
  {
    spec: { name: "header-rebuild", group: "메일 캐시", label: "Header projection 재생성", summary: "MIME 원본에서 typed header projection을 재생성한다.", readOnly: false, destructive: true, args: [{ name: "batchSize", label: "배치 크기", type: "number", required: false }] },
    async run(ctx, args) { return await port(ctx).rebuildHeaders(args.batchSize ? Number(args.batchSize) : undefined); },
  },
  {
    spec: { name: "listing-cache-flush", group: "메일 캐시", label: "Listing cache 비우기", summary: "프로세스 로컬 listing cache를 비운다.", readOnly: false, destructive: true, args: [] },
    async run(ctx) { return await port(ctx).flushListingCache(); },
  },
];
