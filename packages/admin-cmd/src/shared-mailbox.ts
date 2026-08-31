import { CommandError, type Command, type CommandContext } from "./types.ts";
import { ulid } from "@ionosphere/core";
import { directoryMembershipSource } from "@ionosphere/store";

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
    spec: { name: "directory-identity-list", group: "공유 메일함", label: "디렉터리 identity 목록", summary: "동기화된 immutable identity와 로컬 account 연결을 조회한다.", readOnly: true, args: [{ name: "provider", label: "provider", type: "string", required: true }], fields: [{ key: "externalKey", label: "external key" }, { key: "email", label: "주소" }, { key: "accountId", label: "account id" }] },
    async run(ctx, args) {
      const result = await ctx.db.query({ sql: "SELECT external_key, email, display_name, account_id, status FROM directory_identities WHERE tenant_id = ? AND provider = ? ORDER BY external_key", params: [tenantId(ctx), args.provider] });
      return { rows: result.rows.map((row) => ({ externalKey: String(row.external_key), email: row.email == null ? null : String(row.email), displayName: row.display_name == null ? null : String(row.display_name), accountId: row.account_id == null ? null : String(row.account_id), status: Number(row.status) })) };
    },
  },
  {
    spec: { name: "directory-identity-link", group: "공유 메일함", label: "디렉터리 identity 연결", summary: "immutable external key를 같은 테넌트의 로컬 account에 연결한다.", readOnly: false, destructive: true, args: [{ name: "provider", label: "provider", type: "string", required: true }, { name: "externalKey", label: "external key", type: "string", required: true }, { name: "accountId", label: "account id", type: "string", required: true }] },
    async run(ctx, args) {
      const scope = tenantId(ctx);
      const identity = await ctx.db.query({ sql: "SELECT account_id, display_name FROM directory_identities WHERE tenant_id = ? AND provider = ? AND external_key = ? AND status = 1", params: [scope, args.provider, args.externalKey] });
      if (identity.rows.length !== 1) throw new CommandError("notFound", "directory identity를 찾을 수 없습니다");
      const account = await ctx.db.query({ sql: "SELECT id FROM accounts WHERE id = ? AND tenant_id = ? AND status = 1", params: [args.accountId, scope] });
      if (account.rows.length !== 1) throw new CommandError("notFound", "같은 테넌트의 활성 account를 찾을 수 없습니다");
      const otherLink = await ctx.db.query({ sql: "SELECT external_key FROM directory_identities WHERE tenant_id = ? AND provider = ? AND account_id = ? AND external_key <> ?", params: [scope, args.provider, args.accountId, args.externalKey] });
      if (otherLink.rows.length > 0) throw new CommandError("conflict", "이 account는 같은 provider의 다른 identity에 연결되어 있습니다");
      const linked = identity.rows[0]?.account_id;
      if (linked != null && String(linked) !== args.accountId) throw new CommandError("conflict", "directory identity가 다른 account에 연결되어 있습니다");
      const now = Date.now();
      await ctx.db.batch([
        { sql: "UPDATE directory_identities SET account_id = ? WHERE tenant_id = ? AND provider = ? AND external_key = ?", params: [args.accountId, scope, args.provider, args.externalKey] },
        { sql: ctx.db.insertIgnore("principals", ["id", "tenant_id", "kind", "account_id", "provider", "external_key", "display_name", "created_at"]), params: [ulid(), scope, 0, args.accountId, args.provider, args.externalKey, identity.rows[0]?.display_name ?? null, now] },
        { sql: "UPDATE principals SET account_id = ?, display_name = ? WHERE tenant_id = ? AND kind = 0 AND provider = ? AND external_key = ?", params: [args.accountId, identity.rows[0]?.display_name ?? null, scope, args.provider, args.externalKey] },
        { sql: "UPDATE accounts SET permissions_version = permissions_version + 1 WHERE id = ? AND tenant_id = ?", params: [args.accountId, scope] },
      ]);
      return { data: { provider: args.provider, externalKey: args.externalKey, accountId: args.accountId }, message: "directory identity 연결 완료 — group membership 반영을 위해 다시 동기화하세요" };
    },
  },
  {
    spec: { name: "directory-identity-unlink", group: "공유 메일함", label: "디렉터리 identity 연결 해제", summary: "directory 로그인을 끊고 provider group membership을 회수한다.", readOnly: false, destructive: true, args: [{ name: "provider", label: "provider", type: "string", required: true }, { name: "externalKey", label: "external key", type: "string", required: true }] },
    async run(ctx, args) {
      const scope = tenantId(ctx);
      const identity = await ctx.db.query({ sql: "SELECT account_id FROM directory_identities WHERE tenant_id = ? AND provider = ? AND external_key = ?", params: [scope, args.provider, args.externalKey] });
      const accountId = identity.rows[0]?.account_id == null ? null : String(identity.rows[0]?.account_id);
      if (!accountId) throw new CommandError("notFound", "연결된 directory identity를 찾을 수 없습니다");
      await ctx.db.batch([
        { sql: "DELETE FROM account_memberships WHERE account_id = ? AND source = ?", params: [accountId, directoryMembershipSource(args.provider!)] },
        { sql: "UPDATE principals SET account_id = NULL WHERE tenant_id = ? AND kind = 0 AND provider = ? AND external_key = ?", params: [scope, args.provider, args.externalKey] },
        { sql: "UPDATE directory_identities SET account_id = NULL WHERE tenant_id = ? AND provider = ? AND external_key = ?", params: [scope, args.provider, args.externalKey] },
        { sql: "UPDATE accounts SET permissions_version = permissions_version + 1 WHERE id = ? AND tenant_id = ?", params: [accountId, scope] },
      ]);
      return { data: { provider: args.provider, externalKey: args.externalKey }, message: "directory identity 연결 해제 완료" };
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
