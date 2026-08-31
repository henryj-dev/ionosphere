import { CommandError, type CommandResult, type SharedMailboxAdminPort } from "@ionosphere/admin-cmd";
import type { DirectoryIdentity, DirectorySnapshot } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import {
  backfillHeaderProjection,
  directorySyncInputFromSnapshot,
  syncDirectorySnapshot,
  type BlobStore,
  type JmapEmailQueryResult,
  type ListingCache,
} from "@ionosphere/store";

export interface DirectorySnapshotSource {
  read(tenantId: string): Promise<DirectorySnapshot>;
  authenticate?(loginName: string, password: string): Promise<DirectoryIdentity | null>;
  close?(): Promise<void>;
}

export interface SharedMailboxRuntimeOptions {
  db: DbDriver;
  blobs: BlobStore;
  listingCache: ListingCache<JmapEmailQueryResult>;
  directorySources?: Readonly<Record<string, DirectorySnapshotSource>>;
}

/** 관리 명령이 실제 프로세스의 DB·BlobStore·LRU를 만나는 유일한 조립 포트다. */
export class SharedMailboxRuntime implements SharedMailboxAdminPort {
  private readonly opts: SharedMailboxRuntimeOptions;

  constructor(opts: SharedMailboxRuntimeOptions) { this.opts = opts; }

  /** local credential 실패 뒤에만 호출한다. immutable key가 기존 link와 일치해야 계정을 반환한다. */
  async authenticate(loginName: string, password: string): Promise<{ accountId: string; credKind: string } | null> {
    if (password.length === 0) return null;
    const normalized = loginName.toLowerCase();
    const candidates = await this.opts.db.query({
      sql: "SELECT provider, external_key, account_id, login_names, email FROM directory_identities WHERE status = 1 AND account_id IS NOT NULL",
    });
    const authenticated: Array<{ accountId: string; credKind: string }> = [];
    for (const row of candidates.rows) {
      const names = (() => { try { return JSON.parse(String(row.login_names)) as unknown; } catch { return []; } })();
      const matches = (Array.isArray(names) && names.some((name) => typeof name === "string" && name.toLowerCase() === normalized))
        || (typeof row.email === "string" && row.email.toLowerCase() === normalized);
      if (!matches) continue;
      const provider = String(row.provider);
      const source = this.opts.directorySources?.[provider];
      if (!source?.authenticate) continue;
      const identity = await source.authenticate(loginName, password);
      if (identity?.externalKey !== String(row.external_key)) continue;
      const account = await this.opts.db.query({ sql: "SELECT id FROM accounts WHERE id = ? AND status = 1", params: [row.account_id] });
      if (account.rows.length === 1) authenticated.push({ accountId: String(row.account_id), credKind: `directory:${provider}` });
    }
    // 같은 login/password가 여러 provider에서 성공하면 어느 tenant인지 추측하지 않는다.
    return authenticated.length === 1 ? authenticated[0]! : null;
  }

  async sync(tenantId: string, provider: string): Promise<CommandResult> {
    const source = this.opts.directorySources?.[provider];
    if (!source) throw new CommandError("unavailable", `directory provider가 구성되지 않았습니다: ${provider}`);
    const snapshot = await source.read(tenantId);
    const input = await directorySyncInputFromSnapshot(this.opts.db, { tenantId, provider, now: Date.now(), snapshot });
    await syncDirectorySnapshot(this.opts.db, input);
    return { data: { provider, identities: snapshot.identities.length, groups: snapshot.groups.length }, message: "directory snapshot 동기화 완료" };
  }

  async rebuildHeaders(batchSize: number | undefined): Promise<CommandResult> {
    const size = batchSize ?? 100;
    // projection과 checkpoint를 한 배치에서 초기화해야 중간 실패 뒤 일부만 옛 세대인 상태가 없다.
    await this.opts.db.batch([
      { sql: "DELETE FROM message_header_projection" },
      { sql: "UPDATE header_backfill_checkpoints SET last_message_id = ?, updated_at = ? WHERE id = ?", params: ["", Date.now(), "default"] },
    ]);
    let processed = 0;
    for (;;) {
      const count = await backfillHeaderProjection(this.opts.db, this.opts.blobs, { batchSize: size });
      processed += count;
      if (count === 0) break;
    }
    return { data: { processed }, message: `header projection ${processed}건 재생성 완료` };
  }

  async flushListingCache(): Promise<CommandResult> {
    const entries = this.opts.listingCache.size;
    this.opts.listingCache.clear();
    return { data: { entries }, message: `listing cache ${entries}건 삭제 완료` };
  }

  async close(): Promise<void> {
    await Promise.all(Object.values(this.opts.directorySources ?? {}).map(async (source) => source.close?.()));
  }
}
