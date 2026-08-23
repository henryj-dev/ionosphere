import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { Store } from "../src/store.ts";
import type { AppendEnvelope, AppendMessageInput, StoreOptions } from "../src/types.ts";

export async function freshDb(): Promise<DbDriver> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  return db;
}

export interface TestFixture {
  db: DbDriver;
  store: Store;
  tenantId: string;
  accountId: string;
  inboxId: string;
}

/** 테넌트 + 계정(INBOX 자동 생성 포함)까지 준비된 최소 픽스처. storeOpts는 Store 생성자 옵션(예: searchIndexBody). */
export async function setupFixture(storeOpts?: StoreOptions): Promise<TestFixture> {
  const db = await freshDb();
  const store = new Store(db, storeOpts);
  const { tenantId } = await store.createTenant("acme");
  const { accountId, mailboxId } = await store.createAccount({ tenantId, email: `user-${Math.random().toString(36).slice(2)}@acme.test` });
  return { db, store, tenantId, accountId, inboxId: mailboxId };
}

const EMPTY_ENVELOPE: AppendEnvelope = {
  subject: null,
  subjectBase: null,
  msgidHash: null,
  sentAt: null,
  preview: null,
  hasAttachment: false,
  addresses: [],
  threadRefHashes: [],
};

/** appendMessage 입력을 최소 필드만 채워 생성하는 테스트 헬퍼. */
export function makeAppendInput(overrides: Partial<AppendMessageInput> & { accountId: string; mailboxIds: readonly string[] }): AppendMessageInput {
  return {
    blobId: "b".repeat(64),
    sizeBytes: 100,
    receivedAt: Date.now(),
    envelope: EMPTY_ENVELOPE,
    keywords: [],
    ...overrides,
  };
}
