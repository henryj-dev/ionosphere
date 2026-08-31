import type { Migration } from "../migrate.ts";

/** 같은 provider에서 로컬 account 하나를 둘 이상의 외부 identity에 연결하지 못하게 봉인한다. */
export const m024DirectoryIdentityAccountUnique: Migration = {
  version: 24,
  name: "directory identity account unique",
  statements: [
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_directory_identity_account ON directory_identities(tenant_id, provider, account_id)",
  ],
};
