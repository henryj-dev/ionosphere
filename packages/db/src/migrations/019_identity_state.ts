import type { Migration } from "../migrate.ts";

/** Identity/changes를 EmailSubmission과 분리한다. 두 리소스가 같은 state를 쓰면 한쪽 변경이 다른 쪽 ifInState를 오염시킨다. */
export const m019IdentityState: Migration = {
  version: 19,
  name: "identity state",
  statements: ["ALTER TABLE accounts ADD COLUMN state_identity BIGINT NOT NULL DEFAULT 0"],
};
