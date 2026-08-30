#!/usr/bin/env node
/**
 * 공유 메일함 실행판의 단계 게이트.
 * 검사 정의를 데이터로 두고, 봉인 파일은 커밋되는 docs/plan 아래에 둔다.
 * 이 장치는 구현 단계에서 검사 항목을 늘리는 것이 기존 검사 코드의 우회가 되지 않도록
 * 종료 코드와 측정값을 항상 함께 남긴다.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

type Check = { id: string; kind: "file" | "grep" | "command"; path?: string; pattern?: string; command?: string[]; limit?: number };
type Phase = { needs: readonly string[]; outputs: readonly string[]; checks: readonly Check[] };

const root = resolve(new URL("../..", import.meta.url).pathname);
const sealDir = resolve(root, "docs/plan/.gates/shared-mailbox");
const todoPath = "docs/plan/SHARED-MAILBOX-ACL-DIRECTORY-CACHE-todo.md";

const GATES: Record<string, Phase> = {
  P0: {
    needs: [],
    outputs: ["scripts/gates/shared-mailbox.ts", "packages/core/src/principal.ts", "packages/core/src/rights.ts", "packages/core/src/index.ts", "packages/core/test/principal-rights.test.ts", "packages/core/test/gated-todo-gate.test.ts"],
    checks: [
      { id: "G-P0.1", kind: "command", command: ["node", "--test", "packages/core/test/gated-todo-gate.test.ts"] },
      { id: "G-P0.2", kind: "file", path: todoPath },
      { id: "G-P0.3", kind: "grep", path: "packages/core/src/principal.ts", pattern: "PRINCIPAL_KIND" },
      { id: "G-P0.4", kind: "grep", path: "packages/core/src/rights.ts", pattern: "STANDARD_MAILBOX_RIGHTS" },
      { id: "G-P0.5", kind: "command", command: ["node", "--test", "packages/core/test/principal-rights.test.ts"] },
      { id: "G-P0.6", kind: "command", command: ["npm", "run", "lint"] },
      { id: "G-P0.7", kind: "command", command: ["npm", "run", "typecheck"] },
    ],
  },
  P1: {
    needs: ["P0"],
    outputs: ["packages/db/src/migrations/020_mailbox_acl.ts", "packages/db/src/index.ts", "packages/db/test/migrate.test.ts", "packages/core/src/rights.ts", "packages/core/src/index.ts", "packages/core/test/rights.test.ts", "docs/SCHEMA.md"],
    checks: [
      { id: "G-P1.1", kind: "command", command: ["node", "--test", "packages/db/test/migrate.test.ts"] },
      { id: "G-P1.2", kind: "command", command: ["node", "--test", "packages/core/test/rights.test.ts"] },
      { id: "G-P1.3", kind: "command", command: ["node", "--input-type=module", "-e", "import { allMigrations } from './packages/db/src/index.ts'; const versions = allMigrations.map((m) => m.version); if (versions.filter((v) => v === 20).length !== 1 || !versions.includes(20)) process.exit(1);"] },
      { id: "G-P1.4", kind: "grep", path: "docs/SCHEMA.md", pattern: "mailbox_acl" },
    ],
  },
  P2: {
    needs: ["P1"],
    outputs: ["packages/store/src/authorization.ts", "packages/store/src/store.ts", "packages/store/src/index.ts", "packages/store/test/authorization.test.ts"],
    checks: [
      { id: "G-P2.1", kind: "command", command: ["node", "--test", "packages/store/test/authorization.test.ts"] },
      { id: "G-P2.2", kind: "grep", path: "packages/store/src/store.ts", pattern: "authorizeMailbox" },
      { id: "G-P2.3", kind: "grep", path: "packages/store/src/authorization.ts", pattern: "tenant_id = ?" },
      { id: "G-P2.4", kind: "command", command: ["npm", "run", "lint"] },
      { id: "G-P2.5", kind: "command", command: ["npm", "run", "typecheck"] },
    ],
  },
  P3: {
    needs: ["P2"],
    outputs: ["apps/server/src/imap-backend.ts", "packages/store/src/store.ts", "apps/server/test/imap-shared-namespace.test.ts"],
    checks: [
      { id: "G-P3.1", kind: "grep", path: "apps/server/src/imap-backend.ts", pattern: "principalContext" },
      { id: "G-P3.2", kind: "grep", path: "packages/store/src/store.ts", pattern: "listAccessibleMailboxes" },
      { id: "G-P3.3", kind: "command", command: ["node", "--test", "apps/server/test/imap-shared-namespace.test.ts"] },
      { id: "G-P3.4", kind: "command", command: ["npm", "run", "lint"] },
      { id: "G-P3.5", kind: "command", command: ["npm", "run", "typecheck"] },
    ],
  },
  P4: {
    needs: ["P3"],
    outputs: ["packages/store/src/authorization.ts", "packages/store/src/store.ts", "packages/store/test/authorization.test.ts", "packages/proto-imap/src/engine.ts", "packages/proto-imap/src/server.ts", "packages/proto-imap/test/acl-commands.test.ts", "apps/server/src/imap-backend.ts", "apps/server/test/imap-shared-namespace.test.ts"],
    checks: [
      { id: "G-P4.1", kind: "command", command: ["node", "--test", "packages/store/test/authorization.test.ts"] },
      { id: "G-P4.2", kind: "command", command: ["node", "--test", "packages/proto-imap/test/acl-commands.test.ts"] },
      { id: "G-P4.3", kind: "command", command: ["node", "--test", "apps/server/test/imap-shared-namespace.test.ts"] },
      { id: "G-P4.4", kind: "grep", path: "packages/proto-imap/src/engine.ts", pattern: "GETACL" },
      { id: "G-P4.5", kind: "grep", path: "packages/store/src/authorization.ts", pattern: "setMailboxAcl" },
      { id: "G-P4.6", kind: "grep", path: "packages/store/src/authorization.ts", pattern: "deleteMailboxAcl" },
      { id: "G-P4.7", kind: "command", command: ["node", "--test", "apps/server/test/imap-shared-namespace.test.ts"] },
      { id: "G-P4.8", kind: "grep", path: "apps/server/src/imap-backend.ts", pattern: "hasMailboxRight" },
      { id: "G-P4.9", kind: "command", command: ["npm", "run", "lint"] },
      { id: "G-P4.10", kind: "command", command: ["npm", "run", "typecheck"] },
    ],
  },
  P5: {
    needs: ["P4"],
    outputs: ["apps/server/src/jmap-server.ts", "apps/server/src/jmap-backend.ts", "apps/server/src/principal-context.ts", "apps/server/test/jmap-shared-account.test.ts", "packages/store/src/jmap-store.ts", "packages/store/src/store.ts", "packages/store/src/types.ts", "packages/store/src/index.ts", "packages/store/test/authorization.test.ts"],
    checks: [
      { id: "G-P5.1", kind: "command", command: ["node", "--test", "packages/store/test/authorization.test.ts"] },
      { id: "G-P5.2", kind: "command", command: ["node", "--test", "apps/server/test/jmap-shared-account.test.ts"] },
      { id: "G-P5.3", kind: "grep", path: "apps/server/src/jmap-server.ts", pattern: "listAccessibleAccounts" },
      { id: "G-P5.4", kind: "grep", path: "apps/server/src/jmap-backend.ts", pattern: "accessibleJmapMailboxes" },
      { id: "G-P5.5", kind: "grep", path: "apps/server/src/jmap-server.ts", pattern: "isReadOnly" },
      { id: "G-P5.6", kind: "grep", path: "packages/store/src/store.ts", pattern: "listAccessibleAccounts" },
      { id: "G-P5.7", kind: "grep", path: "packages/store/src/jmap-store.ts", pattern: "allowedMailboxIds" },
      { id: "G-P5.8", kind: "grep", path: "packages/store/src/jmap-store.ts", pattern: "permissions_version" },
      { id: "G-P5.9", kind: "grep", path: "apps/server/src/jmap-server.ts", pattern: "requestedAccountId" },
      { id: "G-P5.10", kind: "command", command: ["npm", "run", "lint"] },
      { id: "G-P5.11", kind: "command", command: ["npm", "run", "typecheck"] },
    ],
  },
  P6: {
    needs: ["P5"],
    outputs: ["packages/core/src/directory.ts", "packages/core/src/index.ts", "packages/core/test/directory.test.ts", "packages/db/src/migrations/021_directory_identity.ts", "packages/store/src/directory-sync.ts", "packages/store/test/directory-sync.test.ts", "apps/server/src/directory-ldap.ts", "apps/server/test/directory-ldap.test.ts"],
    checks: [
      { id: "G-P6.1", kind: "command", command: ["node", "--test", "packages/core/test/directory.test.ts"] },
      { id: "G-P6.2", kind: "command", command: ["node", "--test", "packages/db/test/migrate.test.ts"] },
      { id: "G-P6.3", kind: "grep", path: "packages/core/src/directory.ts", pattern: "validateDirectoryConfig" },
      { id: "G-P6.4", kind: "grep", path: "packages/core/src/directory.ts", pattern: "objectGuid" },
      { id: "G-P6.5", kind: "grep", path: "packages/core/src/directory.ts", pattern: "resolveNestedGroups" },
      { id: "G-P6.6", kind: "grep", path: "packages/db/src/migrations/021_directory_identity.ts", pattern: "directory_identities" },
      { id: "G-P6.7", kind: "grep", path: "packages/core/src/directory.ts", pattern: "class DirectoryProvider" },
      { id: "G-P6.8", kind: "grep", path: "apps/server/src/directory-ldap.ts", pattern: "tlsConnect" },
      { id: "G-P6.9", kind: "grep", path: "apps/server/src/directory-ldap.ts", pattern: "startTls" },
      { id: "G-P6.10", kind: "grep", path: "apps/server/src/directory-ldap.ts", pattern: "authenticateUser" },
      { id: "G-P6.11", kind: "command", command: ["node", "--test", "apps/server/test/directory-ldap.test.ts", "packages/store/test/directory-sync.test.ts"] },
      { id: "G-P6.12", kind: "command", command: ["npm", "run", "lint"] },
      { id: "G-P6.13", kind: "command", command: ["npm", "run", "typecheck"] },
    ],
  },
  P7: {
    needs: ["P6"],
    outputs: ["packages/store/src/header-projection.ts", "packages/store/test/header-projection.test.ts", "packages/db/src/migrations/022_header_projection.ts"],
    checks: [
      { id: "G-P7.1", kind: "command", command: ["node", "--test", "packages/store/test/header-projection.test.ts"] },
      { id: "G-P7.2", kind: "command", command: ["node", "--test", "packages/db/test/migrate.test.ts"] },
      { id: "G-P7.3", kind: "grep", path: "packages/store/src/header-projection.ts", pattern: "nameBytes: 190" },
      { id: "G-P7.4", kind: "grep", path: "packages/store/src/header-projection.ts", pattern: "displayBytes: 16" },
      { id: "G-P7.5", kind: "grep", path: "packages/store/src/header-projection.ts", pattern: "sortBytes: 4" },
      { id: "G-P7.6", kind: "grep", path: "packages/store/src/header-projection.ts", pattern: "occurrence: 32" },
      { id: "G-P7.7", kind: "command", command: ["npm", "run", "lint"] },
      { id: "G-P7.8", kind: "command", command: ["npm", "run", "typecheck"] },
    ],
  },
  P8: {
    needs: ["P7"],
    outputs: ["packages/store/src/listing-cache.ts", "packages/store/test/listing-cache.test.ts", "packages/db/src/migrations/023_listing_indexes.ts"],
    checks: [
      { id: "G-P8.1", kind: "command", command: ["node", "--test", "packages/store/test/listing-cache.test.ts"] },
      { id: "G-P8.2", kind: "command", command: ["node", "--test", "packages/db/test/migrate.test.ts"] },
      { id: "G-P8.3", kind: "grep", path: "packages/store/src/listing-cache.ts", pattern: "maxResults: 2_000" },
      { id: "G-P8.4", kind: "grep", path: "packages/store/src/listing-cache.ts", pattern: "minTtlMs: 5_000" },
      { id: "G-P8.5", kind: "grep", path: "packages/store/src/listing-cache.ts", pattern: "maxEntries: 256" },
      { id: "G-P8.6", kind: "grep", path: "packages/store/src/listing-cache.ts", pattern: "permissionsVersion" },
      { id: "G-P8.7", kind: "command", command: ["npm", "run", "lint"] },
      { id: "G-P8.8", kind: "command", command: ["npm", "run", "typecheck"] },
    ],
  },
  P9: {
    needs: ["P8"],
    outputs: ["packages/admin-cmd/src/registry.ts", "packages/admin-cmd/src/shared-mailbox.ts", "packages/admin-cmd/src/dispatch.ts", "packages/admin-cmd/src/types.ts", "packages/admin-cmd/test/shared-mailbox.test.ts"],
    checks: [
      { id: "G-P9.1", kind: "command", command: ["node", "--test", "packages/admin-cmd/test/shared-mailbox.test.ts"] },
      { id: "G-P9.2", kind: "grep", path: "packages/admin-cmd/src/registry.ts", pattern: "sharedMailboxCommands" },
      { id: "G-P9.3", kind: "grep", path: "packages/admin-cmd/src/shared-mailbox.ts", pattern: "directory-sync" },
      { id: "G-P9.4", kind: "grep", path: "packages/admin-cmd/src/shared-mailbox.ts", pattern: "header-rebuild" },
      { id: "G-P9.5", kind: "grep", path: "packages/admin-cmd/src/shared-mailbox.ts", pattern: "listing-cache-flush" },
      { id: "G-P9.6", kind: "grep", path: "packages/admin-cmd/src/dispatch.ts", pattern: "observer" },
      { id: "G-P9.7", kind: "command", command: ["npm", "run", "lint"] },
      { id: "G-P9.8", kind: "command", command: ["npm", "run", "typecheck"] },
    ],
  },
  P10: { needs: ["P9"], outputs: [], checks: [{ id: "G-P10.1", kind: "command", command: ["npm", "run", "verify"] }] },
};

function sealPath(phase: string): string { return resolve(sealDir, `${phase}.json`); }
function phaseNames(): string[] { return Object.keys(GATES); }

function readSeal(phase: string): { phase: string; sealed: boolean; head: string; waived: boolean; reason: string | null } | null {
  const path = sealPath(phase);
  if (!existsSync(path)) return null;
  try { return JSON.parse(readFileSync(path, "utf8")) as { phase: string; sealed: boolean; head: string; waived: boolean; reason: string | null }; } catch { return null; }
}

function hasPrerequisites(phase: string): boolean {
  for (const need of GATES[phase]?.needs ?? []) {
    const seal = readSeal(need);
    if (!seal?.sealed) return false;
  }
  return true;
}

function currentHead(): string { return execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(); }

function isAncestor(head: string): boolean {
  return spawnSync("git", ["merge-base", "--is-ancestor", head, "HEAD"], { cwd: root, stdio: "ignore" }).status === 0;
}

function runCheck(check: Check): { ok: boolean; measured: number | string; limit: number | null; message: string } {
  if (check.kind === "file") {
    const ok = existsSync(resolve(root, check.path ?? ""));
    return { ok, measured: ok ? 1 : 0, limit: 1, message: check.path ?? "" };
  }
  if (check.kind === "grep") {
    const text = readFileSync(resolve(root, check.path ?? ""), "utf8");
    const measured = (text.match(new RegExp(check.pattern ?? "", "g")) ?? []).length;
    const limit = check.limit ?? 1;
    return { ok: measured >= limit, measured, limit, message: `${check.path}: ${check.pattern}` };
  }
  const command = check.command ?? [];
  const result = spawnSync(command[0] ?? "", command.slice(1), { cwd: root, stdio: "inherit" });
  return { ok: result.status === 0, measured: result.status ?? 1, limit: 0, message: command.join(" ") };
}

function evaluate(phase: string): { ok: boolean; checks: Array<{ id: string; ok: boolean; measured: number | string; limit: number | null }> } {
  const definition = GATES[phase];
  if (!definition) throw new Error(`알 수 없는 단계: ${phase}`);
  if (!hasPrerequisites(phase)) throw new Error(`선행 단계 봉인 없음: ${definition.needs.join(", ")}`);
  const checks = definition.checks.map((check) => {
    const result = runCheck(check);
    console.log(`${result.ok ? "PASS" : "FAIL"} ${check.id} measured=${result.measured} limit=${result.limit ?? "-"} ${result.message}`);
    return { id: check.id, ok: result.ok, measured: result.measured, limit: result.limit };
  });
  return { ok: checks.every((check) => check.ok), checks };
}

function seal(phase: string, waivedReason: string | null): number {
  const definition = GATES[phase];
  if (!definition) throw new Error(`알 수 없는 단계: ${phase}`);
  if (waivedReason !== null && waivedReason.length === 0) throw new Error("waive 사유가 비어 있음");
  if (waivedReason === null) {
    const result = evaluate(phase);
    if (!result.ok) return 1;
    mkdirSync(sealDir, { recursive: true });
    writeFileSync(sealPath(phase), JSON.stringify({ phase, sealed: true, head: currentHead(), at: new Date().toISOString(), waived: false, reason: null, checks: result.checks }, null, 2) + "\n");
  } else {
    if (definition.checks.length > 0) throw new Error("검사가 있는 필수 단계는 waive할 수 없음");
    if (!hasPrerequisites(phase)) throw new Error(`선행 단계 봉인 없음: ${definition.needs.join(", ")}`);
    mkdirSync(sealDir, { recursive: true });
    writeFileSync(sealPath(phase), JSON.stringify({ phase, sealed: true, head: currentHead(), at: new Date().toISOString(), waived: true, reason: waivedReason, checks: [] }, null, 2) + "\n");
  }
  return 0;
}

function status(): number {
  for (const phase of phaseNames()) {
    const seal = readSeal(phase);
    const state = !hasPrerequisites(phase) ? "잠김" : !seal ? "열림" : !isAncestor(seal.head) ? "무효" : "봉인";
    console.log(`${phase}\t${state}\t${seal?.head ?? "-"}`);
  }
  return 0;
}

function assertOrder(): number {
  let failed = false;
  for (const [phase, definition] of Object.entries(GATES)) {
    const seal = readSeal(phase);
    if (!seal?.sealed) continue;
    for (const output of definition.outputs) {
      const changed = spawnSync("git", ["diff", "--quiet", `${seal.head}..HEAD`, "--", output], { cwd: root, stdio: "ignore" }).status !== 0;
      if (changed) { console.error(`FAIL ${phase}: 봉인 후 산출물 변경 ${output}`); failed = true; }
    }
  }
  return failed ? 1 : 0;
}

const args = process.argv.slice(2);
try {
  if (args[0] === "--status") process.exit(status());
  if (args[0] === "--assert-order") process.exit(assertOrder());
  const phase = args[0];
  if (!phase) throw new Error("사용법: shared-mailbox.ts <P0..P10> [--seal|--explain]");
  if (args.includes("--seal")) {
    const waiveAt = args.indexOf("--waived");
    process.exit(seal(phase, waiveAt >= 0 ? args[waiveAt + 1] ?? "" : null));
  }
  const result = evaluate(phase);
  process.exit(result.ok ? 0 : 1);
} catch (error) {
  console.error(`GATE ERROR: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
