/**
 * @ionosphere/admin-cmd — 관리 명령 계층(GUI·API·CLI 공용 정본).
 *
 * 의존 방향: core → db → store → **admin-cmd** → api → apps/server.
 * 이 패키지는 HTTP도 argv도 모른다(types.ts 머리말 참조).
 */
export { CommandRegistry, runCommand, usageOf, validateArgs } from "./dispatch.ts";
export { accountCommands } from "./accounts.ts";
export { domainCommands, splitForwardTargets } from "./domains-cmd.ts";
export { opsCommands } from "./ops.ts";
export { ALL_COMMANDS, COMMAND_ENCODINGS, createRegistry, labelFor } from "./registry.ts";
export {
  assertDomainNameAvailable,
  assertUsableDomainName,
  DomainNameError,
  provisionDkimKeys,
  provisionDomain,
  PUBLIC_MAILBOX_DOMAINS,
  RESERVED_DOMAIN_NAMES,
  RESERVED_DOMAIN_SUFFIXES,
  type DkimProvision,
  type DnsRecordInstruction,
  type DomainProvision,
  type ProvisionDomainInput,
} from "./domains.ts";
export {
  CommandError,
  type ArgSpec,
  type Command,
  type CommandContext,
  type CommandFailure,
  type CommandResult,
  type CommandSpec,
  type FieldSpec,
  type TlsAdminPort,
} from "./types.ts";
