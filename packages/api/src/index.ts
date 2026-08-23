// @ionosphere/api — 관리 REST API(HTTP 어댑터). 관리 로직 자체는 @ionosphere/admin-cmd가 소유한다.
export { AdminApiServer, type AdminApiDeps, type TlsAdmin } from "./server.ts";
/**
 * 도메인 프로비저닝은 **@ionosphere/admin-cmd로 이사했다**(GUI·API·CLI가 같은 명령을 쓰게 하려면
 * 명령 계층이 api보다 아래에 있어야 한다 — api를 의존하면 순환이다).
 *
 * 여기서 재export하는 이유는 호환이다: `@ionosphere/api`에서 이 이름들을 가져다 쓰던 곳
 * (apps/server 테스트 등)이 여럿이라, 한 번에 옮기면 이 변경의 본질과 무관한 diff가 커진다.
 * 새 코드는 `@ionosphere/admin-cmd`에서 직접 가져올 것.
 */
export { MAX_ALIAS_TARGETS } from "@ionosphere/core";
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
} from "@ionosphere/admin-cmd";
