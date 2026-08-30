export {
  BatchConflictError,
  type DbDriver,
  type Dialect,
  type QueryResult,
  type Statement,
  type StatementResult,
} from "./types.ts";
// 아래 지연 로드 래퍼(openPostgres/openMysql)의 반환 타입으로 쓴다 — 위 재노출은 값 스코프에 없다.
import type { DbDriver } from "./types.ts";
export {
  ADDRESS_KIND,
  ADDRESS_FIELDS,
  RECIPIENT_KINDS,
  MTA_QUEUE_STATUS,
  PENDING_QUEUE_STATUSES,
  TERMINAL_QUEUE_STATUSES,
  REF_KIND,
  SYSTEM_ACCOUNT_REF,
  BLOB_STATUS,
  CREDENTIAL_KIND,
  credentialKindName,
  SUPPRESSION_REASON,
  ACCOUNT_STATUS,
  DOMAIN_STATUS,
  SMARTHOST_TLS,
  SMARTHOST_TENANT_DEFAULT,
  isAddressKind,
  isMtaQueueStatus,
  isSmarthostTls,
  type AddressField,
  type AddressKind,
  type MtaQueueStatus,
  type MtaQueueStatusName,
  type RefKind,
  type RefKindName,
  type BlobStatus,
  type BlobStatusName,
  type CredentialKind,
  type CredentialKindName,
  type SuppressionReason,
  type SuppressionReasonName,
  type AccountStatus,
  type AccountStatusName,
  type DomainStatus,
  type DomainStatusName,
  type SmarthostTls,
  type SmarthostTlsName,
} from "./columns.ts";
export { openSqlite } from "./sqlite.ts";

/**
 * PG/MySQL 드라이버는 **지연 로드**한다(정적 재노출 금지).
 *
 * ★왜(오픈소스 자립성): SQLite는 런타임 빌트인(`bun:sqlite`/`node:sqlite`)이라 의존성이 없는데,
 * 이 진입점이 `postgres.ts`·`mysql.ts`를 정적으로 재노출하면 **모듈 해석 단계에서** `pg`·`mysql2`를
 * 찾는다. 그래서 SQLite만 쓰려는 사용자도 쓰지도 않을 드라이버 두 개를 설치해야 했다
 * (실측: 두 패키지가 없는 환경에서 `Cannot find package 'pg'`로 진입점 로드 자체가 실패).
 *
 * 두 함수는 원래 `async`였으므로 이 래핑으로 호출 계약이 바뀌지 않는다 — 시그니처 동일.
 * `openDatabase`(open.ts)도 같은 이유로 동적 import를 쓴다.
 */
export async function openPostgres(connectionString: string): Promise<DbDriver> {
  return (await import("./postgres.ts")).openPostgres(connectionString);
}

export async function openMysql(connectionString: string): Promise<DbDriver> {
  return (await import("./mysql.ts")).openMysql(connectionString);
}
export { openD1, type D1Options } from "./d1.ts";
export { migrate, type Migration, type MigrateOptions } from "./migrate.ts";
export { describeDbSpec, openDatabase } from "./open.ts";
export { lookupBlob, type BlobLedgerRow } from "./blob-ledger.ts";
export { m001Init } from "./migrations/001_init.ts";
export {
  lookupDomainRouting,
  isLocallyRoutableDomain,
  canSendFromDomain,
  type DomainRouting,
} from "./domain-lookup.ts";
export { m002Webhooks } from "./migrations/002_webhooks.ts";
export { m003Forwarding } from "./migrations/003_forwarding.ts";
export { m004BlobGc } from "./migrations/004_blob_gc.ts";
export { m005MaildropLock } from "./migrations/005_maildrop_lock.ts";
export { m006AddressFanout } from "./migrations/006_address_fanout.ts";
export { m007Smarthosts } from "./migrations/007_smarthosts.ts";
export { m008SuppressionExpiry } from "./migrations/008_suppression_expiry.ts";
export { m009Complaints } from "./migrations/009_complaints.ts";
export { m010BayesTokens } from "./migrations/010_bayes_tokens.ts";
export { m019IdentityState } from "./migrations/019_identity_state.ts";

import { m001Init } from "./migrations/001_init.ts";
import { m002Webhooks } from "./migrations/002_webhooks.ts";
import { m003Forwarding } from "./migrations/003_forwarding.ts";
import { m004BlobGc } from "./migrations/004_blob_gc.ts";
import { m005MaildropLock } from "./migrations/005_maildrop_lock.ts";
import { m006AddressFanout } from "./migrations/006_address_fanout.ts";
import { m007Smarthosts } from "./migrations/007_smarthosts.ts";
import { m008SuppressionExpiry } from "./migrations/008_suppression_expiry.ts";
import { m009Complaints } from "./migrations/009_complaints.ts";
import { m010BayesTokens } from "./migrations/010_bayes_tokens.ts";
import { m011QueueIndexes } from "./migrations/011_queue_indexes.ts";
import { m012DsnDelayNotice } from "./migrations/012_dsn_delay_notice.ts";
import { m013Vacation } from "./migrations/013_vacation.ts";
import { m014ExpungedFloor } from "./migrations/014_expunged_floor.ts";
import { m015VacationResponse } from "./migrations/015_vacation_response.ts";
import { m016DsnParams } from "./migrations/016_dsn_params.ts";
import { m017Reporting } from "./migrations/017_reporting.ts";
import { m018PushSubscriptions } from "./migrations/018_push_subscriptions.ts";
import { m019IdentityState } from "./migrations/019_identity_state.ts";
import { m020MailboxAcl } from "./migrations/020_mailbox_acl.ts";
import type { Migration } from "./migrate.ts";

/** 전체 마이그레이션 목록 (버전 순). */
export const allMigrations: readonly Migration[] = [m001Init, m002Webhooks, m003Forwarding, m004BlobGc, m005MaildropLock, m006AddressFanout, m007Smarthosts, m008SuppressionExpiry, m009Complaints, m010BayesTokens, m011QueueIndexes, m012DsnDelayNotice, m013Vacation, m014ExpungedFloor, m015VacationResponse, m016DsnParams, m017Reporting, m018PushSubscriptions, m019IdentityState, m020MailboxAcl];
