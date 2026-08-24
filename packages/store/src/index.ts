// Phase 0 스토어 표면. 스토어 계약: docs/SCHEMA.md §7
export {
  authenticate,
  createAppPassword,
  createCredential,
  createOAuthToken,
  generateAppPassword,
  generateOAuthToken,
  hashSecret,
  listCredentials,
  revokeCredential,
  verifySecret,
} from "./auth.ts";
export {
  isBlobGcMode,
  runBlobGc,
  type BlobGcMode,
  type BlobGcOptions,
  type BlobGcResult,
} from "./blob-gc.ts";
export {
  LayeredBlobStore,
  type LayeredBlobStoreOptions,
} from "./layered-blob.ts";
export {
  S3BlobStore,
  type S3BlobStoreOptions,
  // ★SigV4 프리미티브를 재노출한다 — 감사 로그 이관(`apps/server/src/audit-shipper.ts`)이
  // 임의 키로 오브젝트를 올려야 하는데, `S3BlobStore`는 블롭 해시 기반 키만 다룬다.
  // 서명을 다시 구현하면 같은 크립토가 두 곳에 생겨 한쪽만 고쳐지는 그 사고를 만든다.
  canonicalUri,
  formatAmzDate,
  signV4,
  type SigV4Credentials,
  type SigV4Request,
  type SigV4Signed,
} from "./s3-blob.ts";
export {
  blobHash,
  FsBlobStore,
  lookupBlob,
  putBlob,
  type BlobLedgerRow,
  type BlobPutResult,
  type BlobStore,
} from "./blob.ts";
export { StoreConflictError, StoreError, StoreQuotaError } from "./errors.ts";
export { DbMaildropLock, type DbMaildropLockOptions } from "./maildrop-lock.ts";
export { Store } from "./store.ts";
export { tokenize, tokenizeQuery } from "./tokenize.ts";
export type {
  AccountRow,
  AppendAddress,
  AppendEnvelope,
  AppendMessageInput,
  AppendMessageResult,
  AppendSearchText,
  CreateAccountInput,
  CreateAccountResult,
  CreateMailboxInput,
  CreateMailboxResult,
  CopyMessageInput,
  DeleteMailboxInput,
  ExpungeInput,
  ExpungeResult,
  JmapChanges,
  JmapEmailFilter,
  JmapEmailMeta,
  JmapEmailQueryResult,
  JmapEntity,
  JmapStates,
  MailboxRow,
  MessageBlobRef,
  MessageListItem,
  MoveMessageInput,
  MoveMessageResult,
  RenameMailboxInput,
  SearchHit,
  SearchOptions,
  SetDeletedInput,
  SetKeywordsInput,
  StoreOptions,
  TenantUsage,
} from "./types.ts";
export { scramSegment, buildScramSegment, scramKeysFor, scramAuthorize, type StoredScram } from "./auth.ts";
// 자격증명 표면 스코프의 **정본**(감사 G1) — 관문은 `authenticate`/`scramAuthorize` 안에 있고,
// 여기 나가는 것은 표면 이름 목록과 판정 함수다(관리 명령이 입력 검증에 쓴다).
export { AUTH_SURFACES, credentialAllowsSurface, type AuthSurface } from "./auth.ts";
export { createBayesStore } from "./bayes-store.ts";

/**
 * `IN (…)` 읽기 질의의 파라미터 청크 헬퍼 — 조립층(IMAP 백엔드)도 같은 한도를 지켜야 한다.
 * 한도의 소유자는 이 패키지다(`chunk.ts MAX_PARAMS_PER_STATEMENT`).
 */
export { queryInChunks } from "./chunk.ts";

export { runRetention, type RetentionOptions, type RetentionResult } from "./retention.ts";
export { claimVacationReply, sweepVacationSent } from "./vacation-store.ts";
