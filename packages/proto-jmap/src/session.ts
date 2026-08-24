import { MAX_JMAP_UPLOAD_BYTES } from "@ionosphere/core";
/**
 * JMAP Session 리소스 (RFC 8620 §2). GET /jmap/session이 반환하는 서버 능력·계정 디스커버리.
 */

export const CORE_CAPABILITY = "urn:ietf:params:jmap:core";
export const MAIL_CAPABILITY = "urn:ietf:params:jmap:mail";
export const SUBMISSION_CAPABILITY = "urn:ietf:params:jmap:submission";
/** RFC 9425 — 계정 쿼터 조회. IMAP QUOTA(RFC 9208)와 **같은 값**을 다른 표면에 낸다. */
export const QUOTA_CAPABILITY = "urn:ietf:params:jmap:quota";
/** RFC 8621 §8 — 부재 자동 응답 설정. Sieve `vacation`과 같은 게이트를 쓴다. */
export const VACATION_CAPABILITY = "urn:ietf:params:jmap:vacationresponse";

/** RFC 8620 §2 coreCapabilities — 보수적 기본값. */
export interface CoreCapabilityLimits {
  maxSizeUpload: number;
  maxConcurrentUpload: number;
  maxSizeRequestObject: number;
  maxConcurrentRequests: number;
  maxCallsInRequest: number;
  maxObjectsInGet: number;
  maxObjectsInSet: number;
  collationAlgorithms: string[];
}

export const DEFAULT_CORE_LIMITS: CoreCapabilityLimits = {
  maxSizeUpload: MAX_JMAP_UPLOAD_BYTES,
  maxConcurrentUpload: 4,
  maxSizeRequestObject: 10_000_000,
  maxConcurrentRequests: 4,
  maxCallsInRequest: 50,
  maxObjectsInGet: 500,
  maxObjectsInSet: 500,
  collationAlgorithms: ["i;ascii-casemap", "i;unicode-casemap"],
};

export interface SessionAccount {
  accountId: string;
  name: string;
  isPersonal: boolean;
  isReadOnly: boolean;
  /** accountCapabilities[urn] = 계정별 능력 객체(Mail은 maxMailboxDepth 등). */
  accountCapabilities: Record<string, Record<string, unknown>>;
}

export interface SessionOptions {
  accounts: readonly SessionAccount[];
  /** 이 사용자의 주 계정(accountId). */
  primaryAccountId: string;
  username: string;
  apiUrl: string;
  downloadUrl: string;
  uploadUrl: string;
  eventSourceUrl: string;
  state: string;
  coreLimits?: CoreCapabilityLimits;
  /** 서버 전체 capability(urn) 목록 — capabilities 객체 키. */
  capabilities: readonly string[];
}

/** Session JSON 객체 생성 (RFC 8620 §2). */
export function buildSession(opts: SessionOptions): Record<string, unknown> {
  const capabilities: Record<string, unknown> = {};
  for (const cap of opts.capabilities) {
    capabilities[cap] = cap === CORE_CAPABILITY ? (opts.coreLimits ?? DEFAULT_CORE_LIMITS) : {};
  }
  const accounts: Record<string, unknown> = {};
  const primaryAccounts: Record<string, string> = {};
  for (const acc of opts.accounts) {
    accounts[acc.accountId] = {
      name: acc.name,
      isPersonal: acc.isPersonal,
      isReadOnly: acc.isReadOnly,
      accountCapabilities: acc.accountCapabilities,
    };
    for (const cap of Object.keys(acc.accountCapabilities)) {
      if (!(cap in primaryAccounts)) primaryAccounts[cap] = acc.accountId;
    }
  }
  // core는 항상 주 계정을 가리킴
  primaryAccounts[CORE_CAPABILITY] = opts.primaryAccountId;
  return {
    capabilities,
    accounts,
    primaryAccounts,
    username: opts.username,
    apiUrl: opts.apiUrl,
    downloadUrl: opts.downloadUrl,
    uploadUrl: opts.uploadUrl,
    eventSourceUrl: opts.eventSourceUrl,
    state: opts.state,
  };
}
