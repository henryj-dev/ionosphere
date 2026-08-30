/**
 * 메일함 권한 판정에 쓰는 주체 계약.
 * 계정과 주체를 같은 문자열로 취급하면 shared account의 mailboxId만 알아도
 * 권한 검사를 우회하기 쉬우므로 두 축을 타입 수준에서 분리한다.
 */
export const PRINCIPAL_KIND = {
  account: 0,
  group: 1,
  anyone: 2,
  authenticated: 3,
} as const;

export type PrincipalKind = (typeof PRINCIPAL_KIND)[keyof typeof PRINCIPAL_KIND];

export type PrincipalContext = {
  principalId: string;
  primaryAccountId: string;
  accessibleAccountIds: readonly string[];
  groupIds: readonly string[];
  authenticated: boolean;
};

export type MailboxOperation =
  | "lookup"
  | "read"
  | "seen"
  | "write"
  | "insert"
  | "post"
  | "create"
  | "delete"
  | "expunge"
  | "admin";
