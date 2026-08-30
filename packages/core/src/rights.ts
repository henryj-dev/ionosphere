/** RFC 4314 표준 mailbox right. `c`·`d`는 호환용 virtual right이라 저장하지 않는다. */
export const STANDARD_MAILBOX_RIGHTS = ["l", "r", "s", "w", "i", "p", "k", "x", "t", "e", "a"] as const;

export type StandardMailboxRight = (typeof STANDARD_MAILBOX_RIGHTS)[number];
export type MailboxRight = StandardMailboxRight | "c" | "d";

const STANDARD_RIGHT_SET = new Set<string>(STANDARD_MAILBOX_RIGHTS);

/** RFC 4314의 virtual right을 내부 standard right으로 확장한다. */
function expandRight(right: string): readonly StandardMailboxRight[] {
  if (right === "c") return ["k", "x"];
  if (right === "d") return ["e", "t", "x"];
  if (STANDARD_RIGHT_SET.has(right)) return [right as StandardMailboxRight];
  throw new RangeError(`지원하지 않는 mailbox right: ${right}`);
}

/**
 * SETACL 입력을 중복 없는 정렬된 standard right 집합으로 바꾼다.
 * 대문자와 unknown right을 무시하면 오타가 권한 변경으로 둔갑하므로 즉시 거부한다.
 */
export function parseMailboxRights(value: string): ReadonlySet<StandardMailboxRight> {
  const rights = new Set<StandardMailboxRight>();
  for (const right of value) {
    for (const expanded of expandRight(right)) rights.add(expanded);
  }
  return rights;
}

/** 계정·그룹·특수 주체에서 계산된 권리를 합친다. 거부 ACL은 Store 계층에서 별도로 적용한다. */
export function combineMailboxRights(...rightsSets: Iterable<StandardMailboxRight>[]): ReadonlySet<StandardMailboxRight> {
  const rights = new Set<StandardMailboxRight>();
  for (const rightsSet of rightsSets) {
    for (const right of rightsSet) rights.add(right);
  }
  return rights;
}

/** standard right 집합을 RFC 응답 순서로 직렬화한다. */
export function formatMailboxRights(rights: Iterable<StandardMailboxRight>, includeVirtual = true): string {
  const selected = new Set(rights);
  const value = STANDARD_MAILBOX_RIGHTS.filter((right) => selected.has(right)).join("");
  const virtual = includeVirtual
    ? `${selected.has("k") || selected.has("x") ? "c" : ""}${selected.has("e") || selected.has("t") || selected.has("x") ? "d" : ""}`
    : "";
  return value + virtual;
}

export const MAILBOX_OPERATION_RIGHT: Readonly<Record<import("./principal.ts").MailboxOperation, StandardMailboxRight>> = {
  lookup: "l",
  read: "r",
  seen: "s",
  write: "w",
  insert: "i",
  post: "p",
  create: "k",
  delete: "x",
  expunge: "e",
  admin: "a",
};
