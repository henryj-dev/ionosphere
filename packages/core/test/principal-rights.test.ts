import test from "node:test";
import assert from "node:assert/strict";
import {
  MAILBOX_OPERATION_RIGHT,
  PRINCIPAL_KIND,
  STANDARD_MAILBOX_RIGHTS,
  formatMailboxRights,
  parseMailboxRights,
} from "@ionosphere/core";

test("P0 권한 계약은 principal 4종과 RFC standard right 11개를 고정한다", () => {
  assert.deepEqual(Object.keys(PRINCIPAL_KIND), ["account", "group", "anyone", "authenticated"]);
  assert.deepEqual(STANDARD_MAILBOX_RIGHTS, ["l", "r", "s", "w", "i", "p", "k", "x", "t", "e", "a"]);
  assert.equal(Object.keys(MAILBOX_OPERATION_RIGHT).length, 10);
});

test("P0 rights parser는 중복과 virtual right을 정규화한다", () => {
  const rights = parseMailboxRights("llcdd");
  assert.equal(formatMailboxRights(rights), "lkxtecd");
});

test("P0 rights parser는 대문자와 unknown right을 거부한다", () => {
  assert.throws(() => parseMailboxRights("L"), /지원하지 않는 mailbox right/);
  assert.throws(() => parseMailboxRights("q"), /지원하지 않는 mailbox right/);
});
