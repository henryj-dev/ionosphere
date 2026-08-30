import { describe, expect, test } from "@ionosphere/testkit";
import {
  MAILBOX_OPERATION_RIGHT,
  combineMailboxRights,
  formatMailboxRights,
  parseMailboxRights,
} from "@ionosphere/core";

describe("mailbox rights 계약", () => {
  test("virtual right은 standard right으로 확장하고 안정적으로 직렬화한다", () => {
    const rights = parseMailboxRights("lrcd");
    expect(formatMailboxRights(rights, false)).toBe("lrkxte");
    expect(formatMailboxRights(rights)).toBe("lrkxtecd");
  });

  test("주체별 권리는 합집합으로 계산하고 거부 ACL은 포함하지 않는다", () => {
    const account = parseMailboxRights("lr");
    const group = parseMailboxRights("sip");
    const combined = combineMailboxRights(account, group);
    expect(formatMailboxRights(combined, false)).toBe("lrsip");
  });

  test("알 수 없는 right과 대문자는 fail closed 한다", () => {
    expect(() => parseMailboxRights("q")).toThrow();
    expect(() => parseMailboxRights("L")).toThrow();
  });

  test("mailbox operation은 하나의 standard right에 매핑된다", () => {
    expect(MAILBOX_OPERATION_RIGHT.lookup).toBe("l");
    expect(MAILBOX_OPERATION_RIGHT.read).toBe("r");
    expect(MAILBOX_OPERATION_RIGHT.admin).toBe("a");
  });
});
