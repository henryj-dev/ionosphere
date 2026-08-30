import { describe, expect, test } from "@ionosphere/testkit";
import { createRegistry } from "../src/registry.ts";
import { runCommand } from "../src/dispatch.ts";
import type { CommandContext } from "../src/types.ts";

describe("shared mailbox admin surfaces", () => {
  test("registry descriptor 하나가 다섯 shared/cache 명령의 surface 정본이다", () => {
    const names = createRegistry().describe().filter((spec) => spec.group === "공유 메일함" || spec.group === "메일 캐시").map((spec) => spec.name);
    expect(names).toEqual(["shared-account-list", "mailbox-acl-list", "directory-sync", "header-rebuild", "listing-cache-flush"]);
    expect(createRegistry().describe().filter((spec) => names.includes(spec.name)).every((spec) => spec.destructive === true || spec.readOnly)).toBe(true);
  });

  test("secret/filter/header를 관측 이벤트에 싣지 않는다", async () => {
    const events: unknown[] = [];
    const ctx = {
      db: {},
      store: {},
      tenantId: "tenant-test",
      isRoot: true,
      observer: { record: (event: unknown) => events.push(event) },
      sharedMailbox: { sync: async () => ({ message: "ok" }), rebuildHeaders: async () => ({ message: "ok" }), flushListingCache: async () => ({ message: "ok" }) },
    } as unknown as CommandContext;
    await runCommand(createRegistry(), ctx, "listing-cache-flush", { secret: "audit-secret", filter: "Subject: full header" });
    const serialized = JSON.stringify(events);
    expect(serialized.includes("audit-secret")).toBe(false);
    expect(serialized.includes("Subject: full header")).toBe(false);
    expect(serialized).toBe('[{"operation":"listing-cache-flush","outcome":"ok","reason":"success"}]');
  });

  test("관리 포트가 없으면 기능을 열지 않고 unavailable로 관측한다", async () => {
    const events: unknown[] = [];
    const ctx = { db: {}, store: {}, tenantId: "tenant-test", isRoot: true, observer: { record: (event: unknown) => events.push(event) } } as unknown as CommandContext;
    await expect(runCommand(createRegistry(), ctx, "listing-cache-flush", {})).rejects.toThrow("연결되지 않았습니다");
    expect(events).toEqual([{ operation: "listing-cache-flush", outcome: "fail", reason: "unavailable" }]);
  });
});
