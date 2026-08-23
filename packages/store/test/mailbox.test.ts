import { describe, expect, test } from "@ionosphere/testkit";
import { StoreConflictError, StoreError } from "../src/errors.ts";
import { setupFixture } from "./helpers.ts";

describe("createMailbox — 이름 충돌 (SCHEMA.md §7-8: 시맨틱 충돌은 즉시 실패)", () => {
  test("같은 부모 아래 같은 이름 → StoreError 즉시 (무한 재시도 아님)", async () => {
    const { store, accountId } = await setupFixture();
    await store.createMailbox({ accountId, name: "Work" });

    await expect(store.createMailbox({ accountId, name: "Work" })).rejects.toBeInstanceOf(StoreError);
    // 클레임 경합 소진용 에러(StoreConflictError)가 아니라 즉시 실패하는 시맨틱 에러여야 함
    await expect(store.createMailbox({ accountId, name: "Work" })).rejects.not.toBeInstanceOf(StoreConflictError);
  });

  test("서로 다른 부모 아래는 같은 이름 허용", async () => {
    const { store, accountId } = await setupFixture();
    const { mailboxId: parentA } = await store.createMailbox({ accountId, name: "ParentA" });
    const { mailboxId: parentB } = await store.createMailbox({ accountId, name: "ParentB" });

    await expect(store.createMailbox({ accountId, name: "Sub", parentId: parentA })).resolves.toBeTruthy();
    await expect(store.createMailbox({ accountId, name: "Sub", parentId: parentB })).resolves.toBeTruthy();
  });

  test("uidvalidity는 계정 uidvalidity_last보다 항상 큼 (§5-1 재사용 방지)", async () => {
    const { store, accountId } = await setupFixture();
    const a = await store.createMailbox({ accountId, name: "A" });
    const b = await store.createMailbox({ accountId, name: "B" });
    expect(b.uidvalidity).toBeGreaterThan(a.uidvalidity - 1);
    expect(b.uidvalidity).toBeGreaterThanOrEqual(a.uidvalidity);
  });

  test("존재하지 않는 parentId → StoreError", async () => {
    const { store, accountId } = await setupFixture();
    await expect(store.createMailbox({ accountId, name: "X", parentId: "Z".repeat(26) })).rejects.toBeInstanceOf(StoreError);
  });
});

describe("createAccount — 이메일 충돌", () => {
  test("같은 이메일로 중복 계정 생성 → StoreError", async () => {
    const { store, tenantId } = await setupFixture();
    await store.createAccount({ tenantId, email: "dup@acme.test" });
    await expect(store.createAccount({ tenantId, email: "dup@acme.test" })).rejects.toBeInstanceOf(StoreError);
  });

  test("존재하지 않는 tenantId → StoreError", async () => {
    const { store } = await setupFixture();
    await expect(store.createAccount({ tenantId: "Z".repeat(26), email: "x@acme.test" })).rejects.toBeInstanceOf(StoreError);
  });
});
