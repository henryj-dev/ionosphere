/** Session 리소스(RFC 8620 §2) 빌더 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { buildSession, CORE_CAPABILITY, MAIL_CAPABILITY } from "../src/session.ts";

describe("buildSession", () => {
  const session = buildSession({
    accounts: [
      {
        accountId: "acc1",
        name: "you@ionosphere.test",
        isPersonal: true,
        isReadOnly: false,
        accountCapabilities: { [MAIL_CAPABILITY]: { maxMailboxDepth: 10 } },
      },
    ],
    primaryAccountId: "acc1",
    username: "you@ionosphere.test",
    apiUrl: "https://mx.ionosphere.test/jmap/api",
    downloadUrl: "https://mx.ionosphere.test/jmap/download/{accountId}/{blobId}/{name}",
    uploadUrl: "https://mx.ionosphere.test/jmap/upload/{accountId}",
    eventSourceUrl: "https://mx.ionosphere.test/jmap/eventsource",
    state: "sess-1",
    capabilities: [CORE_CAPABILITY, MAIL_CAPABILITY],
  });

  test("capabilities — core는 limits 객체, 나머지는 빈 객체", () => {
    const caps = session.capabilities as Record<string, Record<string, unknown>>;
    expect(caps[CORE_CAPABILITY]!.maxCallsInRequest).toBe(50);
    expect(caps[MAIL_CAPABILITY]).toEqual({});
  });

  test("accounts + primaryAccounts 매핑", () => {
    const accounts = session.accounts as Record<string, { name: string; isPersonal: boolean }>;
    expect(accounts.acc1!.name).toBe("you@ionosphere.test");
    expect(accounts.acc1!.isPersonal).toBe(true);
    const primary = session.primaryAccounts as Record<string, string>;
    expect(primary[CORE_CAPABILITY]).toBe("acc1");
    expect(primary[MAIL_CAPABILITY]).toBe("acc1");
  });

  test("URL·state·username 노출", () => {
    expect(session.apiUrl).toBe("https://mx.ionosphere.test/jmap/api");
    expect(session.state).toBe("sess-1");
    expect(session.username).toBe("you@ionosphere.test");
  });
});

/**
 * 감사 5차 §9-5 조사 중 발견 — 같은 `50_000_000`이 **두 곳에 하드코딩**돼 있었다:
 * 세션이 클라이언트에게 **광고하는** 값과 서버가 실제로 **강제하는** 값. 한쪽만 바꾸면
 * 광고와 실제가 갈라져, 통과할 거라 믿고 올린 업로드가 400으로 끊긴다.
 * 이제 둘 다 `@ionosphere/core`의 `MAX_JMAP_UPLOAD_BYTES` 하나를 본다.
 */
describe("업로드 한도의 소유자는 @ionosphere/core 하나다", () => {
  test("세션이 광고하는 maxSizeUpload가 core 상수와 같다", async () => {
    const { MAX_JMAP_UPLOAD_BYTES } = await import("@ionosphere/core");
    const { DEFAULT_CORE_LIMITS } = await import("../src/session.ts");
    expect(DEFAULT_CORE_LIMITS.maxSizeUpload).toBe(MAX_JMAP_UPLOAD_BYTES);
  });

  test("강제 지점에 리터럴이 남아 있지 않다", async () => {
    const { readFileSync } = await import("node:fs");
    const src = readFileSync(new URL("../../../apps/server/src/jmap-server.ts", import.meta.url), "utf8");
    // 리터럴이 되살아나면 광고와 강제가 다시 갈라진다 — 그 회귀를 여기서 잡는다.
    expect(src).not.toContain("50_000_000");
    expect(src).toContain("MAX_JMAP_UPLOAD_BYTES");
  });
});
