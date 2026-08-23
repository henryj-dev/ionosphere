/**
 * InProcessMaildropLock — MaildropLock 계약(@ionosphere/core) 준수 확인.
 *
 * DB 락과 **같은 계약**을 지켜야 백엔드가 둘을 바꿔 끼울 수 있다. 특히 owner 가드:
 * POP3 어댑터는 인증된 연결이 끊길 때 항상 releaseMaildrop을 부르므로, owner를 안 보면
 * [IN-USE]를 받은 세션이 끊기면서 **남의 락을 푸는** 사고가 난다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { InProcessMaildropLock } from "../src/server.ts";

describe("InProcessMaildropLock", () => {
  test("같은 계정은 하나만 잡는다 / 계정이 다르면 서로 막지 않는다", async () => {
    const lock = new InProcessMaildropLock();
    expect(await lock.acquire("acc-1", "sess-a")).toBe(true);
    expect(await lock.acquire("acc-1", "sess-b")).toBe(false);
    expect(await lock.acquire("acc-2", "sess-b")).toBe(true);
  });

  test("release는 자기 락만 푼다", async () => {
    const lock = new InProcessMaildropLock();
    expect(await lock.acquire("acc-1", "sess-a")).toBe(true);

    await lock.release("acc-1", "sess-b");
    expect(await lock.acquire("acc-1", "sess-b")).toBe(false); // 여전히 sess-a의 것

    await lock.release("acc-1", "sess-a");
    expect(await lock.acquire("acc-1", "sess-b")).toBe(true);
  });

  test("refresh는 소유 여부를 그대로 답한다(만료가 없어 주기 갱신은 불필요)", async () => {
    const lock = new InProcessMaildropLock();
    expect(await lock.refresh("acc-1", "sess-a")).toBe(false); // 잡은 적 없음
    await lock.acquire("acc-1", "sess-a");
    expect(await lock.refresh("acc-1", "sess-a")).toBe(true);
    expect(await lock.refresh("acc-1", "sess-b")).toBe(false);
    expect(lock.refreshIntervalMs).toBe(0);
  });
});
