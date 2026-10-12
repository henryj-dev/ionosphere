/**
 * POP3 maildrop 리스 갱신 타이머 — 갱신이 **실패하거나 락을 잃었을 때**의 동작을 고정한다.
 *
 * 왜 따로 두는가: 저장소 층 테스트는 `refresh()`가 false를 돌려주는 **계약**만 보고, 백엔드 통합
 * 테스트는 획득·해제의 소유권만 본다. 그 사이 — 백엔드 타이머가 false/예외를 받았을 때 무엇을
 * 하는가 — 는 아무도 검사하지 않았다. 그 갈래가 틀리면 두 방향으로 조용히 사고가 난다.
 *  ① 락을 잃었는데 갱신을 계속하면 남의 리스를 두드리고, 경고가 없으면 탈취가 로그에 안 남는다.
 *  ② 일시적 DB 오류에 타이머를 멈추면 TTL(3주기분)이 지나 멀쩡한 세션이 락을 잃는다.
 *
 * DB·소켓 없이 가짜 락·로거·스토어로 백엔드만 돌린다 — 확인할 것은 타이머 갈래뿐이다.
 */
import { afterEach, expect, test } from "@ionosphere/testkit";
import type { LogFields, Logger, MaildropLock } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import type { BlobStore, Store } from "@ionosphere/store";
import { IonospherePop3Backend } from "../src/backend.ts";

/** 실제 리스 주기(수 초)를 기다리지 않도록 짧게 둔다. 갈래 검사에는 주기 길이가 무관하다. */
const TICK_MS = 5;
/** 조건을 기다리는 상한 — 넘으면 타이머가 안 돌았다는 뜻이라 실패로 드러낸다. */
const WAIT_LIMIT_MS = 2000;

type RefreshStep = "held" | "lost" | "throw";

/**
 * 갱신 결과를 순서대로 내주는 가짜 락. 다 쓰면 마지막 결과를 반복한다.
 *
 * ★`refresh`가 즉시 끝난다는 전제에 기댄다. 그래서 갱신이 겹치지 않고 "상실 경고 정확히 1회"가
 * 성립한다. 실제 DB 락처럼 갱신이 주기보다 오래 걸리면 진행 중인 갱신마다 경고가 찍힐 수 있다 —
 * 그건 이 테스트가 아니라 운영 코드 쪽 검토 대상이다.
 */
function scriptedLock(steps: RefreshStep[]): MaildropLock & { refreshCalls: () => number } {
  let calls = 0;
  return {
    refreshIntervalMs: TICK_MS,
    acquire: async () => true,
    refresh: async () => {
      const step = steps[Math.min(calls, steps.length - 1)]!;
      calls += 1;
      if (step === "throw") throw new Error("simulated db outage");
      return step === "held";
    },
    release: async () => {},
    refreshCalls: () => calls,
  };
}

/** warn만 모으는 로거. 백엔드가 `child()`로 감싸므로 자식도 같은 배열에 쓴다. */
function recordingLogger(): Logger & { warns: { msg: string; fields?: LogFields }[] } {
  const warns: { msg: string; fields?: LogFields }[] = [];
  const logger: Logger & { warns: typeof warns } = {
    warns,
    debug: () => {},
    info: () => {},
    warn: (msg, fields) => warns.push({ msg, ...(fields ? { fields } : {}) }),
    error: () => {},
    child: () => logger,
  };
  return logger;
}

/** openMaildrop이 부르는 두 조회만 답하는 스토어. 나머지는 이 테스트에서 불리지 않는다. */
const fakeStore = {
  getMailboxByRole: async () => ({ id: "inbox-1" }),
  listMessages: async () => [],
} as unknown as Store;

const backends: IonospherePop3Backend[] = [];
afterEach(async () => {
  // 타이머를 남기면 다음 테스트의 호출 수가 섞인다.
  for (const b of backends.splice(0)) await b.releaseMaildrop("acc-1");
});

function backendWith(lock: MaildropLock, logger: Logger): IonospherePop3Backend {
  const b = new IonospherePop3Backend({} as DbDriver, fakeStore, {} as BlobStore, logger, lock);
  backends.push(b);
  return b;
}

async function waitUntil(cond: () => boolean, what: string): Promise<void> {
  const until = Date.now() + WAIT_LIMIT_MS;
  while (!cond()) {
    if (Date.now() > until) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, TICK_MS));
  }
}

/** 여러 주기를 흘려보낸다 — 멈췄어야 할 타이머가 계속 도는지 드러낸다. */
const idleTicks = (n: number) => new Promise((r) => setTimeout(r, TICK_MS * n));

test("갱신이 false(락 상실)면 한 번 경고하고 타이머를 멈춘다", async () => {
  const lock = scriptedLock(["held", "lost"]);
  const log = recordingLogger();
  const backend = backendWith(lock, log);

  expect((await backend.openMaildrop("acc-1")).ok).toBe(true);
  await waitUntil(() => log.warns.some((w) => w.msg === "maildrop lease lost"), "lease lost 경고");

  const callsAtLoss = lock.refreshCalls();
  await idleTicks(10);
  // 멈추지 않으면 잃은 락을 계속 갱신하려 든다(남의 리스를 두드린다).
  expect(lock.refreshCalls()).toBe(callsAtLoss);
  const lost = log.warns.filter((w) => w.msg === "maildrop lease lost");
  expect(lost).toHaveLength(1);
  expect(lost[0]!.fields?.accountId).toBe("acc-1");
});

test("갱신이 던지면 경고만 남기고 다음 주기에 다시 시도한다", async () => {
  const lock = scriptedLock(["throw", "throw", "held"]);
  const log = recordingLogger();
  const backend = backendWith(lock, log);

  expect((await backend.openMaildrop("acc-1")).ok).toBe(true);
  // 예외 두 번 뒤에도 세 번째 이후 갱신이 이어져야 한다 — 일시 오류로 세션을 포기하지 않는다.
  await waitUntil(() => lock.refreshCalls() >= 4, "예외 뒤 재시도");

  const failed = log.warns.filter((w) => w.msg === "maildrop lease refresh failed");
  expect(failed).toHaveLength(2);
  for (const w of failed) {
    expect(w.fields?.accountId).toBe("acc-1");
    expect(String(w.fields?.error)).toContain("simulated db outage");
  }
  // 예외는 락 상실이 아니다 — 두 경고를 섞으면 운영에서 탈취와 DB 장애를 구분하지 못한다.
  expect(log.warns.some((w) => w.msg === "maildrop lease lost")).toBe(false);
});

test("해제하면 갱신 타이머도 멈춘다", async () => {
  const lock = scriptedLock(["held"]);
  const backend = backendWith(lock, recordingLogger());

  expect((await backend.openMaildrop("acc-1")).ok).toBe(true);
  await waitUntil(() => lock.refreshCalls() >= 2, "갱신 시작");
  await backend.releaseMaildrop("acc-1");

  const callsAtRelease = lock.refreshCalls();
  await idleTicks(10);
  expect(lock.refreshCalls()).toBe(callsAtRelease);
});
