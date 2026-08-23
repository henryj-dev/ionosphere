/**
 * 계정별 인프로세스 라이터 큐 (SCHEMA.md §3-1) — 1차 직렬화 수단.
 * 계정 스코프 쓰기는 이 큐를 경유해 프로미스 체인으로 순차 실행된다.
 *
 * §3-1이 말하는 "호환 가능한 대기 작업을 한 배치로 합침"은 `submitCoalesced`가 담당한다.
 * 앞 작업이 도는 동안 쌓인 같은 종류의 항목을 모아 **한 번의 exec**로 넘긴다.
 *
 * 왜 이득이 있는가(실측, 라이브 리눅스): 메시지 적재 1건이 약 1.05ms인데 그중 커밋
 * 오버헤드가 0.40ms — 40%가 일이 아니라 트랜잭션 경계 비용이다. macOS에서는 같은 커밋이
 * 0.018ms(7%)라 이득이 보이지 않는다. 로컬 측정만으로 이 최적화를 판단하면 안 된다.
 */

interface Waiter<R> {
  resolve: (r: R) => void;
  reject: (e: unknown) => void;
}

interface Group<I, R> {
  key: string;
  items: I[];
  waiters: Waiter<R>[];
  exec: (items: I[]) => Promise<R[]>;
  maxSize: number;
  /** 큐에 예약된 뒤 더 이상 항목을 받지 않는 상태. */
  closed: boolean;
}

export class WriterQueue {
  private readonly tails = new Map<string, Promise<unknown>>();
  /** 계정별로 "아직 실행 전이라 더 태울 수 있는" 그룹. */
  private readonly groups = new Map<string, Group<never, never>>();

  async run<T>(accountId: string, task: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(accountId) ?? Promise.resolve();
    // 이전 작업이 실패해도(예: StoreError) 뒤에 대기 중인 무고한 작업은 계속 진행돼야 함.
    const settledPrev = prev.then(
      () => undefined,
      () => undefined,
    );
    const run = settledPrev.then(task);
    this.tails.set(
      accountId,
      run.then(
        () => undefined,
        () => undefined,
      ),
    );
    return run;
  }

  /**
   * 코얼레싱 제출 — 같은 `key`로 대기 중인 항목들이 한 번의 `exec` 호출로 합쳐진다.
   * 반환값은 **내 항목 하나의 결과**이므로 호출자는 코얼레싱을 신경 쓸 필요가 없다.
   *
   * ★계약: 코얼레싱은 성능 최적화이지 의미 변경이 아니다. 그룹 실행이 실패하면 각 항목을
   * 하나씩 다시 실행해 **개별 성패를 그대로 돌려준다** — 한 통의 쿼터 초과가 같이 묶였다는
   * 이유만으로 다른 통까지 실패시키면, 배달 결과가 "누구와 같은 순간에 도착했는가"에 따라
   * 달라진다. 재현되지 않는 버그의 전형이라 구조적으로 막는다.
   */
  submitCoalesced<I, R>(
    accountId: string,
    key: string,
    item: I,
    exec: (items: I[]) => Promise<R[]>,
    maxSize: number,
  ): Promise<R> {
    return new Promise<R>((resolve, reject) => {
      let group = this.groups.get(accountId) as Group<I, R> | undefined;
      if (group === undefined || group.closed || group.key !== key || group.items.length >= maxSize) {
        group = { key, items: [], waiters: [], exec, maxSize, closed: false };
        this.groups.set(accountId, group as unknown as Group<never, never>);
        const scheduled = group;
        void this.run(accountId, async () => {
          scheduled.closed = true; // 이 시점 이후 도착분은 다음 그룹으로
          if (this.groups.get(accountId) === (scheduled as unknown as Group<never, never>)) {
            this.groups.delete(accountId);
          }
          await runGroup(scheduled);
        });
      }
      group.items.push(item);
      group.waiters.push({ resolve, reject });
    });
  }
}

/** 그룹 실행 + 실패 시 개별 폴백. 여기서 던지지 않는다 — 성패는 각 waiter로만 전달된다. */
async function runGroup<I, R>(group: Group<I, R>): Promise<void> {
  try {
    const results = await group.exec(group.items);
    group.waiters.forEach((w, i) => w.resolve(results[i]!));
    return;
  } catch (err) {
    if (group.items.length === 1) {
      group.waiters[0]!.reject(err);
      return;
    }
    // 그룹이 통째로 실패했다 — 원인이 어느 항목인지 모르므로 개별로 되돌려 각자 판정받게 한다.
    for (let i = 0; i < group.items.length; i++) {
      try {
        const [only] = await group.exec([group.items[i]!]);
        group.waiters[i]!.resolve(only!);
      } catch (e) {
        group.waiters[i]!.reject(e);
      }
    }
  }
}
