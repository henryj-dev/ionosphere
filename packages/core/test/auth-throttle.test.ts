/**
 * 인증 실패 스로틀 + 클라이언트 IP 판정.
 *
 * 원래 관리 API 안에만 있던 로직이라 나머지 프로토콜에는 시도 제한이 **아예 없었다**.
 * core로 올려 정본을 하나로 두고, 여기서 그 계약을 못박는다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import {
  AuthFailureThrottle,
  blockedUntil,
  clientIpOf,
  normalizeIp,
  throttleKeyOf,
  type SharedThrottleStore,
  type ThrottleCounter,
} from "../src/auth-throttle.ts";
import { createLogger } from "../src/log.ts";

describe("AuthFailureThrottle", () => {
  test("한도 미만은 통과, 초과하면 차단 + 남은 시간 안내", async () => {
    const t = new AuthFailureThrottle({ freeFailures: 3, baseDelayMs: 1000 });
    const now = 10_000;
    expect(await t.blocked("1.2.3.4", now)).toBe(false);
    await t.recordFailure("1.2.3.4", now);
    await t.recordFailure("1.2.3.4", now);
    expect(await t.blocked("1.2.3.4", now)).toBe(false);
    await t.recordFailure("1.2.3.4", now);
    expect(await t.blocked("1.2.3.4", now)).toBe(true);
    expect(await t.retryAfterSeconds("1.2.3.4", now)).toBeGreaterThan(0);
  });

  test("다른 키는 서로 영향을 주지 않는다", async () => {
    const t = new AuthFailureThrottle({ freeFailures: 2, baseDelayMs: 1000 });
    const now = 10_000;
    await t.recordFailure("1.1.1.1", now);
    await t.recordFailure("1.1.1.1", now);
    expect(await t.blocked("1.1.1.1", now)).toBe(true);
    expect(await t.blocked("2.2.2.2", now)).toBe(false);
  });

  test("성공하면 카운터가 지워진다 — 오타 뒤 정상 로그인이 벌받지 않게", async () => {
    const t = new AuthFailureThrottle({ freeFailures: 2, baseDelayMs: 1000 });
    const now = 10_000;
    await t.recordFailure("1.2.3.4", now);
    await t.clear("1.2.3.4");
    await t.recordFailure("1.2.3.4", now);
    expect(await t.blocked("1.2.3.4", now)).toBe(false);
  });

  test("윈도우가 지나면 자동으로 풀린다", async () => {
    const t = new AuthFailureThrottle({ freeFailures: 2, baseDelayMs: 1000 });
    await t.recordFailure("1.2.3.4", 10_000);
    await t.recordFailure("1.2.3.4", 10_000);
    expect(await t.blocked("1.2.3.4", 10_000)).toBe(true);
    expect(await t.blocked("1.2.3.4", 11_500)).toBe(false);
  });
});

describe("clientIpOf", () => {
  test("소켓 상대가 루프백이면 x-forwarded-for를 신뢰한다(우리 프론트가 덮어쓴 값)", async () => {
    expect(clientIpOf("203.0.113.9", "127.0.0.1")).toBe("203.0.113.9");
    expect(clientIpOf("203.0.113.9", "::1")).toBe("203.0.113.9");
    expect(clientIpOf("2001:db8::1", "127.0.0.1")).toBe("2001:db8::1");
    // 대괄호 표기(프록시가 IPv6를 이렇게 적기도 한다)는 벗겨서 받는다.
    expect(clientIpOf("[2001:db8::1]", "::ffff:127.0.0.1")).toBe("2001:db8::1");
  });

  test("루프백이 보낸 쓰레기 XFF는 무시하고 peer를 쓴다 — 로컬 위조로 Map을 오염시킬 수 없어야 한다", async () => {
    // ssh -L 포워딩·같은 호스트 프로세스는 루프백 상대라 신뢰 관문을 통과한다.
    // 형식 검사가 없던 시절엔 아래 값들이 그대로 스로틀 키가 됐다(임의 IP 60초 잠금 + Map 오염).
    for (const junk of ["", "not-an-ip", "1.2.3.4.5", "203.0.113.9:443", "<script>", "999.999.999.999", "  "]) {
      expect(clientIpOf(junk, "127.0.0.1")).toBe("127.0.0.1");
    }
  });

  test("배열 XFF는 신뢰하지 않는다 — node·bun 어느 쪽도 배열을 만들지 않는다(죽은 분기 제거)", async () => {
    expect(clientIpOf(["203.0.113.9, 10.0.0.1"], "127.0.0.1")).toBe("127.0.0.1");
  });

  test("루프백이 아니면 XFF를 무시한다 — 헤더 위조로 스로틀을 우회할 수 없어야 한다", async () => {
    expect(clientIpOf("1.1.1.1", "203.0.113.50")).toBe("203.0.113.50");
    expect(clientIpOf("1.1.1.1", undefined)).toBe("unknown");
  });

  test("XFF가 없으면 소켓 주소", async () => {
    expect(clientIpOf(undefined, "127.0.0.1")).toBe("127.0.0.1");
  });

  test("IPv4-매핑 IPv6는 점표기로 되돌린다 — 표면마다 표기가 갈리면 감사 로그를 IP로 훑을 수 없다", async () => {
    /**
     * 2026-08-04 감사 로그가 드러낸 결함. node 이중스택 리스너는 IPv4 접속의 `remoteAddress`를
     * `::ffff:a.b.c.d`로 준다. 소켓 프로토콜은 `normalizeIp`를 거쳐 점표기를 남기는데 HTTP
     * 표면(JMAP·관리 API)은 이 함수를 쓰므로 매핑 표기가 그대로 남았다 — 라이브 첫 관측에서
     * JMAP만 `::ffff:192.155.90.118`로 찍혔다. 같은 주소가 두 표기로 남으면 IP 단위 집계가 갈린다.
     */
    expect(clientIpOf(undefined, "::ffff:192.155.90.118")).toBe("192.155.90.118");
    // 루프백도 같다(프론트 뒤 구성에서 peer로 떨어지는 값).
    expect(clientIpOf(undefined, "::ffff:127.0.0.1")).toBe("127.0.0.1");
    // XFF 경로도 같은 표기를 쓴다 — 프록시가 매핑 표기로 적어 보내는 경우.
    expect(clientIpOf("::ffff:203.0.113.9", "127.0.0.1")).toBe("203.0.113.9");
    // 순수 IPv6는 건드리지 않는다(매핑이 아니다).
    expect(clientIpOf(undefined, "2001:db8::1")).toBe("2001:db8::1");
  });
});

describe("normalizeIp", () => {
  test("IPv4-mapped IPv6를 순수 IPv4로", async () => {
    expect(normalizeIp("::ffff:1.2.3.4")).toBe("1.2.3.4");
    expect(normalizeIp("2001:db8::1")).toBe("2001:db8::1");
    expect(normalizeIp(undefined)).toBe("unknown");
  });
});

describe("throttleKeyOf — 프리픽스 정규화", () => {
  test("같은 /64 안의 서로 다른 IPv6 주소는 같은 키가 된다", async () => {
    const key = throttleKeyOf("2001:db8:abcd:1234::1");
    expect(throttleKeyOf("2001:db8:abcd:1234::2")).toBe(key);
    expect(throttleKeyOf("2001:db8:abcd:1234:ffff:ffff:ffff:ffff")).toBe(key);
    // 표기가 달라도(선행 0·대문자·압축) 같은 키여야 한다.
    expect(throttleKeyOf("2001:0DB8:ABCD:1234:0:0:0:9")).toBe(key);
  });

  test("다른 /64는 다른 키다 — 프리픽스 묶기가 정상 사용자까지 뭉치지 않아야 한다", async () => {
    expect(throttleKeyOf("2001:db8:abcd:1234::1")).not.toBe(throttleKeyOf("2001:db8:abcd:1235::1"));
  });

  test("IPv4-매핑 IPv6는 평문 IPv4와 같은 키(표기 두 가지로 한도를 두 배 쓰지 못하게)", async () => {
    expect(throttleKeyOf("::ffff:203.0.113.9")).toBe("203.0.113.9");
    expect(throttleKeyOf("::ffff:cb00:7109")).toBe("203.0.113.9");
    expect(throttleKeyOf("[::ffff:203.0.113.9]")).toBe("203.0.113.9");
    expect(throttleKeyOf("203.0.113.9")).toBe("203.0.113.9");
  });

  test("zone id·형식 위반은 fail closed", async () => {
    expect(throttleKeyOf("fe80::1%eth0")).toBe(throttleKeyOf("fe80::2"));
    expect(throttleKeyOf("not-an-ip")).toBe("unknown");
    expect(throttleKeyOf(undefined)).toBe("unknown");
    expect(throttleKeyOf("")).toBe("unknown");
  });
});

describe("IPv6 프리픽스 스로틀 (감사 H-5)", () => {
  test("/64 안에서 주소를 바꿔가며 시도해도 한 버킷에 쌓인다", async () => {
    const t = new AuthFailureThrottle({ freeFailures: 3, baseDelayMs: 1000 });
    const now = 10_000;
    // 위조가 아니라 **실제** 소스 주소를 바꾸는 공격 — VPS 하나가 /64를 통째로 받는다.
    await t.recordFailure("2001:db8:1:1::a", now);
    await t.recordFailure("2001:db8:1:1::b", now);
    await t.recordFailure("2001:db8:1:1::c", now);
    expect(await t.blocked("2001:db8:1:1::d", now)).toBe(true);
    // 다른 /64는 영향 없음
    expect(await t.blocked("2001:db8:1:2::a", now)).toBe(false);
  });

  test("IPv4-매핑과 평문 IPv4가 같은 버킷을 쓴다", async () => {
    const t = new AuthFailureThrottle({ freeFailures: 2, baseDelayMs: 1000 });
    const now = 10_000;
    await t.recordFailure("::ffff:203.0.113.9", now);
    await t.recordFailure("203.0.113.9", now);
    expect(await t.blocked("::ffff:cb00:7109", now)).toBe(true);
  });
});

describe("계정 축 스로틀 (감사 M-6)", () => {
  test("서로 다른 IP에서 오는 같은 계정 대입이 막힌다", async () => {
    const t = new AuthFailureThrottle({ freeFailures: 3, baseDelayMs: 1000 });
    const now = 10_000;
    // 봇넷 — IP 축은 매번 다른 /64라 절대 안 걸린다.
    await t.recordFailure({ ip: "2001:db8:1::1", account: "victim@test.local" }, now);
    await t.recordFailure({ ip: "2001:db8:2::1", account: "victim@test.local" }, now);
    await t.recordFailure({ ip: "2001:db8:3::1", account: "VICTIM@test.local " }, now);
    expect(await t.blocked({ ip: "2001:db8:4::1", account: "victim@test.local" }, now)).toBe(true);
    // 계정 축이 걸린 것이지 IP 축이 걸린 게 아니다.
    expect(await t.blocked({ ip: "2001:db8:4::1" }, now)).toBe(false);
    // 다른 계정은 자유롭다 — 한 계정 잠금이 서버 전체 잠금이 되면 안 된다.
    expect(await t.blocked({ ip: "2001:db8:4::1", account: "other@test.local" }, now)).toBe(false);
  });

  test("성공하면 두 축 모두 지워진다", async () => {
    const t = new AuthFailureThrottle({ freeFailures: 2, baseDelayMs: 1000 });
    const now = 10_000;
    await t.recordFailure({ ip: "203.0.113.9", account: "u@test.local" }, now);
    await t.recordFailure({ ip: "203.0.113.9", account: "u@test.local" }, now);
    expect(await t.blocked({ ip: "203.0.113.9" }, now)).toBe(true);
    await t.clear({ ip: "203.0.113.9", account: "u@test.local" });
    expect(await t.blocked({ ip: "203.0.113.9", account: "u@test.local" }, now)).toBe(false);
  });

  test("문자열 축약형은 IP 축만 센다 — 소켓 어댑터가 이 형태로 부른다", async () => {
    const t = new AuthFailureThrottle({ freeFailures: 1, baseDelayMs: 1000 });
    const now = 10_000;
    await t.recordFailure("203.0.113.9", now);
    expect(await t.blocked("203.0.113.9", now)).toBe(true);
    expect(await t.blocked({ account: "u@test.local" }, now)).toBe(false);
  });
});

describe("스로틀 발동 로깅 (감사 M-6)", () => {
  test("한도에 닿는 순간 축·대상과 함께 남긴다(그 뒤 시도는 로그 폭주를 만들지 않는다)", async () => {
    const lines: string[] = [];
    const t = new AuthFailureThrottle({
      freeFailures: 2,
      baseDelayMs: 1000,
      logger: createLogger({ format: "json", sink: (l) => void lines.push(l) }),
    });
    const now = 10_000;
    await t.recordFailure({ ip: "203.0.113.9", account: "u@test.local" }, now);
    expect(lines).toHaveLength(0);
    await t.recordFailure({ ip: "203.0.113.9", account: "u@test.local" }, now);
    // 두 축이 같은 규칙(공통 수치)이라 경계에서 축마다 한 줄씩이다.
    expect(lines).toHaveLength(2);
    expect(lines[0]!).toContain('"axis":"ip"');
    expect(lines[0]!).toContain("203.0.113.9");
    expect(lines[1]!).toContain('"axis":"account"');
    await t.recordFailure({ ip: "203.0.113.9", account: "u@test.local" }, now);
    expect(lines).toHaveLength(2);
  });
});

/** 테스트용 공유 저장소 — 실제 구현(store 패키지의 DB 테이블)과 같은 계약을 메모리로 흉내 낸다. */
class MemoryShared implements SharedThrottleStore {
  readonly rows = new Map<string, ThrottleCounter>();
  writes = 0;
  failing = false;
  async read(buckets: readonly string[]): Promise<Map<string, ThrottleCounter>> {
    if (this.failing) throw new Error("db down");
    const out = new Map<string, ThrottleCounter>();
    for (const b of buckets) {
      const r = this.rows.get(b);
      if (r) out.set(b, r);
    }
    return out;
  }
  async recordFailure(bucket: string, now: number, resetBefore: number): Promise<void> {
    if (this.failing) throw new Error("db down");
    this.writes++;
    const r = this.rows.get(bucket);
    this.rows.set(bucket, { fails: !r || r.lastFailAt < resetBefore ? 1 : r.fails + 1, lastFailAt: now });
  }
  async clear(buckets: readonly string[]): Promise<void> {
    if (this.failing) throw new Error("db down");
    this.writes++;
    for (const b of buckets) this.rows.delete(b);
  }
  async sweep(before: number): Promise<void> {
    for (const [k, r] of this.rows) if (r.lastFailAt < before) this.rows.delete(k);
  }
}

describe("공통 수치 지연 규칙 (2026-10-18 결정 3)", () => {
  const p = { freeFailures: 5, baseDelayMs: 1000, maxDelayMs: 15 * 60_000, resetAfterMs: 15 * 60_000 };
  test("5회째부터 1초, 그 뒤 실패마다 두 배, 상한 15분", () => {
    const now = 1_000_000;
    expect(blockedUntil({ fails: 4, lastFailAt: now }, now, p)).toBe(0);
    expect(blockedUntil({ fails: 5, lastFailAt: now }, now, p)).toBe(now + 1000);
    expect(blockedUntil({ fails: 6, lastFailAt: now }, now, p)).toBe(now + 2000);
    expect(blockedUntil({ fails: 8, lastFailAt: now }, now, p)).toBe(now + 8000);
    expect(blockedUntil({ fails: 40, lastFailAt: now }, now, p)).toBe(now + 15 * 60_000);
  });
  test("마지막 실패 뒤 15분이 지나면 풀린다 — 영구 잠금이 없다", () => {
    const now = 1_000_000;
    expect(blockedUntil({ fails: 100, lastFailAt: now }, now + 15 * 60_000, p)).toBe(0);
  });
  test("기본값이 공통 수치다", async () => {
    const t = new AuthFailureThrottle();
    const now = 1_000_000;
    for (let i = 0; i < 4; i++) await t.recordFailure("203.0.113.9", now);
    expect(await t.blocked("203.0.113.9", now)).toBe(false);
    await t.recordFailure("203.0.113.9", now);
    expect(await t.retryAfterSeconds("203.0.113.9", now)).toBe(1);
    expect(await t.blocked("203.0.113.9", now + 1000)).toBe(false);
  });
  test("초기화 시간이 지난 뒤의 실패는 1부터 다시 센다", async () => {
    const t = new AuthFailureThrottle({ freeFailures: 2, baseDelayMs: 1000, resetAfterMs: 5000 });
    await t.recordFailure("203.0.113.9", 0);
    await t.recordFailure("203.0.113.9", 10_000);
    expect(await t.blocked("203.0.113.9", 10_000)).toBe(false);
  });
});

describe("공유 저장소 — 서버 여러 대가 함께 센다", () => {
  test("A 서버의 실패가 B 서버의 판정에 보인다", async () => {
    const shared = new MemoryShared();
    const a = new AuthFailureThrottle({ freeFailures: 3, baseDelayMs: 60_000, shared });
    const b = new AuthFailureThrottle({ freeFailures: 3, baseDelayMs: 60_000, shared });
    const now = 10_000;
    await a.recordFailure({ ip: "203.0.113.9", account: "u@test.local" }, now);
    await b.recordFailure({ ip: "203.0.113.10", account: "u@test.local" }, now);
    await a.recordFailure({ ip: "203.0.113.11", account: "u@test.local" }, now);
    // 어느 한 서버도 혼자서는 3회를 보지 못했지만, 계정 축은 함께 세어 막힌다.
    expect(await b.blocked({ account: "u@test.local" }, now)).toBe(true);
  });

  test("저장소를 못 읽으면 이 프로세스의 카운터로 막는다(fail closed)", async () => {
    const shared = new MemoryShared();
    const t = new AuthFailureThrottle({ freeFailures: 2, baseDelayMs: 60_000, shared });
    shared.failing = true;
    await t.recordFailure("203.0.113.9", 10_000);
    await t.recordFailure("203.0.113.9", 10_000);
    expect(await t.blocked("203.0.113.9", 10_000)).toBe(true);
  });

  test("카운터가 없는 계정의 성공 로그인은 쓰기를 만들지 않는다", async () => {
    const shared = new MemoryShared();
    const t = new AuthFailureThrottle({ shared });
    const now = 10_000;
    expect(await t.blocked({ ip: "203.0.113.9", account: "u@test.local" }, now)).toBe(false);
    await t.clear({ ip: "203.0.113.9", account: "u@test.local" }, now);
    expect(shared.writes).toBe(0);
  });

  test("실패가 있던 계정은 성공하면 공유 카운터도 지운다", async () => {
    const shared = new MemoryShared();
    const t = new AuthFailureThrottle({ freeFailures: 2, baseDelayMs: 60_000, shared });
    const other = new AuthFailureThrottle({ freeFailures: 2, baseDelayMs: 60_000, shared });
    const now = 10_000;
    await other.recordFailure({ account: "u@test.local" }, now);
    await other.recordFailure({ account: "u@test.local" }, now);
    expect(await t.blocked({ account: "u@test.local" }, now)).toBe(true);
    await t.clear({ account: "u@test.local" }, now);
    expect(await other.blocked({ account: "u@test.local" }, now)).toBe(false);
  });
});
