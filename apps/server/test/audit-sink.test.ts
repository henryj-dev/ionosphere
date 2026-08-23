/**
 * AuditFileSink — 버퍼링·UTC 일자 회전·종료 시 flush·파일 권한·실패 재시도.
 *
 * 왜 이 테스트가 중요한가: 감사 로그의 가치는 **빠짐이 없다는 신뢰**에서 나온다. 한 줄이라도
 * 조용히 사라지면 "기록에 없다"가 "일어나지 않았다"를 뜻하지 않게 되고, 그 순간 감사 로그는
 * 증거가 아니라 참고자료로 격하된다. 그래서 유실 경로를 하나씩 못박는다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, readFileSync, rmSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AUDIT_OUTCOME, AUDIT_SURFACE, type AuditEvent } from "@ionosphere/core";
import { AuditFileSink } from "../src/audit-sink.ts";

const dirs: string[] = [];
const sinks: AuditFileSink[] = [];

afterEach(async () => {
  await Promise.all(sinks.map((s) => s.stop()));
  sinks.length = 0;
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  dirs.length = 0;
});

function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "ionosphere-audit-"));
  dirs.push(d);
  return d;
}

function sink(dir: string, opts: { flushIntervalMs?: number; maxBufferLines?: number } = {}): AuditFileSink {
  const s = new AuditFileSink({ dir, flushIntervalMs: 50, ...opts });
  sinks.push(s);
  return s;
}

/** 2026-08-04T05:00:00Z — UTC 기준 일자가 명확한 시각. */
const TS = Date.parse("2026-08-04T05:00:00.000Z");

function ev(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    ts: TS,
    surface: AUDIT_SURFACE.imap,
    action: "auth",
    outcome: AUDIT_OUTCOME.fail,
    ip: "203.0.113.5",
    user: "you@example.test",
    ...over,
  };
}

function readDay(dir: string, day: string): string {
  return readFileSync(join(dir, `audit-${day}.jsonl`), "utf8");
}

describe("AuditFileSink — 적재와 flush", () => {
  test("record는 동기이고 flush 전에는 파일이 없다(버퍼링 확인)", async () => {
    const dir = tmp();
    const s = sink(dir);
    s.record(ev());
    // 아직 flush하지 않았다 — 파일이 없어야 버퍼링이 실제로 일어난 것이다.
    expect(existsSync(join(dir, "audit-2026-08-04.jsonl"))).toBe(false);
    await s.flush();
    expect(readDay(dir, "2026-08-04")).toContain('"action":"auth"');
  });

  test("여러 줄이 순서대로 append된다", async () => {
    const dir = tmp();
    const s = sink(dir);
    s.record(ev({ action: "session.open" }));
    s.record(ev({ action: "auth" }));
    s.record(ev({ action: "select", outcome: AUDIT_OUTCOME.ok }));
    await s.flush();
    const lines = readDay(dir, "2026-08-04").trim().split("\n");
    expect(lines).toHaveLength(3);
    expect(lines.map((l) => (JSON.parse(l) as { action: string }).action)).toEqual(["session.open", "auth", "select"]);
  });

  test("두 번째 flush가 기존 파일에 이어 붙인다(덮어쓰지 않는다)", async () => {
    const dir = tmp();
    const s = sink(dir);
    s.record(ev({ action: "first" }));
    await s.flush();
    s.record(ev({ action: "second" }));
    await s.flush();
    const body = readDay(dir, "2026-08-04");
    expect(body).toContain("first");
    expect(body).toContain("second");
  });

  test("빈 버퍼 flush는 파일을 만들지 않는다", async () => {
    const dir = tmp();
    const s = sink(dir);
    await s.flush();
    expect(existsSync(join(dir, "audit-2026-08-04.jsonl"))).toBe(false);
  });

  test("버퍼 상한에 닿으면 간격을 기다리지 않고 flush한다", async () => {
    const dir = tmp();
    const s = sink(dir, { flushIntervalMs: 60_000, maxBufferLines: 3 });
    s.record(ev());
    s.record(ev());
    s.record(ev()); // 여기서 자동 flush
    /**
     * ★**내용**이 갖춰질 때까지 기다린다. 예전에는 파일 **존재**만 폴링했는데, 파일이 생긴
     * 뒤에도 세 줄이 다 쓰이기 전 순간이 있어 부하가 높으면 1~2줄만 읽혔다 —
     * 전체 스위트에서만 간헐 실패하던 원인이다(단독 실행에서는 거의 안 드러난다).
     * 비동기 부수효과를 고정 대기·존재 검사로 확인하면 그 자체가 플레이키의 원인이 된다.
     */
    let lines: string[] = [];
    for (let i = 0; i < 200; i++) {
      lines = existsSync(join(dir, "audit-2026-08-04.jsonl"))
        ? readDay(dir, "2026-08-04").trim().split("\n").filter((l) => l.length > 0)
        : [];
      if (lines.length >= 3) break;
      await new Promise((r) => setTimeout(r, 10));
    }
    expect(lines).toHaveLength(3);
  });

  test("주기 타이머가 자동으로 flush한다", async () => {
    const dir = tmp();
    const s = sink(dir, { flushIntervalMs: 20 });
    s.start();
    s.record(ev());
    for (let i = 0; i < 100 && !existsSync(join(dir, "audit-2026-08-04.jsonl")); i++) {
      await new Promise((r) => setTimeout(r, 10));
    }
    expect(existsSync(join(dir, "audit-2026-08-04.jsonl"))).toBe(true);
  });
});

describe("★UTC 일자 회전", () => {
  /**
   * 로컬 타임존을 쓰면 서버 설정에 따라 파일 경계가 달라져, 세 인스턴스가 같은 버킷에 올릴 때
   * "같은 날짜" 파일이 서로 다른 시간 범위를 담는다. 그러면 시간대를 가로지르는 조회가 틀린다.
   */
  test("UTC 자정을 넘기면 다른 파일로 간다", async () => {
    const dir = tmp();
    const s = sink(dir);
    s.record(ev({ ts: Date.parse("2026-08-04T23:59:59.999Z"), action: "before" }));
    s.record(ev({ ts: Date.parse("2026-08-05T00:00:00.000Z"), action: "after" }));
    await s.flush();
    expect(readDay(dir, "2026-08-04")).toContain("before");
    expect(readDay(dir, "2026-08-05")).toContain("after");
    // 서로 섞이지 않았다 — 경계가 실제로 갈렸다.
    expect(readDay(dir, "2026-08-04")).not.toContain("after");
    expect(readDay(dir, "2026-08-05")).not.toContain("before");
  });

  test("로컬 타임존과 무관하게 UTC 일자를 쓴다", async () => {
    const dir = tmp();
    const s = sink(dir);
    // KST(UTC+9)에서는 2026-08-05 08:00이지만 UTC로는 2026-08-04다.
    s.record(ev({ ts: Date.parse("2026-08-04T23:00:00.000Z") }));
    await s.flush();
    expect(existsSync(join(dir, "audit-2026-08-04.jsonl"))).toBe(true);
    expect(existsSync(join(dir, "audit-2026-08-05.jsonl"))).toBe(false);
  });
});

describe("★종료 시 유실 방지", () => {
  /**
   * 버퍼링을 택한 대가로 SIGKILL에서는 한 주기분이 유실된다(의도된 트레이드오프). 그러나 정상
   * 종료·배포 재시작은 하루에 여러 번 일어나므로 그때마다 구멍이 생기면 기록을 신뢰할 수 없다.
   */
  test("stop()이 남은 버퍼를 flush한다", async () => {
    const dir = tmp();
    const s = new AuditFileSink({ dir, flushIntervalMs: 60_000 });
    s.start();
    s.record(ev({ action: "must-survive" }));
    await s.stop();
    expect(readDay(dir, "2026-08-04")).toContain("must-survive");
  });

  test("stop() 후에는 타이머가 돌지 않는다(그래도 버퍼는 살아 있다)", async () => {
    const dir = tmp();
    const s = new AuditFileSink({ dir, flushIntervalMs: 20 });
    s.start();
    await s.stop();
    s.record(ev({ action: "after-stop" }));
    await new Promise((r) => setTimeout(r, 80)); // 간격의 4배 — 타이머가 살아 있었다면 나갔을 시간
    // 타이머가 꺼졌으므로 자동으로 나가지 않는다. 이것이 stop()의 의미다 —
    // clearInterval을 빼먹으면 stop() 뒤에도 백그라운드 쓰기가 계속돼 종료가 매달린다.
    expect(existsSync(join(dir, "audit-2026-08-04.jsonl"))).toBe(false);
    // 다만 이벤트는 버려지지 않았다 — 수동 flush(또는 재start)로 나간다.
    await s.flush();
    expect(readDay(dir, "2026-08-04")).toContain("after-stop");
  });
});

describe("★파일 권한 — IP·사용자명이 든 파일", () => {
  test("파일 0600 / 디렉터리 0700", async () => {
    const dir = tmp();
    const s = sink(dir);
    s.record(ev());
    await s.flush();
    // mkdtemp가 0700으로 만들지만, 싱크가 만드는 경로도 좁은지 확인한다.
    const sub = join(dir, "nested");
    const s2 = sink(sub);
    s2.record(ev());
    await s2.flush();
    expect(statSync(join(sub, "audit-2026-08-04.jsonl")).mode & 0o777).toBe(0o600);
    expect(statSync(sub).mode & 0o777).toBe(0o700);
  });
});

describe("★쓰기 실패는 서비스를 멈추지 않는다", () => {
  test("디렉터리를 만들 수 없어도 record/flush가 던지지 않는다", async () => {
    // 파일을 디렉터리 경로로 준다 — mkdir이 ENOTDIR로 실패한다.
    const dir = tmp();
    const filePath = join(dir, "not-a-dir");
    const s = sink(join(filePath, "sub"));
    // 먼저 파일을 만들어 경로를 막는다.
    const { writeFileSync } = await import("node:fs");
    writeFileSync(filePath, "x");
    expect(() => s.record(ev())).not.toThrow();
    await expect(s.flush()).resolves.toBeUndefined();
  });

  /**
   * 실패분을 버리면 그 구간의 감사 기록이 영구히 사라진다. 디스크가 일시적으로 찬 경우나
   * 운영자가 권한을 고치는 사이에도 회복 가능해야 한다.
   */
  test("flush 실패분은 버퍼에 남아 다음 flush에서 나간다", async () => {
    const dir = tmp();
    const blocked = join(dir, "blocked");
    const { writeFileSync, unlinkSync } = await import("node:fs");
    writeFileSync(blocked, "x"); // 경로를 파일로 막는다
    const s = sink(join(blocked, "sub"));
    s.record(ev({ action: "retry-me" }));
    await s.flush(); // 실패 — 버퍼에 남아야 한다
    unlinkSync(blocked); // 장애 해소
    await s.flush(); // 이제 나간다
    expect(readDay(join(blocked, "sub"), "2026-08-04")).toContain("retry-me");
  });
});

describe("관측 훅", () => {
  test("onRecord가 이벤트마다 호출된다(메트릭 배선용)", async () => {
    const dir = tmp();
    const seen: string[] = [];
    const s = new AuditFileSink({ dir, flushIntervalMs: 60_000, onRecord: (e) => seen.push(e.action) });
    sinks.push(s);
    s.record(ev({ action: "a" }));
    s.record(ev({ action: "b" }));
    expect(seen).toEqual(["a", "b"]);
  });
});
