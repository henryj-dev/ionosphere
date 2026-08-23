/**
 * AuditShipper — 일별 감사 로그를 오브젝트 스토리지로 이관.
 *
 * 이 파일이 지키는 것은 셋이다:
 *  ① **오늘 파일은 건드리지 않는다** — 싱크가 계속 쓰는 중이라 지우면 그 뒤 이벤트가 사라진다.
 *  ② **업로드 성공을 확인한 뒤에만 지운다** — 되돌릴 수 없는 유실이라 여기서만은 낙관하지 않는다.
 *  ③ **키에 호스트명이 들어간다** — 세 인스턴스가 같은 버킷에 쓰므로 없으면 서로를 덮어쓴다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { AuditShipper, type AuditS3Target } from "../src/audit-shipper.ts";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  dirs.length = 0;
});

function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "ionosphere-ship-"));
  dirs.push(d);
  return d;
}

const NOW = Date.parse("2026-08-04T05:00:00.000Z");

interface Captured {
  url: string;
  body: Uint8Array;
  headers: Record<string, string>;
}

/** PUT을 잡아 두는 가짜 S3. `status`로 실패를 흉내낸다. */
function fakeS3(status = 200): { target: AuditS3Target; puts: Captured[] } {
  const puts: Captured[] = [];
  const target: AuditS3Target = {
    endpoint: "https://s3.example.test",
    bucket: "audit-bucket",
    accessKeyId: "AKIATEST",
    secretAccessKey: "secret",
    prefix: "audit",
    forcePathStyle: true,
    fetch: (async (input: string | URL | Request, init?: RequestInit) => {
      puts.push({
        url: String(input),
        body: new Uint8Array(init?.body as ArrayBufferLike as never),
        headers: (init?.headers ?? {}) as Record<string, string>,
      });
      return new Response(null, { status });
    }) as unknown as typeof fetch,
  };
  return { target, puts };
}

function writeDay(dir: string, day: string, body = '{"action":"auth"}\n'): string {
  const p = join(dir, `audit-${day}.jsonl`);
  writeFileSync(p, body);
  return p;
}

describe("AuditShipper — 이관 대상 선별", () => {
  test("★오늘 파일은 건드리지 않는다(싱크가 계속 쓰는 중이다)", async () => {
    const dir = tmp();
    const { target, puts } = fakeS3();
    writeDay(dir, "2026-08-04"); // 오늘
    const s = new AuditShipper({ dir, host: "node-02", target });
    const r = await s.tick(NOW);
    expect(r.shipped).toBe(0);
    expect(puts).toHaveLength(0);
    expect(existsSync(join(dir, "audit-2026-08-04.jsonl"))).toBe(true);
  });

  test("어제 파일은 올리고 로컬에서 지운다", async () => {
    const dir = tmp();
    const { target, puts } = fakeS3();
    writeDay(dir, "2026-08-03");
    const s = new AuditShipper({ dir, host: "node-02", target });
    const r = await s.tick(NOW);
    expect(r.shipped).toBe(1);
    expect(puts).toHaveLength(1);
    expect(existsSync(join(dir, "audit-2026-08-03.jsonl"))).toBe(false);
  });

  test("여러 날이 밀려 있으면 전부 올린다(날짜 순)", async () => {
    const dir = tmp();
    const { target, puts } = fakeS3();
    writeDay(dir, "2026-08-01");
    writeDay(dir, "2026-08-02");
    writeDay(dir, "2026-08-03");
    writeDay(dir, "2026-08-04"); // 오늘 — 제외
    const s = new AuditShipper({ dir, host: "node-02", target });
    expect((await s.tick(NOW)).shipped).toBe(3);
    expect(puts.map((p) => p.url.match(/audit-(\d{4}-\d{2}-\d{2})/)?.[1])).toEqual([
      "2026-08-01",
      "2026-08-02",
      "2026-08-03",
    ]);
  });

  test("audit-*.jsonl 형식이 아닌 파일은 무시한다", async () => {
    const dir = tmp();
    const { target, puts } = fakeS3();
    writeFileSync(join(dir, "notes.txt"), "x");
    writeFileSync(join(dir, "audit-bad.jsonl"), "x");
    writeFileSync(join(dir, "audit-2026-08-03.jsonl.gz"), "x");
    const s = new AuditShipper({ dir, host: "node-02", target });
    expect((await s.tick(NOW)).shipped).toBe(0);
    expect(puts).toHaveLength(0);
    expect(existsSync(join(dir, "notes.txt"))).toBe(true);
  });

  test("디렉터리가 없어도 던지지 않는다(감사 이벤트가 없었던 경우)", async () => {
    const s = new AuditShipper({ dir: join(tmp(), "missing"), host: "node-02" });
    const r = await s.tick(NOW);
    expect(r).toEqual({ shipped: 0, failed: 0, dropped: 0 });
  });
});

describe("★업로드 실패 시 로컬을 지우지 않는다", () => {
  test("5xx면 파일이 남고 failed로 센다", async () => {
    const dir = tmp();
    const { target, puts } = fakeS3(500);
    writeDay(dir, "2026-08-03");
    const s = new AuditShipper({ dir, host: "node-02", target });
    const r = await s.tick(NOW);
    expect(r.failed).toBe(1);
    expect(r.shipped).toBe(0);
    expect(puts).toHaveLength(1); // 시도는 했다
    // ★핵심: 되돌릴 수 없는 유실이므로 확인 전에 지우지 않는다.
    expect(existsSync(join(dir, "audit-2026-08-03.jsonl"))).toBe(true);
  });

  test("fetch가 던져도 파일이 남는다(네트워크 단절)", async () => {
    const dir = tmp();
    writeDay(dir, "2026-08-03");
    const target: AuditS3Target = {
      endpoint: "https://s3.example.test",
      bucket: "b",
      accessKeyId: "k",
      secretAccessKey: "s",
      forcePathStyle: true,
      fetch: (async () => {
        throw new Error("ECONNREFUSED");
      }) as unknown as typeof fetch,
    };
    const s = new AuditShipper({ dir, host: "node-02", target });
    expect((await s.tick(NOW)).failed).toBe(1);
    expect(existsSync(join(dir, "audit-2026-08-03.jsonl"))).toBe(true);
  });

  test("실패 후 재시도하면 올라간다(회복 가능)", async () => {
    const dir = tmp();
    writeDay(dir, "2026-08-03");
    let status = 500;
    const target: AuditS3Target = {
      endpoint: "https://s3.example.test",
      bucket: "b",
      accessKeyId: "k",
      secretAccessKey: "s",
      forcePathStyle: true,
      fetch: (async () => new Response(null, { status })) as unknown as typeof fetch,
    };
    const s = new AuditShipper({ dir, host: "node-02", target });
    expect((await s.tick(NOW)).failed).toBe(1);
    status = 200; // 장애 해소
    expect((await s.tick(NOW)).shipped).toBe(1);
    expect(existsSync(join(dir, "audit-2026-08-03.jsonl"))).toBe(false);
  });

  test("onShipFailure 훅이 실패마다 호출된다(메트릭 배선)", async () => {
    const dir = tmp();
    const { target } = fakeS3(503);
    writeDay(dir, "2026-08-02");
    writeDay(dir, "2026-08-03");
    let fails = 0;
    const s = new AuditShipper({ dir, host: "node-02", target, onShipFailure: () => fails++ });
    await s.tick(NOW);
    expect(fails).toBe(2);
  });
});

describe("★키에 호스트명이 들어간다 — 세 인스턴스가 같은 버킷을 쓴다", () => {
  test("경로에 host/연/월이 있다", async () => {
    const dir = tmp();
    const { target, puts } = fakeS3();
    writeDay(dir, "2026-08-03");
    const s = new AuditShipper({ dir, host: "node-02", target });
    await s.tick(NOW);
    expect(puts[0]?.url).toContain("/audit/node-02/2026/08/audit-2026-08-03.jsonl.gz");
  });

  /**
   * 이것이 없으면 node-02의 파일이 node-01의 것을 덮어쓴다 — 두 인스턴스의 기록 중 하나가
   * 조용히 사라진다. 감사 로그에서 가장 나쁜 실패 형태다.
   */
  test("호스트가 다르면 키가 다르다(덮어쓰지 않는다)", async () => {
    const keys: string[] = [];
    for (const host of ["node-01", "node-02", "node-03"]) {
      const dir = tmp();
      const { target, puts } = fakeS3();
      writeDay(dir, "2026-08-03");
      await new AuditShipper({ dir, host, target }).tick(NOW);
      keys.push(new URL(puts[0]!.url).pathname);
    }
    expect(new Set(keys).size).toBe(3);
  });

  test("prefix가 없으면 host부터 시작한다", async () => {
    const dir = tmp();
    const { target, puts } = fakeS3();
    delete (target as { prefix?: string }).prefix;
    writeDay(dir, "2026-08-03");
    await new AuditShipper({ dir, host: "mx", target }).tick(NOW);
    expect(new URL(puts[0]!.url).pathname).toBe("/audit-bucket/mx/2026/08/audit-2026-08-03.jsonl.gz");
  });
});

describe("gzip과 서명", () => {
  test("본문이 gzip이고 원본이 복원된다", async () => {
    const dir = tmp();
    const { target, puts } = fakeS3();
    const body = '{"action":"auth","ip":"203.0.113.5"}\n{"action":"select"}\n';
    writeDay(dir, "2026-08-03", body);
    await new AuditShipper({ dir, host: "mx", target }).tick(NOW);
    expect(gunzipSync(puts[0]!.body).toString("utf8")).toBe(body);
  });

  test("SigV4 authorization과 필수 헤더가 붙는다", async () => {
    const dir = tmp();
    const { target, puts } = fakeS3();
    writeDay(dir, "2026-08-03");
    await new AuditShipper({ dir, host: "mx", target }).tick(NOW);
    const h = puts[0]!.headers;
    expect(h.authorization).toContain("AWS4-HMAC-SHA256");
    expect(h.authorization).toContain("AKIATEST");
    expect(h["x-amz-content-sha256"]).toMatch(/^[0-9a-f]{64}$/);
    expect(h["content-type"]).toBe("application/gzip");
  });

  test("빈 파일은 올리지 않고 지운다(빈 객체를 만들면 조회가 헷갈린다)", async () => {
    const dir = tmp();
    const { target, puts } = fakeS3();
    writeDay(dir, "2026-08-03", "");
    const r = await new AuditShipper({ dir, host: "mx", target }).tick(NOW);
    expect(puts).toHaveLength(0);
    expect(r.shipped).toBe(1);
    expect(existsSync(join(dir, "audit-2026-08-03.jsonl"))).toBe(false);
  });
});

describe("★보존기간 — 디스크가 차는 것이 더 나쁘다", () => {
  test("보존기간을 넘긴 실패분은 버린다", async () => {
    const dir = tmp();
    const { target } = fakeS3(500);
    writeDay(dir, "2026-07-20"); // NOW 기준 15일 전
    const s = new AuditShipper({ dir, host: "mx", target, localRetainDays: 7 });
    const r = await s.tick(NOW);
    expect(r.failed).toBe(1);
    expect(r.dropped).toBe(1);
    expect(existsSync(join(dir, "audit-2026-07-20.jsonl"))).toBe(false);
  });

  test("보존기간 안이면 실패해도 남긴다", async () => {
    const dir = tmp();
    const { target } = fakeS3(500);
    writeDay(dir, "2026-08-02"); // 2일 전
    const s = new AuditShipper({ dir, host: "mx", target, localRetainDays: 7 });
    const r = await s.tick(NOW);
    expect(r.dropped).toBe(0);
    expect(existsSync(join(dir, "audit-2026-08-02.jsonl"))).toBe(true);
  });

  test("로컬 전용 구성(target 없음)에서도 보존기간은 적용된다", async () => {
    const dir = tmp();
    writeDay(dir, "2026-07-01");
    writeDay(dir, "2026-08-03");
    const s = new AuditShipper({ dir, host: "mx", localRetainDays: 7 });
    const r = await s.tick(NOW);
    expect(r.dropped).toBe(1); // 오래된 것만
    expect(existsSync(join(dir, "audit-2026-07-01.jsonl"))).toBe(false);
    expect(existsSync(join(dir, "audit-2026-08-03.jsonl"))).toBe(true);
  });
});

describe("워커 수명주기", () => {
  test("재진입 가드 — 진행 중이면 두 번째 tick은 즉시 반환", async () => {
    const dir = tmp();
    writeDay(dir, "2026-08-03");
    let release: (() => void) | null = null;
    const target: AuditS3Target = {
      endpoint: "https://s3.example.test",
      bucket: "b",
      accessKeyId: "k",
      secretAccessKey: "s",
      forcePathStyle: true,
      fetch: (async () => {
        await new Promise<void>((r) => (release = r));
        return new Response(null, { status: 200 });
      }) as unknown as typeof fetch,
    };
    const s = new AuditShipper({ dir, host: "mx", target });
    const first = s.tick(NOW);
    for (let i = 0; i < 100 && !release; i++) await new Promise((r) => setTimeout(r, 5));
    const second = await s.tick(NOW);
    expect(second).toEqual({ shipped: 0, failed: 0, dropped: 0 });
    release!();
    expect((await first).shipped).toBe(1);
  });

  test("start/stop을 반복해도 안전하다(중복 타이머 없음)", async () => {
    const dir = tmp();
    const { target, puts } = fakeS3();
    writeDay(dir, "2026-08-03");
    const s = new AuditShipper({ dir, host: "mx", target, intervalMs: 15 });
    s.start();
    s.start(); // 두 번 불러도 타이머는 하나여야 한다 — 아니면 이관이 중복 실행된다
    for (let i = 0; i < 100 && puts.length === 0; i++) await new Promise((r) => setTimeout(r, 10));
    await s.stop();
    // 파일이 하나였으므로 업로드도 정확히 한 번이다(타이머가 둘이면 두 번 시도한다).
    expect(puts).toHaveLength(1);
    // stop() 뒤 재기동이 가능하다.
    s.start();
    await s.stop();
  });
});
