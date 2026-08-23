/** 관측성 — Counter/Gauge/Histogram 의미론·노출 포맷·수집기·HTTP 왕복. */
import { describe, expect, test } from "@ionosphere/testkit";
import { createIonosphereMetrics, MetricsServer, Registry } from "@ionosphere/metrics";

describe("Counter", () => {
  test("inc 누적·라벨별 분리·음수 거부", () => {
    const r = new Registry();
    const c = r.counter("hits_total", "hits");
    c.inc();
    c.inc({ path: "/a" }, 2);
    c.inc({ path: "/a" });
    expect(c.get()).toBe(1);
    expect(c.get({ path: "/a" })).toBe(3);
    expect(() => c.inc({}, -1)).toThrow();
  });
});

describe("Gauge", () => {
  test("set/inc/dec", () => {
    const r = new Registry();
    const g = r.gauge("depth", "depth");
    g.set(10);
    g.inc({}, 5);
    g.dec({}, 3);
    expect(g.get()).toBe(12);
  });
});

describe("Histogram", () => {
  test("버킷 누적·sum·count·+Inf", () => {
    const r = new Registry();
    const h = r.histogram("lat", "latency", [1, 5, 10]);
    for (const v of [0.5, 2, 7, 20]) h.observe(v);
    const body = h.render();
    expect(body).toContain('lat_bucket{le="1"} 1'); // 0.5
    expect(body).toContain('lat_bucket{le="5"} 2'); // 0.5,2
    expect(body).toContain('lat_bucket{le="10"} 3'); // +7
    expect(body).toContain('lat_bucket{le="+Inf"} 4'); // +20
    expect(body).toContain("lat_sum 29.5");
    expect(body).toContain("lat_count 4");
  });
});

describe("노출 포맷", () => {
  test("HELP/TYPE 헤더 + 라벨 정렬·이스케이프", () => {
    const r = new Registry();
    const c = r.counter("m_total", "도움말");
    c.inc({ b: "2", a: `x"y\\z` });
    const out = r.render();
    expect(out).toContain("# HELP m_total 도움말");
    expect(out).toContain("# TYPE m_total counter");
    // 라벨 알파벳 정렬(a 먼저) + 값 이스케이프
    expect(out).toContain('m_total{a="x\\"y\\\\z",b="2"} 1');
    expect(out.endsWith("\n")).toBe(true);
  });

  test("값 없는 카운터는 0 노출", () => {
    const r = new Registry();
    r.counter("empty_total", "e");
    expect(r.render()).toContain("empty_total 0");
  });

  test("이름 재등록: 동일 타입 멱등, 상이 타입 충돌", () => {
    const r = new Registry();
    const a = r.counter("x_total", "h");
    const b = r.counter("x_total", "h");
    expect(a).toBe(b);
    expect(() => r.gauge("x_total", "h")).toThrow();
  });
});

describe("수집기", () => {
  test("render 전 collect가 게이지 갱신, 실패는 삼킴", async () => {
    const r = new Registry();
    const g = r.gauge("q", "q");
    r.onCollect(() => g.set(42));
    r.onCollect(() => {
      throw new Error("boom");
    });
    await r.collect();
    expect(g.get()).toBe(42);
  });
});

describe("ionosphere 번들 + HTTP", () => {
  test("표준 메트릭 이름 존재", () => {
    const m = createIonosphereMetrics();
    m.received.inc();
    m.delivery.inc({ result: "sent" });
    m.queueDepth.set(3);
    const out = m.registry.render();
    expect(out).toContain("ionosphere_received_messages_total 1");
    expect(out).toContain('ionosphere_delivery_total{result="sent"} 1');
    expect(out).toContain("ionosphere_queue_depth 3");
  });

  test("MetricsServer: /metrics·/healthz·404", async () => {
    const m = createIonosphereMetrics();
    m.registry.onCollect(() => m.queueDepth.set(7));
    const server = new MetricsServer({ registry: m.registry });
    const port = await server.listen(0, "127.0.0.1");
    try {
      const met = await fetch(`http://127.0.0.1:${port}/metrics`);
      expect(met.status).toBe(200);
      expect(met.headers.get("content-type")).toContain("version=0.0.4");
      expect(await met.text()).toContain("ionosphere_queue_depth 7"); // 수집기 반영

      const h = await fetch(`http://127.0.0.1:${port}/healthz`);
      expect(h.status).toBe(200);

      const nf = await fetch(`http://127.0.0.1:${port}/nope`);
      expect(nf.status).toBe(404);
    } finally {
      await server.close();
    }
  });
});
