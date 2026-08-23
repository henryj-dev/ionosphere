/**
 * Prometheus 텍스트 노출 포맷 레지스트리 — 순수(외부 의존 없음, HTTP 무관).
 * Counter/Gauge/Histogram + 라벨 지원. 의존성 제로 원칙(prom-client 미도입).
 *
 * 노출 포맷: https://prometheus.io/docs/instrumenting/exposition_formats/
 * 라벨 값은 백슬래시/따옴표/개행을 이스케이프한다.
 */

export type Labels = Record<string, string>;

/** 라벨 값 이스케이프(\\ → \\\\, " → \\", 개행 → \\n). */
function escapeLabelValue(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

/** 라벨 집합을 정렬된 안정 키로 직렬화(같은 라벨 → 같은 시계열). */
function labelKey(labels: Labels): string {
  const keys = Object.keys(labels).sort();
  return keys.map((k) => `${k}=${labels[k]}`).join("\x1f"); // 내부 키 구분자(US)
}

/** 라벨을 Prometheus 표기(`{a="1",b="2"}`)로. 빈 라벨은 "". */
function renderLabels(labels: Labels): string {
  const keys = Object.keys(labels).sort();
  if (keys.length === 0) return "";
  return `{${keys.map((k) => `${k}="${escapeLabelValue(labels[k]!)}"`).join(",")}}`;
}

abstract class Metric {
  readonly name: string;
  readonly help: string;
  constructor(name: string, help: string) {
    this.name = name;
    this.help = help;
  }
  abstract type(): string;
  abstract renderBody(): string[];
  render(): string {
    const lines = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} ${this.type()}`];
    lines.push(...this.renderBody());
    return lines.join("\n");
  }
}

export class Counter extends Metric {
  private readonly values = new Map<string, { labels: Labels; value: number }>();
  type(): string {
    return "counter";
  }
  inc(labels: Labels = {}, value = 1): void {
    if (value < 0) throw new Error("counter는 음수 증가 불가");
    const key = labelKey(labels);
    const cur = this.values.get(key);
    if (cur) cur.value += value;
    else this.values.set(key, { labels, value });
  }
  get(labels: Labels = {}): number {
    return this.values.get(labelKey(labels))?.value ?? 0;
  }
  renderBody(): string[] {
    if (this.values.size === 0) return [`${this.name} 0`];
    return [...this.values.values()].map((v) => `${this.name}${renderLabels(v.labels)} ${v.value}`);
  }
}

export class Gauge extends Metric {
  private readonly values = new Map<string, { labels: Labels; value: number }>();
  type(): string {
    return "gauge";
  }
  set(value: number, labels: Labels = {}): void {
    this.values.set(labelKey(labels), { labels, value });
  }
  inc(labels: Labels = {}, value = 1): void {
    const key = labelKey(labels);
    const cur = this.values.get(key);
    if (cur) cur.value += value;
    else this.values.set(key, { labels, value });
  }
  dec(labels: Labels = {}, value = 1): void {
    this.inc(labels, -value);
  }
  get(labels: Labels = {}): number {
    return this.values.get(labelKey(labels))?.value ?? 0;
  }
  renderBody(): string[] {
    if (this.values.size === 0) return [`${this.name} 0`];
    return [...this.values.values()].map((v) => `${this.name}${renderLabels(v.labels)} ${v.value}`);
  }
}

interface HistogramSeries {
  labels: Labels;
  counts: number[]; // 버킷별 누적 아님 — 관측값을 버킷에 카운트, 렌더 시 누적
  sum: number;
  count: number;
}

export class Histogram extends Metric {
  private readonly buckets: number[]; // 오름차순 상한(le)
  private readonly series = new Map<string, HistogramSeries>();
  constructor(name: string, help: string, buckets: number[]) {
    super(name, help);
    this.buckets = [...buckets].sort((a, b) => a - b);
  }
  type(): string {
    return "histogram";
  }
  observe(value: number, labels: Labels = {}): void {
    const key = labelKey(labels);
    let s = this.series.get(key);
    if (!s) {
      s = { labels, counts: new Array<number>(this.buckets.length).fill(0), sum: 0, count: 0 };
      this.series.set(key, s);
    }
    s.sum += value;
    s.count += 1;
    // 첫 매칭 버킷에만 카운트(구간별) — render에서 누적해 le 시계열 생성
    for (let i = 0; i < this.buckets.length; i++) {
      if (value <= this.buckets[i]!) {
        s.counts[i]! += 1;
        break;
      }
    }
  }
  renderBody(): string[] {
    const out: string[] = [];
    for (const s of this.series.values()) {
      let cumulative = 0;
      for (let i = 0; i < this.buckets.length; i++) {
        cumulative += s.counts[i]!;
        out.push(`${this.name}_bucket${renderLabels({ ...s.labels, le: String(this.buckets[i]) })} ${cumulative}`);
      }
      out.push(`${this.name}_bucket${renderLabels({ ...s.labels, le: "+Inf" })} ${s.count}`);
      out.push(`${this.name}_sum${renderLabels(s.labels)} ${s.sum}`);
      out.push(`${this.name}_count${renderLabels(s.labels)} ${s.count}`);
    }
    return out;
  }
}

/** 렌더 직전에 호출되는 비동기 수집기(예: 큐 깊이 DB 질의로 게이지 갱신). */
export type Collector = () => void | Promise<void>;

export class Registry {
  private readonly metrics = new Map<string, Metric>();
  private readonly collectors: Collector[] = [];

  counter(name: string, help: string): Counter {
    return this.register(name, new Counter(name, help));
  }
  gauge(name: string, help: string): Gauge {
    return this.register(name, new Gauge(name, help));
  }
  histogram(name: string, help: string, buckets: number[]): Histogram {
    return this.register(name, new Histogram(name, help, buckets));
  }

  /** 렌더 직전 실행할 수집기 등록(게이지 지연 갱신). */
  onCollect(fn: Collector): void {
    this.collectors.push(fn);
  }

  /** 등록된 수집기를 모두 실행(렌더 전 호출). 개별 실패는 무시(관측이 서비스를 막지 않음). */
  async collect(): Promise<void> {
    for (const c of this.collectors) {
      try {
        await c();
      } catch {
        /* 관측 실패는 삼킴 */
      }
    }
  }

  /** Prometheus 텍스트 노출(수집기는 먼저 collect()를 호출할 것). */
  render(): string {
    return `${[...this.metrics.values()].map((m) => m.render()).join("\n\n")}\n`;
  }

  private register<T extends Metric>(name: string, metric: T): T {
    const existing = this.metrics.get(name);
    if (existing) {
      if (existing.constructor !== metric.constructor) throw new Error(`메트릭 이름 충돌(타입 상이): ${name}`);
      return existing as T; // 동일 타입 재등록은 기존 인스턴스 반환(멱등)
    }
    this.metrics.set(name, metric);
    return metric;
  }
}
