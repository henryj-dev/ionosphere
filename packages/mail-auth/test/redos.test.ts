/**
 * 원격이 내용을 정하는 입력이 초선형(superlinear) 비용을 만들지 않는지 지키는 회귀 테스트.
 * (감사 2026-07-30 §8-9 "ReDoS" 항목 — 5차 감사가 담당 lane 유실로 보지 못한 영역)
 *
 * 시간 단언을 넣은 이유: 이 결함들은 "결과가 틀리는" 형태가 아니라 **결과는 맞는데 오래 걸리는**
 * 형태라, 값만 비교하는 테스트로는 되돌아와도 잡히지 않는다. 상한은 실측값 대비 넉넉히 잡아
 * (수정 전 수십 초 → 수정 후 수십 ms) 느린 CI에서도 흔들리지 않게 했다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { canonBody } from "../src/canon.ts";
import { dkimVerify } from "../src/verify.ts";
import { arcVerify } from "../src/arc.ts";
import { checkSpf } from "../src/spf.ts";
import { createHash } from "node:crypto";

function elapsed(fn: () => void): number {
  const t0 = performance.now();
  fn();
  return performance.now() - t0;
}

describe("canonBody relaxed — 공백 런 ReDoS", () => {
  // 수정 전 `line.replace(/[ \t]+$/, "")`는 이 입력에서 O(줄길이²)였다:
  // 공백 128,000개 한 줄에 14초, 0.5MB 본문에 50초(= 인바운드 메시지 한 통으로 이벤트 루프 정지).
  test("공백 런이 긴 줄이 선형 시간에 끝난다", () => {
    const body = " ".repeat(200_000) + "x\r\n";
    const ms = elapsed(() => canonBody(body, "relaxed"));
    expect(ms).toBeLessThan(1000);
  });

  test("최악 본문을 MAX_MESSAGE_BYTES(25MB) 규모로 채워도 선형", () => {
    const body = (" ".repeat(128_000) + "x\r\n").repeat(200);
    const ms = elapsed(() => canonBody(body, "relaxed"));
    expect(ms).toBeLessThan(5000);
  });

  // 성능 수정이 정규화 **의미**를 바꾸지 않았음을 함께 고정한다(RFC 6376 §3.4.4).
  test("정규화 결과는 그대로: 줄 끝 WSP 제거 + 내부 WSP 압축", () => {
    expect(canonBody(" C \r\nD \t E\r\n\r\n\r\n", "relaxed")).toBe(" C\r\nD E\r\n");
    expect(canonBody("a \t b  \t\r\n", "relaxed")).toBe("a b\r\n");
    expect(canonBody("   \r\n", "relaxed")).toBe("");
    expect(canonBody("\t\ta\t\t", "relaxed")).toBe(" a\r\n");
    expect(canonBody("", "relaxed")).toBe("");
    expect(canonBody("", "simple")).toBe("\r\n");
  });
});

describe("DKIM 서명 개수 상한 — DNS 조회 폭주 차단", () => {
  const body = "hi\r\n";
  const bh = createHash("sha256").update(Buffer.from(canonBody(body, "relaxed"), "latin1")).digest("base64");

  /** bh를 맞춰 DNS 조회 단계까지 도달하는 서명 헤더 — 본문은 발신자가 정하므로 자명하게 가능하다. */
  function message(count: number): Uint8Array {
    const sigs = Array.from(
      { length: count },
      (_, k) => `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=${k}.atk.example; s=s; h=from; bh=${bh}; b=A`,
    );
    return Buffer.from(`From: a@b.c\r\n${sigs.join("\r\n")}\r\n\r\n${body}`, "latin1");
  }

  test("서명 5,000개짜리 메시지가 DNS 조회를 10회로 묶고 빠르게 끝난다", async () => {
    let dnsCalls = 0;
    const resolveTxt = async (): Promise<string[]> => {
      dnsCalls++;
      throw new Error("no key");
    };
    const t0 = performance.now();
    const results = await dkimVerify(message(5000), resolveTxt);
    const ms = performance.now() - t0;

    expect(dnsCalls).toBe(10); // 상한 없던 시절엔 5,000회가 그대로 나갔다
    expect(ms).toBeLessThan(5000);
    // 초과분은 조용히 사라지지 않고 permerror로 드러난다.
    expect(results).toHaveLength(11);
    expect(results[10]!.result).toBe("permerror");
    expect(results[10]!.error).toMatch(/상한/);
  });

  test("정상 범위(서명 2개)는 그대로 각각 검증된다", async () => {
    let dnsCalls = 0;
    const resolveTxt = async (): Promise<string[]> => {
      dnsCalls++;
      throw new Error("no key");
    };
    const results = await dkimVerify(message(2), resolveTxt);
    expect(dnsCalls).toBe(2);
    expect(results).toHaveLength(2);
    expect(results.map((r) => r.domain)).toEqual(["0.atk.example", "1.atk.example"]);
  });
});

describe("ARC 체인 길이 상한", () => {
  test("세트 50개 초과는 검증(O(N²) + 세트당 DNS)에 들어가기 전에 잘린다", async () => {
    let dnsCalls = 0;
    const resolver = {
      txt: async (): Promise<string[]> => {
        dnsCalls++;
        throw new Error("no key");
      },
    };
    const hdrs: string[] = [];
    for (let i = 1; i <= 400; i++) {
      hdrs.push(`ARC-Authentication-Results: i=${i}; mx.example; spf=pass`);
      hdrs.push(`ARC-Message-Signature: i=${i}; a=rsa-sha256; d=d.example; s=s; h=from; bh=x; b=${"B".repeat(200)}`);
      hdrs.push(`ARC-Seal: i=${i}; a=rsa-sha256; d=d.example; s=s; cv=none; b=${"B".repeat(200)}`);
    }
    const msg = Buffer.from(`From: a@b.c\r\n${hdrs.join("\r\n")}\r\n\r\nhi\r\n`, "latin1");

    const result = await arcVerify(msg, resolver);
    expect(result.cv).toBe("fail");
    expect(result.reason).toMatch(/상한/);
    expect(dnsCalls).toBe(0);
  });
});

/**
 * `%{p}` 매크로가 RFC 7208 §4.6.4의 10회 예산 **밖**이었다(2026-07-31 실측).
 * 후보 이름 상한이 10이라 한 번의 확장만으로 최대 11회(PTR 1 + A 10)가 예산 없이 나갔고,
 * 캐시가 `evaluateRecord`의 객체 복사로 **레코드마다 리셋**되어 include 10단계에서
 * **총 130회**(PTR 10 + A 100 + TXT 20)가 관측됐다 — 같은 PTR 이름을 10번 다시 물었다.
 *
 * 조회 대상을 발신자가 정하므로(PTR 응답이 곧 A 질의 대상) 우리 리졸버가 제3자를 향한
 * 증폭기가 되는 형태다 — 자기 DoS가 아니라 DKIM 팬아웃과 같은 계열이다.
 */
describe("SPF %{p} 매크로 예산 (증폭 차단)", () => {
  /** 단계마다 exp=%{p}를 둔 include 체인 — 캐시가 리셋되면 비용이 단계 수만큼 곱해진다. */
  async function probe(steps: number, candidates: number) {
    const ptr: string[] = [];
    const a: string[] = [];
    let txt = 0;
    const resolver = {
      txt: async (n: string): Promise<string[]> => {
        txt += 1;
        const m = /^s([0-9]+)\./.exec(n);
        if (!m) return ["v=spf1 include:s0.test -all"];
        const k = Number(m[1]);
        return k < steps - 1
          ? [`v=spf1 include:s${k + 1}.test exp=%{p}.e${k}.test -all`]
          : [`v=spf1 exp=%{p}.e${k}.test -all`];
      },
      ptr: async (n: string): Promise<string[]> => {
        ptr.push(n);
        return Array.from({ length: candidates }, (_, i) => `c${i}.probe.test`);
      },
      // 클라이언트 IP와 **다른** 값 → 후보를 전부 돈다. 값이 있으니 void 예산에도 안 걸린다.
      // (void로 끊긴다고 보면 이 결함을 놓친다 — 그게 이 테스트의 핵심이다.)
      a: async (n: string): Promise<string[]> => {
        a.push(n);
        return ["198.51.100.9"];
      },
      aaaa: async (): Promise<string[]> => [],
      mx: async (): Promise<{ exchange: string; priority: number }[]> => [],
    } as unknown as Parameters<typeof checkSpf>[1];

    await checkSpf({ ip: "203.0.113.5", mailFrom: "u@s0.test", helo: "x.test" }, resolver);
    return { ptr, a, txt, total: ptr.length + a.length + txt };
  }

  test("PTR은 평가 전체에서 한 번만 나간다(캐시가 레코드마다 리셋되지 않는다)", async () => {
    const r = await probe(10, 10);
    expect(r.ptr.length).toBe(1);
  });

  test("include 10단계 × 후보 10개에도 조회 총량이 예산 규모를 유지한다", async () => {
    const r = await probe(10, 10);
    expect(r.total).toBeLessThan(40); // 수정 전 130회
  });

  test("후보 수를 늘려도 A 조회가 곱해지지 않는다", async () => {
    const few = await probe(10, 1);
    const many = await probe(10, 10);
    expect(many.a.length).toBeLessThanOrEqual(few.a.length + 10);
  });
});
