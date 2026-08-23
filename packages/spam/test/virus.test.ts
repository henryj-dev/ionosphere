/**
 * 바이러스 검사 훅 — 이 파일이 고정하는 것은 스캐너의 성능이 아니라
 * **"스캐너가 대답하지 못할 때 메일을 어떻게 하는가"**다. 거기가 유일하게 위험한 자리다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { scanForVirus, type VirusScanner } from "../src/virus.ts";

const RAW = new TextEncoder().encode("From: a@b\r\n\r\nhello");

/** 고정 판정 스캐너. */
function fixed(verdict: "clean" | "infected" | "error", signature?: string): VirusScanner {
  return { scan: async () => ({ verdict, ...(signature ? { signature } : {}) }) };
}

describe("scanForVirus", () => {
  test("clean → 통과", async () => {
    expect(await scanForVirus(fixed("clean"), RAW)).toEqual({ action: "accept" });
  });

  test("infected → 554 거부, 시그니처 이름을 싣는다", async () => {
    const r = await scanForVirus(fixed("infected", "Eicar-Test-Signature"), RAW);
    expect(r.action).toBe("reject");
    if (r.action !== "reject") throw new Error("unreachable");
    expect(r.code).toBe(554);
    expect(r.enhanced).toBe("5.7.1");
    expect(r.message).toContain("Eicar-Test-Signature");
  });

  test("★판정 불가의 기본은 defer(451) — 거부도 통과도 아니다", async () => {
    // accept면 검사 안 된 메일이 배달되고, reject면 스캐너 장애가 영구 실패가 되어 메일이
    // 사라진다. defer는 상대가 재시도하므로 **둘 다 피한다**.
    const r = await scanForVirus(fixed("error"), RAW);
    expect(r.action).toBe("defer");
    if (r.action !== "defer") throw new Error("unreachable");
    expect(r.code).toBe(451);
    expect(r.enhanced).toBe("4.7.1");
  });

  test("★스캐너가 던져도 같은 처리 — 예외와 error 판정은 같은 사실이다", async () => {
    const throwing: VirusScanner = {
      scan: async () => {
        throw new Error("connection refused");
      },
    };
    expect((await scanForVirus(throwing, RAW)).action).toBe("defer");
  });

  test("★스캐너가 멈춰도 트랜잭션을 물지 않는다 — 타임아웃", async () => {
    const hanging: VirusScanner = { scan: () => new Promise(() => undefined) };
    const started = Date.now();
    const r = await scanForVirus(hanging, RAW, { timeoutMs: 50 });
    // 스캔은 SMTP 트랜잭션 안에서 일어난다. 멈춘 스캐너가 커넥션을 물면 동시 연결 상한에
    // 걸려 **수신 전체가 멈춘다**. 스캐너 하나가 메일 서버를 세우게 두지 않는다.
    expect(r.action).toBe("defer");
    expect(Date.now() - started).toBeLessThan(2000);
  });

  test("onError를 명시하면 그대로 따른다", async () => {
    expect((await scanForVirus(fixed("error"), RAW, { onError: "accept" })).action).toBe("accept");
    const rej = await scanForVirus(fixed("error"), RAW, { onError: "reject" });
    expect(rej.action).toBe("reject");
  });

  test("★시그니처 이름의 제어문자를 응답에 싣지 않는다 (SMTP 줄 쪼개기 방지)", async () => {
    const r = await scanForVirus(fixed("infected", "Bad\r\n250 OK\r\nX-Injected"), RAW);
    if (r.action !== "reject") throw new Error("unreachable");
    // 이름은 스캐너가 주는 값이라 우리가 정하지 않는다. CR/LF가 그대로 나가면 응답 줄이
    // 쪼개져 프로토콜이 깨진다(https-front의 프레이밍 거부와 같은 부류).
    expect(r.message).not.toContain("\r");
    expect(r.message).not.toContain("\n");
    expect(r.message).toContain("Bad250 OKX-Injected");
  });

  test("긴 시그니처 이름은 잘린다(응답 줄 상한)", async () => {
    const r = await scanForVirus(fixed("infected", "A".repeat(500)), RAW);
    if (r.action !== "reject") throw new Error("unreachable");
    expect(r.message.length).toBeLessThan(160);
  });
});
