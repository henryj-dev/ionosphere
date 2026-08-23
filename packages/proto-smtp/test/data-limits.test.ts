/**
 * DATA 단계 버퍼 상한 회귀 테스트.
 *
 * 과거 결함: 크기 초과 판정(dataOverflow)이 **완결된 라인**에서만 돌아서, CRLF를 영영 보내지
 * 않는 스트림에는 maxSizeBytes가 아무 효과가 없었다. 25번 포트에 무인증으로 접속해 개행 없는
 * 바이트만 흘리면 버퍼가 무한히 자라 프로세스가 죽는다(실측: 한도 1KB인데 20MB 적재).
 * 덤으로 feed()가 청크마다 버퍼 전체를 복사하므로 CPU도 O(n²)로 탔다.
 *
 * 여기서 지키는 성질 두 가지:
 *  ① 메모리가 상한 안에 묶인다
 *  ② 그러면서도 **세션 동기가 유지된다** — 종료 마커를 계속 스캔해 552로 정상 거절한다.
 *     ②가 없으면 연결이 DATA에 갇혀 유휴 타임아웃까지 소켓을 붙잡는다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { SmtpEngine, type SmtpAction } from "../src/engine.ts";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

/** 1MB(MAX_DATA_LINE)보다 크게 잡아 상한이 실제로 걸리는지 본다. */
const OVER_LINE_LIMIT = 1024 * 1024 + 1;

function replyTexts(actions: readonly SmtpAction[]): string[] {
  return actions.filter((a) => a.kind === "reply").map((a) => (a as { text: string }).text);
}

/** DATA 상태까지 진행한 엔진. maxSizeBytes는 작게 잡아 상한 판정을 분명하게 한다. */
function engineInData(): SmtpEngine {
  const e = new SmtpEngine({ hostname: "srv.test", maxSizeBytes: 1024, tlsAvailable: false });
  e.greeting();
  e.feed(enc("EHLO client.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<c@d.test>\r\n"));
  e.rcptResult({ ok: true });
  e.feed(enc("DATA\r\n"));
  return e;
}

/** 내부 버퍼 크기 — 상한이 실제로 걸렸는지 보는 유일한 직접 관측점. */
function bufferedBytes(e: SmtpEngine): number {
  return (e as unknown as { buffer: Uint8Array }).buffer.length;
}

describe("DATA 단계 버퍼 상한", () => {
  test("CRLF 없는 스트림이 버퍼를 무한히 키우지 않는다", () => {
    const e = engineInData();
    const chunk = new Uint8Array(1_000_000).fill(0x41); // 'A'
    for (let i = 0; i < 8; i++) e.feed(chunk); // 8MB 투입, CRLF 한 번도 없음

    expect(bufferedBytes(e)).toBeLessThanOrEqual(OVER_LINE_LIMIT);
  });

  test("상한 초과 후에도 종료 마커를 인식해 552로 거절한다", () => {
    const e = engineInData();
    const chunk = new Uint8Array(1_000_000).fill(0x41);
    for (let i = 0; i < 4; i++) e.feed(chunk);

    const actions = e.feed(enc("\r\n.\r\n"));
    expect(replyTexts(actions).some((t) => t.startsWith("552 "))).toBe(true);
    // 크기 초과 메시지가 배달 액션으로 새어나가면 안 된다.
    expect(actions.some((a) => a.kind === "deliver")).toBe(false);
  });

  test("폐기 시 끝의 CR을 남겨 청크 경계에 걸친 종료 마커를 놓치지 않는다", () => {
    // 버퍼를 통째로 버리면 앞선 CR이 사라져 `CRLF "." CRLF`를 못 알아보고 세션이 DATA에 갇힌다.
    const e = engineInData();
    const withTrailingCr = new Uint8Array(OVER_LINE_LIMIT + 1);
    withTrailingCr.fill(0x41);
    withTrailingCr[withTrailingCr.length - 1] = 0x0d; // 마지막 바이트만 CR
    e.feed(withTrailingCr);

    const actions = e.feed(enc("\n.\r\n")); // 앞의 CR과 합쳐져야 종료 마커가 완성된다
    expect(replyTexts(actions).some((t) => t.startsWith("552 "))).toBe(true);
  });

  test("awaiting 중 파이프라인 폭주는 재개 시점에 421로 끊는다", () => {
    const e = new SmtpEngine({ hostname: "srv.test", maxSizeBytes: 1024, tlsAvailable: false });
    e.greeting();
    // RCPT 검증 대기 상태 — 이 구간에서는 pump()가 돌지 않아 예전엔 상한이 전혀 없었다.
    e.feed(enc("EHLO client.test\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<c@d.test>\r\n"));
    e.feed(new Uint8Array(2_000_000).fill(0x41));

    expect(bufferedBytes(e)).toBeLessThanOrEqual(1024 * 1024);

    const actions = e.rcptResult({ ok: true });
    expect(replyTexts(actions).some((t) => t.startsWith("421 "))).toBe(true);
    expect(actions.some((a) => a.kind === "close")).toBe(true);
  });
});
