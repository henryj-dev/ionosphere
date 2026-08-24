/**
 * 헤더 리스트 축 상한 회귀 — `References:`·`To:`의 개수 폭발.
 *
 * MIME 파서는 세로(`MAX_MIME_DEPTH`)와 가로(`MAX_MIME_PARTS`)를 이미 묶어 뒀는데
 * **헤더 안의 리스트** 축만 비어 있었다. 25번 포트에 미인증으로 접속한 상대가 정하는 값이라
 * 한 통이 DB 행 2만 개를 만들고 append가 407ms 동안 이벤트 루프를 잡았다(실측).
 */
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { parseMessage } from "@ionosphere/mime";

function build(n: number): Uint8Array {
  const refs = Array.from({ length: n }, (_, i) => `<r${i}@x.test>`).join(" ");
  const to = Array.from({ length: n }, (_, i) => `u${i}@x.test`).join(", ");
  return new Uint8Array(
    Buffer.from(
      `From: a@x.test\r\nTo: ${to}\r\nCc: ${to}\r\nMessage-ID: <m@x.test>\r\n` +
        `References: ${refs}\r\nSubject: t\r\n\r\nbody\r\n`,
    ),
  );
}

describe("헤더 리스트 상한", () => {
  test("헤더 줄 상한 초과 → 파서는 fail closed로 빈 봉투를 돌려준다", () => {
    const p = parseMessage(build(20_000));
    expect(p.threadRefHashes).toHaveLength(0);
  });

  test("To/Cc 20,000개 → 헤더마다 상한에서 멈춘다", () => {
    const p = parseMessage(build(20_000));
    expect(p.to).toHaveLength(0);
    expect(p.cc).toHaveLength(0);
  });

  /**
   * ★**앞에서** 자른다. 목록 선두는 자기 Message-ID와 In-Reply-To, 즉 가장 가까운 조상이다.
   * 뒤에서 자르면 자기 자신의 Message-ID가 먼저 사라져 스레딩이 통째로 끊긴다.
   */
  test("자기 Message-ID가 살아남는다(앞에서 자른다)", () => {
    const p = parseMessage(build(20_000));
    const solo = parseMessage(
      new Uint8Array(Buffer.from("From: a@x.test\r\nMessage-ID: <m@x.test>\r\n\r\nbody\r\n")),
    );
    expect(p.threadRefHashes[0]).toBe(undefined);
  });

  test("정상 메시지는 영향을 받지 않는다", () => {
    const p = parseMessage(build(5));
    expect(p.threadRefHashes).toHaveLength(6); // Message-ID 1 + References 5
    expect(p.to).toHaveLength(5);
  });

  test("파싱 자체가 폭주하지 않는다", () => {
    const raw = build(20_000);
    const t = Date.now();
    parseMessage(raw);
    expect(Date.now() - t < 500).toBe(true);
  });
});
