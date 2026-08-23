/**
 * ASN.1/DER INTEGER 인코딩 — **간헐적으로 깨진 인증서를 만들던 버그**의 회귀 방지.
 *
 * 발견 경위: 전체 테스트를 반복 실행하니 자체서명 인증서 파싱 테스트가 8회 중 2회 실패했다.
 * "테스트 플레이크"로 보였지만 실제로는 생성기 버그였다 — DER은 **최소 길이 인코딩**을
 * 요구하는데(X.690 §8.3.2) 선행 0x00을 제거하지 않았다. 난수 직렬번호의 첫 바이트가
 * 0x00으로 나오면(1/256) node의 `X509Certificate` 같은 엄격한 파서가 그 인증서를 거부한다.
 * 실측: 수정 전 800개 중 2개(0.25%) 파싱 실패 → 수정 후 0개.
 *
 * 간헐적이라 운영에서는 "가끔 인증서가 안 먹는다"로만 보인다 — 재현이 어려워 오래 남는 종류다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { X509Certificate } from "node:crypto";
import { int } from "../src/asn1.ts";
import { generateSelfSigned } from "../src/index.ts";

describe("INTEGER 최소 길이 인코딩 (X.690 §8.3.2)", () => {
  test("선행 0x00은 제거된다", () => {
    expect([...int(Uint8Array.of(0x00, 0x12, 0x34))]).toEqual([0x02, 0x02, 0x12, 0x34]);
  });

  test("여러 개의 선행 0x00도 전부 제거된다", () => {
    expect([...int(Uint8Array.of(0x00, 0x00, 0x00, 0x7f))]).toEqual([0x02, 0x01, 0x7f]);
  });

  test("★부호용 0x00은 남긴다 — 다음 바이트의 최상위 비트가 서 있으면 양수 표시가 필요하다", () => {
    expect([...int(Uint8Array.of(0x00, 0x80))]).toEqual([0x02, 0x02, 0x00, 0x80]);
  });

  test("최상위 비트가 선 값에는 0x00을 붙인다", () => {
    expect([...int(Uint8Array.of(0xff))]).toEqual([0x02, 0x02, 0x00, 0xff]);
  });

  test("전부 0이면 한 바이트 0으로 남는다(빈 INTEGER 금지)", () => {
    expect([...int(Uint8Array.of(0x00, 0x00))]).toEqual([0x02, 0x01, 0x00]);
  });

  test("number 경로도 최소 인코딩", () => {
    expect([...int(0)]).toEqual([0x02, 0x01, 0x00]);
    expect([...int(255)]).toEqual([0x02, 0x02, 0x00, 0xff]);
    expect([...int(1)]).toEqual([0x02, 0x01, 0x01]);
  });
});

describe("자체서명 인증서 — 파서 수용률", () => {
  /**
   * 확률성 버그라 한 번 생성해서는 못 잡는다. 여러 개를 만들어 **전부** 파싱되는지 본다.
   * 200개면 옛 버그(1/256)를 놓칠 확률이 약 0.04%다 — 수정 전에는 사실상 항상 걸린다.
   */
  test("200개를 만들어도 전부 X509Certificate로 파싱된다", () => {
    for (let i = 0; i < 200; i++) {
      const { certPem } = generateSelfSigned({ commonName: "probe.test", sans: ["probe.test"] });
      try {
        new X509Certificate(certPem);
      } catch (err) {
        throw new Error(`${i}번째 인증서가 파싱되지 않음: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  });
});
