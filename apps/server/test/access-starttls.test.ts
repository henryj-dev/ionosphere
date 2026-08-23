/**
 * 143(IMAP)·110(POP3) STARTTLS/STLS 회귀 고정.
 *
 * ★왜 node 하위 프로세스인가: 기본 러너 bun 1.3.14는 서버측 TLS 업그레이드를 못 하고
 * (oven-sh/bun#25044), 그때 조립층이 STARTTLS를 **자동으로 끈다**. bun에서 돌리면
 * "광고 안 됨"이 정상 동작이라 **기능 부재와 구분되지 않는다.** 라이브는 node이므로
 * (운영 저장소의 systemd 유닛) 거기서 끝까지 확인한다 — managesieve-starttls와 같은 규율.
 *
 * ★무엇을 막는가: 이 포트들은 STARTTLS가 없으면 "연결은 되는데 로그인은 영원히 불가능한"
 * 상태가 된다. 오류가 아니라 **기능 없음**이라 아무도 소리치지 않고, 사용자는 "비밀번호가
 * 틀렸다"고 생각한다. 실제로 만들 때 엔진·어댑터를 다 고치고도 조립층이 인증서를 안 넘겨
 * 광고가 안 됐다 — 엔진 단위 테스트만 있었으면 그 상태로 통과했을 것이다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { spawnSync } from "node:child_process";
import { PROBE_OK, probeVerdict } from "./helpers.ts";

describe("접근 프로토콜 STARTTLS (143 IMAP · 110 POP3)", () => {
  test("[node] 광고 → 평문 인증 차단 → 업그레이드 후 로그인 성공", () => {
    const probe = new URL("./access-starttls-probe.ts", import.meta.url).pathname;
    const r = spawnSync("node", [probe], { encoding: "utf8", timeout: 90_000 });
    expect(probeVerdict(r)).toBe(PROBE_OK);
  }, 90_000);
});
