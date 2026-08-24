/**
 * 통합테스트의 소켓 데드라인 — **한 곳에서 정한다.**
 *
 * ★왜 상수로 올렸나(2026-08-23 검수): 소켓 왕복을 하는 테스트 15곳이 각자
 * `setTimeout(… , 4000)`을 들고 있었고, 전체 병렬 실행에서 **산발적으로 터졌다**
 * (`phase2.test.ts`·`access-starttls.test.ts`, 단독 실행은 통과). 원인은 코드가 아니라
 * 러너 부하다 — AUTH PLAIN이 scrypt를 도는 테스트라 4초는 실제로 빠듯하다.
 *
 * 그게 왜 중요한가: CLAUDE.md는 push 전 `npm run verify` 통과를 요구한다. **게이트 자체가
 * 흔들리면 그 규율이 무의미해진다** — 사람은 "가끔 깨지는 테스트"로 읽고 재실행으로 넘긴다.
 * 그러면 진짜 회귀도 같은 취급을 받는다.
 *
 * 값의 근거: 러너의 `--test-timeout`이 20초다(package.json). 그보다 확실히 짧아야 **어느
 * 단계에서 멈췄는지**가 드러나고(테스트 내부 데드라인은 소켓을 정리하며 실패한다), 정상
 * 왕복보다는 한참 길어야 부하에 흔들리지 않는다. 15초가 그 사이다.
 *
 * 느린 CI에서는 `IONOSPHERE_TEST_DEADLINE_MS`로 올린다 — 코드를 고치지 않고.
 */
const DEFAULT_DEADLINE_MS = 15_000;

function fromEnv(): number | null {
  const raw = Number(process.env.IONOSPHERE_TEST_DEADLINE_MS);
  return Number.isInteger(raw) && raw > 0 ? raw : null;
}

/** 소켓 왕복 하나가 끝나기를 기다리는 상한(ms). */
export const SOCKET_DEADLINE_MS = fromEnv() ?? DEFAULT_DEADLINE_MS;

/**
 * **하위 프로세스 프로브**의 소켓 데드라인 — 인프로세스 테스트보다 넉넉하다.
 *
 * ★왜 나눴나(2026-08-24): `access-starttls-probe`는 node를 새로 띄우고 그 안에서 서버를
 * 통째로 기동한 뒤 왕복한다. 인프로세스 테스트가 내는 비용에 **프로세스·서버 기동**이
 * 얹히는데 같은 15초를 쓰고 있었다 — 실측이 8.4초라 여유가 거의 없었고, 스위트가 커지면서
 * (2350건) 부하가 늘자 산발적으로 넘겼다.
 *
 * 상한을 그냥 올리지 않고 **계층을 나눈** 이유: 인프로세스 왕복이 15초를 넘으면 그건 진짜
 * 회귀다. 한 값을 같이 올리면 그 신호까지 무뎌진다.
 *
 * 러너의 `--test-timeout`(20초) 제약을 받지 않는다 — 이 값을 쓰는 테스트는 자기 타임아웃을
 * 따로 90초로 선언하고 하위 프로세스도 같은 상한을 둔다.
 */
export const PROBE_DEADLINE_MS = fromEnv() ?? 45_000;
