/**
 * 구 `MAILER_*` 환경변수를 새 `IONOSPHERE_*` 이름으로 넘겨준다 — 개명 전환용.
 *
 * ★왜 필요한가: 프로젝트 이름이 mailer → ionosphere로 바뀌면서 env 접두사도 바뀌었다. 그런데
 * 라이브 3대의 `/etc/mailer.env`는 배포 **뒤에** 사람이 바꾼다. 그 사이에 새 코드가 옛 env를
 * 못 읽으면, 리스너 주소·마스터키·DB URL이 전부 기본값으로 떨어진 채 기동한다 — 그중 최악은
 * `IONOSPHERE_MASTER_KEY` 부재로 DKIM 개인키를 못 여는 상태다. 그래서 **코드 배포와 env 교체를
 * 분리**할 수 있게 한 단계 끼운다.
 *
 * ★왜 부수효과 import가 아니라 명시 호출인가: CLAUDE.md가 "이름·시그니처로 드러나지 않는
 * 부수효과 금지"를 규약으로 둔다. import만으로 `process.env`가 바뀌면 그 규약을 어긴다.
 * 진입점(`main.ts`·`cli.ts`·`scripts/audit-ship.ts`)이 **첫 문장으로** 부른다 — env를 모듈
 * 최상위에서 읽는 곳이 그 세 파일뿐이라(라이브러리 모듈은 전부 함수 안에서 읽는다) 그것으로 충분하다.
 *
 * ★왜 값이 다르면 죽는가: 전환 중에는 두 이름이 동시에 존재할 수 있다. 다른 값이 들어 있으면
 * 어느 쪽이 운영자의 의도인지 알 수 없다 — 하나를 골라 조용히 기동하면 "바꿨다고 생각한 설정이
 * 안 바뀐" 상태가 되고 그건 조용하다. 이 저장소는 그런 자리에서 시끄럽게 죽는 쪽을 골라 왔다
 * (리스너 파싱 실패가 기동을 막는 것과 같은 이유).
 */

const LEGACY_PREFIX = "MAILER_";
const PREFIX = "IONOSPHERE_";

export class LegacyEnvConflictError extends Error {}

/** 저널에 값을 남기면 안 되는 이름 — 마스터키·토큰·비밀번호 계열. */
function secret(key: string): boolean {
  return /KEY|SECRET|TOKEN|PASSWORD|_URL$/.test(key);
}

/**
 * `MAILER_X`를 `IONOSPHERE_X`로 복사한다(새 이름이 이미 있으면 그대로 둔다).
 *
 * @returns 넘겨준 구 이름 목록 — 호출자가 "아직 옛 이름을 쓰고 있다"고 경고하는 데 쓴다.
 * @throws LegacyEnvConflictError 두 이름이 **다른 값**으로 동시에 있을 때
 */
export function applyLegacyEnvAliases(env: Record<string, string | undefined> = process.env): readonly string[] {
  const moved: string[] = [];
  const conflicts: string[] = [];
  for (const key of Object.keys(env)) {
    if (!key.startsWith(LEGACY_PREFIX)) continue;
    const value = env[key];
    if (value === undefined) continue;
    const renamed = PREFIX + key.slice(LEGACY_PREFIX.length);
    const existing = env[renamed];
    if (existing === undefined) {
      env[renamed] = value;
      moved.push(key);
      continue;
    }
    // 비밀값은 이름만 알린다 — 이 오류는 systemd 저널에 그대로 남는다.
    if (existing !== value) conflicts.push(secret(key) ? `${key} ≠ ${renamed} (값 생략)` : `${key}=${value} ≠ ${renamed}=${existing}`);
  }
  if (conflicts.length > 0) {
    throw new LegacyEnvConflictError(
      `구 이름과 새 이름이 다른 값으로 동시에 설정됐다 — 어느 쪽이 의도인지 알 수 없다:\n  ${conflicts.join("\n  ")}\n` +
        `구 이름(${LEGACY_PREFIX}*)을 지우고 새 이름(${PREFIX}*)만 남길 것.`,
    );
  }
  return moved;
}
