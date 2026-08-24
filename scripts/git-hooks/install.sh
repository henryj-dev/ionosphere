#!/usr/bin/env bash
# 도구 중립 git 훅을 이 클론에 연결한다. **머신마다 한 번** 실행해야 한다.
#
# `.git/hooks/` 는 커밋되지 않으므로 훅을 거기 두면 클론마다 사라진다. 그래서 훅은
# 추적되는 `scripts/git-hooks/` 에 두고 `core.hooksPath` 로 가리킨다.
#
# ⚠️ `core.hooksPath` 는 `.git/config`(공용)에 들어가므로 **워크트리에도 함께 적용**된다.
#    훅 자신이 「메인 트리인가」를 보고 워크트리는 통과시키므로 그래도 된다.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
COMMON="$(git rev-parse --path-format=absolute --git-common-dir)"
MAIN="$(dirname "$COMMON")"

git -C "$MAIN" config core.hooksPath scripts/git-hooks

# ⚠️ 없는 훅을 그냥 `chmod` 하면 `set -e` 로 **그 줄에서 죽고**, 나오는 것은
#    `chmod: … No such file or directory` 뿐이다. 이 파일은 **다른 저장소로 사본이
#    떠 가는데**(parallax 가 2026-08-17 에 그렇게 했다) 그쪽엔 `docs/exchange` 가 없어
#    `pre-push` 를 안 둔다 — 통째로 가져가면 정확히 그 자리에서 멈춘다.
#    막지는 않는다(우리 쪽에선 없으면 실제로 문제다). **왜 멈췄는지 말한다.**
for hook in pre-commit; do
  path="$MAIN/scripts/git-hooks/$hook"
  if [[ ! -f "$path" ]]; then
    echo "❌ 훅이 없다: $path" >&2
    echo "   이 저장소에 그 훅이 필요 없다면 이 목록에서 빼야 한다 —" >&2
    echo "   사본을 뜬 저장소라면 「뒤처짐」이 아니라 「맞음」일 수 있다." >&2
    exit 1
  fi
  chmod +x "$path"
done

echo "core.hooksPath = $(git -C "$MAIN" config core.hooksPath)"
echo "설치됨:"
echo "  pre-commit — 에이전트의 메인 트리 커밋 차단 (사람은 통과)"
echo
echo "확인:  사람 셸에서 git commit --allow-empty -m probe        → 통과돼야 정상"
echo "       에이전트 세션에서 같은 명령                            → 거부돼야 정상"
echo "       python3 scripts/git-hooks/test-pre-commit.py         → 실패 0 이어야 정상"
echo "⚠️  --no-verify 로는 우회됩니다. 이건 경계가 아니라 위생 장치입니다."
