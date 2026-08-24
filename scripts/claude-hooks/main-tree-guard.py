#!/usr/bin/env python3
"""메인 작업 트리를 읽기 전용으로 묶는 PreToolUse 훅.

**왜 있나.** 이 레포는 여러 Claude 세션이 **같은 작업 트리**를 쓴다. 그러면 인덱스가
공유 자원이 되어 `git add` 와 `git commit` 사이에 남의 미완성 변경이 끼어든다.
2026-08-13~14 에 **네 번** 터졌다 — `89a03ea` 가 남의 `PLAN.md` 를, `d88dcd3` 가 남의
`host-proxy.ts` 를 삼켰다. `dispatcher/**`·`dashboard/**` 가 섞이면 **GHA 가 그대로
빌드·배포**하므로 문서 문제로 끝나지 않는다.

**무엇을 하나.** 메인 트리에서의 `Edit`/`Write`/트리 변경 git 명령을 **항상 거부**하고
워크트리로 보낸다. 워크트리는 자기 인덱스와 자기 작업 트리를 갖기 때문에 위 사고가
**구조적으로 일어나지 않는다**.

**메인을 아무도 안 쓰면 항상 pull 할 수 있다** — 그게 이 규칙의 두 번째 값이다.
누가 작업 중인지 따질 필요가 없어져 세션 종료 정리가 조건 없이 최신화된다.
(2026-08-14 에 세션 락 방식으로 먼저 만들었다가 이 방식으로 바꿨다. 락은 「먼저 잡은
세션은 메인에서 작업」을 허용했는데, 그 세션이 커밋·푸시할 때마다 메인이 더러워져
**pull 을 계속 미루게** 됐다. 실제로 그날 푸시가 두 번 막혔다.)

**읽기는 막지 않는다** — `Read`·`Grep`·`git status`·`log`·`diff`·`pull`·`fetch` 는 통과.
메인 트리는 **기본 브랜치의 읽기 전용 사본**으로 쓴다.

**우리 저장소의 메인 트리만 지킨다.** 레포 안에 다른 저장소를 sub-checkout 해 두었다면
(`target/…` 같은) 관여하지 않는다 — 거기서의 머지·커밋은 그 저장소의 규칙을 따른다.
판정을 「메인 트리인가」로 두면 *어느* 저장소든 참이 되어 남의 레포를 우리 규칙으로 막는다.
물어야 할 것은 **「*이 스크립트가 속한 저장소의* 메인 트리인가」**다.

⚠️ **이것은 보안 경계가 아니라 위생 장치다.** 내부 오류는 **통과**시킨다(fail-open) —
훅 버그로 전 세션이 멈추는 것이 동시 편집보다 나쁘다. 그래서 「훅이 있으니 안전하다」로
읽으면 안 된다. 사용자가 자기 셸에서 하는 작업은 애초에 이 훅을 거치지 않는다.
"""
import json
import fcntl
import os
import re
import subprocess
import sys
import time

OWNERS = "claude-worktree-owners.json"
OWNER_LOCK = "claude-worktree-owners.lock"

# 트리를 바꾸는 git 하위명령만 본다. 읽기(status·log·diff·show)와 pull/fetch 는 통과 —
# 메인 트리는 「읽기 + 최신화」 는 계속 할 수 있어야 한다.
#
# 🔴 **전역 옵션 부분은 「한 갈래로만 읽히게」 써야 한다 — 아니면 지수 백트래킹이다.**
# 예전 모양 `(?:\s+-[-\w]+(?:=\S+)?|\s+-C\s+\S+|\s+-c\s+\S+)*` 은 토큰 하나를 두 가지로 읽을
# 수 있었다: `-C` 는 「인자를 먹는 옵션」이자 「평범한 옵션」이고, `--=!` 는 `(?:=\S+)?` 를
# 쓰거나 안 쓰거나였다. 토큰당 갈래가 곱해져 반복마다 4배가 된다.
#
# 실측(2026-08-23, Python 3.9): `"git" + " -C --=!" * n` 에 대해
#     n=14 → 9 ms · n=18 → 140 ms · n=22 → 2.3 s · n=26 → 40 s
# **이 훅은 모든 도구 호출 앞에서 돈다.** 그리고 이 저장소가 세 층에 걸어 둔 fail-open 은
# 「오류가 나면 통과」이지 「멈추면 통과」가 아니다 — 매달리면 세션이 통째로 선다. 거부보다
# 나쁘다.
#
# 고친 모양은 `-C`/`-c` 뒤에 공백이 오면 **반드시** 인자를 먹게 하고(부정 전방탐색이 평범한
# 옵션으로 읽는 갈래를 막는다), 나머지 옵션은 `-\S*` 로 토큰 하나를 통째로 문다. 갈래가
# 하나뿐이라 위 수열이 전부 0.01 ms 다.
#
# ⚠️ 판정이 달라진다 — 그리고 **달라지는 쪽이 옳다.** 옛 모양은 `git -c add x` 같은 것도
# 막았는데, 그건 `-c` 를 평범한 옵션으로 읽어야만 나오는 해석이다. 진짜 git 은 `-c` 뒤 토큰을
# **항상** 인자로 먹으므로 그 `add` 를 하위명령으로 실행하는 일이 없다.
# git 자신의 전역 옵션 파싱(git.c `handle_options`)을 그대로 흉내 낸 모델로 148,000여 개
# 문자열을 돌려 확인했다: **git 이 실제로 실행할 변경 하위명령 68,016건을 둘 다 하나도 놓치지
# 않는다.** 옛 모양은 거기에 더해 git 이 애초에 거부하는 5,086건을 같이 막고 있었을 뿐이다.
MUTATING = re.compile(
    r"\bgit\b(?:\s+-[Cc]\s+\S+|\s+-(?![Cc](?:\s|$))\S*)*\s+"
    r"(commit|push|add|stage|merge|rebase|cherry-pick|revert|reset|mv|rm|apply|restore|switch|checkout|stash|clean|tag|worktree)"
    r"(?![-\w])"
)
# ⚠️ 끝을 `\b` 로 두면 **하이픈으로 이어지는 다른 하위명령까지 잡는다** — 정규식에서 `-` 는
# 단어 경계라 `merge` 가 `merge-base` 에 매치된다. 2026-08-15 에 `git merge-base` (읽기
# 전용)가 그렇게 막혀 브랜치 비교조차 못 했다. `(?![-\w])` 로 「그 이름으로 끝날 때만」
# 잡는다 — 목록에 이미 있는 `cherry-pick` 은 통째로 적혀 있어 그대로 매치된다.
# 위 목록엔 **메인 트리를 안 바꾸는 형태**가 섞여 있다 — `worktree list`·`stash list`·`tag -l`
# 은 읽기이고, `worktree remove|prune|…` 은 *다른* 디렉토리를 지운다. 2026-08-14 에
# `git worktree list` 가 막혀 상태 조회조차 못 했고, 2026-08-15 에는 `worktree remove` 가
# 막혀 **남은 워크트리를 회수할 방법이 없었다**(종료 훅은 같은 명령을 쓰는데, 훅은 이
# 가드를 안 거친다). `worktree add` 는 계속 막는다 — 임의 경로·ref를 허용하지 않고
# 도구 중립 생성기 `scripts/claude-hooks/enter-worktree.py` 로 만들어야 한다. 생성기가
# 소유자를 즉시 기록하고 이 훅도 후속 변경 때 갱신하므로 종료·다음 시작 회수 규칙이 적용된다.
# ⚠️ 「막는 쪽」만 검사하면 이런 오탐이 안 잡힌다. 통과 검사를 함께 둘 것.
ALLOWED = re.compile(r"\bgit\b.*\b(?:worktree|stash|remote|branch|tag|submodule)\s+list\b"
                     r"|\bgit\b.*\btag\s+(?:-l|--list)\b"
                     r"|\bgit\b.*\bstash\s+(?:show|list)\b"
                     r"|\bgit\b.*\bworktree\s+(?:remove|prune|lock|unlock|move|repair)\b")
# 🔴 **명령 전체가 아니라 조각마다 본다.** 통째로 걸면 `git stash list && git commit -m x`
# 에서 앞 조각이 «읽기 전용» 으로 매치되어 **뒤의 커밋까지 통과**한다 — 2026-08-15 에
# 실측으로 확인한 우회로다(3케이스 전부 통과했다). 오탐 셋과 뿌리가 같다: **한 문자열에
# 정규식 하나를 걸고 여러 명령을 판정하려 한 것.**
SEGMENT = re.compile(r"&&|\|\||;|\n|\|")

# 구제 통로: 이 파일이 있으면 메인 트리 수정을 허용한다. 끝난 세션이 메인에 남긴 작업을
# 커밋해 구조할 때처럼, 규칙이 오히려 방해가 되는 자리가 실제로 있다.
# **30분이면 저절로 만료**된다 — 켜 두고 잊으면 규칙이 조용히 사라지기 때문이다.
RESCUE = "claude-main-tree-rescue"
RESCUE_TTL = 1800
DASH_C = re.compile(r"\bgit\b(?:\s+-c\s+\S+)*\s+-C\s+(\S+)")
# 명령 앞머리의 `cd <경로>` 도 봐야 한다. 2026-08-14 에 `cd target/idp && git merge` 가
# 막혔다 — 훅이 받는 cwd 는 세션의 cwd(메인 트리)라 `cd` 를 안 읽으면 대상을 틀리게 잡는다.
CD = re.compile(r"(?:^|[;&|\n])\s*cd\s+(?:-{1,2}\s+)?([^\s;&|]+)")
WORKTREE_DIR = ".claude/worktrees/"     # 이 아래는 정의상 메인 트리가 아니다

# 레포마다 다른 것은 **적어 두지 않고 읽는다** — 기본 브랜치는 git 에게 묻고, 워크트리
# 준비 절차(의존성 설치·코드 생성)는 이 파일이 있으면 붙인다. 스킬로 이식할 때 사람이
# 문구를 고쳐야 하면 **고치는 것을 잊은 클론에서 메세지가 거짓말을 한다.**
BOOTSTRAP = os.path.join(".claude", "worktree-bootstrap.md")

DENY = """메인 작업 트리는 읽기 전용입니다. 수정은 워크트리에서 하십시오.

이 레포는 여러 세션·도구가 같은 작업 트리를 공유합니다. 여기서 고치면 인덱스가 섞여
남의 미완성 변경이 내 커밋에 딸려 들어갑니다. CI 가 붙어 있으면 그것이 그대로
빌드·배포됩니다. 그리고 메인이 더러워지면 세션 종료 시 자동 pull 이 계속 미뤄집니다.

→ **워크트리에서 작업하십시오.** 하네스 전용 도구가 있으면 그것을 쓰고, 없으면:
   python3 scripts/claude-hooks/enter-worktree.py <이름>

생성기가 출력한 경로로 이동해 작업하십시오. 임의 `git worktree add` 는 계속 거부됩니다.

끝나면 그 워크트리 안에서:
   git fetch origin && git rebase {base} && git push origin HEAD:{branch}

메인 트리는 세션이 시작·종료할 때 자동으로 fast-forward 됩니다 — 직접 올릴 필요 없습니다.
🚨 끝난 세션이 메인에 남긴 작업을 구조해야 하는 등 정말 메인에서 해야 하면
   `touch {rescue}` (30분 후 자동 만료). **사용자 승인 후에만.**{extra}"""


def deny_text(cwd, common):
    """거부 메세지를 **그 레포의 실제 값으로** 채운다.

    기준은 `origin/HEAD` 가 **아니라 메인 트리가 지금 올라가 있는 브랜치**다. 기본 브랜치로
    적으면 feature 브랜치에서 작업하는 레포에서 메세지가 「그 작업을 버리고 기본 브랜치에서
    새로 따서, 기본 브랜치로 push 하라」고 말한다 — 2026-08-17 barycenter 에서 실측했다:
    메인이 `design/…` 에 있고 그 브랜치에만 177 커밋, origin 에는 아직 없는 상태인데
    메세지는 `origin/main` 에서 따서 `HEAD:main` 으로 밀라고 인쇄했다. 브랜치 이름은 한 번도
    나오지 않았다. **막는 것은 맞았고 시키는 것이 틀렸다** — 이쪽이 더 위험하다. 거부는
    사람이 다시 생각하게 만들지만, 조언은 그대로 복사되기 때문이다.

    push 대상은 그 브랜치, 분기·rebase 기준은 **그 브랜치의 업스트림**이다. 업스트림이
    없으면(아직 안 밀어 본 브랜치) 로컬 팁에서 딴다 — 그 경우 `git fetch` 가 기준을 앞으로
    옮기지 못하므로 뒤따르는 rebase 는 사실상 no-op 이다. 틀린 곳으로 보내는 것보다 낫다.

    push 대상은 로컬 이름이 아니라 **`branch.<n>.merge` 가 가리키는 원격 쪽 이름**이다. 둘은
    다를 수 있다(`git push -u origin feat:feat-remote`). 로컬 이름으로 적으면 추적하던 ref 를
    갱신하는 대신 **원격에 갈라진 두 번째 브랜치를 만든다.**

    detached HEAD 처럼 브랜치를 모를 때만 `origin/HEAD` 로 폴백하고, 그것도 없으면
    자리표시자를 남긴다 — **모르는 것을 아는 척해 `origin/main` 으로 적으면 틀린 명령을 주게
    된다.** 커밋이 하나도 없는 저장소(unborn HEAD)도 여기 속한다: `symbolic-ref` 는 그때도
    **성공하므로** 이름을 그대로 믿으면 `-b <이름> trunk` 처럼 **존재하지 않는 ref** 를 기준으로
    주게 된다(`fatal: invalid reference`). 그래서 HEAD 가 가리키는 커밋이 실재하는지 따로 본다.

    ⚠️ 못 덮는 것 둘. (1) rebase·bisect 중이면 HEAD 가 «이유 있게» detached 라 기본 브랜치로
    폴백한다 — 원래 브랜치는 `.git/rebase-merge/head-name` 에 있지만 읽지 않는다. 고치기 전보다
    나쁘지는 않으나 맞지도 않다. (2) 이 문장은 그대로 복사해 셸에 붙이는 것인데 브랜치 이름을
    따옴표 없이 끼운다 — `wip/a&b` 같은 이름은 셸이 쪼갠다. 로컬 이름을 새로 끌어들인 만큼
    이쪽 노출은 늘었다. 둘 다 «조용히 틀리는» 자리이므로 여기 적어 둔다.
    """
    branch = ""
    if git(cwd, "rev-parse", "--verify", "--quiet", "HEAD") is not None:
        branch = git(cwd, "symbolic-ref", "--short", "HEAD") or ""
    if branch:
        # push 대상은 원격 쪽 이름. 추적이 없으면(아직 안 밀어 본 브랜치) 같은 이름으로 생긴다.
        merge = git(cwd, "config", "--get", f"branch.{branch}.merge") or ""
        base = git(cwd, "rev-parse", "--abbrev-ref", "@{u}") or branch
        if merge.startswith("refs/heads/"):
            branch = merge[len("refs/heads/"):]
    else:
        base = git(cwd, "symbolic-ref", "--short", "refs/remotes/origin/HEAD") or ""
        branch = base.split("/", 1)[1] if "/" in base else ""
    extra = ""
    try:
        with open(os.path.join(os.path.dirname(common), BOOTSTRAP), encoding="utf-8") as f:
            body = f.read().strip()
        if body:
            extra = "\n⚠️ 이 워크트리를 쓰기 전에:\n" + "\n".join(
                "   " + ln for ln in body.splitlines())
    except Exception:
        pass
    return DENY.format(base=base or "origin/<기준브랜치>",
                       branch=branch or "<대상브랜치>",
                       rescue=os.path.join(common, RESCUE),
                       extra=extra)


def git(cwd, *args, timeout=15):
    """git 한 번. 실패·시간초과면 `None`(= 모른다).

    🔴 **상한이 필요하다.** 이 훅은 **모든 툴 호출 앞**에서 돈다 — git 이 매달리면
    (인덱스 락 대기, 네트워크가 붙은 하위 명령 등) **세션이 통째로 선다.** 그리고
    훅의 fail-open 은 *오류* 를 통과시키는 장치이지 *침묵* 을 통과시키지 못한다 —
    **매달림은 실패가 아니라 침묵**이라 그 안전판에 안 걸린다.
    상한에 걸리면 `None` 을 돌려 기존 「모르면 통과」 경로로 합류한다.

    (같은 파일의 `proc_start`·`proc_cmd` 는 처음부터 `timeout=5` 를 갖고 있었다.
     여기만 없었다 — 2026-08-17, parallax 123 §3 의 「이름이 아니라 API 로 훑어라」를
     우리 훅에 대 보다 나왔다.)
    """
    try:
        r = subprocess.run(("git", "-C", cwd) + args, capture_output=True, text=True,
                           timeout=timeout)
    except Exception:
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def protected_main():
    """이 훅이 지키는 저장소의 메인 트리. **이 스크립트 자신의 위치**에서 구한다.

    ⚠️ 「git-dir == git-common-dir 이면 메인 트리」로 판정하면 **어느 저장소든** 메인 트리는
    참이 된다. `target/` 아래 sub-checkout(idp·heliopause·parallax…)이 전부 걸린다 —
    남의 저장소를 우리 규칙으로 막는 것이고, 2026-08-14 에 `target/idp` 머지가 그렇게 막혔다.
    **지킬 대상은 「어떤 메인 트리」가 아니라 「이 저장소의 메인 트리」다.**
    """
    here = os.path.dirname(os.path.abspath(__file__))
    common = git(here, "rev-parse", "--path-format=absolute", "--git-common-dir")
    return (os.path.dirname(common), common) if common else (None, None)


def is_main_tree(cwd):
    """그 경로가 **이 저장소의** 메인 작업 트리인가."""
    guarded, common = protected_main()
    if not guarded:
        return None, None
    top = git(cwd, "rev-parse", "--show-toplevel")
    if not top:
        return None, common
    return os.path.realpath(top) == os.path.realpath(guarded), common


def shell_command(tool_input):
    """셸 명령 문자열. 없으면 `""`.

    ⚠️ **하네스마다 모양이 다르다.** Claude 는 `{"command": "git status"}` 로 주고,
    codex 계열은 `{"command": ["/bin/zsh","-lc","git status"]}` 처럼 **배열**로 줄 수 있다.
    문자열만 가정하면 배열이 통째로 무시되어 **가드가 조용히 안 돈다** — 「막는 훅이 있다」와
    「막는다」가 갈리는 자리다. 그래서 여기서 한 모양으로 모은다.
    """
    # 🔴 **패치인지 먼저 묻는다 — 문자열이든 배열이든.** 이 판정이 아래 문자열 분기에만
    #    있었고, 그래서 배열로 온 패치는 **본문이 그대로 셸 명령이 됐다**. `relevant()` 는
    #    그것을 MUTATING 에 대 보고 안 걸리면 거기서 끝내므로, `edit_paths()` 의 경로 추출은
    #    **도달하지 못한다.** 실측(수정 전):
    #
    #        {"command": "*** Begin Patch\n*** Update File: README.md\n…"}            → 거부
    #        {"command": ["/bin/zsh","-lc","*** Begin Patch\n*** Update File: …"]}   → 통과
    #        {"command": "*** Update File: README.md\n…"}                            → 통과
    #
    #    앞의 둘은 같은 패치다. 모양만 바꾸면 가드가 안 본다.
    if patch_text(tool_input):
        return ""
    c = tool_input.get("command")
    if isinstance(c, str):
        # 🔴 **`command` 가 셸 명령이라는 보장이 없다** (2026-08-15 codex 실측):
        #    `apply_patch` 는 **패치 본문을 `command` 에** 담아 보낸다. 그것을 셸 명령으로
        #    읽으면 MUTATING 정규식에 안 걸려 **편집이 통째로 통과한다** — 실제로 메인
        #    트리에 파일이 생겼다. 같은 키가 두 가지 뜻을 갖는다는 것을 여기서 가른다.
        return c
    if isinstance(c, (list, tuple)):
        parts = [str(x) for x in c]
        # `["/bin/zsh", "-lc", "<스크립트>"]` — 셸 플래그 **뒤의 한 덩어리가 스크립트**다.
        # 🔴 그냥 이어 붙이면 `cd` 앞에 `-lc ` 가 붙어 **줄 첫머리 판정이 깨진다**
        #    (2026-08-15 실측: `cd` 접기가 통째로 안 먹었다). 셸 호출은 벗겨 내야 한다.
        for i, p in enumerate(parts[:-1]):
            if re.fullmatch(r"-[a-z]*c", p):
                return parts[i + 1]
        return " ".join(parts)
    return ""


# apply_patch 계열은 파일 경로를 **본문 안에** 담는다.
PATCH_PATH = re.compile(r"^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s*(.+?)\s*$", re.M)
PATCH_MARK = "*** Begin Patch"          # 2026-08-15 codex 실측 형식

# 패치 본문이 실려 올 수 있는 키들. `command` 가 여기 있는 것이 요점이다 — codex 의
# `apply_patch` 는 패치를 그 키로 보낸다(실측).
PATCH_KEYS = ("command", "input", "patch", "content", "diff")


def patch_text(tool_input):
    """이 호출이 들고 있는 **패치 본문**. 없으면 `""`.

    🔴 **「패치인가」를 묻는 곳이 세 군데였고 답이 두 가지였다.** `edit_paths()` 는
    `PATCH_PATH`(`*** Update File:` 류)로 알아보는데 `shell_command()` 와
    `writes_content()` 는 `PATCH_MARK`(`*** Begin Patch`)로만 알아봤다. 봉투 머리말이
    없는 본문은 한쪽에는 패치이고 다른 쪽에는 셸 명령이다 — 그리고 관문인 `relevant()` 는
    후자를 믿는다.

    🔴 게다가 둘 다 `isinstance(v, str)` 만 봤다. 하네스에 따라 `command` 는
    `["/bin/zsh","-lc","<본문>"]` 같은 **배열**로 온다. 그러면 봉투 머리말이 멀쩡히 있어도
    아무도 그것을 안 본다. `shell_command()` 가 배열을 풀어 본문을 셸 명령으로 돌려주고,
    거기서 판정이 끝난다.

    그래서 **한 함수가 두 신호를 다 보고, 두 모양을 다 본다.** 둘 중 하나라도 걸리면 패치다.
    넓게 잡는 방향이라 오탐은 「셸 명령을 패치로 오인」인데, 그 경우 판정은 경로+내용
    쪽으로 넘어가 **막는 쪽**으로 떨어진다. 이 가드에서 틀려도 되는 방향은 그쪽뿐이다.
    """
    for key in PATCH_KEYS:
        v = tool_input.get(key)
        if isinstance(v, str):
            text = v
        elif isinstance(v, (list, tuple)):
            text = "\n".join(str(x) for x in v)
        else:
            continue
        if text and (PATCH_MARK in text or PATCH_PATH.search(text)):
            return text
    return ""


def writes_content(tool_input):
    """**새로 쓸 내용**이 실려 있는가. 읽기와 쓰기를 가르는 것은 경로가 아니라 이것이다.

    🔴 경로만 보면 `Read` 가 편집으로 잡힌다(2026-08-15 에 실제로 그랬다) — 읽기도 파일
    경로를 준다. 반대로 내용만 보면 이름 없는 새 쓰기 도구도 잡힌다. **모르는 이름이어도
    「내용을 들고 그 파일을 가리키면」 쓰기다.**
    """
    for k in ("content", "new_string", "new_str", "new_source", "patch", "diff",
              "edits", "replacements"):
        if tool_input.get(k) not in (None, "", [], {}):
            return True
    # 패치를 들고 있으면 쓰기다 — 어느 키로, 어느 모양으로 왔든. `patch_text` 가 그 판정을
    # 혼자 갖는다(예전에는 여기서도 문자열 + `*** Begin Patch` 만 봤다).
    if patch_text(tool_input):
        return True
    return False


def edit_paths(tool_input):
    """이 호출이 쓰려는 파일 경로들. 도구 이름을 몰라도 **입력 모양**으로 알아낸다.

    🔴 **도구 이름으로 판정하지 말 것.** Claude 는 `Edit`/`Write`/`NotebookEdit` 이지만
    다른 하네스는 `apply_patch` 처럼 전혀 다른 이름을 쓴다. 이름 목록으로 막으면 **새 이름이
    생길 때마다 조용히 뚫린다** — 모르는 이름은 「안전한 것」이 아니라 **모르는 것**이다.
    """
    out = []
    for k in ("file_path", "notebook_path", "path", "filePath"):
        v = tool_input.get(k)
        if isinstance(v, str) and v:
            out.append(v)
    # ⚠️ `command` 가 여기 들어 있는 것이 요점이다 — codex 의 `apply_patch` 는 패치를
    #    **`command` 로** 보낸다(실측). 「명령 키니까 셸이겠지」로 넘기면 편집이 통과한다.
    body = patch_text(tool_input)
    if body:
        out += PATCH_PATH.findall(body)
    files = tool_input.get("files") or tool_input.get("changes")
    if isinstance(files, (list, tuple)):
        for f in files:
            if isinstance(f, str):
                out.append(f)
            elif isinstance(f, dict):
                for k in ("path", "file_path", "filePath"):
                    if isinstance(f.get(k), str):
                        out.append(f[k])
    return [unquote(p) for p in out if p]


def unquote(s):
    """`git -C ".../x"` 의 따옴표를 벗긴다. 안 벗기면 **어떤 경로도 `isdir` 이 안 되어**
    항상 cwd(=메인)로 떨어진다 — 2026-08-15 에 `git -C "<워크트리>" …` 가 그렇게 막혔다."""
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1]
    return s


def fold_cd(cmd, cwd):
    """명령 앞머리의 `cd` 들을 **차례로 접어** 최종 디렉토리를 구한다.

    🔴 **마지막 `cd` 하나만 보고 세션 cwd 기준으로 풀면 안 된다** (2026-08-15 실측):
    `cd <임시경로> && … && cd ..` 에서 `cd ..` 가 **`<세션cwd>/..`** 로 풀렸고, 그것이
    `.claude/worktrees` 였다. 그 디렉토리의 `--show-toplevel` 은 **메인 트리**라, 메인과
    아무 상관 없는 임시 저장소 작업이 「메인 수정」으로 거부됐다. 상대 경로는 **그 앞의
    `cd` 들이 이동한 자리**에서 풀어야 한다.

    ⚠️ 서브셸 `( cd x && … )` 의 `cd` 는 바깥에 남지 않으므로 애초에 매치하지 않는다
    (앞 문자 집합에 `(` 가 없다). 그대로 두는 것이 맞다.
    """
    cur = cwd
    for m in CD.finditer(cmd):
        p = unquote(m.group(1))
        cur = p if os.path.isabs(p) else os.path.join(cur, p)
    return os.path.normpath(cur)


def target_cwd(tool, tool_input, cwd):
    """이 호출이 실제로 건드리는 디렉토리. `git -C <path>` 는 그 경로가 대상이다."""
    cmd = shell_command(tool_input)
    if cmd:
        base = fold_cd(cmd, cwd)                     # `cd` 를 먼저 접고
        m = DASH_C.search(cmd)                       # `git -C <path>` 가 가장 구체적이다
        if m:
            raw = unquote(m.group(1))
            d = raw if os.path.isabs(raw) else os.path.join(base, raw)
            if os.path.isdir(d):
                return d
            # 셸 변수가 안 풀린 경로(`"$w"`)는 여기서 확인할 수 없다. 그래도 **워크트리
            # 디렉토리 아래인 것이 글자로 드러나면** 우리 메인이 아닌 것이 확정이다 —
            # 판정 불가를 「메인」으로 떨어뜨리면 워크트리 조작이 통째로 막힌다.
            if WORKTREE_DIR in raw.replace(os.sep, "/"):
                return None                          # 우리 메인이 아니다
        return base
    # 🔴 **경로가 여럿이면 「우리 메인인 것」이 이긴다 — 첫 번째가 아니라.**
    #
    #    예전에는 첫 번째로 존재하는 경로 하나로 대상 저장소를 정하고 끝냈다. 저장소 안에
    #    **다른 저장소를 가리키는 경로**가 있으면(중첩 체크아웃, 또는 밖으로 걸린 심링크 —
    #    heliopause 의 `docs/`·`policy/` 가 그렇다) 그것을 앞에 세운 다중 경로 편집은
    #    「우리 메인이 아니다」 분기로 빠져 **뒤에 붙은 추적 파일이 그대로 실려 갔다.**
    #    실측 재현:
    #
    #        {"tool_name":"Write","tool_input":{"files":["<repo>/docs/x.md",
    #                                                    "<repo>/README.md"],"content":"x"}}
    #        → 통과. 순서를 뒤집으면 거부.
    #
    #    `main()` 은 대상 저장소가 우리 메인이 아니면 거기서 돌아선다. 그러니 나머지 경로를
    #    볼 기회 자체가 없었다 — 고칠 자리는 판정이 아니라 **대상을 고르는 여기**다.
    #
    #    우리 메인이 하나도 없으면 옛 동작 그대로 첫 번째 존재 경로를 준다. 넓어지는 것은
    #    「우리 메인이 섞여 있는」 경우뿐이고, 그건 원래 막았어야 하는 경우다.
    fallback = None
    for path in edit_paths(tool_input):          # 상대 경로는 그 호출의 cwd 기준이다
        p = path if os.path.isabs(path) else os.path.join(cwd, path)
        # 새 중첩 디렉터리에 Add File 하는 경우, 바로 위 부모는 아직 없다. 이때
        # 세션 cwd(대개 메인)로 떨어지면 워크트리 편집을 메인 편집으로 오인한다.
        # 실제로 존재하는 가장 가까운 부모까지 올라가서 git 최상위를 판정한다.
        d = os.path.dirname(os.path.abspath(p))
        while not os.path.isdir(d):
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
        if not os.path.isdir(d):
            continue
        if fallback is None:
            fallback = d
        mine, _ = is_main_tree(d)
        if mine is True:
            return d
    return fallback if fallback is not None else cwd


def relevant(tool, tool_input):
    """이 호출이 파일을 바꾸려 하는가. **도구 이름이 아니라 입력 모양으로** 본다.

    이름 목록(`Edit`/`Write`/…)은 Claude 것이고, 다른 하네스는 `apply_patch` 같은 다른
    이름을 쓴다. 이름으로만 막으면 **이름이 바뀌는 순간 조용히 뚫린다.**
    """
    if tool in ("Edit", "Write", "NotebookEdit"):
        return True                             # Claude 의 이름 — 입력이 비어도 편집이다
    cmd = shell_command(tool_input)
    if cmd:
        for seg in SEGMENT.split(cmd):          # 조각마다 — 위 SEGMENT 주석 참고
            if ALLOWED.search(seg):
                continue
            if MUTATING.search(seg):
                return True
        return False
    # 모르는 이름이어도 **내용을 들고 파일을 가리키면** 편집이다.
    return bool(edit_paths(tool_input)) and writes_content(tool_input)


def proc_start(pid):
    """그 pid 의 **시작 시각** 문자열. 못 읽으면 `""`.

    pid 는 재사용된다 — 시작 시각을 함께 봐야 「그때 그 프로세스」임이 확정된다.
    """
    try:
        r = subprocess.run(["ps", "-p", str(pid), "-o", "lstart="],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def proc_cmd(pid):
    """그 pid 의 실행 파일 이름(짧게). 회수 규칙이 **가정 대신 검증**하는 데 쓴다."""
    try:
        r = subprocess.run(["ps", "-p", str(pid), "-o", "comm="],
                           capture_output=True, text=True, timeout=5)
        return os.path.basename(r.stdout.strip())[:40] if r.returncode == 0 else ""
    except Exception:
        return ""


def record_owner(common, tcwd, sid):
    """워크트리를 누가 쓰는지 적어 둔다 — 세션 종료 정리가 「내 것만」 회수하게."""
    top = git(tcwd, "rev-parse", "--show-toplevel")
    if not top:
        return
    p = os.path.join(common, OWNERS)
    # 🔎 **주인이 살아 있는지 나중에 물으려면 프로세스를 적어 둬야 한다.** `SessionEnd` 가
    #    안 뜨는 하네스(codex 실측)에서는 「끝났다」는 신호가 아예 없으므로, 다음 세션이
    #    **시작할 때** 죽은 주인의 워크트리를 회수하는 수밖에 없다.
    #    ⚠️ pid 만으로는 안 된다 — 재사용되면 남의 프로세스를 「내 주인」으로 본다.
    #       그래서 **시작 시각**을 함께 적어 둘을 대조한다.
    #    ⚠️ 여기서 적는 pid 는 **훅의 부모**다. 그것이 에이전트 프로세스인지 아니면 곧
    #       사라질 셸인지는 하네스마다 다를 수 있어, 회수 쪽에서 그것을 **가정하지 않고**
    #       검증한다(`worktree-reap` 규칙 참고).
    ppid = os.getppid()
    try:
        with open(os.path.join(common, OWNER_LOCK), "a+", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                with open(p, encoding="utf-8") as f:
                    owners = json.load(f)
            except Exception:
                owners = {}
            owners[os.path.realpath(top)] = {
                "session_id": sid, "ts": time.time(),
                "pid": ppid, "pid_start": proc_start(ppid), "pid_cmd": proc_cmd(ppid),
            }
            tmp = p + f".{os.getpid()}"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(owners, f, ensure_ascii=False)
            os.replace(tmp, p)
    except Exception:
        pass


def main():
    data = json.load(sys.stdin)
    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}
    sid = data.get("session_id") or "unknown"
    cwd = data.get("cwd") or os.getcwd()

    if not relevant(tool, tool_input):
        return

    tcwd = target_cwd(tool, tool_input, cwd)
    if tcwd is None:
        return                          # 워크트리인 것이 글자로 확정됐다 — 막지 않는다
    main_tree, common = is_main_tree(tcwd)
    if main_tree is False and common:
        # 우리 저장소의 워크트리일 때만 소유자를 적는다. 위치는 상관없다 —
        # 다른 팀 세션이 `/private/tmp/...` 에 우리 워크트리를 만든 실례가 있다.
        # 반대로 `target/` 아래 남의 저장소는 적으면 안 된다(우리가 회수할 것이 아니다).
        theirs = git(tcwd, "rev-parse", "--path-format=absolute", "--git-common-dir")
        if theirs and os.path.realpath(theirs) == os.path.realpath(common):
            record_owner(common, tcwd, sid)
        return                          # 우리 메인이 아니다 — 막지 않는다
    if main_tree is not True:
        return                          # git 밖 — 관여하지 않는다

    rescue = os.path.join(common, RESCUE)
    try:
        if time.time() - os.path.getmtime(rescue) < RESCUE_TTL:
            return                      # 구제 모드 — 명시적으로 켠 것이므로 통과
        os.remove(rescue)               # 만료된 것은 치운다
    except Exception:
        pass

    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": deny_text(tcwd, common),
    }}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass                            # fail-open — 훅 버그가 전 세션을 멈추면 안 된다
