#!/usr/bin/env python3
"""세션 종료 정리 — 메인 트리 최신화 + 이 세션이 쓰던 워크트리·브랜치 회수.

세션이 끝나면 ① 이 세션이 만든 워크트리와 브랜치를 지우고 ② 메인 트리를
`git pull --ff-only` 로 올린다. 메인은 읽기 전용이라(가드 훅) 아무도 안 쓰므로
**pull 이 조건 없이 성립한다** — 다음 세션은 항상 최신에서 시작한다.

🔴 **파괴적 자동화라서 안전판을 코드가 아니라 git 에 맡긴다.**
  - `git worktree remove` 를 **`--force` 없이** 쓴다 → 미커밋 변경이 있으면 git 이 거부한다
  - `git branch -d`(소문자) 를 쓴다 → 머지 안 된 커밋이 있으면 git 이 거부한다
  즉 이 스크립트는 **일을 지울 수 없다**. 거부되면 그대로 두고 기록만 남긴다.
  `-D`/`--force` 를 여기에 넣지 말 것 — 그 순간 이 문단의 보장이 사라진다.

⚠️ 정리 대상은 **이 세션이 소유한 워크트리뿐**이다(`main-tree-guard.py` 가 기록한다).
   남의 세션이 쓰는 워크트리를 「깨끗해 보인다」는 이유로 지우면 그쪽 발밑을 빼는 것이다.

⚠️ 메인 트리 pull 은 실패해도 정상 종료한다 — 다른 세션의 미커밋 변경과 겹치면
   `--ff-only` 가 거부하는데, 그건 사고가 아니라 **보호가 동작한 것**이다.

기록: `<git-common-dir>/claude-session-end.log`
"""
import json
import fcntl
import os
import subprocess
import sys
import time

OWNERS = "claude-worktree-owners.json"
OWNER_LOCK = "claude-worktree-owners.lock"
LOG = "claude-session-end.log"


def git(cwd, *args, timeout=60):
    try:
        r = subprocess.run(("git", "-C", cwd) + args, capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as e:
        return 1, str(e)


def pull_blocked_by(status):
    """메인 트리를 지금 pull 해도 되는가. 안 되면 사유 문자열, 되면 None.

    메인은 가드 훅이 읽기 전용으로 묶으므로 보통 깨끗하다. 그래도 **깨끗한지 확인한 뒤**
    당긴다 — 사용자가 자기 셸에서 직접 고쳤을 수 있고, 훅은 fail-open 이라 새어나갈 수 있다.

    ⚠️ **`--ff-only` 는 「남의 작업을 안 건드린다」를 보장하지 않는다** (2026-08-14 실측):
    들어오는 커밋이 상대가 손댄 *것과 다른* 파일만 바꾸면 **그대로 fast-forward 되어
    상대 발밑에서 파일이 바뀐다**. 겹칠 때만 거부한다. 그래서 「겹치면 git 이 막아 주겠지」
    로는 부족하고, 더러우면 아예 하지 않는다.
    """
    return "메인 트리에 미커밋 변경이 있다" if status.strip() else None


def live_worktrees(main_tree):
    """git 이 **워크트리로 아는** 경로들(realpath). 못 물어보면 `None`.

    `None` 을 「하나도 없다」로 읽으면 소유자 기록을 통째로 날린다 — 그래서 빈 집합과
    구분한다. 호출부는 `None` 이면 아무것도 정리하지 않는다.
    """
    rc, out = git(main_tree, "worktree", "list", "--porcelain")
    if rc:
        return None
    return {os.path.realpath(line[9:].strip())
            for line in out.splitlines() if line.startswith("worktree ")}


def fast_forward_main(git, main_tree):
    """메인 트리를 업스트림까지 fast-forward. 반환 `(성공?, 메시지 or None)`.

    메시지가 `None` 이면 **이미 최신**이다.

    🔴 **`git pull` 을 쓰지 않는다 — 동시에 돌면 실제로 깨진다.**
    `pull` 은 자기 fetch 결과를 **공유 파일 `FETCH_HEAD`** 로 머지 단계에 넘기는데, 세션
    종료는 여러 개가 같은 순간에 몰린다. 쓰기가 섞이면 머지 대상이 둘 이상으로 보여
    **`fatal: Cannot fast-forward to multiple branches.`** 로 죽는다. 2026-08-15 14:13:11 에
    여섯 세션이 동시 종료하며 **전부** 이걸로 실패했고(`claude-session-end.log`), 격리
    재현에서 **8/8 실패**했다. 원격 추적 ref 를 대상으로 `merge --ff-only` 를 쓰면
    FETCH_HEAD 를 안 거쳐 그 경합이 사라진다(같은 재현에서 6~7/8 성공, 최종 HEAD 일치).

    ⚠️ **경합에서 진 것을 실패로 적지 말 것.** 남는 실패는 `index.lock`·ref 경합이고 그건
    **다른 프로세스가 먼저 성공했다**는 뜻이다. 그래서 실패하면 HEAD 를 다시 읽어
    업스트림과 같은지 본다 — 같으면 목적은 달성됐다. 이 확인이 없으면 트리는 멀쩡한데
    로그만 「최신화 실패」로 도배되는, 사람을 헛짚게 하는 기록이 남는다.
    그 재확인이 어떻게 틀렸었는지는 `_lost_the_race` 에 있다.

    ⚠️ 이 함수는 `session-start-pull.py` 와 **일부러 중복**돼 있다. 검사 하네스가 훅
    스크립트 **한 파일만** 격리 저장소에 심어 돌리므로 공용 모듈로 빼면 그 자리가 깨진다.
    같은 이유로 `_lost_the_race` 도 양쪽에 각각 있다 — **한쪽만 고치지 말 것.**
    """
    # 대상은 **현재 브랜치의 업스트림**이다. `origin/HEAD` 로 폴백하지 말 것 — 메인이
    # 어쩌다 다른 브랜치에 있으면 그 브랜치를 기본 브랜치 끝으로 조용히 밀어 버린다.
    # `git pull` 은 그런 적이 없다. 업스트림이 없으면 아무것도 안 하는 것이 맞다.
    rc, upstream = git(main_tree, "rev-parse", "--abbrev-ref", "@{u}")
    if rc or not upstream:
        return True, None                # 업스트림이 없다 — 당길 것이 없다
    rc, head = git(main_tree, "rev-parse", "HEAD")
    rc2, target = git(main_tree, "rev-parse", upstream)
    if rc or rc2:
        return False, "HEAD/업스트림을 못 읽었다"
    if head == target:
        return True, None                # 이미 최신
    rc, out = git(main_tree, "merge", "--ff-only", upstream)
    if rc == 0:
        return True, (out.splitlines() or ["ok"])[0][:80]
    return _lost_the_race(git, main_tree, upstream, out)


# 재확인 횟수와 간격. 합쳐서 0.4 초 — 세션 종료 경로라 사람을 기다리게 하지 않으면서,
# 이긴 쪽이 ref 를 갱신할 시간으로는 넉넉하다.
RECHECK_ATTEMPTS = 5
RECHECK_DELAY_S = 0.1


def _lost_the_race(git, main_tree, upstream, merge_output):
    """merge 가 실패했다. **다른 세션이 이미 올렸기 때문인가?**

    이 확인은 원래 즉시 한 번 읽는 것이었고, 그래서 **두 방향으로** 틀렸다. 둘 다
    2026-08-23 에 parallax 의 CI 가 이 스위트를 처음 실제로 돌리기 시작하면서 드러났다.

    🔴 **낙관 방향이 더 나쁘다.** 경합 중에는 `rev-parse` 자체가 죽을 수 있는데, 반환
    코드를 안 보면 두 호출이 **같은 에러 문자열**을 돌려준다. 그러면 `head2 == target2`
    가 참이 되어 「남이 올렸다」로 읽고 **모르는 채로 성공을 보고한다** — 트리가 실제로
    뒤처져 있어도 그렇다. 그래서 rc 를 본다. 못 읽었으면 같다고도 다르다고도 하지 않는다.

    ⚠️ 비관 방향은 시끄러울 뿐이다. 이긴 쪽이 merge 를 끝냈지만 **아직 ref 를 갱신하기
    전**에 진 쪽이 읽으면 「아직 아니다」가 되어 실패로 적는다. 트리는 곧 최신이 되는데
    로그만 「최신화 실패」로 남는다 — 위 docstring 이 없애려던 바로 그 기록이, 그 창에서
    다시 생긴다. parallax CI 에서 8 스레드 동시 실행이 **11회 중 1회** 이 창에 걸렸다.
    그래서 한 번이 아니라 짧게 재시도한다.

    두 창 모두 `test-session-end-cleanup.py` 가 git 대역으로 **결정적으로** 고정한다.
    타이밍으로는 재현되지 않는다 — 이 기계에서 32 스레드 20 라운드에도 0 회였다.
    """
    for attempt in range(RECHECK_ATTEMPTS):
        if attempt:
            time.sleep(RECHECK_DELAY_S)
        rc_head, head2 = git(main_tree, "rev-parse", "HEAD")
        rc_target, target2 = git(main_tree, "rev-parse", upstream)
        if rc_head or rc_target:
            continue                     # 못 읽었다 — 판단하지 않는다
        if head2 == target2:
            return True, None            # 경합에서 졌을 뿐 — 다른 세션이 이미 올렸다
        # ⚠️ **다시 읽는 것만으로는 부족한 경우가 하나 남는다.** 위 두 줄은 「남이 이미
        #    올렸는가」만 답한다. 우리 merge 가 `index.lock` 을 놓쳐 실패했는데 **아무도
        #    이기지 않았다면**, HEAD 는 영원히 업스트림과 다르고 이 루프는 몇 번을 읽어도
        #    실패로 끝난다 — 한 번 더 시도했으면 성공했을 자리에서. 락을 놓친 것뿐이면
        #    이번엔 우리가 잡는다.
        rc_retry, out_retry = git(main_tree, "merge", "--ff-only", upstream)
        if rc_retry == 0:
            return True, (out_retry.splitlines() or ["ok"])[0][:80]
    return False, (merge_output.splitlines() or ["merge 실패"])[0][:80]


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        data = {}
    sid = data.get("session_id") or ""
    cwd = data.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()

    rc, common = git(cwd, "rev-parse", "--path-format=absolute", "--git-common-dir")
    if rc:
        return
    main_tree = os.path.dirname(common)
    lines = []

    # 1) 이 세션이 소유한 워크트리 회수
    owners_path = os.path.join(common, OWNERS)
    owner_lock = open(os.path.join(common, OWNER_LOCK), "a+", encoding="utf-8")
    fcntl.flock(owner_lock, fcntl.LOCK_EX)
    try:
        with open(owners_path, encoding="utf-8") as f:
            owners = json.load(f)
    except Exception:
        owners = {}

    rc, base = git(main_tree, "rev-parse", "--abbrev-ref", "origin/HEAD")
    if rc:
        base = "origin/HEAD"
    git(main_tree, "fetch", "origin")

    # 워크트리가 아닌 기록은 **누구 것이든** 걷어낸다. 소유자만 지우게 두면 그 세션이 끝난 뒤
    # 아무도 못 지워 기록이 계속 자란다 — 2026-08-15 에 죽은 항목 5건이 그렇게 남아 있었고,
    # 전부 주인 세션이 이미 종료한 것이었다.
    # 🔴 **판정을 `os.path.isdir` 로 하면 안 된다** (2026-08-15 실측): `origin-error-detect` 는
    #    체크아웃이 사라졌는데 `.omc/state/` 캐시 파일 하나 때문에 **디렉토리는 남아 있었고**,
    #    git 등록은 없었다. 그래서 `worktree prune` 도 이 기록 정리도 그것을 못 봤다 —
    #    **「경로가 있는가」가 아니라 「git 이 워크트리로 아는가」를 물어야 한다.**
    # ⚠️ 이것은 **기록만** 지운다. 워크트리를 지우는 아래 경로는 여전히 내 것만 본다.
    registered = live_worktrees(main_tree)
    if registered is not None:
        dead = [p for p in owners if os.path.realpath(p) not in registered]
        for p in dead:
            owners.pop(p, None)
        if dead:
            lines.append(f"소유자 기록 정리: 워크트리가 아닌 항목 {len(dead)}건")
        # 🚨 고아 디렉토리는 **알리기만 한다.** 자동으로 지우지 않는다 — 이 스크립트의
        #    안전판은 「일을 지울 수 없다」이고, 등록 없는 디렉토리는 git 이 내용을
        #    보증해 주지 못해 그 안전판이 통하지 않는다. 사람이 보고 지우게 둔다.
        wt_dir = os.path.join(main_tree, ".claude", "worktrees")
        try:
            strays = sorted(n for n in os.listdir(wt_dir)
                            if os.path.isdir(os.path.join(wt_dir, n))
                            and os.path.realpath(os.path.join(wt_dir, n)) not in registered)
        except Exception:
            strays = []
        if strays:
            lines.append("🚨 등록 없는 디렉토리(손으로 확인): " + ", ".join(strays[:5]))

    mine = [p for p, v in owners.items() if v.get("session_id") == sid]
    for path in mine:
        name = os.path.basename(path)
        if not os.path.isdir(path):
            owners.pop(path, None)
            continue
        if os.path.realpath(path) == os.path.realpath(main_tree):
            # 메인 트리가 소유자 목록에 들어오는 일이 실제로 있었다(2026-08-14, 변이
            # 테스트 잔재). git 이 `is a main working tree` 로 막지만, 여기서 먼저
            # 걸러 «메인을 지우려 했다» 는 시도 자체를 없앤다.
            owners.pop(path, None)
            lines.append("건너뜀: 메인 트리가 소유자 목록에 있었다(기록 정리)")
            continue
        rc, branch = git(path, "rev-parse", "--abbrev-ref", "HEAD")
        branch = branch if rc == 0 else ""

        # 머지 여부를 **제거 전에** 본다. 뒤에 보면 미머지 브랜치의 체크아웃만
        # 사라져 「커밋은 있는데 작업 트리가 없는」 상태가 된다.
        if branch and branch != "HEAD":
            rc, ahead = git(main_tree, "rev-list", "--count", f"{base}..{branch}")
            if rc or not ahead.isdigit():
                lines.append(f"보존: {name} — 머지 여부를 판정 못 했다")
                continue
            if int(ahead) > 0:
                lines.append(f"보존: {name} — {base} 에 없는 커밋 {ahead}개")
                continue

        # --force 없음: 미커밋 변경이 있으면 git 이 거부한다 (그게 안전판이다)
        rc, out = git(main_tree, "worktree", "remove", path)
        if rc:
            lines.append(f"보존: {name} — {(out.splitlines() or [''])[0][:80]}")
            continue
        lines.append(f"워크트리 제거: {name}")
        owners.pop(path, None)
        if branch and branch != "HEAD":
            # -d 소문자: 머지 안 된 커밋이 있으면 git 이 거부한다
            rc, out = git(main_tree, "branch", "-d", branch)
            lines.append(f"브랜치 삭제: {branch}" if rc == 0
                         else f"브랜치 보존: {branch} — 미머지 커밋이 있다")
    try:
        tmp = owners_path + f".{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(owners, f, ensure_ascii=False)
        os.replace(tmp, owners_path)
    except Exception:
        pass
    fcntl.flock(owner_lock, fcntl.LOCK_UN)
    owner_lock.close()
    git(main_tree, "worktree", "prune")

    # 2) 메인 트리 최신화. fetch 는 작업 트리를 안 건드리므로 언제나 해도 된다.
    git(main_tree, "fetch", "origin")
    _, status = git(main_tree, "status", "--porcelain")
    blocked = pull_blocked_by(status)
    if blocked:
        lines.append(f"메인 pull 건너뜀 — {blocked}")
    else:
        ok, msg = fast_forward_main(git, main_tree)
        if msg is None:
            lines.append("메인 pull: 이미 최신")
        else:
            lines.append(("메인 pull: " if ok else "메인 pull 실패: ") + msg)

    if lines:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(os.path.join(common, LOG), "a", encoding="utf-8") as f:
                f.write(f"[{stamp}] {sid[:8]} " + " · ".join(lines) + "\n")
        except Exception:
            pass
        print(json.dumps({"systemMessage": "세션 정리 — " + " · ".join(lines)}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass                     # fail-open — 정리 실패가 종료를 막으면 안 된다
