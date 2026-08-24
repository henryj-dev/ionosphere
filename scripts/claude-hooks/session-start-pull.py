#!/usr/bin/env python3
"""세션 시작 시 메인 트리를 최신화하는 SessionStart 훅.

**왜 시작 쪽에도 거나.** 원래는 `SessionEnd` 에만 걸었는데, 2026-08-14 실측으로
**한 번도 안 돌았다**(`claude-session-end.log` 에 실제 세션 기록 0건). 그날 세션들이
훅보다 먼저 시작해서 그것을 로드한 적이 없었기 때문이고, 그 상태는 **다음 종료 때까지
확인되지 않는다.**

목적이 「다음 세션은 최신 메인에서 시작한다」라면 **시작할 때 당기는 것이 직접적**이다.
종료 훅은 「내가 만든 워크트리를 치운다」에 집중하고, 최신화는 양쪽에 둔다 — 한쪽이
안 돌아도 다른 쪽이 메운다.

⚠️ **훅을 고치면 그 수정은 메인이 pull 하기 전까지 안 먹는다.** 훅은
`$CLAUDE_PROJECT_DIR/scripts/claude-hooks/*.py` 를 읽는데, 메인에서 도는 세션에게 그것은
메인 트리의 파일이다. 이 스크립트가 있는 이유 중 하나가 그 창을 좁히는 것이다.

⚠️ **깨끗할 때만 당긴다.** `--ff-only` 는 「남의 작업을 안 건드린다」를 보장하지 않는다 —
들어오는 커밋이 상대가 손댄 것과 *다른* 파일만 바꾸면 그대로 fast-forward 되어 상대
발밑에서 파일이 바뀐다(2026-08-14 실측). 겹칠 때만 거부한다.

fail-open: 무슨 일이 있어도 세션 시작을 막지 않는다.
"""
import json
import fcntl
import os
import subprocess
import sys
import time

LOG = "claude-session-end.log"      # 종료 훅과 같은 기록에 남긴다


def git(cwd, *args, timeout=60):
    try:
        r = subprocess.run(("git", "-C", cwd) + args, capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as e:
        return 1, str(e)


def fast_forward_main(git, main_tree):
    """메인 트리를 업스트림까지 fast-forward. 반환 `(성공?, 메시지 or None)`.

    메시지가 `None` 이면 **이미 최신** — 부르는 쪽은 조용히 끝내면 된다.

    🔴 **`git pull` 을 쓰지 않는다 — 동시에 돌면 실제로 깨진다.**
    `pull` 은 자기 fetch 결과를 **공유 파일 `FETCH_HEAD`** 로 머지 단계에 넘기는데, 이 레포는
    여러 세션이 같은 메인 트리를 향해 동시에 이 훅을 돌린다. 쓰기가 섞이면 머지 대상이 둘
    이상으로 보여 **`fatal: Cannot fast-forward to multiple branches.`** 로 죽는다.
    2026-08-15 14:13:11 에 여섯 세션이 동시 종료하며 **전부** 이걸로 실패했고(그 시각 로그),
    격리 재현에서 **8/8 실패**했다. 원격 추적 ref 를 대상으로 `merge --ff-only` 를 쓰면
    FETCH_HEAD 를 안 거치므로 그 경합이 사라진다(같은 재현에서 6~7/8 성공, 최종 HEAD 일치).

    ⚠️ **경합에서 진 것을 실패로 적지 말 것.** 남은 실패는 `index.lock`·ref 경합인데, 그건
    **다른 프로세스가 먼저 성공했다**는 뜻이다. 그래서 실패하면 HEAD 를 다시 읽어
    업스트림과 같은지 본다 — 같으면 목적이 달성된 것이다. 이 확인이 없으면 로그가
    「최신화 실패」로 도배되는데 트리는 멀쩡한, 사람을 헛짚게 하는 기록이 남는다.

    ⚠️ 이 함수는 두 훅에 **일부러 중복**돼 있다. 검사 하네스가 훅 스크립트 **한 파일만**
    격리 저장소에 심어 돌리므로, 공용 모듈로 빼면 그 자리에서 import 가 깨진다.
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


# 재확인 횟수와 간격. 합쳐서 0.4 초.
RECHECK_ATTEMPTS = 5
RECHECK_DELAY_S = 0.1


def _lost_the_race(git, main_tree, upstream, merge_output):
    """merge 가 실패했다. **다른 세션이 이미 올렸기 때문인가?**

    ⚠️ `session-end-cleanup.py` 의 같은 이름 함수와 **일부러 같다.** 검사 하네스가 훅
    스크립트 한 파일만 격리 저장소에 심어 돌리므로 공용 모듈로 뺄 수 없다. 한쪽만
    고치면 다른 쪽이 조용히 옛 판정을 유지한다 — **두 파일을 함께 고칠 것.** 왜 이렇게
    생겼는지의 전체 기록은 그쪽 docstring 에 있다. 요약하면 즉시 한 번만 읽는 재확인이
    두 방향으로 틀렸다:

    🔴 `rev-parse` 가 경합으로 죽으면 두 호출이 같은 에러 문자열을 돌려줘 「같다」로
    읽히고, **모르는 채로 성공을 보고한다.** 그래서 rc 를 본다.

    ⚠️ 이긴 쪽이 아직 ref 를 갱신하기 전에 읽으면 실패로 적는다. 그래서 짧게 재시도한다.
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


OWNERS = "claude-worktree-owners.json"
OWNER_LOCK = "claude-worktree-owners.lock"
GRACE = 120          # 방금 기록한 세션을 죽었다고 오판하지 않기 위한 여유(초)


def alive(pid, start):
    """그 프로세스가 **그때 그 프로세스 그대로** 살아 있는가.

    🔴 pid 만 보면 안 된다 — 재사용되면 남의 프로세스를 「주인이 살아 있다」로 읽는다.
    시작 시각까지 같아야 같은 프로세스다.
    """
    try:
        r = subprocess.run(["ps", "-p", str(pid), "-o", "lstart="],
                           capture_output=True, text=True, timeout=5)
    except Exception:
        return True                     # 판정 불가 — **살아 있다고 본다**(안 건드린다)
    if r.returncode != 0:
        return False
    return r.stdout.strip() == (start or "").strip()


def reap_dead_owners(main_tree, common, my_sid):
    """주인 프로세스가 **죽은** 워크트리를 회수한다. 기록할 줄들을 돌려준다.

    **왜 시작 훅에 있나.** codex 는 `SessionEnd` 를 발화하지 않는다(2026-08-15 실측).
    즉 그 세션에게는 「끝났다」고 말할 기회가 없고, 자기 워크트리를 스스로 못 치운다.
    게다가 소유권은 **마지막에 건드린 세션**으로 넘어가므로, codex 가 남의 워크트리를
    만지면 그 워크트리의 회수 주체까지 사라진다. 그래서 **다음 세션이 시작할 때** 죽은
    주인을 알아보고 대신 치운다 — 종료 신호가 없는 하네스를 덮는 유일한 자리다.

    실측(2026-08-15): 훅의 부모는 양쪽 다 **에이전트 프로세스 자신**이다
    (Claude=`claude`, codex=`codex`) — codex 쪽은 exec 가 끝나는 즉시 죽는다.

    🔴 **안전판은 그대로 git 에 맡긴다** — `worktree remove` 를 `--force` 없이,
    `git branch -d`(소문자)로. 미커밋 변경이나 미머지 커밋이 있으면 git 이 거부한다.
    즉 이 함수도 **일을 지울 수 없다**. `-D`/`--force` 를 넣지 말 것.

    안 건드리는 것: 내 세션 소유 · 기록이 `GRACE` 보다 최근 · **pid 를 모르는 옛 기록**
    (모르는 것은 죽은 것이 아니다) · 판정 불가(ps 실패).
    """
    lines = []
    path_owners = os.path.join(common, OWNERS)
    rc, out = git(main_tree, "worktree", "list", "--porcelain")
    if rc:
        return lines                    # 목록을 못 읽으면 아무것도 안 한다
    registered = {os.path.realpath(l[9:].strip())
                  for l in out.splitlines() if l.startswith("worktree ")}

    # 생성기·가드·시작·종료 훅이 같은 JSON을 갱신한다. RMW 전체를 잠그지 않으면 동시
    # 세션 둘이 서로의 소유자 기록을 마지막 os.replace로 잃는다.
    owner_lock = open(os.path.join(common, OWNER_LOCK), "a+", encoding="utf-8")
    fcntl.flock(owner_lock, fcntl.LOCK_EX)
    try:
        with open(path_owners, encoding="utf-8") as f:
            owners = json.load(f)
    except Exception:
        owners = {}

    rc, base = git(main_tree, "rev-parse", "--abbrev-ref", "origin/HEAD")
    if rc:
        base = "origin/HEAD"
    now = time.time()
    changed = False

    for path, v in list(owners.items()):
        real = os.path.realpath(path)
        if real not in registered or real == os.path.realpath(main_tree):
            continue                    # 워크트리가 아니다 (기록 정리는 종료 훅 몫)
        if v.get("session_id") == my_sid:
            continue                    # 내 것 — 내가 쓸 것이다
        if now - float(v.get("ts") or 0) < GRACE:
            continue                    # 방금 기록됐다 — 시작 중일 수 있다
        pid, start = v.get("pid"), v.get("pid_start")
        if not pid or not start:
            continue                    # 모르는 것은 죽은 것이 아니다
        if alive(pid, start):
            continue

        name = os.path.basename(path)
        rc, branch = git(path, "rev-parse", "--abbrev-ref", "HEAD")
        branch = branch if rc == 0 else ""
        if branch and branch != "HEAD":
            rc, ahead = git(main_tree, "rev-list", "--count", f"{base}..{branch}")
            if rc or not ahead.isdigit() or int(ahead) > 0:
                continue                # 안 밀린 커밋이 있거나 판정 불가 → 보존
        rc, out2 = git(main_tree, "worktree", "remove", path)   # --force 없음
        if rc:
            continue                    # 미커밋 변경 등 — git 이 거부했다. 그대로 둔다
        lines.append(f"죽은 주인 회수: {name}({(v.get('pid_cmd') or '?')})")
        owners.pop(path, None)
        changed = True
        if branch and branch != "HEAD":
            git(main_tree, "branch", "-d", branch)              # -D 아님

    if changed:
        try:
            tmp = path_owners + f".{os.getpid()}"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(owners, f, ensure_ascii=False)
            os.replace(tmp, path_owners)
        except Exception:
            pass
    fcntl.flock(owner_lock, fcntl.LOCK_UN)
    owner_lock.close()
    return lines


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        data = {}
    sid = (data.get("session_id") or "")[:8]

    # 지킬 대상은 **이 스크립트가 속한 저장소**의 메인 트리다(가드와 같은 기준).
    here = os.path.dirname(os.path.abspath(__file__))
    rc, common = git(here, "rev-parse", "--path-format=absolute", "--git-common-dir")
    if rc or not common:
        return
    main_tree = os.path.dirname(common)

    git(main_tree, "fetch", "origin")
    _, status = git(main_tree, "status", "--porcelain")
    lines = []
    if status.strip():
        lines.append("시작 pull 건너뜀 — 메인 트리에 미커밋 변경이 있다")
    else:
        ok, msg = fast_forward_main(git, main_tree)
        if msg is not None:             # `None` 이면 이미 최신 — 조용히 넘어간다
            lines.append(f"시작 pull: {msg}" if ok else f"시작 pull 실패: {msg}")

    lines += reap_dead_owners(main_tree, common, data.get("session_id") or "")

    if not lines:
        return                          # 할 일이 없었다 — 로그를 채우지 않는다
    line = " · ".join(lines)
    try:
        with open(os.path.join(common, LOG), "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {sid} {line}\n")
    except Exception:
        pass
    print(json.dumps({"systemMessage": line}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass                            # fail-open — 시작을 막으면 안 된다
