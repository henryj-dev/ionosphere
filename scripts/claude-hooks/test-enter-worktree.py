#!/usr/bin/env python3
"""enter-worktree.py 회귀 검사 — 격리 저장소에서 실제 git worktree를 만든다."""
import json
import os
import shutil
import subprocess
import tempfile


SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "enter-worktree.py")
tmp = tempfile.mkdtemp(prefix="enter-worktree-test-")
repo = os.path.join(tmp, "repo")
fail = 0


def run(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=30)


def check(label, ok, detail=""):
    global fail
    fail += not ok
    print(f"{'✓' if ok else '✗'} {label}" + (f": {detail}" if detail and not ok else ""))


try:
    os.makedirs(os.path.join(repo, "scripts", "claude-hooks"))
    shutil.copy2(SOURCE, os.path.join(repo, "scripts", "claude-hooks", "enter-worktree.py"))
    run("git", "init", "-b", "main", repo)
    run("git", "-C", repo, "config", "user.email", "test@example.com")
    run("git", "-C", repo, "config", "user.name", "Test")
    with open(os.path.join(repo, "tracked"), "w", encoding="utf-8") as f:
        f.write("base\n")
    run("git", "-C", repo, "add", "tracked")
    run("git", "-C", repo, "commit", "-m", "base")

    script = os.path.join(repo, "scripts", "claude-hooks", "enter-worktree.py")

    # `.claude/worktrees` 자체가 밖을 가리키면 이름 검증만으로는 경로 경계를 지킬 수 없다.
    os.makedirs(os.path.join(repo, ".claude"), exist_ok=True)
    outside = os.path.join(tmp, "outside")
    os.makedirs(outside)
    os.symlink(outside, os.path.join(repo, ".claude", "worktrees"))
    escaped = run("python3", script, "escape-via-link", cwd=repo)
    check("심링크 루트는 거절", escaped.returncode != 0)
    check("심링크 대상 밖에 생성하지 않음", not os.path.exists(os.path.join(outside, "escape-via-link")))
    os.unlink(os.path.join(repo, ".claude", "worktrees"))

    made = run("python3", script, "agent-one", "--json", cwd=repo)
    data = json.loads(made.stdout) if made.returncode == 0 else {}
    expected = os.path.join(repo, ".claude", "worktrees", "agent-one")
    check("허용 루트 아래 실제 워크트리 생성", made.returncode == 0 and os.path.realpath(expected) == data.get("path"), made.stderr)
    check("격리 branch 생성", run("git", "-C", repo, "show-ref", "--verify", "refs/heads/worktree-agent-one").returncode == 0)
    check("생성된 경로는 같은 common-dir 공유", run("git", "-C", expected, "rev-parse", "--git-common-dir").returncode == 0)
    owners_path = os.path.join(repo, ".git", "claude-worktree-owners.json")
    owners = json.load(open(owners_path, encoding="utf-8"))
    check("생성 즉시 소유자 기록", os.path.realpath(expected) in owners)
    owner = owners.get(os.path.realpath(expected), {})
    check("소유 세션·pid 기록", bool(owner.get("session_id") and owner.get("pid")))

    p2 = subprocess.Popen(("python3", script, "agent-two"), cwd=repo,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p3 = subprocess.Popen(("python3", script, "agent-three"), cwd=repo,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _, e2 = p2.communicate(timeout=30)
    _, e3 = p3.communicate(timeout=30)
    check("동시 생성 둘 다 성공", p2.returncode == 0 and p3.returncode == 0, e2 + e3)
    owners = json.load(open(owners_path, encoding="utf-8"))
    concurrent_paths = {
        os.path.realpath(os.path.join(repo, ".claude", "worktrees", "agent-two")),
        os.path.realpath(os.path.join(repo, ".claude", "worktrees", "agent-three")),
    }
    check("동시 소유자 기록을 둘 다 보존", concurrent_paths <= set(owners))

    duplicate = run("python3", script, "agent-one", cwd=repo)
    check("중복 경로/branch는 거절", duplicate.returncode != 0)
    for bad in ("../escape", "/tmp/escape", "UPPER", "a b", "x" * 65):
        rejected = run("python3", script, bad, cwd=repo)
        check(f"위험한 이름 거절: {bad[:16]}", rejected.returncode != 0)
    check("허용 루트 밖에 파일을 만들지 않음", not os.path.exists(os.path.join(tmp, "escape")))
    unknown = run("python3", script, "agent-four", "--base", "main", cwd=repo)
    check("임의 base 옵션을 제공하지 않음", unknown.returncode != 0)

    # ── 불완전한 체크아웃을 잡는가 (2026-08-24) ─────────────────────────────────
    #
    # 🔴 codex 샌드박스 안에서 `git worktree add` 가 **exit 0 을 주고도 추적 파일 194개를
    #    안 썼다.** 대조군(샌드박스 밖)은 0, codex 로 한 번 더 돌리면 또 0 — **일회성**이라
    #    원인을 아는 것으로는 못 막는다. 빠진 채로 시작하면 `git status` 가 그것들을
    #    **삭제로** 보여주고, 그 상태의 커밋은 **없는 줄 알고 지운 것**이 된다.
    #
    # ⚠️ 여기서는 `worktree add` 를 못 망가뜨리므로 **판정 함수를 직접** 부른다.
    #    (배선은 위 케이스들이, 판정은 여기가 잰다.)
    import importlib.util
    spec = importlib.util.spec_from_file_location("ew", script)
    ew = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ew)

    victim = os.path.join(repo, ".claude", "worktrees", "agent-one")
    # 통과 쪽 먼저 — 멀쩡한 워크트리를 실패로 세면 그것이 다음 사고다.
    ok_raised = False
    try:
        ew.verify_checkout(repo, victim, "worktree-agent-one")
    except RuntimeError:
        ok_raised = True
    check("멀쩡한 체크아웃은 통과", not ok_raised)

    os.unlink(os.path.join(victim, "tracked"))
    raised = ""
    try:
        ew.verify_checkout(repo, victim, "worktree-agent-one")
    except RuntimeError as exc:
        raised = str(exc)
    check("빠진 추적 파일을 잡는다", "불완전" in raised, raised or "예외 없음")
    # 깨진 워크트리를 남기면 다음 실행이 「이미 존재합니다」로 막혀 사람이 손으로 치워야 한다.
    check("깨진 워크트리를 회수한다", not os.path.exists(victim))
    check("그 branch 도 지운다",
          run("git", "-C", repo, "show-ref", "--verify", "refs/heads/worktree-agent-one").returncode != 0)

    # 변이 — 판정을 `git_text`(실패 시 빈 문자열)로 되돌리면 **공허하게 통과**한다.
    # 그 형태가 왜 안 되는지를 검사가 직접 보여 준다.
    empty = [e[3:] for e in "".split("\0") if e[:2] == " D"]
    check("변이본(빈 출력)은 아무것도 못 잡는다 — 판정이 공허해진다", empty == [])
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n실패 {fail} 건")
raise SystemExit(1 if fail else 0)
