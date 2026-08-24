#!/usr/bin/env python3
"""도구 중립 에이전트 워크트리 생성기.

하네스 전용 ``EnterWorktree`` 도구가 없어도 모든 에이전트가 같은 안전 경로로 격리
워크트리를 만들 수 있게 한다. 임의 경로와 임의 branch/ref 조합은 받지 않고, 이 저장소의
메인 트리 아래 ``.claude/worktrees/<name>`` 에서만 새 branch를 만든다.
"""
import argparse
import fcntl
import json
import os
import re
import subprocess
import sys


NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
WORKTREE_ROOT = os.path.join(".claude", "worktrees")
BRANCH_PREFIX = "worktree-"
OWNERS = "claude-worktree-owners.json"
OWNER_LOCK = "claude-worktree-owners.lock"


def git(cwd, *args, check=True, timeout=15):
    result = subprocess.run(
        ("git", "-C", cwd) + args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "git 실패").strip())
    return result


def git_text(cwd, *args):
    result = git(cwd, *args, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def repo_paths():
    here = os.path.dirname(os.path.abspath(__file__))
    common = git_text(here, "rev-parse", "--path-format=absolute", "--git-common-dir")
    if not common:
        raise RuntimeError("이 스크립트가 git 저장소 안에 있지 않습니다")
    main = os.path.dirname(os.path.realpath(common))
    return main, os.path.realpath(common)


def default_base(main):
    """메인 트리의 현재 branch upstream, 없으면 현재 branch/HEAD를 기준으로 쓴다."""
    if not git_text(main, "rev-parse", "--verify", "--quiet", "HEAD"):
        raise RuntimeError("커밋이 없는 저장소에서는 워크트리를 만들 수 없습니다")
    branch = git_text(main, "symbolic-ref", "--quiet", "--short", "HEAD")
    if branch:
        upstream = git_text(main, "rev-parse", "--abbrev-ref", "@{u}")
        return upstream or branch
    remote_head = git_text(main, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")
    return remote_head or "HEAD"


def registered_paths(main):
    result = git(main, "worktree", "list", "--porcelain")
    return {
        os.path.realpath(line[len("worktree "):])
        for line in result.stdout.splitlines()
        if line.startswith("worktree ")
    }


def proc_value(pid, field):
    try:
        result = subprocess.run(
            ("ps", "-p", str(pid), "-o", f"{field}="),
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def owner_process():
    """곧 끝나는 생성기 셸 대신 그 위의 장기 생존 호출자를 고른다."""
    shell_pid = os.getppid()
    parent = proc_value(shell_pid, "ppid")
    try:
        pid = int(parent)
    except (TypeError, ValueError):
        pid = shell_pid
    return pid, proc_value(pid, "lstart"), os.path.basename(proc_value(pid, "comm"))[:40]


def session_id(pid):
    for key in (
        "CODEX_SESSION_ID", "CODEX_THREAD_ID", "CLAUDE_SESSION_ID",
        "GROK_SESSION_ID", "CURSOR_SESSION_ID", "GEMINI_SESSION_ID",
        "ANTIGRAVITY_SESSION_ID",
    ):
        if os.environ.get(key):
            return os.environ[key]
    return f"agent-process-{pid}"


def record_owner(common, path):
    owners_path = os.path.join(common, OWNERS)
    pid, started, command = owner_process()
    with open(os.path.join(common, OWNER_LOCK), "a+", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            with open(owners_path, encoding="utf-8") as f:
                owners = json.load(f)
        except Exception:
            owners = {}
        owners[os.path.realpath(path)] = {
            "session_id": session_id(pid), "ts": __import__("time").time(),
            "pid": pid, "pid_start": started, "pid_cmd": command,
        }
        tmp = owners_path + f".{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(owners, f, ensure_ascii=False)
        os.replace(tmp, owners_path)


def create(name):
    if not NAME_RE.fullmatch(name):
        raise ValueError("이름은 1~64자의 소문자·숫자·점·밑줄·하이픈만 사용할 수 있습니다")
    main, common = repo_paths()
    claude_dir = os.path.join(main, ".claude")
    root = os.path.join(main, WORKTREE_ROOT)
    if os.path.islink(claude_dir) or os.path.islink(root):
        raise RuntimeError(".claude 또는 .claude/worktrees 심링크는 허용하지 않습니다")
    real_main, real_root = os.path.realpath(main), os.path.realpath(root)
    if os.path.commonpath((real_main, real_root)) != real_main:
        raise RuntimeError("워크트리 루트가 저장소 밖을 가리킵니다")
    path = os.path.realpath(os.path.join(real_root, name))
    if os.path.commonpath((real_root, path)) != real_root:
        raise ValueError("워크트리 경로가 허용된 루트를 벗어났습니다")
    branch = BRANCH_PREFIX + name
    start = default_base(main)
    start_sha = git_text(main, "rev-parse", "--verify", f"{start}^{{commit}}")
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", start_sha):
        raise RuntimeError(f"기준 ref를 commit으로 확정할 수 없습니다: {start}")

    if path in registered_paths(main) or os.path.lexists(path):
        raise RuntimeError(f"워크트리 경로가 이미 존재합니다: {path}")
    if git_text(main, "show-ref", "--verify", f"refs/heads/{branch}"):
        raise RuntimeError(f"branch가 이미 존재합니다: {branch}")

    os.makedirs(root, exist_ok=True)
    if os.path.islink(claude_dir) or os.path.islink(root):
        raise RuntimeError("생성 중 워크트리 루트가 심링크로 바뀌었습니다")
    git(main, "worktree", "add", "-b", branch, path, start_sha, timeout=None)
    record_owner(common, path)
    return {"path": path, "branch": branch, "base": start, "base_sha": start_sha}


def main_cli():
    parser = argparse.ArgumentParser(description="격리된 에이전트 워크트리를 생성합니다")
    parser.add_argument("name", help="워크트리 이름")
    parser.add_argument("--json", action="store_true", help="결과를 JSON으로 출력")
    args = parser.parse_args()
    try:
        result = create(args.name)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"enter-worktree: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, ensure_ascii=False))
    else:
        print(f"워크트리 생성 완료: {result['path']}")
        print(f"branch: {result['branch']} (base: {result['base']})")
        print(f"이후 명령은 이 경로에서 실행하십시오: cd {result['path']}")
        bootstrap = os.path.join(repo_paths()[0], ".claude", "worktree-bootstrap.md")
        if os.path.isfile(bootstrap):
            print(f"준비 절차: {bootstrap}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_cli())
