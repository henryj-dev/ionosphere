#!/usr/bin/env python3
"""main-tree-guard 훅 판정 검사 — 메인은 읽기 전용, 워크트리는 자유.

「막는다」와 「통과시킨다」를 함께 고정한다. 통과 쪽을 안 재면 **전부 막는 훅**도
검사를 통과해 버린다 — 그러면 메인에서 `git log` 조차 못 하게 된 것을 아무도 모른다.

⚠️ 이 검사는 소유자 기록 파일을 건드린다. 원본을 백업했다가 끝에 되돌린다 —
   안 되돌렸다가 실제로 «메인 트리가 워크트리로 등록되는» 잔재를 남긴 적이 있다.
"""
import hashlib, json, os, subprocess, sys, tempfile

COMMON = subprocess.run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
                        capture_output=True, text=True, check=True).stdout.strip()
MAIN = os.path.dirname(COMMON)
# ⚠️ 검사 대상은 **이 파일 옆의 사본**이다. MAIN 경로를 쓰면 워크트리에서 고친 것을
#    못 보고 메인 트리의 옛 버전을 검사한다 — 이 레포에서 두 번 겪었다.
#    MAIN 은 git 워크트리 조작에만 쓴다.
HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "main-tree-guard.py")
OWNERS = f"{COMMON}/claude-worktree-owners.json"
# 🔴 **레포마다 다른 경로여야 한다.** `/tmp/_wtguard` 하나를 공용으로 쓰던 동안, 이 검사를
#    두 체크아웃에서 동시에 돌리면 뒤에 온 쪽이 그 경로를 못 만들어 **워크트리 케이스가 통째로
#    무너졌다** — 2026-08-17 실측: 동시 실행에서 실패 22건·1건, 순차에서는 양쪽 0건.
#    하필 무너지는 모양이 「DENY 케이스가 ALLOW 로 통과」라 **「가드가 안 막힌다」로 읽힌다.**
#    가드 검사에서 이보다 나쁜 거짓 신호는 없다. 경로를 MAIN 으로 갈라 닫는다.
WT = os.path.join(tempfile.gettempdir(),
                  "_wtguard-" + hashlib.sha1(MAIN.encode()).hexdigest()[:8])

_saved = open(OWNERS, "rb").read() if os.path.exists(OWNERS) else None

# 레포 안에 **다른 저장소**가 중첩된 상황을 재현하는 픽스처. 여기서 만들고 끝에 지운다.
# ⚠️ 있는 디렉토리(`target/idp` 같은 sub-checkout)를 골라 쓰면 **그 레포에 그것이 있을 때만**
#    검사가 성립한다 — 없는 레포에서는 통과 케이스 2건이 조용히 실패한다(이식하며 실측).
#    검사는 자기가 필요로 하는 모양을 **자기가 세워야** 어느 레포에서도 같은 것을 잰다.
NESTED = "_guard_probe_foreign"
FOREIGN = os.path.join(MAIN, NESTED)
SUBDIR = "_guard_probe_sub"          # 「메인의 하위 디렉토리로 cd」 케이스용 — 있는 것을
                                     # 고르면(`docs` 등) 그것이 없는 레포에서 판정이 달라진다
_made_sub = not os.path.isdir(os.path.join(MAIN, SUBDIR))
if _made_sub:
    os.makedirs(os.path.join(MAIN, SUBDIR), exist_ok=True)
_made_foreign = not os.path.isdir(FOREIGN)
if _made_foreign:
    os.makedirs(FOREIGN, exist_ok=True)
    subprocess.run(["git", "init", "-q", FOREIGN], capture_output=True)


def call(sid, cwd, tool, ti, script=GUARD):
    p = subprocess.run(["python3", script], input=json.dumps(
        {"session_id": sid, "cwd": cwd, "tool_name": tool, "tool_input": ti}),
        capture_output=True, text=True)
    out = p.stdout.strip()
    if not out:
        return "ALLOW", ""
    d = json.loads(out)["hookSpecificOutput"]
    return d["permissionDecision"].upper(), d["permissionDecisionReason"].split("\n")[0]


CASES = [
    # 메인 트리 — 수정은 전부 막는다. 「먼저 온 세션」 같은 예외가 없다.
    ("메인에서 Edit",                      "S1", MAIN,   "Edit", {"file_path": f"{MAIN}/PLAN.md"},        "DENY"),
    ("메인에서 Write",                     "S1", MAIN,   "Write", {"file_path": f"{MAIN}/docs/x.md"},      "DENY"),
    ("메인에서 git commit",                "S1", MAIN,   "Bash", {"command": "git commit -m x"},           "DENY"),
    ("메인에서 git add",                   "S1", MAIN,   "Bash", {"command": "git add ."},                 "DENY"),
    ("다른 세션도 똑같이 막힌다",            "S2", MAIN,   "Edit", {"file_path": f"{MAIN}/PLAN.md"},        "DENY"),
    ("밖에서 -C 로 메인을 노려도 막힌다",     "S2", "/tmp", "Bash", {"command": f"git -C {MAIN} commit -m x"}, "DENY"),
    # 🔴 **경로가 여럿이면 앞의 하나가 판정을 대표하지 않는다.** 예전에는 첫 번째로 존재하는
    #    경로로 대상 저장소를 정하고 끝냈다. 그래서 **다른 저장소의 경로를 앞에 세우면**
    #    「우리 메인이 아니다」로 빠지고, 뒤에 붙은 우리 트리의 파일이 그대로 실려 갔다.
    #    순서를 뒤집으면 막혔다 — 즉 판정이 순서에 달려 있었다.
    ("섞임 — 남의 저장소가 앞, 우리 메인이 뒤",  "S1", MAIN, "Write",
     {"files": [f"{FOREIGN}/x.md", f"{MAIN}/PLAN.md"], "content": "x"},                  "DENY"),
    ("섞임 — 순서를 뒤집어도 같다",             "S1", MAIN, "Write",
     {"files": [f"{MAIN}/PLAN.md", f"{FOREIGN}/x.md"], "content": "x"},                  "DENY"),
    # ⚠️ 그리고 넓힌 판정이 **남의 저장소만 건드리는 편집**까지 막으면 안 된다.
    ("남의 저장소만이면 그대로 통과",            "S1", MAIN, "Write",
     {"files": [f"{FOREIGN}/x.md", f"{FOREIGN}/y.md"], "content": "x"},                  "ALLOW"),
    # 메인 트리 — 읽기와 최신화는 통과해야 한다
    ("메인에서 Read",                      "S1", MAIN,   "Read", {"file_path": f"{MAIN}/PLAN.md"},        "ALLOW"),
    ("메인에서 git status",                "S1", MAIN,   "Bash", {"command": "git status --short"},        "ALLOW"),
    ("메인에서 git log",                   "S1", MAIN,   "Bash", {"command": "git log --oneline -3"},      "ALLOW"),
    ("메인에서 git diff",                  "S1", MAIN,   "Bash", {"command": "git diff --stat"},           "ALLOW"),
    ("메인에서 git pull",                  "S1", MAIN,   "Bash", {"command": "git pull --ff-only"},        "ALLOW"),
    ("메인에서 git fetch",                 "S1", MAIN,   "Bash", {"command": "git fetch origin"},          "ALLOW"),
    # 읽기 전용인데 하위명령 이름이 겹치는 것들 — 2026-08-14 에 worktree list 가 막혔다
    ("메인에서 git worktree list",         "S1", MAIN,   "Bash", {"command": "git worktree list"},         "ALLOW"),
    ("메인에서 git stash list",            "S1", MAIN,   "Bash", {"command": "git stash list"},            "ALLOW"),
    ("메인에서 git tag -l",                "S1", MAIN,   "Bash", {"command": "git tag -l v1*"},            "ALLOW"),
    ("임의 git worktree add 는 계속 막힌다",  "S1", MAIN,   "Bash", {"command": "git worktree add /tmp/x"},   "DENY"),
    ("그래도 git stash push 는 막힌다",      "S1", MAIN,   "Bash", {"command": "git stash push -u"},         "DENY"),
    # 워크트리 — 전부 통과
    ("워크트리에서 Edit",                   "S2", WT,     "Edit", {"file_path": f"{WT}/PLAN.md"},           "ALLOW"),
    ("워크트리에서 commit",                 "S2", WT,     "Bash", {"command": "git commit -m x"},           "ALLOW"),
    ("워크트리에서 push",                   "S2", WT,     "Bash", {"command": "git push origin HEAD:v1.1"}, "ALLOW"),
    ("git 밖에서는 관여 안 함",              "S2", "/tmp", "Edit", {"file_path": "/tmp/zz.md"},              "ALLOW"),
    # 레포 안에 중첩된 **남의 저장소**(sub-checkout 등)는 우리 규칙 밖이다. 2026-08-14 에 `cd target/idp && git merge` 가 막혔다 —
    # ① 훅이 받는 cwd 는 세션 cwd(메인)라 `cd` 를 안 읽으면 대상을 틀리게 잡고
    # ② 「git-dir == common-dir」로 판정하면 **어느 저장소든** 메인 트리가 참이 된다.
    ("중첩 저장소로 cd 후 git merge",        "S1", MAIN,   "Bash", {"command": f"cd {FOREIGN}\ngit merge --no-edit upstream/main"}, "ALLOW"),
    ("중첩 저장소로 cd 후 git commit",       "S1", MAIN,   "Bash", {"command": f"cd {FOREIGN} && git commit -m x"}, "ALLOW"),
    ("상대경로 cd 도 통과",       "S1", MAIN,   "Bash", {"command": f"cd {NESTED} && git merge upstream/main"}, "ALLOW"),
    ("git -C 중첩 저장소도 통과",          "S1", MAIN,   "Bash", {"command": f"git -C {FOREIGN} commit -m x"}, "ALLOW"),
    ("하위 디렉토리로 cd 후에도 막힌다",       "S1", MAIN,   "Bash", {"command": f"cd {SUBDIR} && git commit -m x"},      "DENY"),
    ("cd 로 메인에 돌아오면 막힌다",          "S1", "/tmp", "Bash", {"command": f"cd {MAIN} && git commit -m x"},        "DENY"),
    # 2026-08-15 오탐 3종. 셋 다 **실제로 작업을 막았다** — 정리 사이클이 여기서 멈췄다.
    # ① `cd` 를 하나만 보고 세션 cwd 기준으로 풀면, 체인 뒤쪽의 상대 `cd` 가 엉뚱한 곳으로
    #    간다. `cd /tmp/x && … && cd ..` 의 `cd ..` 가 `<세션cwd>/..` 로 풀려 그것이
    #    `.claude/worktrees` 였고, 그 디렉토리의 toplevel 은 **메인 트리**다.
    ("체인 cd 는 차례로 접힌다",             "S2", WT,     "Bash", {"command": "cd /tmp && mkdir -p _g/a && cd _g/a && git commit -m x && cd .."}, "ALLOW"),
    ("접은 결과가 메인이면 막는다",           "S1", "/tmp", "Bash", {"command": f"cd {MAIN}/{SUBDIR} && cd .. && git commit -m x"}, "DENY"),
    # ② `git -C "<따옴표>"` 는 어떤 경로도 isdir 이 안 되어 **항상 메인으로 떨어졌다**.
    ("git -C 따옴표 경로",                  "S1", MAIN,   "Bash", {"command": f'git -C "{FOREIGN}" commit -m x'}, "ALLOW"),
    # ③ 셸 변수가 안 풀린 워크트리 경로. 판정 불가를 「메인」으로 떨어뜨리면 안 된다 —
    #    `.claude/worktrees/` 아래인 것이 글자로 드러나면 우리 메인이 아닌 것이 확정이다.
    ("git -C 미전개 변수 워크트리 경로",       "S1", MAIN,   "Bash", {"command": 'git -C ".claude/worktrees/$w" checkout -- .'}, "ALLOW"),
    ("미전개 변수인데 워크트리가 아니면 막는다", "S1", MAIN,   "Bash", {"command": 'git -C "$d" commit -m x'},              "DENY"),
    # 워크트리 회수 — 종료 훅이 쓰는 그 명령이다. 막으면 남은 워크트리를 치울 길이 없다.
    ("메인에서 worktree remove",           "S1", MAIN,   "Bash", {"command": "git worktree remove .claude/worktrees/x"}, "ALLOW"),
    ("메인에서 worktree prune",            "S1", MAIN,   "Bash", {"command": "git worktree prune"},          "ALLOW"),
    ("도구 중립 생성기는 메인을 직접 안 고친다", "S1", MAIN, "Bash", {"command": "python3 scripts/claude-hooks/enter-worktree.py agent-x"}, "ALLOW"),
    # 🔴 통과 검사가 뒤따르는 변경까지 덮던 우회로 (2026-08-15 실측 — 셋 다 통과했다).
    #    판정은 **명령 조각마다** 해야 한다.
    ("stash list 뒤의 commit 은 막힌다",    "S1", MAIN,   "Bash", {"command": "git stash list && git commit -m x"}, "DENY"),
    ("tag -l 뒤의 add 는 막힌다",           "S1", MAIN,   "Bash", {"command": "git tag -l && git add PLAN.md"},     "DENY"),
    ("worktree list 뒤의 reset 은 막힌다",  "S1", MAIN,   "Bash", {"command": "git worktree list && git reset --hard"}, "DENY"),
    ("worktree remove 뒤의 commit 은 막힌다", "S1", MAIN, "Bash", {"command": "git worktree remove /tmp/x && git commit -m y"}, "DENY"),
    # 🔴 **도구 중립** — 다른 하네스(codex 등)는 툴 이름도 입력 모양도 다르다. 이름 목록으로
    #    막으면 이름이 바뀌는 순간 조용히 뚫린다. 그래서 **입력 모양**으로 판정한다.
    #    ⚠️ 아래 모양은 codex 문서/바이너리에서 읽은 것이고 **라이브로 확인하지 못했다**
    #       (프로젝트 훅은 신뢰 승인 전엔 안 돈다). 모양이 다르면 여기부터 고칠 것.
    ("배열 command 도 막는다",              "S1", MAIN,   "Bash", {"command": ["/bin/zsh", "-lc", "git commit -m x"]}, "DENY"),
    ("배열 command 의 읽기는 통과",          "S1", MAIN,   "Bash", {"command": ["/bin/zsh", "-lc", "git status"]},     "ALLOW"),
    ("배열 command 도 cd 를 접는다",         "S1", MAIN,   "Bash", {"command": ["/bin/zsh", "-lc", f"cd {FOREIGN} && git commit -m x"]}, "ALLOW"),
    # 🔴 **codex 실측(2026-08-15)**: `apply_patch` 는 패치를 `input` 이 아니라 **`command`**
    #    로 보낸다. 그것을 셸 명령으로 읽으면 정규식에 안 걸려 **편집이 통째로 통과한다** —
    #    실제로 메인 트리에 `_codex_probe.txt` 가 생겼다. 같은 키가 두 뜻을 갖는다.
    ("apply_patch(command 키) 메인 편집 → 막는다", "S1", MAIN, "apply_patch", {"command": f"*** Begin Patch\n*** Add File: {MAIN}/_probe.txt\n+x\n*** End Patch"}, "DENY"),
    ("apply_patch(command 키) 워크트리는 통과",   "S1", MAIN, "apply_patch", {"command": f"*** Begin Patch\n*** Update File: {WT}/PLAN.md\n+x\n*** End Patch"}, "ALLOW"),
    ("apply_patch 새 워크트리 하위 경로는 통과", "S1", MAIN, "apply_patch", {"command": f"*** Begin Patch\n*** Add File: {WT}/_new_route/deep/+page.svelte\n+x\n*** End Patch"}, "ALLOW"),
    ("apply_patch 새 메인 하위 경로는 막는다",   "S1", MAIN, "apply_patch", {"command": f"*** Begin Patch\n*** Add File: {MAIN}/_new_route/deep/+page.svelte\n+x\n*** End Patch"}, "DENY"),
    ("apply_patch(input 키)도 막는다",           "S1", MAIN, "apply_patch", {"input": f"*** Begin Patch\n*** Update File: {MAIN}/PLAN.md\n+x\n*** End Patch"}, "DENY"),
    ("모르는 이름 + 워크트리 경로는 통과",     "S1", MAIN,   "apply_patch", {"input": f"*** Begin Patch\n*** Update File: {WT}/PLAN.md\n+x\n*** End Patch"}, "ALLOW"),
    ("모르는 이름 + path/content 도 막는다",  "S1", MAIN,   "write_file", {"path": f"{MAIN}/docs/x.md", "content": "x"}, "DENY"),
    # 🔴 읽기는 경로가 있어도 통과해야 한다 — 경로만 보고 판정하면 `Read` 가 편집으로 잡힌다
    #    (2026-08-15 에 실제로 그렇게 깨졌다). 가르는 것은 **쓸 내용이 실려 있는가**다.
    ("모르는 이름 + 경로만 = 읽기 → 통과",    "S1", MAIN,   "read_file", {"path": f"{MAIN}/PLAN.md"},                  "ALLOW"),
    ("모르는 이름 + offset/limit 도 읽기",    "S1", MAIN,   "read_file", {"path": f"{MAIN}/PLAN.md", "offset": 1, "limit": 5}, "ALLOW"),
    # 🔴 하이픈으로 이어지는 **다른 하위명령**을 잡던 오탐 (2026-08-15): 정규식에서 `-` 는
    #    단어 경계라 `\bmerge\b` 가 `merge-base` 에 매치됐다. `merge-base` 는 읽기 전용인데
    #    막혀서 브랜치 비교조차 못 했다 — `worktree list` 와 같은 부류의 세 번째 사례다.
    ("메인에서 git merge-base",            "S1", MAIN,   "Bash", {"command": "git merge-base origin/v1.1 HEAD"}, "ALLOW"),
    ("그래도 git merge 는 막힌다",          "S1", MAIN,   "Bash", {"command": "git merge origin/v1.1"},          "DENY"),
    ("cherry-pick 은 계속 막힌다",          "S1", MAIN,   "Bash", {"command": "git cherry-pick abc1234"},        "DENY"),
]

fail = 0
try:
    subprocess.run(["git", "-C", MAIN, "worktree", "add", "-q", WT, "--detach", "HEAD"],
                   capture_output=True)
    for name, sid, cwd, tool, ti, want in CASES:
        got, why = call(sid, cwd, tool, ti)
        ok = got == want
        fail += not ok
        print(f"{'✓' if ok else '✗'} {name:28s} 기대 {want:5s} 실제 {got:5s} {why[:36]}")

    # 워크트리 소유자가 기록되는가 — 세션 종료 정리가 이 기록으로 「내 것만」 회수한다
    call("OWNER-CHECK", WT, "Edit", {"file_path": f"{WT}/PLAN.md"})
    owners = json.load(open(OWNERS, encoding="utf-8")) if os.path.exists(OWNERS) else {}
    rec = owners.get(os.path.realpath(WT), {}).get("session_id")
    fail += rec != "OWNER-CHECK"
    print(f"{'✓' if rec == 'OWNER-CHECK' else '✗'} 워크트리 소유자가 기록된다")
    fail += os.path.realpath(MAIN) in owners
    print(f"{'✓' if os.path.realpath(MAIN) not in owners else '✗'} 메인 트리는 소유자로 등록되지 않는다")
    sub = os.path.join(MAIN, "target", "idp")
    if os.path.isdir(sub):
        call("SUBREPO", sub, "Bash", {"command": "git commit -m x"})
        owners2 = json.load(open(OWNERS, encoding="utf-8")) if os.path.exists(OWNERS) else {}
        ok = os.path.realpath(sub) not in owners2
        fail += not ok
        print(f"{'✓' if ok else '✗'} target/ 아래 남의 저장소는 소유자로 등록되지 않는다")

    # 구제 통로 — 켜면 통과하고, 만료되면 다시 막혀야 한다
    RESCUE = f"{COMMON}/claude-main-tree-rescue"
    open(RESCUE, "w").close()
    got, _ = call("S1", MAIN, "Edit", {"file_path": f"{MAIN}/PLAN.md"})
    fail += got != "ALLOW"
    print(f"{'✓' if got == 'ALLOW' else '✗'} 구제 파일이 있으면 통과한다")
    os.utime(RESCUE, (0, 0))                      # 30분보다 훨씬 오래된 것으로
    got, _ = call("S1", MAIN, "Edit", {"file_path": f"{MAIN}/PLAN.md"})
    fail += got != "DENY"
    print(f"{'✓' if got == 'DENY' else '✗'} 만료된 구제 파일은 통과시키지 않는다")
    fail += os.path.exists(RESCUE)
    print(f"{'✓' if not os.path.exists(RESCUE) else '✗'} 만료된 구제 파일은 치워진다")

    # 거부 메세지가 **어느 브랜치를 가리키는가.** 위 케이스들은 ALLOW/DENY 만 재고,
    # `call()` 은 이유의 첫 줄만 돌려주므로 base·push 대상 줄은 아무도 안 봤다. 그래서
    # 이 저장소가 기본 브랜치에 있는 동안에는 틀린 값이 조용히 통과했다 — 2026-08-17
    # barycenter 에서 드러났다(메인이 `design/…`, 그 브랜치에만 177 커밋, origin 에 없음,
    # 그런데 메세지는 `origin/main` 에서 따서 `HEAD:main` 으로 밀라고 했다).
    #
    # 실제 저장소의 브랜치를 바꿀 수는 없으므로 `deny_text` 를 **격리 픽스처에 대고**
    # 직접 부른다. cwd·common 을 인자로 받는 함수라 그것이 가능하다.
    import importlib.util, tempfile, shutil
    spec = importlib.util.spec_from_file_location("_mtg", GUARD)
    mtg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mtg)                  # `__main__` 이 아니므로 훅은 안 돈다

    FIX = tempfile.mkdtemp(prefix="denytext-")
    try:
        def fixture(branch, upstream):
            """브랜치가 `branch` 인 저장소 하나. `upstream` 이면 원격까지 세운다."""
            r = tempfile.mkdtemp(prefix="repo-", dir=FIX)
            subprocess.run(["git", "init", "-q", r], check=True)
            for k, v in (("user.email", "t@t"), ("user.name", "t")):
                subprocess.run(["git", "-C", r, "config", k, v], capture_output=True)
            open(os.path.join(r, "A.md"), "w").write("v1\n")
            for a in (("add", "A.md"), ("commit", "-qm", "init"), ("checkout", "-q", "-b", branch)):
                subprocess.run(["git", "-C", r] + list(a), capture_output=True)
            if upstream:
                b = tempfile.mkdtemp(prefix="bare-", dir=FIX)
                subprocess.run(["git", "init", "-q", "--bare", b], check=True)
                subprocess.run(["git", "-C", r, "remote", "add", "origin", b], capture_output=True)
                subprocess.run(["git", "-C", r, "push", "-q", "-u", "origin", branch],
                               capture_output=True)
                # 🔴 `origin/HEAD` 를 **함께** 세운다. 없으면 예전 로직도 자기 `@{u}` 폴백으로
                # 같은 답을 내서 이 검사가 **공허해진다**(2026-08-17 실측: 옛/새 출력이 바이트
                # 동일). 갈라지는 모양은 「업스트림과 origin/HEAD 가 함께 있는」 것뿐이고,
                # 그것이 이 수정을 부른 barycenter 의 모양이다.
                subprocess.run(["git", "-C", r, "push", "-q", "origin", "HEAD:refs/heads/trunk"],
                               capture_output=True)
                subprocess.run(["git", "-C", r, "remote", "set-head", "origin", "trunk"],
                               capture_output=True)
            return r, os.path.join(r, ".git")

        def denies(branch, upstream):
            r, common = fixture(branch, upstream)
            return mtg.deny_text(r, common)

        t = denies("design/feature-x", upstream=False)
        ok = "HEAD:design/feature-x" in t and "rebase design/feature-x" in t
        fail += not ok
        print(f"{'✓' if ok else '✗'} 업스트림 없는 feature 브랜치 — 그 브랜치를 기준·대상으로 준다")

        t = denies("design/feature-y", upstream=True)
        ok = ("origin/design/feature-y" in t and "HEAD:design/feature-y" in t
              and "HEAD:trunk" not in t)      # origin/HEAD 가 있어도 끌려가지 않는다
        fail += not ok
        print(f"{'✓' if ok else '✗'} 업스트림·origin/HEAD 가 함께 있어도 그 브랜치를 준다")

        # 변이 — 기준을 예전처럼 `origin/HEAD` 에서만 읽으면 그 브랜치를 놓치는가.
        # 위 두 검사가 공허하지 않다는 증거다.
        srcd = open(GUARD, encoding="utf-8").read()
        mutd = srcd.replace('branch = git(cwd, "symbolic-ref", "--short", "HEAD") or ""',
                            'branch = ""')
        assert mutd != srcd, "변이가 안 심겼다 — 이 검사는 무의미하다"
        MD = GUARD.replace(".py", "_mutd.py")
        open(MD, "w", encoding="utf-8").write(mutd)
        spec2 = importlib.util.spec_from_file_location("_mtgd", MD)
        mtgd = importlib.util.module_from_spec(spec2)
        spec2.loader.exec_module(mtgd)
        r, common = fixture("design/feature-z", upstream=False)
        got = "HEAD:design/feature-z" in mtgd.deny_text(r, common)
        fail += got
        print(f"{'✓' if not got else '✗'} 변이본은 feature 브랜치를 놓친다(기준 검사가 공허하지 않음)")
        os.remove(MD)
    finally:
        shutil.rmtree(FIX, ignore_errors=True)

    # 변이 — 메인 판정을 무력화하면 차단이 사라져야 한다(검사가 공허하지 않다는 증거)
    src = open(GUARD, encoding="utf-8").read()
    mut = src.replace("return os.path.realpath(top) == os.path.realpath(guarded), common",
                      "return False, common")
    assert mut != src, "변이가 안 심겼다 — 이 검사는 무의미하다"
    MUT = GUARD.replace(".py", "_mut.py")
    open(MUT, "w", encoding="utf-8").write(mut)
    got, _ = call("S3", MAIN, "Edit", {"file_path": f"{MAIN}/PLAN.md"}, script=MUT)
    fail += got != "ALLOW"
    print(f"{'✓' if got == 'ALLOW' else '✗'} 변이본은 메인을 안 막는다(검사가 공허하지 않음)")
    os.remove(MUT)

    # 변이 2 — `cd` 접기를 「마지막 하나만, 세션 cwd 기준」으로 되돌리면 그 케이스가
    # 정말 뒤집히는가. 2026-08-15 오탐의 원본 동작이다.
    mut2 = src.replace("        cur = p if os.path.isabs(p) else os.path.join(cur, p)",
                       "        cur = p if os.path.isabs(p) else os.path.join(cwd, p)")
    assert mut2 != src, "변이가 안 심겼다 — 이 검사는 무의미하다"
    open(MUT, "w", encoding="utf-8").write(mut2)
    got, _ = call("S1", "/tmp", "Bash", {"command": f"cd {MAIN}/{SUBDIR} && cd .. && git commit -m x"},
                  script=MUT)
    fail += got != "ALLOW"
    print(f"{'✓' if got == 'ALLOW' else '✗'} 변이본(cd 안 접음)은 메인을 놓친다(접기 검사가 공허하지 않음)")
    os.remove(MUT)

    # 변이 3 — 조각 단위 판정을 명령 전체로 되돌리면 우회로가 되살아나는가.
    mut3 = src.replace("for seg in SEGMENT.split(cmd):", "for seg in [cmd]:")
    assert mut3 != src, "변이가 안 심겼다 — 이 검사는 무의미하다"
    open(MUT, "w", encoding="utf-8").write(mut3)
    got, _ = call("S1", MAIN, "Bash", {"command": "git stash list && git commit -m x"}, script=MUT)
    fail += got != "ALLOW"
    print(f"{'✓' if got == 'ALLOW' else '✗'} 변이본(명령 전체 판정)은 우회를 통과시킨다(조각 검사가 공허하지 않음)")
finally:
    for leftover in (GUARD.replace(".py", "_mut.py"), f"{COMMON}/claude-main-tree-rescue"):
        if os.path.exists(leftover):
            os.remove(leftover)
    subprocess.run(["git", "-C", MAIN, "worktree", "remove", WT, "--force"], capture_output=True)
    subprocess.run(["git", "-C", MAIN, "worktree", "prune"], capture_output=True)
    # 픽스처 정리 — **내가 만든 것만** 지운다. 이미 있던 디렉토리는 남의 것이다.
    import shutil
    if _made_foreign:
        shutil.rmtree(FOREIGN, ignore_errors=True)
    if _made_sub:
        shutil.rmtree(os.path.join(MAIN, SUBDIR), ignore_errors=True)
    if _saved is None:
        if os.path.exists(OWNERS):
            os.remove(OWNERS)
    else:
        open(OWNERS, "wb").write(_saved)      # 남의 기록을 훔친 채 끝내지 않는다
    print("(소유자 기록 복원됨)")

print("\n실패", fail, "건")
sys.exit(1 if fail else 0)
