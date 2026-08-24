#!/usr/bin/env python3
"""session-end-cleanup 검사 — **일을 지우지 않는다**는 성질을 고정한다.

파괴적 자동화라서 「돌아간다」보다 「안 지운다」가 중요하다. 그래서 지우는 경로 1건과
**보존하는 경로 3건**을 함께 검사하고, 마지막에 안전판을 무력화한 변이본이 실제로
일을 지우는지 확인한다(검사가 공허하지 않다는 증거).

⚠️ 이 검사는 실제 레포에 임시 워크트리를 만들었다 지운다. 소유자 기록·락 파일은
   원본을 백업·복원한다.
"""
import json, os, shutil, subprocess, sys, tempfile

COMMON = subprocess.run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
                        capture_output=True, text=True, check=True).stdout.strip()
MAIN = os.path.dirname(COMMON)
# ⚠️ 검사 대상은 **이 파일 옆의 사본**이다. MAIN 경로를 쓰면 워크트리에서 고친 것을
#    못 보고 메인 트리의 옛 버전을 검사한다(실제로 한 번 그랬다). MAIN 은 git
#    워크트리 조작에만 쓴다.
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "session-end-cleanup.py")
OWNERS = f"{COMMON}/claude-worktree-owners.json"
SID = "TESTSESSION0001"
TMP = tempfile.mkdtemp(prefix="wtclean-")

ENDLOG = f"{COMMON}/claude-session-end.log"   # 검사가 운영 로그를 더럽히지 않게 복원한다
saved = {p: (open(p, "rb").read() if os.path.exists(p) else None)
         for p in (OWNERS, ENDLOG)}
made = []


def git(cwd, *a):
    r = subprocess.run(("git", "-C", cwd) + a, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def mkwt(name, *, dirty=False, unmerged=False):
    path = os.path.join(TMP, name)
    rc, out = git(MAIN, "worktree", "add", "-q", path, "-b", f"t-{name}", "origin/HEAD")
    assert rc == 0, out
    made.append((path, f"t-{name}"))
    if unmerged:
        open(os.path.join(path, "_probe.txt"), "w").write("x")
        git(path, "add", "_probe.txt")
        git(path, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "probe")
    if dirty:
        open(os.path.join(path, "_dirty.txt"), "w").write("x")
        git(path, "add", "_dirty.txt")
    return path


def run(sid=SID):
    p = subprocess.run(["python3", SCRIPT], input=json.dumps({"session_id": sid, "cwd": MAIN}),
                       capture_output=True, text=True)
    return p.stdout.strip()


def isolated_behind():
    """뒤처진 작업 트리 하나를 격리 저장소로 세워 돌려준다 — `(work, origin_sha)`.

    ⚠️ 실제 메인 트리로는 이 검사를 못 한다. 최신화를 진짜로 돌려 보는 검사라
    메인을 움직이게 되고, 그건 검사가 검사 대상을 오염시키는 형태다.
    """
    root = tempfile.mkdtemp(prefix="ff-", dir=TMP)
    origin, work = (os.path.join(root, n) for n in ("origin.git", "work"))
    subprocess.run(["git", "init", "-q", "--bare", origin], check=True)
    seed = os.path.join(root, "seed")
    # capture_output: 빈 저장소 clone 경고를 검사 출력에 섞지 않는다
    subprocess.run(["git", "clone", "-q", origin, seed], check=True, capture_output=True)
    for k, v in (("user.email", "t@t"), ("user.name", "t")):
        git(seed, "config", k, v)
    open(os.path.join(seed, "A.md"), "w").write("v1\n")
    git(seed, "add", "."); git(seed, "commit", "-qm", "init")
    git(seed, "branch", "-M", "main"); git(seed, "push", "-q", "-u", "origin", "main")
    # 브랜치가 여럿이어야 실제 조건이 된다 — FETCH_HEAD 에 여러 줄이 실린다
    for b in ("feat-a", "feat-b", "feat-c"):
        git(seed, "branch", b)
    git(seed, "push", "-q", "origin", "--all")
    subprocess.run(["git", "clone", "-q", "-b", "main", origin, work], check=True)
    open(os.path.join(seed, "A.md"), "w").write("v2\n")
    git(seed, "commit", "-qam", "next"); git(seed, "push", "-q", "origin", "main")
    return work


def concurrent_ff(mod, work, n=8):
    """`fast_forward_main` 을 n개 스레드로 **동시에** 부른다. 결과 리스트를 돌려준다."""
    import threading
    results = [None] * n
    def one(i):
        git(work, "fetch", "origin")
        results[i] = mod.fast_forward_main(git, work)
    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return results


fail = 0


def check(label, ok):
    global fail
    fail += not ok
    print(f"{'✓' if ok else '✗'} {label}")


try:
    clean = mkwt("clean")                       # 머지됨·깨끗 → 지워져야 한다
    dirty = mkwt("dirty", dirty=True)           # 미커밋 변경 → 보존돼야 한다
    ahead = mkwt("ahead", unmerged=True)        # 미머지 커밋 → 보존돼야 한다
    other = mkwt("other")                       # 남의 세션 소유 → 손대면 안 된다

    # 이미 없어진 경로 — 주인은 **남의(끝난) 세션**이다. 소유자만 지우게 두면 영영 안 지워진다.
    gone = os.path.join(TMP, "gone-already")
    # 🔴 «디렉토리는 있는데 git 은 워크트리로 모르는» 고아. `os.path.isdir` 로 판정하면
    #    이것이 영원히 남는다 — 2026-08-15 에 실제로 `.omc/state/` 캐시 하나 때문에 그랬다.
    orphan = os.path.join(MAIN, ".claude", "worktrees", "_test_orphan")
    os.makedirs(os.path.join(orphan, ".omc", "state"), exist_ok=True)
    open(os.path.join(orphan, ".omc", "state", "x.json"), "w").write("{}")
    json.dump({clean: {"session_id": SID}, dirty: {"session_id": SID},
               ahead: {"session_id": SID}, other: {"session_id": "SOMEONE-ELSE"},
               gone: {"session_id": "ENDED-SESSION"},
               orphan: {"session_id": "ENDED-SESSION"}},
              open(OWNERS, "w"))

    out = run()
    owners_after = json.load(open(OWNERS, encoding="utf-8"))
    check("없어진 경로의 기록은 남의 것이어도 걷어낸다", gone not in owners_after)
    check("디렉토리만 남은 고아의 기록도 걷어낸다", orphan not in owners_after)
    check("등록 없는 디렉토리를 사람에게 알린다", "_test_orphan" in out)
    check("고아 디렉토리를 자동으로 지우지는 않는다", os.path.isdir(orphan))
    check("살아 있는 남의 워크트리 기록은 남는다", other in owners_after)
    shutil.rmtree(orphan, ignore_errors=True)
    check("깨끗+머지된 워크트리는 제거된다", not os.path.isdir(clean))
    check("미커밋 변경이 있으면 보존된다", os.path.isdir(dirty))
    check("미머지 커밋이 있으면 보존된다", os.path.isdir(ahead))
    check("남의 세션 워크트리는 손대지 않는다", os.path.isdir(other))
    rc, branches = git(MAIN, "branch", "--list", "t-clean", "t-ahead", "t-other")
    check("머지된 브랜치만 삭제된다", "t-clean" not in branches
          and "t-ahead" in branches and "t-other" in branches)
    check("요약이 사용자에게 보고된다", "systemMessage" in out)

    # pull 판정은 순수 함수라 직접 검사한다 — 진짜 pull 을 돌리면 검사 자체가
    # 메인 트리를 건드리게 된다(검사가 검사 대상을 오염시키는 형태).
    sys.path.insert(0, os.path.dirname(SCRIPT))
    import importlib.util
    spec = importlib.util.spec_from_file_location("sec", SCRIPT)
    sec = importlib.util.module_from_spec(spec); spec.loader.exec_module(sec)
    check("메인이 깨끗하면 pull 한다", sec.pull_blocked_by("") is None)
    check("미커밋 변경이 있으면 pull 안 한다", bool(sec.pull_blocked_by(" M x.md\n")))
    check("스테이징만 있어도 pull 안 한다", bool(sec.pull_blocked_by("A  x.md\n")))
    check("untracked 만 있어도 pull 안 한다", bool(sec.pull_blocked_by("?? x.md\n")))

    # 변이: 안전판(--force 없음 / -d)을 무력화하면 정말 일을 지우는가
    src = open(SCRIPT, encoding="utf-8").read()
    mut = src.replace('git(main_tree, "worktree", "remove", path)',
                      'git(main_tree, "worktree", "remove", "--force", path)')
    mut = mut.replace('if int(ahead) > 0:', 'if False:')
    assert mut != src, "변이가 안 심겼다 — 이 검사는 무의미하다"
    open(SCRIPT + ".mut", "w", encoding="utf-8").write(mut)
    json.dump({dirty: {"session_id": SID}}, open(OWNERS, "w"))
    subprocess.run(["python3", SCRIPT + ".mut"], input=json.dumps({"session_id": SID, "cwd": MAIN}),
                   capture_output=True, text=True)
    check("변이본은 미커밋 변경을 날린다(검사가 공허하지 않음)", not os.path.isdir(dirty))
    os.remove(SCRIPT + ".mut")

    # pull 게이트 변이 — 상태 검사를 빼면 정말 통과시키는가
    MUT2 = SCRIPT.replace('.py', '_mut2.py')   # import 하려면 확장자가 .py 여야 한다
    mut2 = src.replace("if status.strip() else None", "if False else None")
    assert mut2 != src, "변이가 안 심겼다"
    open(MUT2, "w", encoding="utf-8").write(mut2)
    spec2 = importlib.util.spec_from_file_location("sec2", MUT2)
    sec2 = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(sec2)
    check("변이본은 더러운 트리에도 pull 한다(게이트가 공허하지 않음)",
          sec2.pull_blocked_by(" M x.md\n") is None)
    os.remove(MUT2)

    # 동시 최신화 — 세션 종료는 여러 개가 같은 순간에 몰린다. 2026-08-15 14:13:11 에
    # 여섯 세션이 동시에 `Cannot fast-forward to multiple branches` 로 전부 실패했다.
    work = isolated_behind()
    res = concurrent_ff(sec, work)
    check("동시 8개에서도 실제로 최신화된다",
          open(os.path.join(work, "A.md")).read().strip() == "v2")
    check("동시 실행을 실패로 보고하지 않는다", all(ok for ok, _ in res))

    # 「경합에서 졌나」 재확인의 두 창 — 타이밍이 아니라 **git 대역**으로 고정한다.
    #
    # ⚠️ 위의 동시 8개는 이 두 창을 못 잡는다. 이 기계에서는 32 스레드 20 라운드에도
    #    한 번도 안 걸렸고, parallax 의 CI 에서는 11회 중 1회 걸렸다 — 즉 **재현이
    #    기계에 달린** 검사라 그것만으로는 회귀를 막지 못한다. 진 쪽이 실제로 보는
    #    상태를 그대로 먹이면 타이밍 없이 결정적으로 잰다.
    def ff_with(second_read, merge_rc=1):
        """merge 는 실패하고, 그 뒤 재확인이 `second_read` 를 보는 상황."""
        BEHIND, AHEAD = "aaaaaaa", "bbbbbbb"
        state = {"reads": 0}

        def fake(cwd, *args):
            if args[:2] == ("rev-parse", "--abbrev-ref"):
                return 0, "origin/main"
            if args[0] == "rev-parse":
                state["reads"] += 1
                if state["reads"] <= 2:          # merge 이전의 두 번
                    return 0, (BEHIND if args[1] == "HEAD" else AHEAD)
                return second_read(args[1], state["reads"])
            if args[0] == "merge":
                return merge_rc, "fatal: Unable to create '.../index.lock': File exists."
            return 0, ""
        return sec.fast_forward_main(fake, "/x")

    # 창 1 — 이긴 쪽이 아직 ref 를 안 올렸다. 잠시 뒤 올라온다.
    #         한 번만 읽으면 실패로 적는다. 재시도가 있으면 사실대로 「졌을 뿐」이 된다.
    def late(ref, reads):
        if reads <= 4:                            # 첫 재확인에는 아직 안 보인다
            return 0, ("aaaaaaa" if ref == "HEAD" else "bbbbbbb")
        return 0, "bbbbbbb"                       # 그다음부터는 이긴 쪽의 결과가 보인다
    ok_late, _ = ff_with(late)
    check("이긴 쪽의 ref 갱신이 늦어도 실패로 적지 않는다", ok_late)

    # 창 2 — 🔴 재확인의 `rev-parse` 자체가 죽는다. 반환 코드를 안 보면 두 호출이 **같은
    #         에러 문자열**을 돌려줘 「같다」로 읽히고, 트리가 뒤처진 채 성공이 보고된다.
    ok_broken, _ = ff_with(lambda ref, reads: (128, "fatal: unable to read ref"))
    check("재확인을 못 하면 성공이라고 하지 않는다", not ok_broken)

    # 그리고 진짜로 뒤처진 채로 계속 다르면 실패여야 한다 — 재시도가 판정을 무르게
    # 만들지 않았는지.
    ok_stuck, _ = ff_with(lambda ref, reads: (0, "aaaaaaa" if ref == "HEAD" else "bbbbbbb"))
    check("끝까지 다르면 실패로 적는다", not ok_stuck)

    # ⚠️ **위 셋은 「남이 이미 올렸는가」만 묻는다.** 락을 놓쳐 실패했는데 아무도 이기지
    #    않았다면 HEAD 는 끝까지 업스트림과 다르고, 다시 읽는 것만으로는 영원히 실패다 —
    #    한 번 더 시도했으면 성공했을 자리에서. merge 가 처음엔 실패하고 그 다음엔
    #    성공하는 대역으로 그 자리를 고정한다.
    def ff_retry():
        state = {"merges": 0}

        def fake(cwd, *args):
            if args[:2] == ("rev-parse", "--abbrev-ref"):
                return 0, "origin/main"
            if args[0] == "rev-parse":
                return 0, ("aaaaaaa" if args[1] == "HEAD" else "bbbbbbb")
            if args[0] == "merge":
                state["merges"] += 1
                if state["merges"] == 1:
                    return 1, "fatal: Unable to create '.../index.lock': File exists."
                return 0, "Updating aaaaaaa..bbbbbbb"
            return 0, ""
        return sec.fast_forward_main(fake, "/x"), state

    (ok_retry, _m), st_retry = ff_retry()
    check("락을 놓쳤을 뿐이면 다시 시도해서 실제로 당긴다", ok_retry and st_retry["merges"] >= 2)

    # 변이 검사 — 위 셋이 공허하지 않은가. rc 확인을 지우면 창 2 가 통과해 버려야 한다.
    src_ff = open(SCRIPT, encoding="utf-8").read()
    mut_ff = src_ff.replace("        if rc_head or rc_target:\n            continue",
                            "        if False:\n            continue")
    assert mut_ff != src_ff, "변이가 안 심겼다 — 이 검사는 무의미하다"
    MUT3 = SCRIPT.replace(".py", "_mut3.py")
    open(MUT3, "w", encoding="utf-8").write(mut_ff)
    spec3 = importlib.util.spec_from_file_location("sec3", MUT3)
    sec3 = importlib.util.module_from_spec(spec3); spec3.loader.exec_module(sec3)
    # ⚠️ `saved` 라는 이름을 쓰지 말 것 — 이 파일 끝에서 소유자 기록 복원에 쓰는 dict 가
    #    그 이름이다. 처음에 겹쳐 써서 `saved.items()` 가 모듈을 만나 죽었다.
    sec_real, sec = sec, sec3
    ok_mut, _ = ff_with(lambda ref, reads: (128, "fatal: unable to read ref"))
    sec = sec_real
    os.remove(MUT3)
    check("변이본(rc 무시)은 모르는 채로 성공을 보고한다(검사가 공허하지 않음)", ok_mut)

    # 업스트림이 없으면 아무것도 안 한다 — `origin/HEAD` 로 폴백하면 메인이 어쩌다 다른
    # 브랜치에 있을 때 그 브랜치를 기본 브랜치 끝으로 조용히 민다(`git pull` 은 안 그런다).
    solo = isolated_behind()
    git(solo, "checkout", "-q", "-b", "sidetrack")      # 업스트림 없는 브랜치
    _, before = git(solo, "rev-parse", "HEAD")
    git(solo, "fetch", "origin")
    ok, note = sec.fast_forward_main(git, solo)
    _, after = git(solo, "rev-parse", "HEAD")
    check("업스트림이 없으면 브랜치를 안 움직인다", before == after)
    check("업스트림이 없으면 조용하다", ok and note is None)

    # `git pull` 을 다시 쓰면 안 된다 — 공유 `FETCH_HEAD` 경합으로 동시 종료가 전부 깨진다.
    # ⚠️ **여기서는 그것을 「변이본이 깨지는가」로 재지 않는다** — 처음에 그렇게 넣었다가
    #    깜빡였다. 이 파일의 동시 실행은 한 프로세스의 스레드라 한쪽이 먼저 성공하면
    #    복구 로직(`HEAD == 업스트림`이면 성공)이 나머지의 실패를 **정당하게** 가린다.
    #    깜빡이는 검사는 없느니만 못하다. 행동으로 재는 쪽은 `test-session-start-pull.py`
    #    가 **별도 프로세스 8개**로 결정적으로 하고, 여기서는 성질을 소스로 고정한다.
    check("스크립트가 git pull 을 쓰지 않는다", '"pull", "--ff-only"' not in src)

    # 변이 — 기록 정리를 «경로가 있는가»(`isdir`)로 되돌리면 고아가 정말 살아남는가.
    # 이것이 2026-08-15 이전의 동작이고, 그래서 `origin-error-detect` 가 안 지워졌다.
    MUT3 = SCRIPT.replace('.py', '_mut3.py')
    mut3 = src.replace("dead = [p for p in owners if os.path.realpath(p) not in registered]",
                       "dead = [p for p in owners if not os.path.isdir(p)]")
    assert mut3 != src, "변이가 안 심겼다 — 이 검사는 무의미하다"
    open(MUT3, "w", encoding="utf-8").write(mut3)
    os.makedirs(os.path.join(orphan, ".omc"), exist_ok=True)
    json.dump({orphan: {"session_id": "ENDED-SESSION"}}, open(OWNERS, "w"))
    subprocess.run(["python3", MUT3], input=json.dumps({"session_id": SID, "cwd": MAIN}),
                   capture_output=True, text=True)
    survived = orphan in json.load(open(OWNERS, encoding="utf-8"))
    check("변이본(isdir 판정)은 고아 기록을 남긴다(검사가 공허하지 않음)", survived)
    os.remove(MUT3)
    shutil.rmtree(orphan, ignore_errors=True)
finally:
    # 변이본은 실패해도 남으면 안 된다 — 실제로 한 번 남겨서 레포를 더럽혔다
    for leftover in (SCRIPT + ".mut", SCRIPT.replace(".py", "_mut2.py"),
                     SCRIPT.replace(".py", "_mut3.py"), SCRIPT + ".mut2"):
        if os.path.exists(leftover):
            os.remove(leftover)
    for path, br in made:
        subprocess.run(["git", "-C", MAIN, "worktree", "remove", "--force", path],
                       capture_output=True)
        subprocess.run(["git", "-C", MAIN, "branch", "-D", br], capture_output=True)
    subprocess.run(["git", "-C", MAIN, "worktree", "prune"], capture_output=True)
    shutil.rmtree(TMP, ignore_errors=True)
    for p, blob in saved.items():           # 남의 기록·락을 훔친 채 끝내지 않는다
        if blob is None:
            if os.path.exists(p):
                os.remove(p)
        else:
            open(p, "wb").write(blob)
    print("(소유자 기록·로그 복원됨)")

print("\n실패", fail, "건")
sys.exit(1 if fail else 0)
