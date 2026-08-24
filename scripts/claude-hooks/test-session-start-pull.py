#!/usr/bin/env python3
"""session-start-pull 검사 — **실제로 당기는지**와 **더러우면 안 당기는지**를 함께 잰다.

훅을 그냥 돌려 보면 빈 출력이 나오는데, 그것이 「이미 최신」인지 「아무것도 안 했다」인지
구분되지 않는다. 그래서 격리된 저장소를 세워 **원격을 한 커밋 앞세운 뒤** 당겼는지를
파일 내용으로 확인한다.

⚠️ 실제 레포를 건드리지 않는다 — 임시 디렉토리에 origin/main 을 새로 만든다.
"""
import json, os, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "session-start-pull.py")
TMP = tempfile.mkdtemp(prefix="startpull-")
fail = 0


def git(cwd, *a):
    r = subprocess.run(("git", "-C", cwd) + a, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def check(label, ok):
    global fail
    fail += not ok
    print(f"{'✓' if ok else '✗'} {label}")


def build(script_src):
    """격리 저장소를 세우고 훅 스크립트를 그 안에 심는다(protected_main 이 거기를 가리키게)."""
    root = tempfile.mkdtemp(prefix="repo-", dir=TMP)
    origin, work, up = (os.path.join(root, n) for n in ("origin.git", "work", "up"))
    subprocess.run(["git", "init", "-q", "--bare", origin], check=True)
    # 🔴 bare 쪽 HEAD 도 **픽스처가 정한다.** 이 줄이 없으면 기본 브랜치 이름을 git **빌드**가
    #    정하고, 그 값은 머신마다 다르다 — 실측: Apple Git 2.50 은 `init.defaultBranch` 가
    #    없어도 `main`, GitHub 러너의 git 은 `master`. 후자에서는 이 bare 의 HEAD 가 존재하지
    #    않는 `refs/heads/master` 로 남는다.
    #    그때 `git clone` 은 **경고 한 줄만 내고 성공한다**
    #    (`remote HEAD refers to nonexistent ref, unable to checkout`) — 아무것도 체크아웃하지
    #    않은 채로. `check=True` 로도 안 잡힌다. 실패는 한참 뒤 `work/A.md` 가 없다는
    #    FileNotFoundError 로 나타나 **「당기지 못했다」로 읽힌다** — 훅은 멀쩡한데 픽스처가
    #    깨진 모양이고, 이 검사에서 가장 헷갈리는 거짓 신호다.
    #    heliopause 가 이 스위트를 CI 에 넣은 첫날 이렇게 죽었다(2026-08-23).
    #    `test-pre-commit.py` ⑨ 에 같은 교훈이 이미 적혀 있었다 — 그 파일만 지키고 있었다.
    git(origin, "symbolic-ref", "HEAD", "refs/heads/main")
    subprocess.run(["git", "init", "-q", up], check=True)
    for k, v in (("user.email", "t@t"), ("user.name", "t")):
        git(up, "config", k, v)
    git(up, "symbolic-ref", "HEAD", "refs/heads/main")
    open(os.path.join(up, "A.md"), "w").write("v1\n")
    # ⚠️ 훅 스크립트를 작업 트리에 심으면 그 자체가 «미커밋 변경»이 되어 훅이 건너뛴다.
    #    처음에 이걸 빠뜨려 «안 당긴다»는 거짓 실패가 났다 — 스크립트는 맞게 돌고 있었다.
    #    검사가 검사 대상의 입력을 바꿔 버린 형태다.
    open(os.path.join(up, ".gitignore"), "w").write("scripts/\n")
    git(up, "add", "."); git(up, "commit", "-qm", "init")
    git(up, "remote", "add", "origin", origin); git(up, "push", "-q", "-u", "origin", "main")
    subprocess.run(["git", "clone", "-q", origin, work], check=True)
    d = os.path.join(work, "scripts", "claude-hooks")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "session-start-pull.py"), "w", encoding="utf-8").write(script_src)
    return work, up, os.path.join(d, "session-start-pull.py")


def advance(up, text):
    open(os.path.join(up, "A.md"), "w").write(text)
    git(up, "commit", "-qam", "remote change"); git(up, "push", "-q", "origin", "main")


def msg(out):
    """⚠️ 원문 문자열로 매칭하지 말 것 — json.dumps 가 한글을 \\uXXXX 로 이스케이프하면
    substring 검사가 조용히 빗나간다(실제로 한 번 그랬다)."""
    out = out.strip()
    if not out:
        return ""
    try:
        return json.loads(out).get("systemMessage", "")
    except Exception:
        return out


def run(script):
    """훅 출력의 사용자 메시지."""
    return run_sid(script, "T")


def run_sid(script, sid):
    """세션 id 를 지정해 돌린다 — 회수기가 「내 것」을 가려내는지 재려면 필요하다."""
    return msg(subprocess.run(["python3", script], input=json.dumps({"session_id": sid}),
                              capture_output=True, text=True).stdout)


def run_many(script, n):
    """훅 **n개를 동시에** 돌린다. 이 레포는 세션이 겹치는 것이 기본형이라, 한 번에 하나만
    돌려 보는 검사는 실제 조건을 재현하지 못한다 — `git pull` 이 공유 `FETCH_HEAD` 로
    깨지는 것을 그래서 못 잡고 있었다(2026-08-15, 라이브에서 여섯 세션 동시 실패).

    ⚠️ **stdin 을 띄우자마자 닫는다.** `communicate()` 를 순서대로 부르면 각 프로세스가
    stdin 을 기다리며 멈춰 **사실상 직렬 실행**이 된다 — 그러면 이 검사는 동시성을 재현하는
    척만 하고 아무것도 못 잡는다.
    """
    procs = []
    for _ in range(n):
        p = subprocess.Popen(["python3", script], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        p.stdin.write(json.dumps({"session_id": "T"}))
        p.stdin.close()
        procs.append(p)
    outs = [msg(p.stdout.read()) for p in procs]
    for p in procs:
        p.wait()
    return outs


try:
    src = open(SCRIPT, encoding="utf-8").read()

    # ① 뒤처져 있고 깨끗하면 → 당긴다
    work, up, hook = build(src)
    advance(up, "v2\n")
    out = run(hook)
    pulled = open(os.path.join(work, "A.md")).read().strip() == "v2"
    check("뒤처져 있으면 실제로 당긴다", pulled)
    check("당겼으면 사용자에게 알린다", "pull" in out)

    # ② 이미 최신이면 → 조용히(로그를 채우지 않는다)
    check("이미 최신이면 조용하다", run(hook) == "")

    # ③ 더러우면 → 안 당긴다
    work2, up2, hook2 = build(src)
    open(os.path.join(work2, "LOCAL.md"), "w").write("남의 작업\n")
    git(work2, "add", "LOCAL.md")
    advance(up2, "v9\n")
    out2 = run(hook2)
    stayed = open(os.path.join(work2, "A.md")).read().strip() == "v1"
    check("미커밋 변경이 있으면 안 당긴다", stayed)
    check("건너뛴 이유를 알린다", "건너뜀" in out2)
    check("남의 작업은 그대로다", os.path.exists(os.path.join(work2, "LOCAL.md")))

    # ④ 변이 — 더러움 검사를 빼면 정말 당기는가(검사가 공허하지 않다는 증거)
    mut = src.replace("if status.strip():", "if False:")
    assert mut != src, "변이가 안 심겼다 — 이 검사는 무의미하다"
    work3, up3, hook3 = build(mut)
    open(os.path.join(work3, "LOCAL.md"), "w").write("남의 작업\n")
    git(work3, "add", "LOCAL.md")
    advance(up3, "v9\n")
    run(hook3)
    check("변이본은 더러운 트리에도 당긴다(검사가 공허하지 않음)",
          open(os.path.join(work3, "A.md")).read().strip() == "v9")

    # ⑤ 동시 실행 — 세션이 겹치는 것이 이 레포의 기본형이다(2026-08-15 여섯 세션 동시 실패)
    work4, up4, hook4 = build(src)
    advance(up4, "v5\n")
    outs4 = run_many(hook4, 8)
    check("동시 8개에서도 실제로 당긴다",
          open(os.path.join(work4, "A.md")).read().strip() == "v5")
    check("동시 실행을 실패로 보고하지 않는다", not [o for o in outs4 if "실패" in o])

    # ⑤-1 「경합에서 졌나」 재확인의 두 창 — git 대역으로 **결정적으로** 잰다.
    #
    # ⚠️ 이 함수는 `session-end-cleanup.py` 에 일부러 복제돼 있고, 그쪽 스위트에 같은
    #    검사가 있다. **양쪽에 다 두는 것이 요점이다** — 한쪽만 있으면 다른 쪽 사본이
    #    조용히 옛 판정으로 되돌아가도 아무도 모른다. 그 복제가 이 코드의 전제다.
    # ⚠️ ⑤의 동시 8개로는 이 둘을 못 잡는다. 재현이 기계 속도에 달려 있어서다 —
    #    이 기계 32 스레드 20 라운드 0회, parallax CI 11회 중 1회.
    import importlib.util
    spec_ff = importlib.util.spec_from_file_location("sp_ff", SCRIPT)
    sp = importlib.util.module_from_spec(spec_ff); spec_ff.loader.exec_module(sp)

    def ff_with(second_read, module=None):
        state = {"reads": 0}

        def fake(cwd, *args):
            if args[:2] == ("rev-parse", "--abbrev-ref"):
                return 0, "origin/main"
            if args[0] == "rev-parse":
                state["reads"] += 1
                if state["reads"] <= 2:
                    return 0, ("aaaaaaa" if args[1] == "HEAD" else "bbbbbbb")
                return second_read(args[1], state["reads"])
            if args[0] == "merge":
                return 1, "fatal: Unable to create '.../index.lock': File exists."
            return 0, ""
        return (module or sp).fast_forward_main(fake, "/x")

    def late(ref, reads):
        if reads <= 4:
            return 0, ("aaaaaaa" if ref == "HEAD" else "bbbbbbb")
        return 0, "bbbbbbb"
    check("이긴 쪽의 ref 갱신이 늦어도 실패로 적지 않는다", ff_with(late)[0])
    broken = lambda ref, reads: (128, "fatal: unable to read ref")
    check("재확인을 못 하면 성공이라고 하지 않는다", not ff_with(broken)[0])
    check("끝까지 다르면 실패로 적는다",
          not ff_with(lambda ref, reads: (0, "aaaaaaa" if ref == "HEAD" else "bbbbbbb"))[0])

    # ⚠️ **위 셋은 「남이 이미 올렸는가」만 묻는다.** 락을 놓쳐 실패했는데 **아무도 이기지
    #    않은** 경우는 그 질문으로 답이 안 나온다 — HEAD 는 영원히 업스트림과 다르고,
    #    몇 번을 다시 읽어도 실패다. 한 번 더 시도했으면 성공했을 자리에서.
    #    merge 가 처음엔 실패하고 그 다음엔 성공하는 대역으로 그 자리를 고정한다.
    def ff_retry(module=None):
        state = {"reads": 0, "merges": 0}

        def fake(cwd, *args):
            if args[:2] == ("rev-parse", "--abbrev-ref"):
                return 0, "origin/main"
            if args[0] == "rev-parse":
                state["reads"] += 1
                # 끝까지 뒤처진 채로 보인다 — 이긴 쪽은 없다.
                return 0, ("aaaaaaa" if args[1] == "HEAD" else "bbbbbbb")
            if args[0] == "merge":
                state["merges"] += 1
                if state["merges"] == 1:
                    return 1, "fatal: Unable to create '.../index.lock': File exists."
                return 0, "Updating aaaaaaa..bbbbbbb"
            return 0, ""
        return (module or sp).fast_forward_main(fake, "/x"), state

    (ok_retry, _msg), st = ff_retry()
    check("락을 놓쳤을 뿐이면 다시 시도해서 실제로 당긴다", ok_retry and st["merges"] >= 2)

    # 변이 — rc 확인을 지우면 「모르는 채로 성공」이 돌아와야 한다.
    mut_rc = src.replace("        if rc_head or rc_target:\n            continue",
                         "        if False:\n            continue")
    assert mut_rc != src, "변이가 안 심겼다 — 이 검사는 무의미하다"
    MUTRC = SCRIPT.replace(".py", "_mutrc.py")
    open(MUTRC, "w", encoding="utf-8").write(mut_rc)
    spec_rc = importlib.util.spec_from_file_location("sp_rc", MUTRC)
    sp_rc = importlib.util.module_from_spec(spec_rc); spec_rc.loader.exec_module(sp_rc)
    check("변이본(rc 무시)은 모르는 채로 성공을 보고한다(검사가 공허하지 않음)",
          ff_with(broken, sp_rc)[0])
    os.remove(MUTRC)

    # ⑥ 변이 — `git pull` 로 되돌리면 동시 실행이 정말 깨지는가.
    #    ⑤가 공허하지 않다는 증거이자, 이 수정이 고친 것이 무엇인지의 기록이다.
    # ⚠️ **재시도도 함께 걷어내야 한다.** 이 변이는 「`merge --ff-only` 로 바꾸기 전의 코드」를
    #    복원하는 것이어야 그 시절에 실측된 8/8 과 같은 것을 잰다. 재시도를 남겨 두면 변이본이
    #    경합이 잦아든 뒤 `pull` 을 다시 시도해 **스스로 낫는다** — 그러면 이 공허성 검사가
    #    바로 아래 문단이 피하겠다고 적어 둔 그 「깜빡이는 검사」가 된다. 실측: 이 기계의
    #    평범한 환경에서는 통과하고 다른 git 설정에서는 실패했다.
    mut_pull = src.replace("    for attempt in range(RECHECK_ATTEMPTS):",
                           "    for attempt in range(0):")
    assert mut_pull != src, "재시도 루프를 못 찾았다 — 변이가 옛 코드가 아니다"
    mut_pull = mut_pull.replace('git(main_tree, "merge", "--ff-only", upstream)',
                                'git(main_tree, "pull", "--ff-only")')
    assert 'git(main_tree, "merge"' not in mut_pull, "변이가 안 심겼다 — 이 검사는 무의미하다"
    # ⚠️ 최대 3회까지 본다. 경합이라 이론상 한 라운드가 통째로 비껴갈 수 있는데(먼저 성공한
    #    프로세스가 있으면 나머지는 「이미 최신」으로 정당하게 끝난다), **깜빡이는 검사는
    #    없느니만 못하다**. 실측으론 8/8 이 3라운드 내내 깨졌다.
    broke = False
    for _ in range(3):
        work5, up5, hook5 = build(mut_pull)
        advance(up5, "v5\n")
        if [o for o in run_many(hook5, 8) if "실패" in o]:
            broke = True
            break
    check("변이본(git pull)은 동시 실행에서 깨진다(검사가 공허하지 않음)", broke)

    # ⑦ 죽은 주인의 워크트리 회수 — `SessionEnd` 가 안 뜨는 하네스(codex)를 덮는 자리다.
    #    **보존하는 쪽을 함께 재지 않으면** 「전부 지우는 회수기」도 검사를 통과한다.
    def reap_case(label, *, dead=True, dirty=False, ahead=False, mine=False,
                  no_pid=False, fresh=False, src_override=None):
        work, up, hook = build(src_override or src)
        wt = os.path.join(os.path.dirname(work), f"wt-{label}")
        git(work, "worktree", "add", "-q", wt, "-b", f"b-{label}")
        if dirty:
            open(os.path.join(wt, "D.md"), "w").write("남의 미커밋 작업\n")
        if ahead:
            open(os.path.join(wt, "C.md"), "w").write("x\n")
            git(wt, "add", "C.md")
            git(wt, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "ahead")
        rec = {"session_id": "MINE" if mine else "OTHER",
               "ts": time.time() - (5 if fresh else 600)}
        if not no_pid:
            if dead:
                rec["pid"], rec["pid_start"] = 999999, "그런 프로세스 없음"
            else:                       # 살아 있는 주인 = 이 검사 프로세스 자신
                rec["pid"] = os.getpid()
                rec["pid_start"] = subprocess.run(
                    ["ps", "-p", str(os.getpid()), "-o", "lstart="],
                    capture_output=True, text=True).stdout.strip()
            rec["pid_cmd"] = "codex"
        json.dump({os.path.realpath(wt): rec},
                  open(os.path.join(work, ".git", "claude-worktree-owners.json"), "w"))
        out = run_sid(hook, "MINE")
        return wt, out

    wt, out = reap_case("clean")
    check("죽은 주인의 깨끗·머지된 워크트리는 회수된다", not os.path.isdir(wt))
    check("회수를 사람에게 알린다", "회수" in out)

    wt, _ = reap_case("dirty", dirty=True)
    check("죽은 주인이어도 미커밋 변경이 있으면 보존", os.path.isdir(wt))

    wt, _ = reap_case("ahead", ahead=True)
    check("죽은 주인이어도 미푸시 커밋이 있으면 보존", os.path.isdir(wt))

    wt, _ = reap_case("alive", dead=False)
    check("주인이 살아 있으면 손대지 않는다", os.path.isdir(wt))

    wt, _ = reap_case("nopid", no_pid=True)
    check("pid 기록이 없으면 손대지 않는다(모르는 것 ≠ 죽은 것)", os.path.isdir(wt))

    wt, _ = reap_case("mine", mine=True)
    check("내 세션 소유는 손대지 않는다", os.path.isdir(wt))

    wt, _ = reap_case("fresh", fresh=True)
    check("방금 기록된 것은 손대지 않는다(시작 중일 수 있다)", os.path.isdir(wt))

    # 변이 — 생존 판정을 무력화하면 **살아 있는 주인의 것도** 지우는가
    mut_alive = src.replace("    if r.returncode != 0:\n        return False",
                            "    if True:\n        return False")
    assert mut_alive != src, "변이가 안 심겼다 — 이 검사는 무의미하다"
    wt, _ = reap_case("mut", dead=False, src_override=mut_alive)
    check("변이본은 살아 있는 주인의 것도 지운다(생존 판정이 공허하지 않음)",
          not os.path.isdir(wt))
finally:
    shutil.rmtree(TMP, ignore_errors=True)

print("\n실패", fail, "건")
sys.exit(1 if fail else 0)
