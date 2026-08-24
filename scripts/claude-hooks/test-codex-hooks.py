#!/usr/bin/env python3
"""`.codex/hooks.json` 검사 — 등록이 살아 있고, 런처가 스크립트를 찾아 판정하는가.

**왜 따로 있나.** codex 는 Claude 와 같은 훅 이벤트·같은 입력 스키마를 쓰므로 스크립트를
공유한다. 그런데 **연결 부위가 다르다** — 등록 파일이 `.codex/hooks.json` 이고, 명령이
`$CLAUDE_PROJECT_DIR` 를 못 쓰므로 런처 셸 한 줄이 경로를 스스로 찾는다. 그 한 줄이
깨지면 **훅이 있는데 아무것도 안 도는** 상태가 되고, 그건 조용하다.

⚠️ **이 검사가 재는 것과 못 재는 것을 구분할 것.**
  - 잰다: JSON 유효성 · 셋(PreToolUse·SessionStart·SessionEnd) 등록 여부 · 런처가 경로를
    찾는가 · 메인/워크트리 판정 · 저장소 밖에서 조용히 통과하는가 · codex 모양(배열
    command·apply_patch) 처리.
  - 못 잰다: **codex 가 실제로 이 훅을 부르는지.** 프로젝트 훅은 `~/.codex/config.toml`
    의 `[hooks.state]` 에 `trusted_hash` 가 있어야 발화한다(사용자 승인). 승인 전에는
    이 검사가 전부 통과해도 **라이브에서는 아무 일도 안 일어난다.**
  - 못 잰다: **툴 이름과 입력 모양이 실제로 이것인지.** 아래 모양은 codex 바이너리에서
    읽은 것이고 라이브 발화로 확인하지 못했다. 다르면 여기부터 고칠 것.

⚠️ 런처는 `git rev-parse --show-toplevel` 로 스크립트를 찾는다. 즉 **워크트리에서 부르면
   워크트리의 사본**을, 메인에서 부르면 **메인의 사본**을 쓴다. 훅을 고쳐도 메인이 pull
   하기 전까지 메인 세션에는 안 먹는다(§2-1 의 그 지연이 여기에도 있다).
"""
import json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def sh(*a, **kw):
    return subprocess.run(a, capture_output=True, text=True, **kw)


TOP = sh("git", "-C", HERE, "rev-parse", "--show-toplevel").stdout.strip()
COMMON = sh("git", "-C", HERE, "rev-parse", "--path-format=absolute",
            "--git-common-dir").stdout.strip()
MAIN = os.path.dirname(COMMON)
CONF = os.path.join(TOP, ".codex", "hooks.json")
fail = 0


def check(label, ok):
    global fail
    fail += not ok
    print(f"{'✓' if ok else '✗'} {label}")


def run(cmd, payload, cwd):
    p = subprocess.run(["sh", "-c", cmd], input=json.dumps(payload),
                       capture_output=True, text=True, cwd=cwd)
    return p.returncode, p.stdout.strip()


try:
    d = json.load(open(CONF, encoding="utf-8"))
    check("`.codex/hooks.json` 이 유효한 JSON 이다", True)
except Exception as e:
    print(f"✗ `.codex/hooks.json` 파싱 실패: {e}")
    sys.exit(1)

cmds, others = {}, 0
for ev, groups in (d.get("hooks") or {}).items():
    for g in groups:
        for h in g.get("hooks", []):
            c = h.get("command", "")
            if "main-tree-guard" in c:
                cmds["PreToolUse"] = c
            elif "session-start-pull" in c:
                cmds["SessionStart"] = c
            elif "session-end-cleanup" in c:
                cmds["SessionEnd"] = c
            else:
                others += 1

check("세 훅이 전부 등록돼 있다", set(cmds) == {"PreToolUse", "SessionStart", "SessionEnd"})
# 기존 규칙(ssh 허용 등)을 덮어쓰지 않았는가 — 남의 규칙을 조용히 지우면 그쪽이 조용히 깨진다.
# ⚠️ **이것은 개수일 뿐 검사가 아니다.** 원래 몇 개였는지 모르므로 「지워졌다」를 잴 수 없다.
#    실패로 세면 규칙이 원래 없던 레포에서 정상을 고장으로 오판한다(이식하며 실측).
#    병합했는지는 설치할 때 사람이 봐야 한다.
print(f"ℹ️ 우리 것 외 등록 {others} 건 — 원래 있던 규칙은 그대로여야 합니다(개수로는 못 잽니다)")

if "PreToolUse" not in cmds:
    print("\n실패", fail + 1, "건")
    sys.exit(1)

G = cmds["PreToolUse"]
WT = TOP if os.path.realpath(TOP) != os.path.realpath(MAIN) else None

rc, out = run(G, {"tool_name": "Edit", "tool_input": {"file_path": f"{MAIN}/PLAN.md"},
                  "cwd": MAIN, "session_id": "T"}, MAIN)
check("메인에서 편집 → deny", "deny" in out)

if WT:
    rc, out = run(G, {"tool_name": "Edit", "tool_input": {"file_path": f"{WT}/PLAN.md"},
                      "cwd": WT, "session_id": "T"}, WT)
    check("워크트리에서 편집 → 통과", "deny" not in out)

# codex 모양 — 배열 command 와 apply_patch
rc, out = run(G, {"tool_name": "shell",
                  "tool_input": {"command": ["/bin/zsh", "-lc", "git commit -m x"]},
                  "cwd": MAIN, "session_id": "T"}, MAIN)
check("배열 command 로 메인 커밋 → deny", "deny" in out)

rc, out = run(G, {"tool_name": "shell",
                  "tool_input": {"command": ["/bin/zsh", "-lc", "git status --short"]},
                  "cwd": MAIN, "session_id": "T"}, MAIN)
check("배열 command 의 읽기 → 통과", "deny" not in out)

# 🔴 실측 형식 — `apply_patch` 는 패치를 **`command`** 로 보낸다(2026-08-15 codex 실측).
#    `input` 으로 가정했던 첫 판이 이 자리를 통과시켜 메인 트리에 파일이 생겼다.
rc, out = run(G, {"tool_name": "apply_patch",
                  "tool_input": {"command": f"*** Begin Patch\n*** Add File: {MAIN}/_probe.txt\n+x\n*** End Patch"},
                  "cwd": MAIN, "session_id": "T"}, MAIN)
check("apply_patch(command 키) 메인 편집 → deny", "deny" in out)

rc, out = run(G, {"tool_name": "apply_patch",
                  "tool_input": {"command": f"*** Begin Patch\n*** Update File: {WT or MAIN}/PLAN.md\n+x\n*** End Patch"},
                  "cwd": WT or MAIN, "session_id": "T"}, WT or MAIN)
check("apply_patch(command 키) 워크트리 → 통과", ("deny" not in out) if WT else True)

# ── 같은 패치, 다른 모양 ──────────────────────────────────────────────────────
#
# 🔴 **위 두 케이스가 예전에 재던 전부였고, 그것이 마침 유일하게 되던 모양이었다.**
#    「이것이 패치인가」를 묻는 곳이 셋인데 답이 둘이었다: `edit_paths()` 는
#    `*** Update File:` 류로 알아보고, `shell_command()`·`writes_content()` 는
#    `*** Begin Patch` 로만 알아봤다. 게다가 뒤의 둘은 `isinstance(v, str)` 만 봤다.
#    그래서 **같은 편집이라도 모양만 바꾸면 지나갔다** — 관문인 `relevant()` 가 본문을
#    셸 명령으로 읽고, MUTATING 에 안 걸리니 거기서 끝냈기 때문이다. 경로 추출은
#    올바른데 도달하지 못했다.
#
# ⚠️ 아래는 런처가 아니라 **이 파일 옆의 사본**을 직접 부른다. 런처는
#    `git rev-parse --show-toplevel` 로 스크립트를 찾으므로 워크트리에서 부르면
#    **메인 트리의 사본**을 재고, 그러면 검토 중인 수정이 아니라 옛 사본을 재게 된다.
#    위 케이스들은 배선을 재는 것이라 런처가 맞고, 여기는 판정을 재는 것이라 사본이 맞다.
LOCAL_GUARD = os.path.join(HERE, "main-tree-guard.py")


def judge(tool_input, cwd):
    """이 파일 옆의 가드에 물어본다. `True` 면 거부."""
    p = subprocess.run([sys.executable, LOCAL_GUARD],
                       input=json.dumps({"tool_name": "apply_patch", "tool_input": tool_input,
                                         "cwd": cwd, "session_id": "T"}),
                       capture_output=True, text=True, cwd=cwd)
    return "deny" in p.stdout


ENVELOPE = f"*** Begin Patch\n*** Add File: {MAIN}/_probe.txt\n+x\n*** End Patch"

check("apply_patch 가 배열로 와도 메인 편집 → deny",
      judge({"command": ["/bin/zsh", "-lc", ENVELOPE]}, MAIN))
check("셸 플래그 없는 배열도 메인 편집 → deny",
      judge({"command": ["apply_patch", ENVELOPE]}, MAIN))
check("봉투 머리말 없는 패치도 메인 편집 → deny",
      judge({"command": f"*** Update File: {MAIN}/PLAN.md\n@@\n+x\n"}, MAIN))
check("Delete File 도 메인 편집 → deny",
      judge({"command": f"*** Delete File: {MAIN}/PLAN.md\n"}, MAIN))
check("`input` 키로 온 패치도 메인 편집 → deny",
      judge({"input": ENVELOPE}, MAIN))

# ⚠️ **막는 쪽만 재면 「전부 막는 훅」도 통과한다.** 같은 모양들이 워크트리에서는 지나가야
#    한다 — 넓힌 판정이 워크트리 작업을 막기 시작하면 그것이 다음 사고다.
if WT:
    WT_ENVELOPE = f"*** Begin Patch\n*** Update File: {WT}/PLAN.md\n+x\n*** End Patch"
    check("배열 apply_patch 도 워크트리 → 통과",
          not judge({"command": ["/bin/zsh", "-lc", WT_ENVELOPE]}, WT))
    check("머리말 없는 패치도 워크트리 → 통과",
          not judge({"command": f"*** Update File: {WT}/PLAN.md\n@@\n+x\n"}, WT))

# ⚠️ 그리고 **패치가 아닌 것을 패치로 오인하지 않는가.** 넓힌 신호가 평범한 읽기 명령까지
#    삼키면 메인에서 `git status` 조차 못 하게 된다 — 2026-08-14 에 실제로 겪은 모양이다.
rc, out = run(G, {"tool_name": "shell", "tool_input": {"command": "git status --short"},
                  "cwd": MAIN, "session_id": "T"}, MAIN)
check("패치 신호를 넓혀도 평범한 읽기는 통과", "deny" not in out)

# fail-open — 저장소 밖에서 불려도 조용히 통과해야 한다(훅이 남의 작업을 막으면 안 된다)
rc, out = run(G, {"tool_name": "Edit", "tool_input": {"file_path": "/tmp/x.md"},
                  "cwd": "/tmp", "session_id": "T"}, "/tmp")
check("저장소 밖에서는 조용히 통과(rc=0)", rc == 0 and "deny" not in out)

# ── `.claude/settings.json` — codex 도 이것을 읽는다 ────────────────────────────
#
# 🔴 **2026-08-24 라이브 사고.** codex 0.149.1 은 `.codex/hooks.json` 말고 **`.claude/settings.json`
#    의 `hooks` 도 읽어 실행한다**(바이너리에 `settings.json`·`disableAllHooks`·`PreToolUse` 가
#    있고, 그 파일의 명령이 실제로 발화했다). 그런데 **`$CLAUDE_PROJECT_DIR` 를 세팅하지 않는다** —
#    그래서 `python3 "$CLAUDE_PROJECT_DIR/scripts/..."` 가 `/scripts/...` 로 풀려
#    `can't open file` + **exit 2** 가 됐다. codex 는 PreToolUse 의 exit 2 를 **거부**로 읽으므로
#    `git status` 같은 **읽기까지 전부 막혔고**, 세션이 통째로 멈췄다.
#    🔴 **한동안 여기 「이 층은 신뢰 승인 없이 발화한다」고 적혀 있었는데 틀렸다**(2026-08-24
#    같은 날 정정). 근거로 쓴 것이 `[hooks.state]` 에 항목이 **없다**는 부재였다 — 부재 위에
#    이론을 지은 것이다. 직접 재니 반대였다: ① 신뢰 항목이 하나도 없는 경로(새 워크트리)에
#    표식 훅을 넣고 `codex exec` → **안 찍혔다** ② `.codex/hooks.json` 해시를 깨뜨린 레포에서
#    codex 로 메인 편집 → **그대로 통과했다**(이 층이 돌았다면 막혔어야 한다).
#    → **`.codex/hooks.json` 을 고치면 그 프로젝트의 codex 가드가 통째로 풀린다.** 파일을
#      고쳤으면 **재승인까지가 그 작업이다.** matcher 의 codex 툴 이름은 그와 무관하게 필요하다.
#
# 그래서 세 훅의 명령은 `${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}` 로
# **스스로 경로를 찾는다.** Claude 에서는 앞의 변수가, codex 에서는 뒤의 git 이 답한다.
SETTINGS = os.path.join(TOP, ".claude", "settings.json")
try:
    sd = json.load(open(SETTINGS, encoding="utf-8"))
    check("`.claude/settings.json` 이 유효한 JSON 이다", True)
except Exception as e:
    print(f"✗ `.claude/settings.json` 파싱 실패: {e}")
    sd = {}
    fail += 1

scmds, smatcher = {}, ""
for ev, groups in (sd.get("hooks") or {}).items():
    for g in groups:
        if ev == "PreToolUse":
            smatcher = g.get("matcher", "")
        for h in g.get("hooks", []):
            scmds[ev] = h.get("command", "")

check("세 훅이 `.claude/settings.json` 에도 등록돼 있다",
      set(scmds) == {"PreToolUse", "SessionStart", "SessionEnd"})

# 🔴 **핵심 회귀** — 세 명령 중 하나라도 `$CLAUDE_PROJECT_DIR` 에만 기대면 codex 가 멈춘다.
for ev, c in sorted(scmds.items()):
    check(f"{ev} 명령이 `$CLAUDE_PROJECT_DIR` 없이도 경로를 찾는다",
          "rev-parse --show-toplevel" in c)

# codex 의 편집 툴 이름이 matcher 에 있는가. `apply_patch`·`shell` 은 Claude 에 없는 이름이라
# 넣어도 Claude 동작은 안 바뀌고, codex 에서는 이것이 없으면 **패치 편집이 이 층을 통과한다**.
for name in ("apply_patch", "shell"):
    check(f"PreToolUse matcher 가 codex 툴 `{name}` 을 덮는다", name in smatcher)


def run_codex(cmd, payload, cwd):
    """codex 조건 재현 — `CLAUDE_PROJECT_DIR` 를 **지우고** 부른다."""
    env = dict(os.environ)
    env.pop("CLAUDE_PROJECT_DIR", None)
    p = subprocess.run(["sh", "-c", cmd], input=json.dumps(payload),
                       capture_output=True, text=True, cwd=cwd, env=env)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


if "PreToolUse" in scmds:
    SG = scmds["PreToolUse"]
    rc, out, err = run_codex(SG, {"tool_name": "Edit",
                                  "tool_input": {"file_path": f"{MAIN}/PLAN.md"},
                                  "cwd": MAIN, "session_id": "T"}, MAIN)
    # ⚠️ rc 를 함께 본다. 옛 형태의 증상은 「deny 가 없다」가 아니라 **exit 2 + 빈 stdout** 이었다 —
    #    판정을 stdout 으로만 하면 그 사고가 「통과」로 보인다.
    check("codex 조건에서 메인 편집 → deny", rc == 0 and "deny" in out)
    check("codex 조건에서 해석 실패 흔적이 없다", "can't open file" not in err)

    if WT:
        rc, out, _ = run_codex(SG, {"tool_name": "Edit",
                                    "tool_input": {"file_path": f"{WT}/PLAN.md"},
                                    "cwd": WT, "session_id": "T"}, WT)
        check("codex 조건에서 워크트리 편집 → 통과", rc == 0 and "deny" not in out)

    rc, out, _ = run_codex(SG, {"tool_name": "apply_patch",
                                "tool_input": {"command": f"*** Begin Patch\n*** Add File: {MAIN}/_probe.txt\n+x\n*** End Patch"},
                                "cwd": MAIN, "session_id": "T"}, MAIN)
    check("codex 조건에서 apply_patch 메인 편집 → deny", rc == 0 and "deny" in out)

    rc, out, _ = run_codex(SG, {"tool_name": "Edit", "tool_input": {"file_path": "/tmp/x.md"},
                                "cwd": "/tmp", "session_id": "T"}, "/tmp")
    check("codex 조건에서 저장소 밖은 조용히 통과(rc=0)", rc == 0 and "deny" not in out)

    # ⚠️ **막는 쪽만 재면 「전부 막는 훅」이 통과한다.** 읽기가 계속 통과해야 한다 —
    #    이번 사고의 실제 피해가 「읽기까지 막힌 것」이었다.
    rc, out, _ = run_codex(SG, {"tool_name": "shell",
                                "tool_input": {"command": "git status --short"},
                                "cwd": MAIN, "session_id": "T"}, MAIN)
    check("codex 조건에서 메인의 읽기 명령은 통과", rc == 0 and "deny" not in out)

    # Claude 쪽 경로도 살아 있는가 — 변수가 있으면 **그것을** 쓴다(워크트리에서 훅을 고쳐도
    # 메인 세션엔 메인 사본이 먹는 §2-1 의 성질이 여기 달려 있다).
    env = dict(os.environ, CLAUDE_PROJECT_DIR=MAIN)
    p = subprocess.run(["sh", "-c", SG],
                       input=json.dumps({"tool_name": "Edit",
                                         "tool_input": {"file_path": f"{MAIN}/PLAN.md"},
                                         "cwd": "/tmp", "session_id": "T"}),
                       capture_output=True, text=True, cwd="/tmp", env=env)
    check("`$CLAUDE_PROJECT_DIR` 가 있으면 그것으로 찾는다(Claude 경로)",
          p.returncode == 0 and "deny" in p.stdout)


print("\n실패", fail, "건")
sys.exit(1 if fail else 0)
