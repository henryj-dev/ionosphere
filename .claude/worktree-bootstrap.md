# 워크트리 준비

새 워크트리에는 `node_modules/` 가 없다. 이 저장소는 의존성이 **pg·mysql2 둘뿐**이지만
`npm test` · `npm run typecheck` 는 `typescript` 등 devDependency 를 필요로 하므로 없으면
검증이 통째로 안 돈다.

```bash
cd .claude/worktrees/<이름>
ln -s ../../../node_modules node_modules   # 메인 트리의 것을 그대로 쓴다 (빠르다)
# 또는 격리가 필요하면: npm ci
npm run verify                              # lint + typecheck + test + smoke
```

`.claude/settings.json` 의 `worktree.symlinkDirectories` 가 Claude 전용 워크트리 도구에서는
이 심링크를 자동으로 걸어 주지만, 도구 중립 생성기(`scripts/claude-hooks/enter-worktree.py`)
는 그 설정을 읽지 않는다 — 그쪽으로 만들었으면 위 `ln -s` 를 손으로 건다.
