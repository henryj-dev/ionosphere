# 워크트리 준비

새 워크트리에는 `node_modules/` 가 없다. 이 저장소는 의존성이 **pg·mysql2 둘뿐**이지만
`npm test` · `npm run typecheck` 는 `typescript` 등 devDependency 를 필요로 하므로 없으면
검증이 통째로 안 돈다.

```bash
cd .claude/worktrees/<이름>
npm ci                                     # 워크트리 전용 의존성 (1초 안팎)
npm run verify                              # lint + typecheck + test + smoke
```

⚠ **메인 트리의 `node_modules` 를 심링크하지 말 것.** 예전에는 `ln -s ../../../node_modules`
를 권했는데, 그러면 `@ionosphere/*` 워크스페이스 링크가 **메인 트리의 `packages/`** 를 가리켜
워크트리에서 `npm run verify` 를 돌려도 메인 코드를 검증한다(2026-09-30 실측, `readlink
node_modules/@ionosphere/core` 로 확인할 수 있다). `npm ci` 는 워크트리 자기 `packages/` 를 링크한다.

`.claude/settings.json` 의 `worktree.symlinkDirectories` 는 Claude 전용 워크트리 도구에서 같은
심링크를 자동으로 건다 — 같은 문제가 있다. 도구 중립 생성기(`scripts/claude-hooks/enter-worktree.py`)
는 그 설정을 읽지 않는다. 그 도구로 만든 워크트리라면 심링크를 지우고 `npm ci` 를 돌린다.
