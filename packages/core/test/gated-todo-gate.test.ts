import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(new URL("../../..", import.meta.url).pathname);
const gate = resolve(root, "scripts/gates/shared-mailbox.ts");
const sealDir = resolve(root, "docs/plan/.gates/shared-mailbox");

function run(...args: string[]) {
  return spawnSync(process.execPath, [gate, ...args], { cwd: root, encoding: "utf8" });
}

test("P0 gate: 선행 봉인 없이는 다음 단계 검사를 실행하지 않는다", () => {
  const result = run("P1");
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, /선행 단계 봉인 없음/);
  assert.doesNotMatch(`${result.stdout}${result.stderr}`, /G-P1/);
});

test("P0 gate: status는 P0 열림과 P1 잠김을 구분한다", () => {
  const result = run("--status");
  assert.equal(result.status, 0);
  assert.match(result.stdout, /P0\t열림/);
  assert.match(result.stdout, /P1\t잠김/);
});

test("P0 gate: 봉인 디렉터리는 운영 무시 경로가 아닌 계획 경로다", () => {
  assert.equal(sealDir.endsWith("docs/plan/.gates/shared-mailbox"), true);
  assert.equal(existsSync(gate), true);
});

test("P0 gate: 빈 waive 사유는 거부한다", () => {
  const result = run("P0", "--seal", "--waived", "");
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, /waive 사유가 비어 있음/);
});
