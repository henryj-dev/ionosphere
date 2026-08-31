import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(new URL("../../..", import.meta.url).pathname);
const gate = resolve(root, "scripts/gates/shared-mailbox.ts");
const sealDir = resolve(root, "docs/plan/.gates/shared-mailbox");

function run(...args: string[]) {
  return spawnSync(process.execPath, [gate, ...args], { cwd: root, encoding: "utf8" });
}

test("P0 gate: 선행 봉인 없이는 다음 단계 검사를 실행하지 않는다", () => {
  const seal = resolve(sealDir, "P0.json");
  const backup = resolve(sealDir, "P0.json.gate-test-backup");
  const hadSeal = existsSync(seal);
  if (hadSeal) renameSync(seal, backup);
  try {
    const result = run("P1");
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}${result.stderr}`, /선행 단계 봉인 없음/);
    assert.doesNotMatch(`${result.stdout}${result.stderr}`, /G-P1/);
  } finally {
    if (hadSeal) renameSync(backup, seal);
  }
});

test("P0 gate: status는 P0 봉인과 P1 열림을 구분한다", () => {
  const p1Seal = resolve(sealDir, "P1.json");
  const backup = resolve(sealDir, "P1.json.gate-test-backup");
  const hadSeal = existsSync(p1Seal);
  if (hadSeal) renameSync(p1Seal, backup);
  try {
    const result = run("--status");
    assert.equal(result.status, 0);
    assert.match(result.stdout, /P0\t봉인/);
    assert.match(result.stdout, /P1\t열림/);
  } finally {
    if (hadSeal) renameSync(backup, p1Seal);
  }
});

test("P0 gate: squash로 commit ancestry가 사라져도 산출물 digest가 같으면 봉인을 유지한다", () => {
  const seal = resolve(sealDir, "P0.json");
  const original = readFileSync(seal, "utf8");
  const changed = JSON.parse(original) as { head: string };
  changed.head = "0".repeat(40);
  writeFileSync(seal, `${JSON.stringify(changed, null, 2)}\n`);
  try {
    const result = run("--status");
    assert.equal(result.status, 0);
    assert.match(result.stdout, /P0\t봉인/);
  } finally {
    writeFileSync(seal, original);
  }
});

test("P0 gate: 산출물 digest가 달라지면 봉인을 무효화한다", () => {
  const seal = resolve(sealDir, "P0.json");
  const original = readFileSync(seal, "utf8");
  const changed = JSON.parse(original) as { outputs: Record<string, string> };
  const output = Object.keys(changed.outputs)[0]!;
  changed.outputs[output] = "0".repeat(64);
  writeFileSync(seal, `${JSON.stringify(changed, null, 2)}\n`);
  try {
    const result = run("--status");
    assert.equal(result.status, 0);
    assert.match(result.stdout, /P0\t무효/);
    const order = run("--assert-order");
    assert.notEqual(order.status, 0);
    assert.match(`${order.stdout}${order.stderr}`, /FAIL P0/);
  } finally {
    writeFileSync(seal, original);
  }
});

test("P0 gate: digest 없는 구형 봉인은 승인하지 않는다", () => {
  const seal = resolve(sealDir, "P0.json");
  const original = readFileSync(seal, "utf8");
  const changed = JSON.parse(original) as { sealVersion?: number; outputs?: Record<string, string> };
  delete changed.sealVersion;
  delete changed.outputs;
  writeFileSync(seal, `${JSON.stringify(changed, null, 2)}\n`);
  try {
    const result = run("P1");
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}${result.stderr}`, /선행 단계 봉인 없음/);
    assert.doesNotMatch(`${result.stdout}${result.stderr}`, /G-P1/);
  } finally {
    writeFileSync(seal, original);
  }
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
