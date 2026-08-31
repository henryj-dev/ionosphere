import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const root = resolve(new URL("../../..", import.meta.url).pathname);
const gate = resolve(root, "scripts/gates/shared-mailbox.ts");
const sealDir = resolve(root, "docs/plan/.gates/shared-mailbox");

function run(...args: string[]) {
  return spawnSync(process.execPath, [gate, ...args], { cwd: root, encoding: "utf8" });
}

function runWithSealFixture(excludedPhase: string, ...args: string[]) {
  const fixture = mkdtempSync(resolve(tmpdir(), "ionosphere-gate-"));
  cpSync(sealDir, fixture, { recursive: true });
  rmSync(resolve(fixture, `${excludedPhase}.json`), { force: true });
  for (let index = 0; index <= 11; index += 1) {
    const path = resolve(fixture, `P${index}.json`);
    if (existsSync(path)) refreshSealOutputsAt(path);
  }
  try {
    return spawnSync(process.execPath, [gate, ...args], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, IONOSPHERE_GATE_SEAL_DIR: fixture },
    });
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}

function runWithOnlySealFixture(includedPhase: string, ...args: string[]) {
  const fixture = mkdtempSync(resolve(tmpdir(), "ionosphere-gate-bootstrap-"));
  cpSync(sealDir, fixture, { recursive: true });
  for (let index = 0; index <= 11; index += 1) {
    const phase = `P${index}`;
    const path = resolve(fixture, `${phase}.json`);
    if (phase === includedPhase && existsSync(path)) refreshSealOutputsAt(path);
    else rmSync(path, { force: true });
  }
  try {
    return spawnSync(process.execPath, [gate, ...args], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, IONOSPHERE_GATE_SEAL_DIR: fixture },
    });
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}

function refreshSealOutputsAt(path: string): string {
  const original = readFileSync(path, "utf8");
  const seal = JSON.parse(original) as { outputs: Record<string, string>; contentDigest: string };
  seal.outputs = Object.fromEntries(Object.keys(seal.outputs).map((output) => [
    output,
    createHash("sha256").update(readFileSync(resolve(root, output))).digest("hex"),
  ]));
  const entries = Object.entries(seal.outputs).sort(([left], [right]) => left.localeCompare(right));
  seal.contentDigest = createHash("sha256").update(JSON.stringify(entries)).digest("hex");
  writeFileSync(path, `${JSON.stringify(seal, null, 2)}\n`);
  return original;
}

function refreshSealOutputs(phase: string): string {
  return refreshSealOutputsAt(resolve(sealDir, `${phase}.json`));
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
  const p0Seal = resolve(sealDir, "P0.json");
  const p0Original = refreshSealOutputs("P0");
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
    writeFileSync(p0Seal, p0Original);
  }
});

test("P0 gate: squash로 commit ancestry가 사라져도 산출물 digest가 같으면 봉인을 유지한다", () => {
  const seal = resolve(sealDir, "P0.json");
  const original = refreshSealOutputs("P0");
  const changed = JSON.parse(readFileSync(seal, "utf8")) as { head: string };
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

test("P0 gate: complete 검사는 최종 단계 봉인이 없으면 실패한다", () => {
  const result = runWithSealFixture("P11", "--assert-complete");
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, /FAIL P11: 봉인 없음/);
});

test("P0 gate: 단계 실행용 order 검사는 자기봉인이 없어도 bootstrap을 허용한다", () => {
  // 후속 단계 정의가 바뀌어 기존 seal이 무효여도 P0부터 다시 봉인할 수 있어야 한다.
  const result = runWithOnlySealFixture("P0", "--assert-order");
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
});

test("P0 gate: complete 검사는 후행 봉인이 남아 있어도 중간 누락을 거부한다", () => {
  assert.equal(existsSync(resolve(sealDir, "P6.json")), true);
  const result = runWithSealFixture("P5", "--assert-complete");
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, /FAIL P5: 봉인 없음/);
  assert.match(`${result.stdout}${result.stderr}`, /FAIL P6: 선행 봉인 chain 불완전/);
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
