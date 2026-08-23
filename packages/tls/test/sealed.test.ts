/** sealedFileCertSource — 개인키 masterKey 봉인 저장 + 언봉인 로드(관리 UI 업로드용). */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateSelfSigned, sealedFileCertSource } from "@ionosphere/tls";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  dirs.length = 0;
});
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "ionosphere-sealed-"));
  dirs.push(d);
  return d;
}

const MK = "master-key-test-0123456789";
const { certPem, keyPem } = generateSelfSigned({ commonName: "mx.test.local", sans: ["mx.test.local"] });

describe("sealedFileCertSource", () => {
  test("write → 개인키는 봉인 저장(평문 아님), resolve는 언봉인 왕복", async () => {
    const dir = tmp();
    const s = sealedFileCertSource({ dir, masterKey: MK });
    // 업로드 전 resolve는 실패
    await expect(s.resolve()).rejects.toBeTruthy();
    await s.write(certPem, keyPem);
    // 디스크의 키 파일은 원본 PEM이 아님(봉인됨)
    const sealedOnDisk = readFileSync(join(dir, "tls.key.pem.sealed"), "utf8");
    expect(sealedOnDisk).not.toContain("BEGIN");
    expect(sealedOnDisk).not.toBe(keyPem);
    // cert는 평문(공개물)
    expect(readFileSync(join(dir, "tls.cert.pem"), "utf8")).toBe(certPem);
    // resolve는 원본 키/인증서 복원
    const m = await s.resolve();
    expect(Buffer.from(m!.key).toString()).toBe(keyPem);
    expect(Buffer.from(m!.cert).toString()).toBe(certPem);
  });

  test("잘못된 masterKey로는 언봉인 실패", async () => {
    const dir = tmp();
    await sealedFileCertSource({ dir, masterKey: MK }).write(certPem, keyPem);
    const wrong = sealedFileCertSource({ dir, masterKey: "different-master-key-9876" });
    await expect(wrong.resolve()).rejects.toBeTruthy();
  });

  test("status는 업로드 전/후 상태 반영", async () => {
    const dir = tmp();
    const s = sealedFileCertSource({ dir, masterKey: MK });
    expect((await s.status()).enabled).toBe(false);
    await s.write(certPem, keyPem);
    const st = await s.status();
    expect(st).toMatchObject({ mode: "file", enabled: true });
    expect(st.sans).toEqual(["mx.test.local"]);
  });

  test("잘못된 PEM 업로드 거부", async () => {
    const s = sealedFileCertSource({ dir: tmp(), masterKey: MK });
    await expect(s.write("not a cert", keyPem)).rejects.toBeTruthy();
  });
});
