/** CertSource — none/file 소스, inspectCert, file watch 핫리로드. */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createCertSource, fileCertSource, inspectCert, noneCertSource } from "@ionosphere/tls";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "../../proto-smtp/test/fixtures");
const CERT = readFileSync(join(fixtures, "cert.pem"));
const KEY = readFileSync(join(fixtures, "key.pem"));

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  dirs.length = 0;
});
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "ionosphere-tls-"));
  dirs.push(d);
  return d;
}

describe("noneCertSource", () => {
  test("resolve=null, status disabled", async () => {
    const s = noneCertSource();
    expect(s.mode).toBe("none");
    expect(await s.resolve()).toBeNull();
    expect(await s.status()).toMatchObject({ mode: "none", enabled: false });
  });
});

describe("inspectCert", () => {
  test("fixture 인증서 파싱 — subject/notAfter/selfSigned", () => {
    const info = inspectCert(CERT);
    expect(info.error).toBeUndefined();
    expect(info.subject).toBeTruthy();
    expect(typeof info.notAfter).toBe("number");
    expect(info.selfSigned).toBe(true); // 테스트 fixture는 셀프사인
  });
  test("잘못된 PEM → error", () => {
    expect(inspectCert("not a cert").error).toBeTruthy();
  });
});

describe("fileCertSource", () => {
  test("resolve가 파일 바이트를 그대로", async () => {
    const d = tmp();
    writeFileSync(join(d, "k.pem"), KEY);
    writeFileSync(join(d, "c.pem"), CERT);
    const s = fileCertSource({ keyPath: join(d, "k.pem"), certPath: join(d, "c.pem") });
    const m = await s.resolve();
    expect(Buffer.from(m!.cert).equals(CERT)).toBe(true);
    expect(Buffer.from(m!.key).equals(KEY)).toBe(true);
    const st = await s.status();
    expect(st).toMatchObject({ mode: "file", enabled: true });
    expect(st.notAfter).toBeGreaterThan(0);
    s.close?.();
  });

  test("경로 없음 → status error/비활성", async () => {
    const s = fileCertSource({ keyPath: "/no/k", certPath: "/no/c" });
    expect((await s.status()).enabled).toBe(false);
    await expect(s.resolve()).rejects.toBeTruthy();
  });

  test("watch: 파일 변경 시 onChange로 새 자료", async () => {
    const d = tmp();
    const kp = join(d, "k.pem");
    const cp = join(d, "c.pem");
    writeFileSync(kp, KEY);
    writeFileSync(cp, "OLD");
    const s = fileCertSource({ keyPath: kp, certPath: cp, debounceMs: 20 });
    let unsub = () => {};
    const changed = new Promise<Buffer>((resolve) => {
      unsub = s.watch!((m) => {
        const buf = Buffer.from(m.cert);
        if (buf.equals(CERT)) resolve(buf); // 스퍼리어스/중간 이벤트 무시, 최종 CERT만 확정
      });
    });
    await new Promise((r) => setTimeout(r, 50)); // watch 등록 안정화
    writeFileSync(cp, CERT); // 갱신 유발
    const newCert = await Promise.race([changed, new Promise<Buffer>((_, rej) => setTimeout(() => rej(new Error("timeout")), 3000))]);
    expect(newCert.equals(CERT)).toBe(true);
    unsub();
    s.close?.();
  });
});

describe("createCertSource 팩토리", () => {
  test("none / file 모드 선택", () => {
    expect(createCertSource({ mode: "none" }).mode).toBe("none");
    expect(createCertSource({ mode: "file", keyPath: "k", certPath: "c" }).mode).toBe("file");
  });
});
