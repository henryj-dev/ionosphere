/**
 * sealed CertSource — 관리 UI 업로드용. 인증서는 공개물이라 평문, **개인키는 masterKey로
 * secretbox 봉인**해 디스크에 저장한다(@ionosphere/core seal/open). write()로 업로드분을 봉인 저장.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { watch as fsWatch, type FSWatcher } from "node:fs";
import { join } from "node:path";
import { open, seal } from "@ionosphere/core";
import { inspectCert } from "./inspect.ts";
import { assertUsableCert } from "./verify.ts";
import type { CertSource, CertStatus, TlsMaterial } from "./types.ts";

export interface SealedSourceOptions {
  dir: string;
  masterKey: string;
}

/** CertSource + 업로드 저장(write). app의 TlsAdmin.upload가 write를 호출한다. */
export type SealedCertSource = CertSource & { write(certPem: string, keyPem: string): Promise<TlsMaterial> };

export function sealedFileCertSource(opts: SealedSourceOptions): SealedCertSource {
  const certPath = join(opts.dir, "tls.cert.pem"); // 인증서=공개, 평문
  const keyPath = join(opts.dir, "tls.key.pem.sealed"); // 개인키=봉인
  const watchers: FSWatcher[] = [];

  async function load(): Promise<TlsMaterial | null> {
    try {
      const [cert, sealedKey] = await Promise.all([readFile(certPath), readFile(keyPath, "utf8")]);
      if (inspectCert(cert).error) return null;
      return { cert, key: open(sealedKey, opts.masterKey) };
    } catch {
      return null;
    }
  }

  async function write(certPem: string, keyPem: string): Promise<TlsMaterial> {
    /**
     * ★키/인증서 **쌍**을 저장 전에 확인한다(검사 본체는 verify.ts 공용). 예전엔 형식 검증을
     * "리슨 시 node:tls가 한다"고 미뤘는데, 업로드 성공 응답 뒤에 `reloadAllTls`가 곧바로 돌아
     * **모든 TLS 리스너를 한꺼번에 망가뜨린다.** 되돌릴 수단도 그 리스너를 통해야 해서(관리
     * 콘솔이 TLS 뒤에 있다) 스스로를 잠그는 형태가 된다. 저장 전에 실패시키는 것이 유일하게
     * 안전한 순서다. 호스트명은 대조하지 않는다 — 업로드는 운영자가 의도를 직접 표명한 경로다.
     */
    assertUsableCert("업로드 TLS 자재", certPem, keyPem);
    await mkdir(opts.dir, { recursive: true });
    await writeFile(certPath, certPem);
    await writeFile(keyPath, seal(keyPem, opts.masterKey).value, { mode: 0o600 });
    return { cert: certPem, key: keyPem };
  }

  return {
    mode: "file",
    async resolve() {
      const m = await load();
      if (!m) throw new Error("sealed cert 없음 — 관리 UI로 업로드 필요");
      return m;
    },
    async refresh() {
      const m = await load();
      if (!m) throw new Error("sealed cert 없음");
      return m;
    },
    write,
    watch(onChange) {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const fire = () => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => void load().then((m) => m && onChange(m)).catch(() => {}), 200);
      };
      for (const p of [certPath, keyPath]) {
        try {
          watchers.push(fsWatch(p, fire));
        } catch {
          /* 미존재 — 업로드 후 재시작에 반영 */
        }
      }
      return () => {
        for (const w of watchers) w.close();
        watchers.length = 0;
        if (timer) clearTimeout(timer);
      };
    },
    async status(): Promise<CertStatus> {
      try {
        const cert = await readFile(certPath);
        return { mode: "file", enabled: true, source: `sealed:${certPath}`, ...inspectCert(cert) };
      } catch {
        return { mode: "file", enabled: false, source: `sealed:${certPath}`, error: "미업로드" };
      }
    },
    close() {
      for (const w of watchers) w.close();
      watchers.length = 0;
    },
  };
}
