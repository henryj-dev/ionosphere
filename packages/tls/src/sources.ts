/** 기본 CertSource 구현 — none(사용안함) + file(파일 경로, fs.watch 핫리로드). */
import { readFile } from "node:fs/promises";
import { watch as fsWatch, type FSWatcher } from "node:fs";
import { inspectCert } from "./inspect.ts";
import type { CertSource, CertStatus, TlsMaterial } from "./types.ts";

/** TLS 비활성 — resolve()가 null(평문만/프록시 종단). */
export function noneCertSource(): CertSource {
  return {
    mode: "none",
    resolve: async () => null,
    status: async () => ({ mode: "none", enabled: false, source: "disabled" }),
  };
}

export interface FileCertOptions {
  keyPath: string;
  certPath: string;
  /** 파일 변경 감지 디바운스(ms). 기본 200. */
  debounceMs?: number;
}

/** 로컬 파일에서 키/체인을 읽는다. watch()로 파일 변경 시 재로딩(무중단 교체용). */
export function fileCertSource(opts: FileCertOptions): CertSource {
  const debounce = opts.debounceMs ?? 200;
  const watchers: FSWatcher[] = [];

  const resolve = async (): Promise<TlsMaterial> => {
    const [key, cert] = await Promise.all([readFile(opts.keyPath), readFile(opts.certPath)]);
    return { key, cert };
  };

  return {
    mode: "file",
    resolve,
    watch(onChange) {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const fire = () => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => {
          void resolve()
            .then(onChange)
            .catch(() => {
              /* 재로딩 실패는 무시 — 기존 컨텍스트 유지 */
            });
        }, debounce);
      };
      for (const p of [opts.keyPath, opts.certPath]) {
        try {
          const w = fsWatch(p, fire);
          watchers.push(w);
        } catch {
          /* 감시 실패(경로 없음 등) — 다른 파일만이라도 감시 */
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
        const cert = await readFile(opts.certPath);
        return { mode: "file", enabled: true, source: opts.certPath, ...inspectCert(cert) };
      } catch (err) {
        return { mode: "file", enabled: false, source: opts.certPath, error: err instanceof Error ? err.message : String(err) };
      }
    },
    close() {
      for (const w of watchers) w.close();
      watchers.length = 0;
    },
  };
}
