/**
 * ManageSieve 백엔드 — store 연동 (RFC 5804). 스크립트 검증은 @ionosphere/sieve 파서로.
 */
import { authenticate, Store, StoreError } from "@ionosphere/store";
import type { DbDriver } from "@ionosphere/db";
import { parseSieve } from "@ionosphere/sieve";
import type { ManageSieveBackend } from "@ionosphere/proto-managesieve";

export class IonosphereManageSieveBackend implements ManageSieveBackend {
  private readonly db: DbDriver;
  private readonly store: Store;
  private readonly authenticatePassword: (user: string, pass: string) => Promise<{ accountId: string; credKind?: string | undefined } | null>;

  constructor(db: DbDriver, store: Store, authenticatePassword?: (user: string, pass: string) => Promise<{ accountId: string; credKind?: string | undefined } | null>) {
    this.db = db;
    this.store = store;
    this.authenticatePassword = authenticatePassword ?? (async (user, pass) => authenticate(this.db, user, pass, "sieve"));
  }

  /**
   * `credKind`를 어댑터로 올린다 — 감사 로그가 기본 비번/앱 비번/OAuth를 구분해야 한다.
   * 여기서 기록하지 않는 이유: 이 클래스에는 IP가 없다(어댑터만 소켓을 본다).
   */
  async authenticate(user: string, pass: string): Promise<{ accountId: string; credKind?: string | undefined } | null> {
    const r = await this.authenticatePassword(user, pass);
    return r === null ? null : { accountId: r.accountId, credKind: r.credKind };
  }

  /** 파서로 문법 검증(require 미지원 확장 등도 여기선 파싱만 — 실행 검증은 배달 시). */
  checkScript(content: string): { ok: true } | { ok: false; message: string } {
    try {
      parseSieve(content);
      return { ok: true };
    } catch (err) {
      return { ok: false, message: err instanceof Error ? err.message : "parse error" };
    }
  }

  async putScript(accountId: string, name: string, content: string): Promise<{ ok: true } | { ok: false; message: string }> {
    try {
      await this.store.putSieveScript(accountId, name, content);
      return { ok: true };
    } catch (err) {
      return { ok: false, message: err instanceof StoreError ? err.message : "put failed" };
    }
  }

  listScripts(accountId: string): Promise<{ name: string; active: boolean }[]> {
    return this.store.listSieveScripts(accountId);
  }

  getScript(accountId: string, name: string): Promise<string | null> {
    return this.store.getSieveScript(accountId, name);
  }

  async deleteScript(accountId: string, name: string): Promise<{ ok: true } | { ok: false; code?: string; message: string }> {
    try {
      await this.store.deleteSieveScript(accountId, name);
      return { ok: true };
    } catch (err) {
      const msg = err instanceof StoreError ? err.message : "delete failed";
      return { ok: false, ...(msg.includes("active") ? { code: "ACTIVE" } : {}), message: msg };
    }
  }

  async setActive(accountId: string, name: string): Promise<{ ok: true } | { ok: false; message: string }> {
    try {
      await this.store.setActiveSieveScript(accountId, name);
      return { ok: true };
    } catch (err) {
      return { ok: false, message: err instanceof StoreError ? err.message : "setactive failed" };
    }
  }

  async renameScript(accountId: string, from: string, to: string): Promise<{ ok: true } | { ok: false; message: string }> {
    try {
      await this.store.renameSieveScript(accountId, from, to);
      return { ok: true };
    } catch (err) {
      return { ok: false, message: err instanceof StoreError ? err.message : "rename failed" };
    }
  }
}
