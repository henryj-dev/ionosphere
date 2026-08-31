import { DirectoryError, type DirectoryConfig, type DirectoryIdentity } from "@ionosphere/core";
import { directoryProvider, directorySnapshotReader, type DirectoryLdapClientOptions } from "./directory-ldap.ts";
import type { DirectorySnapshotSource } from "./shared-mailbox-runtime.ts";

export interface LdapDirectorySourceOptions {
  tenantId: string;
  config: DirectoryConfig;
  ldap: DirectoryLdapClientOptions;
}

/** 한 provider를 한 tenant에 고정해 관리 명령의 tenant 인자로 다른 directory를 읽지 못하게 한다. */
export class LdapDirectorySource implements DirectorySnapshotSource {
  private readonly tenantId: string;
  private readonly config: DirectoryConfig;
  private readonly ldap: DirectoryLdapClientOptions;
  private readonly reader;

  constructor(options: LdapDirectorySourceOptions) {
    if (!options.tenantId) throw new DirectoryError("directory tenantId가 비어 있음");
    this.tenantId = options.tenantId;
    this.config = options.config;
    this.ldap = options.ldap;
    this.reader = directorySnapshotReader(options.config, options.ldap);
  }

  async read(tenantId: string) {
    if (tenantId !== this.tenantId) throw new DirectoryError("directory provider의 tenant 범위 불일치");
    return await this.reader.readSnapshot();
  }

  async authenticate(tenantId: string, loginName: string, password: string): Promise<DirectoryIdentity | null> {
    // provider 이름은 tenant마다 재사용될 수 있으므로 인증도 snapshot과 같은 tenant 경계를 적용한다.
    if (tenantId !== this.tenantId) return null;
    // DirectoryProvider는 연결 하나를 소유한다. 요청마다 만들어야 동시 인증이 서로의 bind를 덮지 않는다.
    const provider = directoryProvider(this.config, this.ldap);
    try { return await provider.authenticate(loginName, password); }
    finally { await provider.close().catch(() => undefined); }
  }

  async close(): Promise<void> {
    await this.reader.close();
  }
}
