/**
 * TLS 인증서 소스 추상화 — 셀프사인/파일/외부URL/ACME/사용안함을 하나의 계약으로 수렴.
 * 모든 소스는 `{key,cert} | null`(null=TLS 끔)로 귀결하고, 갱신은 watch로 무중단 교체한다.
 */

export type CertMode = "none" | "selfsigned" | "file" | "url" | "acme";

/** node:tls createServer/setSecureContext에 그대로 넣을 수 있는 키/체인. */
export interface TlsMaterial {
  key: string | Buffer;
  cert: string | Buffer;
}

/** 관리 UI/API 표시용 상태(개인키 미포함). */
export interface CertStatus {
  mode: CertMode;
  enabled: boolean;
  source: string;
  subject?: string;
  sans?: string[];
  notBefore?: number;
  notAfter?: number;
  /** 자기서명 여부(issuer==subject). */
  selfSigned?: boolean;
  error?: string;
}

/**
 * 인증서 소스. resolve()는 현재 유효 자료(없으면 null=TLS 비활성)를 돌려주고,
 * watch()는 갱신 시 onChange로 새 자료를 밀어준다(반환값=구독 해제 함수).
 */
export interface CertSource {
  readonly mode: CertMode;
  resolve(): Promise<TlsMaterial | null>;
  watch?(onChange: (m: TlsMaterial) => void): () => void;
  status(): Promise<CertStatus>;
  /** 강제 재취득(selfsigned=재생성 / url=재페치 / acme=갱신). 새 자료 반환. 관리 UI 액션용. */
  refresh?(): Promise<TlsMaterial>;
  close?(): void;
}
