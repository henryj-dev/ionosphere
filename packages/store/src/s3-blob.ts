/**
 * S3 호환 오브젝트 스토리지 BlobStore — 역할별 서버 분리(MX / 릴레이 / MRA)의 전제.
 *
 * FsBlobStore는 로컬 디스크라 본문이 그 서버에만 있다. MX가 받은 메일을 릴레이나 MRA가
 * 읽어야 하는 순간 구조가 막힌다. 같은 버킷을 여러 노드가 보게 해서 그 벽을 없앤다.
 *
 * 의존성 0 — AWS SDK 없이 node:crypto로 Signature V4를 직접 서명한다(이 저장소가 ACME/JOSE/
 * X.509를 손으로 짠 것과 같은 이유: npm 의존 금지 + 서명 규칙이 공개 규격이라 재현 가능).
 *
 * ── 운영자가 알아야 할 것 ─────────────────────────────────────────────────────
 *
 * **필요한 버킷 권한**: `s3:PutObject` / `s3:GetObject` / `s3:DeleteObject`, 대상은
 * `arn:aws:s3:::<bucket>/<prefix>/*` 하나면 된다. **ListBucket은 필요 없다** — 모든 접근이
 * 키를 직접 지정하는 방식이라 목록 권한을 주면 권한만 넓어진다. 버킷은 반드시 비공개:
 * blobId는 내용의 sha256이고 블롭은 전역 dedup되므로, 해시를 아는 사람이 곧 읽을 수 있는
 * 사람이 된다(테넌트 인가는 DB의 blob_refs가 담당한다 — SCHEMA.md §9-5).
 *
 * **path-style이 필요한 사업자**: Vultr Object Storage, MinIO, 온프렘 S3 게이트웨이는
 * `forcePathStyle: true`(경로 `/<bucket>/<key>`)가 필요하다. AWS S3와 Cloudflare R2는
 * virtual-host 스타일(`<bucket>.<endpoint>/<key>`)이 기본이라 그대로 두면 된다.
 * 틀리면 증상이 404/SignatureDoesNotMatch로 나와 원인 파악이 오래 걸린다.
 *
 * **버킷 versioning / object lock은 끌 것**: 켜져 있으면 DELETE가 delete marker만 남기고
 * 용량이 회수되지 않아 블롭 GC가 사실상 무효가 된다.
 *
 * **이 백엔드를 쓰면 GC의 사고 반경이 커진다**: 로컬 FS일 때 GC 실수는 그 서버 디스크에
 * 갇혀 있었다. 공유 버킷에서는 어느 한 노드의 GC 2단계가 **모든 노드의 본문**을 지운다.
 * 그게 목적이지만 전제가 하나 붙는다 — **blobs 원장(DB)과 버킷은 1:1로 짝지어야 한다.**
 * 짝이 어긋난 채(예: 스테이징 DB + 프로덕션 버킷) GC를 돌리면 참조가 0으로 보여 남의 본문을
 * 지운다. 블롭 키가 내용 해시라 두 배포가 같은 버킷+prefix를 쓰면 파일이 겹치는 것도 같은
 * 함정이다. 배포마다 버킷 또는 `prefix`를 분리하라. **prefix는 네임스페이스지 인가 경계가
 * 아니다** — 같은 자격증명이면 다른 prefix도 그대로 읽힌다.
 */
import { createHash, createHmac } from "node:crypto";
import { blobHash, type BlobPutResult, type BlobStore } from "./blob.ts";

const ALGORITHM = "AWS4-HMAC-SHA256";
/** SigV4 서비스 이름 — S3 호환 API는 사업자와 무관하게 "s3"로 서명한다. */
const S3_SERVICE = "s3";
/** 빈 페이로드의 sha256(GET/DELETE의 x-amz-content-sha256). 리터럴 오타를 피하려 계산해 둔다. */
const EMPTY_PAYLOAD_SHA256 = createHash("sha256").update("").digest("hex");

/** 요청 1회당 타임아웃. 안 걸면 오브젝트 스토리지 장애가 메일 수신을 무한 정지시킨다. */
const DEFAULT_TIMEOUT_MS = 30_000;
/** 재시도 총 시도 횟수(최초 포함). 최악 지연 = MAX_ATTEMPTS × timeoutMs + 백오프 합. */
const MAX_ATTEMPTS = 4;
const RETRY_BASE_MS = 100;
const RETRY_MAX_MS = 2_000;

// ── SigV4 ────────────────────────────────────────────────────────────────────

export interface SigV4Request {
  method: string;
  /** URI 인코딩 **전** 경로(예: `/bucket/ab/<hash>/0`). 세그먼트 단위로 인코딩된다. */
  path: string;
  /** 정규화된 쿼리 문자열(없으면 ""). */
  query: string;
  /** 서명 대상 헤더. 여기 없는 헤더는 서명되지 않는다(host는 반드시 포함할 것). */
  headers: Record<string, string>;
  /** 페이로드 sha256 hex. UNSIGNED-PAYLOAD를 쓰지 않는 이유는 아래 sha256Hex 주석 참조. */
  payloadSha256: string;
}

export interface SigV4Credentials {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  service: string;
}

export interface SigV4Signed {
  canonicalRequest: string;
  stringToSign: string;
  signature: string;
  /** Authorization 헤더 값 그대로. */
  authorization: string;
}

/**
 * RFC 3986 unreserved(A-Z a-z 0-9 - _ . ~)를 뺀 모든 **바이트**를 퍼센트 인코딩.
 * JS의 encodeURIComponent는 `!'()*`를 남겨서 AWS 규칙과 어긋난다 — 그래서 직접 짠다.
 */
function uriEncodeSegment(segment: string): string {
  let out = "";
  for (const byte of new TextEncoder().encode(segment)) {
    const ch = String.fromCharCode(byte);
    if ((byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a) || (byte >= 0x30 && byte <= 0x39) || ch === "-" || ch === "_" || ch === "." || ch === "~") {
      out += ch;
    } else {
      out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    }
  }
  return out;
}

/** 경로를 세그먼트별로 인코딩(`/`는 구분자로 보존). S3는 비-S3 서비스와 달리 이중 인코딩하지 않는다. */
export function canonicalUri(path: string): string {
  const encoded = path.split("/").map(uriEncodeSegment).join("/");
  return encoded.startsWith("/") ? encoded : `/${encoded}`;
}

function hmac(key: Uint8Array | string, data: string): Uint8Array {
  return new Uint8Array(createHmac("sha256", key).update(data).digest());
}

function hmacHex(key: Uint8Array, data: string): string {
  return createHmac("sha256", key).update(data).digest("hex");
}

function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * AWS Signature Version 4 서명(AWS4-HMAC-SHA256).
 *
 * 중간 산물(canonicalRequest·stringToSign)을 반환하는 이유: 서명이 틀렸을 때 사업자가 주는
 * 정보는 "SignatureDoesNotMatch"뿐이라, 두 문자열을 눈으로 비교하지 않으면 진단이 불가능하다.
 * 테스트도 이 값들을 AWS 공식 테스트 벡터와 대조한다.
 *
 * @param amzDate ISO8601 basic 형식(YYYYMMDDTHHMMSSZ). headers["x-amz-date"]와 같아야 한다.
 */
export function signV4(req: SigV4Request, cred: SigV4Credentials, amzDate: string): SigV4Signed {
  const names = Object.keys(req.headers)
    .map((n) => n.toLowerCase())
    .sort();
  const lowered = new Map<string, string>();
  for (const [k, v] of Object.entries(req.headers)) lowered.set(k.toLowerCase(), v.trim());
  const canonicalHeaders = names.map((n) => `${n}:${lowered.get(n) ?? ""}\n`).join("");
  const signedHeaders = names.join(";");

  const canonicalRequest = [
    req.method,
    canonicalUri(req.path),
    req.query,
    canonicalHeaders,
    signedHeaders,
    req.payloadSha256,
  ].join("\n");

  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/${cred.region}/${cred.service}/aws4_request`;
  const stringToSign = [ALGORITHM, amzDate, scope, sha256Hex(canonicalRequest)].join("\n");

  // 서명 키 유도(날짜→리전→서비스→aws4_request) — 키가 날짜·리전에 묶여 유출 반경을 좁힌다.
  let key = hmac(`AWS4${cred.secretAccessKey}`, dateStamp);
  key = hmac(key, cred.region);
  key = hmac(key, cred.service);
  key = hmac(key, "aws4_request");
  const signature = hmacHex(key, stringToSign);

  return {
    canonicalRequest,
    stringToSign,
    signature,
    authorization: `${ALGORITHM} Credential=${cred.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

/** ISO8601 basic(YYYYMMDDTHHMMSSZ) — SigV4가 요구하는 유일한 형식. */
export function formatAmzDate(date: Date): string {
  return date.toISOString().replace(/[-:]|\.\d{3}/g, "");
}

// ── BlobStore 구현 ───────────────────────────────────────────────────────────

export interface S3BlobStoreOptions {
  /** 스킴 포함 엔드포인트(예: `https://ewr1.vultrobjects.com`). 버킷은 포함하지 않는다. */
  endpoint: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  /** 버킷 안 네임스페이스(배포 분리용). 인가 경계가 아님 — 파일 상단 주석 참조. */
  prefix?: string;
  /** Vultr·MinIO는 true 필수. AWS S3·R2는 생략(virtual-host 스타일). */
  forcePathStyle?: boolean;
  /** 요청 1회당 타임아웃(기본 30s). */
  timeoutMs?: number;
  /** 테스트 주입용(ACME 클라이언트와 같은 패턴). */
  fetch?: typeof fetch;
}

interface S3Response {
  status: number;
  body: Uint8Array;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * 지수 백오프 + full jitter. 여러 노드가 같은 버킷을 두드리므로 고정 간격이면 장애 복구
 * 시점에 재시도가 한꺼번에 몰린다(thundering herd).
 */
function backoffMs(attempt: number): number {
  return Math.random() * Math.min(RETRY_BASE_MS * 2 ** (attempt - 1), RETRY_MAX_MS);
}

/** 응답 본문이 XML 에러라 진단 메시지에 그대로 싣는다(길면 잘라서). */
function errorDetail(res: S3Response): string {
  const text = new TextDecoder().decode(res.body).replace(/\s+/g, " ").trim();
  return text.length > 300 ? `${text.slice(0, 300)}…` : text;
}

/**
 * S3 호환 BlobStore. 키 레이아웃은 FsBlobStore와 **동일**하다(`<hash 앞2자>/<hash>/<generation>`) —
 * 세대 분리는 GC와 라이터가 같은 경로를 다투지 않게 하는 계약(SCHEMA.md §9-5)이라
 * 백엔드가 바뀐다고 달라지면 안 된다. 백엔드 교체만으로 기존 GC 로직이 그대로 돈다.
 */
export class S3BlobStore implements BlobStore {
  private readonly bucket: string;
  private readonly cred: SigV4Credentials;
  private readonly protocol: string;
  private readonly endpointHost: string;
  private readonly prefix: string;
  private readonly pathStyle: boolean;
  private readonly timeoutMs: number;
  private readonly f: typeof fetch;

  constructor(opts: S3BlobStoreOptions) {
    const endpoint = new URL(opts.endpoint);
    this.bucket = opts.bucket;
    this.cred = {
      accessKeyId: opts.accessKeyId,
      secretAccessKey: opts.secretAccessKey,
      region: opts.region,
      service: S3_SERVICE,
    };
    this.protocol = endpoint.protocol;
    this.endpointHost = endpoint.host;
    // 앞뒤 슬래시를 정규화해 키 조립부에서 `//`가 생기지 않게 한다(S3에서 빈 세그먼트는 별개 키).
    const trimmed = (opts.prefix ?? "").replace(/^\/+|\/+$/g, "");
    this.prefix = trimmed === "" ? "" : `${trimmed}/`;
    this.pathStyle = opts.forcePathStyle ?? false;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.f = opts.fetch ?? fetch;
  }

  /** 저장 키 = `<prefix><hash 앞2자>/<hash>/<generation>` — FsBlobStore 경로와 1:1. */
  private objectKey(blobId: string, generation: number): string {
    return `${this.prefix}${blobId.slice(0, 2)}/${blobId}/${generation}`;
  }

  /** 요청 URL과 서명용 Host를 함께 만든다(둘이 어긋나면 SignatureDoesNotMatch). */
  private target(key: string): { url: string; host: string; path: string } {
    const host = this.pathStyle ? this.endpointHost : `${this.bucket}.${this.endpointHost}`;
    const path = this.pathStyle ? `/${this.bucket}/${key}` : `/${key}`;
    return { url: `${this.protocol}//${host}${canonicalUri(path)}`, host, path };
  }

  /**
   * 서명 + 전송 + 재시도. 재시도는 **5xx와 네트워크/타임아웃 오류만** — 4xx(자격증명 오류,
   * 잘못된 버킷, path-style 미설정)는 몇 번을 보내도 같은 답이라, 재시도하면 진단만 느려진다.
   * PUT/GET/DELETE 모두 멱등이라 재시도가 안전하다.
   */
  private async send(method: string, key: string, body?: Uint8Array): Promise<S3Response> {
    const { url, host, path } = this.target(key);
    const payloadSha256 = body === undefined ? EMPTY_PAYLOAD_SHA256 : sha256Hex(body);

    let lastError: unknown;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      const amzDate = formatAmzDate(new Date());
      const wireHeaders: Record<string, string> = {
        "x-amz-content-sha256": payloadSha256,
        "x-amz-date": amzDate,
      };
      // host는 **서명에만** 넣고 실제 요청 헤더로는 보내지 않는다 — URL의 호스트가 그대로
      // Host 헤더가 되고, fetch 구현에 따라 Host 수동 설정은 금지(무시)돼 서명이 어긋난다.
      const signHeaders = { host, ...wireHeaders };
      const { authorization } = signV4({ method, path, query: "", headers: signHeaders, payloadSha256 }, this.cred, amzDate);

      try {
        const res = await this.f(url, {
          method,
          headers: { ...wireHeaders, authorization },
          ...(body === undefined ? {} : { body }),
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        const buf = new Uint8Array(await res.arrayBuffer());
        if (res.status >= 500 && attempt < MAX_ATTEMPTS) {
          lastError = new Error(`S3 ${method} ${key}: ${res.status}`);
          await sleep(backoffMs(attempt));
          continue;
        }
        return { status: res.status, body: buf };
      } catch (err) {
        // 네트워크 단절·타임아웃(AbortError). 상한까지만 재시도한다.
        lastError = err;
        if (attempt >= MAX_ATTEMPTS) break;
        await sleep(backoffMs(attempt));
      }
    }
    throw new Error(`S3 ${method} ${key}: ${MAX_ATTEMPTS}회 시도 실패 — ${String(lastError)}`, { cause: lastError });
  }

  async put(content: Uint8Array, generation = 0): Promise<BlobPutResult> {
    const blobId = blobHash(content);
    const res = await this.send("PUT", this.objectKey(blobId, generation), content);
    if (res.status !== 200 && res.status !== 201) {
      throw new Error(`S3 put ${blobId}/${generation}: HTTP ${res.status} ${errorDetail(res)}`);
    }
    return { blobId, size: content.byteLength, generation };
  }

  /** 없는 블롭은 **throw** — FsBlobStore(ENOENT)와 의미를 맞춘다. 호출부(MTA 워커의 defer,
   *  JMAP 다운로드의 404)가 예외를 전제로 짜여 있어 여기서 빈 바이트를 주면 빈 메일이 배달된다. */
  async get(blobId: string, generation = 0): Promise<Uint8Array> {
    const res = await this.send("GET", this.objectKey(blobId, generation));
    if (res.status !== 200) {
      throw new Error(`S3 get ${blobId}/${generation}: HTTP ${res.status} ${errorDetail(res)}`);
    }
    return res.body;
  }

  /** 없는 키도 성공으로 친다(FsBlobStore가 `force: true`인 것과 같은 이유 — GC 2단계는
   *  중단 후 재실행될 수 있어 멱등해야 한다). S3는 보통 204를 주지만 404를 주는 구현도 있다. */
  async remove(blobId: string, generation: number): Promise<void> {
    const res = await this.send("DELETE", this.objectKey(blobId, generation));
    if (res.status !== 200 && res.status !== 204 && res.status !== 404) {
      throw new Error(`S3 remove ${blobId}/${generation}: HTTP ${res.status} ${errorDetail(res)}`);
    }
  }
}
