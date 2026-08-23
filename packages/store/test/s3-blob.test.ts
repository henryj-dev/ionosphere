/**
 * S3BlobStore 테스트 — **네트워크 없이** 돈다(CI는 오프라인).
 * node:http로 가짜 S3를 띄워 실소켓 왕복을 검증하고, SigV4는 AWS 공식 테스트 벡터로 대조한다.
 */
import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { Socket } from "node:net";
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { canonicalUri, formatAmzDate, S3BlobStore, signV4 } from "../src/s3-blob.ts";

// ── 가짜 S3 ──────────────────────────────────────────────────────────────────

interface Recorded {
  method: string;
  path: string;
  host: string;
  headers: Record<string, string>;
  body: Uint8Array;
}

interface FakeS3 {
  port: number;
  requests: Recorded[];
  objects: Map<string, Uint8Array>;
  /** 앞에서부터 하나씩 소비되는 강제 상태코드(재시도 검증용). */
  failures: number[];
  /** true면 응답하지 않는다(타임아웃 검증용). */
  hang: boolean;
  close: () => Promise<void>;
}

async function startFakeS3(): Promise<FakeS3> {
  const objects = new Map<string, Uint8Array>();
  const requests: Recorded[] = [];
  const failures: number[] = [];
  const sockets = new Set<Socket>();
  const state = { hang: false };

  const srv: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Uint8Array[] = [];
    req.on("data", (c: Uint8Array) => chunks.push(c));
    req.on("end", () => {
      const total = chunks.reduce((n, c) => n + c.byteLength, 0);
      const body = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) {
        body.set(c, off);
        off += c.byteLength;
      }
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) headers[k] = Array.isArray(v) ? v.join(",") : (v ?? "");
      const path = req.url ?? "";
      requests.push({ method: req.method ?? "", path, host: headers.host ?? "", headers, body });

      if (state.hang) return; // 응답 없음 — 클라이언트 타임아웃 유도
      const forced = failures.shift();
      if (forced !== undefined) {
        res.writeHead(forced, { "content-type": "application/xml" });
        res.end(`<Error><Code>Forced</Code><Status>${forced}</Status></Error>`);
        return;
      }

      if (req.method === "PUT") {
        objects.set(path, body);
        res.writeHead(200);
        res.end();
      } else if (req.method === "GET") {
        const obj = objects.get(path);
        if (!obj) {
          res.writeHead(404, { "content-type": "application/xml" });
          res.end("<Error><Code>NoSuchKey</Code></Error>");
          return;
        }
        res.writeHead(200, { "content-length": String(obj.byteLength) });
        res.end(Buffer.from(obj));
      } else if (req.method === "DELETE") {
        // 실제 S3처럼 없는 키도 204(멱등).
        objects.delete(path);
        res.writeHead(204);
        res.end();
      } else {
        res.writeHead(405);
        res.end();
      }
    });
  });
  srv.on("connection", (s: Socket) => {
    sockets.add(s);
    s.on("close", () => sockets.delete(s));
  });

  const port = await new Promise<number>((resolve) => {
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      resolve(typeof addr === "object" && addr !== null ? addr.port : 0);
    });
  });

  return {
    port,
    requests,
    objects,
    failures,
    get hang(): boolean {
      return state.hang;
    },
    set hang(v: boolean) {
      state.hang = v;
    },
    close: async () => {
      for (const s of sockets) s.destroy();
      await new Promise<void>((r) => srv.close(() => r()));
    },
  };
}

let fake: FakeS3 | undefined;
afterEach(async () => {
  await fake?.close();
  fake = undefined;
});

function storeFor(f: FakeS3, prefix?: string): S3BlobStore {
  return new S3BlobStore({
    endpoint: `http://127.0.0.1:${f.port}`,
    region: "us-east-1",
    bucket: "mail-blobs",
    accessKeyId: "AKIDEXAMPLE",
    secretAccessKey: "secret",
    forcePathStyle: true,
    timeoutMs: 2_000,
    ...(prefix === undefined ? {} : { prefix }),
  });
}

const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);
const text = (b: Uint8Array): string => new TextDecoder().decode(b);

/** URL만 기록하고 고정 응답을 주는 fetch(주소 스타일·상태코드 검증용). */
function fakeFetch(respond: () => Response, onUrl?: (url: string) => void): typeof fetch {
  return ((input: unknown) => {
    onUrl?.(String(input));
    return Promise.resolve(respond());
  }) as unknown as typeof fetch;
}

// ── SigV4 정확성 ─────────────────────────────────────────────────────────────

describe("SigV4 (aws-sig-v4-test-suite)", () => {
  // get-vanilla — 공식 테스트 스위트의 표준 자격증명/시각.
  const CRED = {
    accessKeyId: "AKIDEXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    region: "us-east-1",
    service: "service",
  };
  const AMZ_DATE = "20150830T123600Z";
  const EMPTY = createHash("sha256").update("").digest("hex");

  test("get-vanilla: canonical request / string to sign / signature 일치", () => {
    const signed = signV4(
      {
        method: "GET",
        path: "/",
        query: "",
        headers: { Host: "example.amazonaws.com", "X-Amz-Date": AMZ_DATE },
        payloadSha256: EMPTY,
      },
      CRED,
      AMZ_DATE,
    );

    expect(signed.canonicalRequest).toBe(
      ["GET", "/", "", "host:example.amazonaws.com", `x-amz-date:${AMZ_DATE}`, "", "host;x-amz-date", EMPTY].join("\n"),
    );
    expect(signed.stringToSign).toBe(
      ["AWS4-HMAC-SHA256", AMZ_DATE, "20150830/us-east-1/service/aws4_request", "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"].join("\n"),
    );
    expect(signed.signature).toBe("5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
    expect(signed.authorization).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
    );
  });

  test("서명은 요청 요소(메서드·경로·헤더·페이로드)에 실제로 의존한다", () => {
    const base = {
      method: "GET",
      path: "/",
      query: "",
      headers: { host: "example.amazonaws.com", "x-amz-date": AMZ_DATE },
      payloadSha256: EMPTY,
    };
    const sig = (o: Partial<typeof base>): string => signV4({ ...base, ...o }, CRED, AMZ_DATE).signature;
    const baseline = sig({});

    expect(sig({ method: "PUT" })).not.toBe(baseline);
    expect(sig({ path: "/other" })).not.toBe(baseline);
    expect(sig({ query: "x=1" })).not.toBe(baseline);
    expect(sig({ headers: { host: "other.amazonaws.com", "x-amz-date": AMZ_DATE } })).not.toBe(baseline);
    expect(sig({ payloadSha256: createHash("sha256").update("x").digest("hex") })).not.toBe(baseline);
    // 키·시각도 서명에 들어간다.
    expect(signV4(base, { ...CRED, secretAccessKey: "other" }, AMZ_DATE).signature).not.toBe(baseline);
    expect(signV4(base, CRED, "20150831T123600Z").signature).not.toBe(baseline);
  });

  test("canonicalUri: unreserved 외 바이트는 퍼센트 인코딩(encodeURIComponent와 다름)", () => {
    expect(canonicalUri("/bucket/a b")).toBe("/bucket/a%20b");
    expect(canonicalUri("/bucket/a(b)*c")).toBe("/bucket/a%28b%29%2Ac");
    expect(canonicalUri("/bucket/ab/cd/0")).toBe("/bucket/ab/cd/0");
  });

  test("formatAmzDate: ISO8601 basic", () => {
    expect(formatAmzDate(new Date(Date.UTC(2015, 7, 30, 12, 36, 0)))).toBe("20150830T123600Z");
  });
});

// ── 왕복·키 레이아웃 ─────────────────────────────────────────────────────────

describe("S3BlobStore 왕복 (가짜 S3)", () => {
  test("put/get 왕복 + blobId = sha256 + 키 레이아웃 <aa>/<hash>/<gen>", async () => {
    fake = await startFakeS3();
    const store = storeFor(fake);
    const content = bytes("hello object storage");

    const { blobId, size, generation } = await store.put(content);
    expect(blobId).toBe(createHash("sha256").update(content).digest("hex"));
    expect(size).toBe(content.byteLength);
    expect(generation).toBe(0);

    const put = fake.requests[0];
    expect(put?.method).toBe("PUT");
    expect(put?.path).toBe(`/mail-blobs/${blobId.slice(0, 2)}/${blobId}/0`);
    expect(text(await store.get(blobId))).toBe("hello object storage");
  });

  test("prefix는 키 앞에 붙고 세대 레이아웃은 그대로", async () => {
    fake = await startFakeS3();
    const store = storeFor(fake, "/prod/");
    const { blobId } = await store.put(bytes("prefixed"));
    expect(fake.requests[0]?.path).toBe(`/mail-blobs/prod/${blobId.slice(0, 2)}/${blobId}/0`);
  });

  test("세대 분리: 같은 내용도 generation마다 다른 키(§9-5 라이터/GC 레이스 방지)", async () => {
    fake = await startFakeS3();
    const store = storeFor(fake);
    const g0 = bytes("generation body");
    await store.put(g0, 0);
    await store.put(g0, 1);
    const { blobId } = await store.put(g0, 0);

    expect([...fake.objects.keys()].sort()).toEqual([
      `/mail-blobs/${blobId.slice(0, 2)}/${blobId}/0`,
      `/mail-blobs/${blobId.slice(0, 2)}/${blobId}/1`,
    ]);
    // 한 세대를 지워도 다른 세대는 남는다 — GC가 라이터의 새 세대를 못 지우게 하는 계약.
    await store.remove(blobId, 0);
    await expect(store.get(blobId, 0)).rejects.toThrow();
    expect(text(await store.get(blobId, 1))).toBe("generation body");
  });

  test("x-amz-content-sha256은 UNSIGNED-PAYLOAD가 아니라 실제 본문 해시", async () => {
    fake = await startFakeS3();
    const store = storeFor(fake);
    const content = bytes("integrity matters");
    await store.put(content);
    expect(fake.requests[0]?.headers["x-amz-content-sha256"]).toBe(createHash("sha256").update(content).digest("hex"));

    await store.get(createHash("sha256").update(content).digest("hex")).catch(() => {});
    // GET은 빈 페이로드 해시.
    expect(fake.requests[1]?.headers["x-amz-content-sha256"]).toBe(createHash("sha256").update("").digest("hex"));
  });

  test("Authorization 헤더에 서명된 host는 실제 전송 Host와 같다", async () => {
    fake = await startFakeS3();
    const store = storeFor(fake);
    await store.put(bytes("host check"));
    const req = fake.requests[0];
    expect(req?.host).toBe(`127.0.0.1:${fake.port}`);
    expect(req?.headers.authorization).toContain("SignedHeaders=host;x-amz-content-sha256;x-amz-date");
    expect(req?.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/\d{8}\/us-east-1\/s3\/aws4_request, /);
  });
});

// ── 주소 스타일 ──────────────────────────────────────────────────────────────

describe("주소 스타일", () => {
  test("virtual-host 스타일은 버킷을 호스트에 넣는다(AWS·R2 기본)", async () => {
    let seen = "";
    const store = new S3BlobStore({
      endpoint: "https://ewr1.vultrobjects.com",
      region: "ewr",
      bucket: "mail-blobs",
      accessKeyId: "k",
      secretAccessKey: "s",
      fetch: fakeFetch(() => new Response(null, { status: 200 }), (u) => (seen = u)),
    });
    const { blobId } = await store.put(bytes("vhost"));
    expect(seen).toBe(`https://mail-blobs.ewr1.vultrobjects.com/${blobId.slice(0, 2)}/${blobId}/0`);
  });

  test("path-style은 버킷을 경로에 넣는다(Vultr·MinIO 필수)", async () => {
    let seen = "";
    const store = new S3BlobStore({
      endpoint: "https://ewr1.vultrobjects.com",
      region: "ewr",
      bucket: "mail-blobs",
      accessKeyId: "k",
      secretAccessKey: "s",
      forcePathStyle: true,
      fetch: fakeFetch(() => new Response(null, { status: 200 }), (u) => (seen = u)),
    });
    const { blobId } = await store.put(bytes("pathstyle"));
    expect(seen).toBe(`https://ewr1.vultrobjects.com/mail-blobs/${blobId.slice(0, 2)}/${blobId}/0`);
  });
});

// ── 오류 의미 (FsBlobStore와 동일해야 한다) ──────────────────────────────────

describe("오류 의미", () => {
  test("없는 블롭 get은 throw (호출부가 예외를 전제로 defer/404 처리한다)", async () => {
    fake = await startFakeS3();
    const store = storeFor(fake);
    await expect(store.get("0".repeat(64))).rejects.toThrow(/404/);
  });

  test("없는 키 remove는 조용히 성공 (GC 2단계 멱등성)", async () => {
    fake = await startFakeS3();
    const store = storeFor(fake);
    await expect(store.remove("0".repeat(64), 3)).resolves.toBeUndefined();
  });

  test("remove: 404를 주는 구현에서도 성공으로 친다", async () => {
    const store = new S3BlobStore({
      endpoint: "https://example.invalid",
      region: "r",
      bucket: "b",
      accessKeyId: "k",
      secretAccessKey: "s",
      fetch: fakeFetch(() => new Response("<Error><Code>NoSuchKey</Code></Error>", { status: 404 })),
    });
    await expect(store.remove("a".repeat(64), 0)).resolves.toBeUndefined();
  });

  test("put 실패(4xx)는 throw하고 본문을 진단에 싣는다", async () => {
    fake = await startFakeS3();
    fake.failures.push(403);
    const store = storeFor(fake);
    await expect(store.put(bytes("denied"))).rejects.toThrow(/403/);
  });
});

// ── 재시도·타임아웃 ──────────────────────────────────────────────────────────

describe("재시도·타임아웃", () => {
  test("5xx는 재시도 후 성공한다(멱등 연산이라 안전)", async () => {
    fake = await startFakeS3();
    fake.failures.push(503, 500);
    const store = storeFor(fake);
    const { blobId } = await store.put(bytes("retry me"));
    expect(fake.requests).toHaveLength(3);
    expect(text(await store.get(blobId))).toBe("retry me");
  });

  test("4xx는 즉시 실패한다(설정 오류를 무한 반복하면 진단이 어려워진다)", async () => {
    fake = await startFakeS3();
    fake.failures.push(403, 403, 403, 403);
    const store = storeFor(fake);
    await expect(store.put(bytes("bad creds"))).rejects.toThrow(/403/);
    expect(fake.requests).toHaveLength(1);
  });

  test("재시도 상한을 넘긴 5xx는 마지막 응답 그대로 throw", async () => {
    fake = await startFakeS3();
    fake.failures.push(500, 500, 500, 500);
    const store = storeFor(fake);
    await expect(store.get("b".repeat(64))).rejects.toThrow(/500/);
    expect(fake.requests).toHaveLength(4);
  });

  test("응답 없는 서버는 타임아웃으로 끊는다(무한 정지 금지)", async () => {
    fake = await startFakeS3();
    fake.hang = true;
    const store = new S3BlobStore({
      endpoint: `http://127.0.0.1:${fake.port}`,
      region: "us-east-1",
      bucket: "mail-blobs",
      accessKeyId: "k",
      secretAccessKey: "s",
      forcePathStyle: true,
      timeoutMs: 60,
    });
    const started = Date.now();
    await expect(store.get("c".repeat(64))).rejects.toThrow(/시도 실패/);
    // 4회 × 60ms + 백오프 상한 — 무한 대기가 아니라는 것만 보증한다.
    expect(Date.now() - started).toBeLessThan(4_000);
    expect(fake.requests).toHaveLength(4);
  });
});
