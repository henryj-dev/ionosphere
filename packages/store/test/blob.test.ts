import { createHash } from "node:crypto";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "@ionosphere/testkit";
import { FsBlobStore } from "../src/blob.ts";

async function tmpRoot(): Promise<string> {
  return mkdtemp(join(tmpdir(), "ionosphere-blob-"));
}

describe("FsBlobStore (SCHEMA.md §9-5)", () => {
  test("put: sha256 hex 64자 blobId 반환 + 콘텐츠 왕복", async () => {
    const store = new FsBlobStore(await tmpRoot());
    const content = new TextEncoder().encode("hello world");
    const { blobId, size } = await store.put(content);

    expect(blobId).toHaveLength(64);
    expect(blobId).toBe(createHash("sha256").update(content).digest("hex"));
    expect(size).toBe(content.byteLength);

    const roundtrip = await store.get(blobId);
    expect(new TextDecoder().decode(roundtrip)).toBe("hello world");
  });

  test("경로 레이아웃 = <root>/<aa>/<hash>/<generation> — generation 0", async () => {
    const root = await tmpRoot();
    const store = new FsBlobStore(root);
    const content = new TextEncoder().encode("path layout check");
    const { blobId } = await store.put(content);

    const shardDir = await readdir(join(root, blobId.slice(0, 2), blobId));
    expect(shardDir).toContain("0");
  });

  test("동일 콘텐츠 재put은 같은 blobId (콘텐츠 주소화)", async () => {
    const store = new FsBlobStore(await tmpRoot());
    const content = new TextEncoder().encode("dedup me");
    const a = await store.put(content);
    const b = await store.put(content);
    expect(a.blobId).toBe(b.blobId);
  });

  test("get: 존재하지 않는 blobId는 실패", async () => {
    const store = new FsBlobStore(await tmpRoot());
    await expect(store.get("0".repeat(64))).rejects.toThrow();
  });
});

/**
 * 경로 조립부의 심층방어 가드 — 지금은 호출부가 전부 DB를 거쳐 도달 불가지만,
 * 안전성이 흩어진 호출부에 있으면 새 호출부 하나로 무너진다.
 */
describe("blobPath 가드", () => {
  test("경로 탈출 id는 던진다 (root 컨테인먼트)", async () => {
    const store = new FsBlobStore(await tmpRoot());
    await expect(store.get("../../../../etc/passwd")).rejects.toThrow(/sha256 hex 64자/);
    await expect(store.remove("../../../../etc/passwd", 0)).rejects.toThrow(/sha256 hex 64자/);
  });

  test("길이·문자셋이 어긋난 id도 던진다", async () => {
    const store = new FsBlobStore(await tmpRoot());
    await expect(store.get("abc")).rejects.toThrow(/sha256 hex 64자/);
    await expect(store.get("A".repeat(64))).rejects.toThrow(/sha256 hex 64자/); // 대문자 hex는 blobHash 출력이 아니다
    await expect(store.get("z".repeat(64))).rejects.toThrow(/sha256 hex 64자/);
  });

  test("정상 id는 가드를 통과한다 — 실패하더라도 사유는 ENOENT다", async () => {
    const store = new FsBlobStore(await tmpRoot());
    const err = await store.get("0".repeat(64)).then(
      () => null,
      (e: unknown) => e as NodeJS.ErrnoException,
    );
    expect(err?.code).toBe("ENOENT");
  });

  test("generation은 0 이상 정수여야 한다", async () => {
    const store = new FsBlobStore(await tmpRoot());
    await expect(store.get("0".repeat(64), -1)).rejects.toThrow(/generation/);
  });
});
