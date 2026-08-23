/**
 * 계층형 BlobStore — FS→공유 스토리지 전환기의 읽기 폴백과 양쪽 회수.
 *
 * 여기서 고정하는 것은 "전환 중에 **아무것도 사라지지 않는다**"이다:
 * 옛 블롭이 계속 읽히고, GC가 어느 쪽에 있든 회수하고, 새 블롭은 새 백엔드로만 모인다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { blobHash, LayeredBlobStore, type BlobPutResult, type BlobStore } from "../src/index.ts";

/** 메모리 BlobStore — 어느 쪽이 응답했는지 보려고 직접 만든다. */
class MemBlobStore implements BlobStore {
  readonly objects = new Map<string, Uint8Array>();
  failGet = false;
  failRemove = false;

  private key(id: string, g: number): string {
    return `${id}/${g}`;
  }

  async put(content: Uint8Array, generation = 0): Promise<BlobPutResult> {
    const blobId = blobHash(content);
    this.objects.set(this.key(blobId, generation), content);
    return { blobId, size: content.byteLength, generation };
  }

  async get(blobId: string, generation = 0): Promise<Uint8Array> {
    if (this.failGet) throw new Error("backend down");
    const v = this.objects.get(this.key(blobId, generation));
    if (!v) throw new Error("not found");
    return v;
  }

  async remove(blobId: string, generation: number): Promise<void> {
    if (this.failRemove) throw new Error("remove failed");
    this.objects.delete(this.key(blobId, generation));
  }
}

const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);

describe("계층형 BlobStore", () => {
  test("새 블롭은 primary에만 쓴다 — fallback에도 쓰면 전환이 끝나지 않는다", async () => {
    const primary = new MemBlobStore();
    const fallback = new MemBlobStore();
    const layered = new LayeredBlobStore({ primary, fallback });

    await layered.put(bytes("new"));
    expect(primary.objects.size).toBe(1);
    expect(fallback.objects.size).toBe(0);
  });

  test("★옛 블롭은 fallback에서 읽힌다 — 전환 직후 본문이 사라지지 않는다", async () => {
    const primary = new MemBlobStore();
    const fallback = new MemBlobStore();
    const { blobId } = await fallback.put(bytes("old mail body")); // 전환 전에 쌓인 것

    const hits: string[] = [];
    const layered = new LayeredBlobStore({ primary, fallback, onFallbackHit: (id) => hits.push(id) });

    expect(new TextDecoder().decode(await layered.get(blobId))).toBe("old mail body");
    expect(hits).toEqual([blobId]); // 전환 완료 판단의 근거가 되는 지표
  });

  test("primary에 있으면 fallback을 보지 않는다", async () => {
    const primary = new MemBlobStore();
    const fallback = new MemBlobStore();
    const { blobId } = await primary.put(bytes("x"));
    const hits: string[] = [];
    const layered = new LayeredBlobStore({ primary, fallback, onFallbackHit: (id) => hits.push(id) });

    await layered.get(blobId);
    expect(hits).toEqual([]);
  });

  test("primary 장애 시에도 옛 블롭은 읽힌다(가용성)", async () => {
    const primary = new MemBlobStore();
    const fallback = new MemBlobStore();
    const { blobId } = await fallback.put(bytes("y"));
    primary.failGet = true;

    const layered = new LayeredBlobStore({ primary, fallback });
    expect(new TextDecoder().decode(await layered.get(blobId))).toBe("y");
  });

  test("★양쪽 다 실패하면 primary 오류를 cause로 남긴다 — 진단 가능해야 한다", async () => {
    const primary = new MemBlobStore();
    const fallback = new MemBlobStore();
    primary.failGet = true; // "S3가 죽음"
    const layered = new LayeredBlobStore({ primary, fallback });

    let caught: unknown;
    try {
      await layered.get("f".repeat(64));
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(Error);
    // fallback의 "not found"만 보이면 S3 장애를 부재로 오진한다
    expect(String((caught as Error).cause)).toContain("backend down");
  });

  test("★GC 삭제는 양쪽에서 — 어느 쪽에 있든 회수된다", async () => {
    const primary = new MemBlobStore();
    const fallback = new MemBlobStore();
    const { blobId } = await fallback.put(bytes("z")); // 옛 백엔드에만 존재
    await primary.put(bytes("z")); // 같은 내용이 새 백엔드에도 있을 수 있다(전역 dedup)

    const layered = new LayeredBlobStore({ primary, fallback });
    await layered.remove(blobId, 0);

    expect(primary.objects.size).toBe(0);
    expect(fallback.objects.size).toBe(0);
  });

  test("primary 삭제가 실패해도 fallback은 회수하고, 오류는 감추지 않는다", async () => {
    const primary = new MemBlobStore();
    const fallback = new MemBlobStore();
    const { blobId } = await fallback.put(bytes("w"));
    primary.failRemove = true;

    const layered = new LayeredBlobStore({ primary, fallback });
    await expect(layered.remove(blobId, 0)).rejects.toThrow("remove failed");
    expect(fallback.objects.size).toBe(0); // 한쪽 장애가 다른 쪽 회수를 막으면 누수가 남는다
  });

  test("관측 훅이 던져도 읽기는 성공한다", async () => {
    const primary = new MemBlobStore();
    const fallback = new MemBlobStore();
    const { blobId } = await fallback.put(bytes("v"));
    const layered = new LayeredBlobStore({
      primary,
      fallback,
      onFallbackHit: () => {
        throw new Error("metrics down");
      },
    });
    expect(new TextDecoder().decode(await layered.get(blobId))).toBe("v");
  });
});
