/**
 * 계층형 BlobStore — **로컬 FS에서 공유 스토리지로 넘어가는 기간**을 위한 것.
 *
 * 문제: 백엔드를 바꾸는 순간 이미 쌓인 블롭은 옛 백엔드에만 있다. 그대로 전환하면
 *  - 읽기: 옛 메일의 본문을 못 읽는다(IMAP FETCH가 빈손, MTA 워커가 발송 지연)
 *  - GC: 새 백엔드만 보고 지우므로 옛 백엔드의 파일은 **영원히 회수되지 않는다**
 * 스키마의 `blobs.backend` 컬럼이 원래 이 판별을 위한 자리인데 아무도 읽지 않는다(항상 0을 쓴다).
 * 컬럼을 되살리려면 마이그레이션 + 모든 쓰기 경로 수정이 필요한 반면, 읽기를 폴백시키면
 * **원장을 건드리지 않고** 같은 결과를 얻는다. 그래서 이 방식을 택했다.
 *
 * 규칙:
 *  - `put`  → **primary에만**. 새 블롭은 전부 새 백엔드로 모인다(전환이 실제로 진행된다).
 *  - `get`  → primary 먼저, 실패하면 fallback. 옛 블롭이 계속 읽힌다.
 *  - `remove` → **양쪽 모두**. GC가 어느 쪽에 있는지 몰라도 회수된다(두 백엔드 다 멱등).
 *
 * ⚠ 전환이 끝났다고 판단하는 기준은 "fallback에서 읽힌 적이 없는 기간"이다. 그 판단을 위해
 * fallback 적중을 훅으로 노출한다 — 지표로 0을 확인한 뒤에 이 래퍼를 벗겨야 한다.
 * 지표를 안 보고 벗기면 **옛 메일의 본문만 조용히 사라진다**.
 */
import type { BlobPutResult, BlobStore } from "./blob.ts";

export interface LayeredBlobStoreOptions {
  /** 새 블롭이 쓰이는 곳(예: S3). 읽기도 여기부터. */
  primary: BlobStore;
  /** 전환 전 블롭이 남아 있는 곳(예: 로컬 FS). 읽기 폴백 + 삭제 대상. */
  fallback: BlobStore;
  /**
   * fallback에서 읽혔을 때 호출(관측용). **이 값이 0으로 수렴해야 전환 완료**다.
   * 던져도 읽기는 성공 처리한다 — 관측이 본업을 막으면 안 된다.
   */
  onFallbackHit?: (blobId: string, generation: number) => void;
}

export class LayeredBlobStore implements BlobStore {
  private readonly primary: BlobStore;
  private readonly fallback: BlobStore;
  private readonly onFallbackHit?: (blobId: string, generation: number) => void;

  constructor(opts: LayeredBlobStoreOptions) {
    this.primary = opts.primary;
    this.fallback = opts.fallback;
    if (opts.onFallbackHit) this.onFallbackHit = opts.onFallbackHit;
  }

  /** 새 블롭은 primary에만 — fallback에도 쓰면 전환이 영원히 끝나지 않는다. */
  put(content: Uint8Array, generation?: number): Promise<BlobPutResult> {
    return this.primary.put(content, generation);
  }

  /**
   * primary 실패 시 fallback. **primary의 오류를 삼키지 않는다** — 양쪽 다 실패하면
   * primary 쪽 오류를 원인(cause)으로 달아 던진다. 전환기에는 "S3가 죽은 것"과
   * "옛 블롭이라 없는 것"을 구분해야 하는데, fallback 오류만 보이면 진단이 불가능하다.
   */
  async get(blobId: string, generation?: number): Promise<Uint8Array> {
    try {
      return await this.primary.get(blobId, generation);
    } catch (primaryErr) {
      try {
        const bytes = await this.fallback.get(blobId, generation);
        try {
          this.onFallbackHit?.(blobId, generation ?? 0);
        } catch {
          // 관측 훅 실패는 무시 — 본문은 이미 읽었다.
        }
        return bytes;
      } catch (fallbackErr) {
        throw new Error(
          `blob ${blobId}/${generation ?? 0}: primary·fallback 모두 실패 (fallback: ${String(fallbackErr)})`,
          { cause: primaryErr },
        );
      }
    }
  }

  /**
   * 양쪽에서 지운다. 어느 쪽에 있는지 모르고, 둘 다 없는 키에 대해 멱등하기 때문에 안전하다.
   * primary 삭제가 실패하면 fallback도 시도한 뒤 원래 오류를 던진다 — 한쪽 장애가
   * 다른 쪽 회수까지 막으면 누수가 남는다.
   */
  async remove(blobId: string, generation: number): Promise<void> {
    let primaryErr: unknown;
    try {
      await this.primary.remove(blobId, generation);
    } catch (err) {
      primaryErr = err;
    }
    await this.fallback.remove(blobId, generation);
    if (primaryErr !== undefined) throw primaryErr;
  }
}
