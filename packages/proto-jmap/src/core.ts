/**
 * JMAP Core capability 메서드 (RFC 8620 §4). 현재 Core/echo만 — 파이프라인 검증용.
 * (Blob/copy 등 나머지 Core 메서드는 블롭 배선 시 추가.)
 */
import { CORE_CAPABILITY } from "./session.ts";
import type { CapabilityModule } from "./types.ts";

/** Core/echo (RFC 8620 §4) — 인자를 그대로 반환. 5분 작업, 라운드트립 검증. */
export const coreModule: CapabilityModule = {
  capability: CORE_CAPABILITY,
  methods: {
    "Core/echo": async (args) => args,
  },
};
