/**
 * ionosphere 표준 메트릭 번들 — 이름/도움말을 한 곳에서 정의(app.ts 배선과 워커 훅이 공유).
 * 명명 규약: ionosphere_<subsystem>_<unit>_total(카운터) / ionosphere_<subsystem>_<unit>(게이지).
 */
import { Counter, Gauge, Registry } from "./registry.ts";

export interface IonosphereMetrics {
  registry: Registry;
  /** 수신 배달 완료(계정 메일함 반영) 수. */
  received: Counter;
  /** 아웃바운드 결과별 수 — 라벨 result=sent|deferred|bounced. */
  delivery: Counter;
  /** Abuse 자동 정지된 계정 수(§8 통제 ④). */
  suspended: Counter;
  /** 발송 큐 깊이(queued) — onCollect로 갱신. */
  queueDepth: Gauge;
  /** 블롭 GC 1단계: 참조 0으로 판정된 블롭 수. sweep 승격 전 관측 지표다. */
  blobsDoomed: Counter;
  /** 블롭 GC 2단계: 파일까지 회수한 블롭 수. */
  blobsSwept: Counter;
  /** 블롭 GC로 회수한 바이트. */
  blobBytesFreed: Counter;
  /**
   * 계층형 블롭 저장소에서 **옛 백엔드(fallback)로 읽은 횟수**.
   * FS→공유 스토리지 전환 완료 판단의 근거 — 이 값이 0으로 수렴해야 래퍼를 벗길 수 있다.
   * 안 보고 벗기면 옛 메일의 본문만 조용히 사라진다.
   */
  blobFallbackReads: Counter;
  /**
   * 접근 감사 이벤트 수 — 라벨 surface=imap|pop3|managesieve|submission|smtp|lmtp|jmap|api,
   * outcome=ok|fail|throttled|denied.
   *
   * 왜 라벨을 둘 두는가: **`outcome=throttled`·`fail`의 급증이 곧 대입 공격 신호**다. 감사 파일을
   * 뒤지지 않고 그래프에서 바로 보이는 것이 요점이고, 어느 표면인지 알아야 대응할 포트를 안다.
   */
  auditEvents: Counter;
  /**
   * 감사 로그 이관 실패 수. **0이 아니면 장기 보존이 끊긴 상태**다 — 로컬에는 남아 있지만
   * `localRetainDays`가 지나면 버려지므로, 이 값이 오르면 그 기간 안에 손을 써야 한다.
   */
  auditShipFailures: Counter;
}

export function createIonosphereMetrics(registry: Registry = new Registry()): IonosphereMetrics {
  return {
    registry,
    received: registry.counter("ionosphere_received_messages_total", "수신 배달 완료 메시지 수"),
    delivery: registry.counter("ionosphere_delivery_total", "아웃바운드 배달 결과 수(result=sent|deferred|bounced)"),
    suspended: registry.counter("ionosphere_accounts_suspended_total", "abuse 자동 정지된 계정 수"),
    queueDepth: registry.gauge("ionosphere_queue_depth", "발송 큐 깊이(status=queued)"),
    blobsDoomed: registry.counter("ionosphere_blobs_doomed_total", "참조 0으로 판정된 블롭 수(GC 1단계)"),
    blobsSwept: registry.counter("ionosphere_blobs_swept_total", "파일까지 회수한 블롭 수(GC 2단계)"),
    blobBytesFreed: registry.counter("ionosphere_blob_bytes_freed_total", "블롭 GC로 회수한 바이트"),
    blobFallbackReads: registry.counter("ionosphere_blob_fallback_reads_total", "옛 블롭 백엔드로 폴백해 읽은 횟수(전환 완료 판단용)"),
    auditEvents: registry.counter("ionosphere_audit_events_total", "접근 감사 이벤트 수(surface, outcome)"),
    auditShipFailures: registry.counter("ionosphere_audit_ship_failures_total", "감사 로그 오브젝트 스토리지 이관 실패 수"),
  };
}
