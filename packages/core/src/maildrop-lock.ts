/**
 * POP3 maildrop 배타 잠금의 **공통 계약** — RFC 1939 §3("서버는 maildrop에 배타적 접근을 준다").
 *
 * 왜 core가 소유하는가: 구현이 둘 이상이고 서로 다른 패키지에 산다.
 *  · `@ionosphere/proto-pop3`의 인프로세스 락 — DB 없는 구성·테스트·단일 프로세스용
 *  · `@ionosphere/store`의 DB 락 — MRA를 2대 이상 띄우는 순간 유일하게 유효한 구현
 * 백엔드(apps/server)는 둘 중 하나를 주입받아야 하므로, 계약이 어느 한쪽 구현 패키지에 있으면
 * 의존 방향(core → db → store → apps)이 뒤집힌다. SASL 파싱을 core로 올린 것과 같은 이유다.
 *
 * 소유자(owner) 인자가 계약에 있는 이유: 해제와 갱신은 **자기 락에만** 적용돼야 한다.
 * 소유자 없이 accountId만으로 푸는 API는 "락을 뺏긴 세션이 남의 락을 푸는" 사고를 구조적으로
 * 허용한다(POP3는 세션이 끊길 때 항상 release를 부르므로 실제로 일어난다).
 */
export interface MaildropLock {
  /**
   * 리스 갱신 권고 주기(ms). 0이면 갱신이 필요 없다(만료가 없는 인프로세스 락).
   *
   * 호출자가 타이머를 소유하도록 값만 노출한다 — 락 객체가 몰래 타이머를 돌려 DB에 쓰면
   * "이름·시그니처에 드러나지 않는 부수효과"가 되어 수명 관리가 호출자에게 안 보인다.
   */
  readonly refreshIntervalMs: number;

  /** 배타 획득 시도. true면 이 owner가 maildrop을 잡았다. */
  acquire(accountId: string, owner: string, now?: number): Promise<boolean>;

  /**
   * 리스 연장. false면 **이미 락을 잃었다**(만료 후 다른 세션이 탈취) — 호출자는
   * 세션을 계속 신뢰하면 안 된다.
   */
  refresh(accountId: string, owner: string, now?: number): Promise<boolean>;

  /** 해제 — owner가 일치할 때만 푼다. 남의 락에는 무해한 no-op. */
  release(accountId: string, owner: string): Promise<void>;
}
