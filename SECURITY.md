# 보안 정책

이 저장소는 **메일 서버 구현체**다. SMTP·POP3·IMAP·JMAP·ManageSieve·LMTP의 프로토콜
상태머신과 DKIM·SPF·DMARC·ARC·MTA-STS·ACME를 외부 라이브러리 없이 직접 구현했다.
그 말은 **일반적인 애플리케이션보다 취약점의 영향 범위가 넓다**는 뜻이다 — 인증 우회 하나가
남의 메일함 접근이고, 릴레이 판정 결함 하나가 오픈 릴레이다.

## 신고 방법

**공개 이슈로 올리지 말 것.** GitHub의 비공개 취약점 신고를 쓴다:

> 저장소 상단 **Security** 탭 → **Report a vulnerability**

신고에 아래가 있으면 판정이 빨라진다.

- 영향받는 표면(SMTP 수신 / 제출 / IMAP / JMAP / 관리 API / CLI 중 어디인가)
- 재현 절차 — 가능하면 이 저장소의 테스트 형태로. `packages/*/test/`의 기존 테스트가 참고가 된다
- 공격자가 **무엇을 얻는가**(메일 열람 / 발송 권한 / 서비스 정지 / 정보 노출)
- 인증이 필요한가, 필요하다면 어느 등급인가(익명 / 계정 / 관리자)

응답은 **영업일 기준 3일 이내**를 목표로 한다. 이 프로젝트는 개인이 유지보수하므로
그보다 늦어질 수 있고, 늦어지면 늦어진다고 알린다.

## 범위

**범위 안**

- 인증·인가 우회(SASL, 앱 비밀번호, 관리 API 토큰, JMAP 세션)
- 릴레이 판정 결함 — 인증 없이 외부 주소로 배달되는 경로
- 메일 격리 위반 — 다른 계정·다른 테넌트의 메시지나 메타데이터 접근
- 메일 인증 판정 위조(DKIM/SPF/DMARC/ARC 결과를 공격자가 원하는 값으로 만드는 것)
- 파서 취약점 — MIME·헤더·프로토콜 파서의 메모리·CPU 고갈, 무한 루프
- 암호 사용 오류 — 키 관리, 상수시간 비교, TLS 설정
- 저장 데이터 노출(DKIM 개인키, 비밀번호 해시, 스마트호스트 토큰)

**범위 밖**

- 운영자가 잘못 설정한 결과(예: TLS 없이 평문 AUTH를 켜는 것). 다만 **기본값이 안전하지 않다면**
  그것은 범위 안이다 — 이 프로젝트는 "실패 시 더 안전한 쪽"을 설계 기준으로 삼는다
- 인증된 관리자가 할 수 있는 파괴적 동작(설계상 그 권한이 있다)
- 실제 서비스 인스턴스에 대한 스캔·부하 시험. **하지 말 것.** 신고는 코드에 대해 한다
- 표준을 따른 결과 생기는 스팸·남용 가능성 일반론(예: SMTP가 평문 프로토콜이라는 사실)

## 알고 있는 한계

숨기지 않는다. 아래는 인지하고 있으며 취약점 신고 대상이 아니다.

- **LMTP·ManageSieve는 기본 미기동**이고, 켜면 배치에 따라 평문 인증이 가능하다.
  내부망 전용으로 쓰도록 설계됐다
- **메트릭 엔드포인트에 인증이 없다.** 주소 바인딩으로 제한하는 것을 전제한다
  (`IONOSPHERE_LISTEN_METRICS`에 공인 주소를 넣지 말 것)
- **DNSSEC 부재 증명(NSEC/NSEC3)을 검증하지 않는다.** DS 레코드를 지우는 공격은
  DANE 미적용으로 귀결된다
- 새로 만든 구현이라 **오래 검증된 MTA만큼의 실전 노출을 겪지 않았다**

## 지원 버전

`main`만 지원한다. 릴리스 브랜치를 두지 않으므로 수정은 `main`에 올라간다.

---

## English

This is a from-scratch mail server (SMTP/POP3/IMAP/JMAP/ManageSieve/LMTP, plus DKIM/SPF/
DMARC/ARC/MTA-STS/ACME implemented without external libraries). Please report vulnerabilities
privately via **Security → Report a vulnerability**, not as a public issue.

In scope: authentication/authorization bypass, relay decision flaws (open relay), cross-account
mail access, forged mail-authentication results, parser DoS, cryptographic misuse, and exposure
of stored secrets. Out of scope: operator misconfiguration (unless the *default* is unsafe),
actions available to an authenticated administrator by design, and scanning live instances —
please don't. Report against the code.

Known limitations are listed in Korean above; the short version is that LMTP/ManageSieve are
off by default and assume an internal network, the metrics endpoint relies on address binding
rather than authentication, and DNSSEC proof-of-absence is not validated.

Target response time is 3 business days. This is maintained by one person.
