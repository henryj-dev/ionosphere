# ionosphere — TypeScript 메일 플랫폼 계획서

> 작성일: 2026-07-22 · **상태: 원안 (구현 전에 쓴 것 — 이후 갱신하지 않았다)**
> 프로토콜별 구현 가능 기능 전체 카탈로그(RFC/중요도/난이도/스키마 영향): [docs/PROTOCOLS.md](docs/PROTOCOLS.md)
>
> ⚠ **이 문서는 "무엇을 왜 하기로 했는가"의 원안이지 현재 상태가 아니다.** 계획된 것은
> 대부분 구현됐고, 몇 가지 결정은 뒤집혔다. 현재 상태는 [docs/STATUS.md](docs/STATUS.md),
> 규약은 [CLAUDE.md](CLAUDE.md)가 정본이다.
>
> 원안에서 **바뀐 결정**(2026-08-12 기준):
> - **런타임**: "Bun 워크스페이스 + 듀얼 테스트" → **node 전용**(2026-08-02 bun 지원 종료).
>   계기는 bun의 서버측 STARTTLS 미지원이었다(MTA-STS enforce의 전제라 타협 불가).
>   그래서 §7의 "CI: Bun + Node 듀얼 매트릭스"도 **틀렸다** — 지금은 node 24 단일 잡이고
>   테스트 러너는 `node --test`(+`@ionosphere/testkit` shim)다.
> - **배포 형태**: 단일 노드 → **역할별 3대**(MX/MRA/MSA, 2026-08-02). [docs/SPLIT.md](docs/SPLIT.md)
> - **블롭·DB**: 로컬 FS·SQLite → 라이브는 **공유 PostgreSQL + S3(MinIO)**. 추상화는 원안대로다.
> - **관리 레이어**: §4의 트리에 있는 `apps/admin-ui`는 **만들지 않았다.** 대신 관리 기능이
>   **GUI→API→CLI 3층**으로 정리됐고 명령의 정본은 `@ionosphere/admin-cmd`다(2026-08-10, Phase 6).
>   콘솔은 별도 앱이 아니라 `@ionosphere/api`가 서빙하는 무상태 렌더러다.
> - **패키지 구성**: 원안의 9개 → 실제 24개(`dns`·`spam`·`srs`·`mta-sts`·`tls`·`metrics`·
>   `webhook`·`testkit`·`admin-cmd`·프로토콜별 분리 등). 현재 목록은 [docs/STATUS.md](docs/STATUS.md) §3.
>
> **원안이 그대로 지켜진 것**(뒤집힌 것만 보고 원안 전체를 의심하지 말 것): 프로토콜 직접 구현,
> 순수 엔진 + 얇은 어댑터, 단일 원자 배치, 멀티테넌시 day-1, 의존성 최소화(pg·mysql2뿐),
> §8의 SaaS 통제 4개(전부 완료 — 아래 표).

## 1. 비전

TypeScript로 구현하는 올인원 메일 플랫폼. SMTP/IMAP/POP3/JMAP 프로토콜을 직접 구현하고,
멀티테넌트 SaaS를 지향한다. 포지셔닝 참고 대상: **Stalwart**(Rust 올인원 메일 서버),
**WildDuck/ZoneMTA/Haraka**(Node 프로토콜 구현 선례).

## 2. 확정된 결정사항

| 항목 | 결정 | 비고 |
|---|---|---|
| 구현 방식 | 프로토콜 직접 구현 | 관리 레이어(Postfix 래핑) 아님 |
| 목적 | 제품/SaaS 지향 | 멀티테넌시·API-first·운영성 중심 |
| 메타데이터 DB | **멀티 백엔드: SQLite / PG / MySQL(MariaDB) / Cloudflare D1** | SQLite(빌트인 ~~`bun:sqlite`~~·`node:sqlite`)가 dev/테스트 기본, PG가 프로덕션 기본(라이브는 PG). MySQL·D1 어댑터는 인터페이스 검증 후(Phase 2~). D1은 REST `/raw`를 fetch로 직접(의존성 제로). wire 계약·한도·원자 배치 실측은 [d1-jdbc DESIGN.md](../d1-jdbc/docs/DESIGN.md) 참조 — `{batch:[...]}` 원자성 확정, SQL 100KB/파라미터 100개/문장·배치 1,000문장 한도, bool→1/0·BLOB→number[] 정규화, DB당 10GB(엣지/소형 배포 타깃) |
| 블롭 저장소 | **로컬 FS 기본 + S3 호환 어댑터** (R2 포함) | 원본 메시지(불변). BlobStore 추상화 |
| 검색 | **자체 역색인 테이블 (표준 SQL) + 앱 레벨 바이그램 토크나이저** | 4개 DB 백엔드 전부에서 동일 동작(Stalwart 방식). 추후 PG tsvector 가속 어댑터를 옵션으로 |
| 발송 | **처음부터 자체 MTA** | 큐·재시도·바운스·DKIM 서명을 1단계부터 구현 |
| 런타임 | ~~Bun 워크스페이스, 듀얼 테스트~~ → **node 전용**(2026-08-02) | 원안의 근거(코드는 `node:net`/`node:tls` 기반 런타임 중립)는 유지된다. 바뀐 것은 **런타임 하나를 고른 것**이고, 이유는 bun의 서버측 STARTTLS 미지원이다 |
| 의존성 | **외부 의존 최소화 (Stalwart 모델)** | 단일 노드 최소 배포 = 우리 프로세스 + SQLite(빌트인)로 인프라 의존 제로. npm은 런타임 빌트인 우선 + 드라이버 화이트리스트(`pg`, `mysql2` — SQLite·D1은 의존성 제로). 스팸 필터·재귀 DNS 리졸버·ACME까지 자체 구현. AV만 옵셔널 플러그인 훅(기본 비활성) |

## 3. 스코프

### 프로토콜 (직접 구현)
- **SMTP** — 수신(25), Submission(587), SMTPS(465), STARTTLS
- **IMAP** — IMAP4rev1 + 확장: IDLE, UIDPLUS, MOVE, SPECIAL-USE, CONDSTORE, QRESYNC, NAMESPACE, ENABLE
- **POP3** — POP3S 포함 (가장 작으므로 파이프라인 검증용으로 먼저)
- **JMAP** — RFC 8620/8621. JSON over HTTP, TS와 궁합 최고
- **LMTP** — MTA → 메일스토어 내부 배달
- **ManageSieve** + Sieve 인터프리터

### 메일 인증/보안 스택
- 수신: SPF·DKIM·DMARC 검증, DNSBL, greylisting, 레이트리밋
- 발신: DKIM 서명, SRS(포워딩 시 발신자 재작성)
- 이후: ARC ✅, MTA-STS ✅, TLS-RPT ✅, DNSSEC ✅, DANE ✅(`IONOSPHERE_DANE=1`, 기본 꺼짐)
  - **전제부터 세우고 올렸다.** RFC 7672는 TLSA 조회가 **DNSSEC로 검증**될 것을 요구한다.
    검증 없이 TLSA를 믿으면 DNS를 속일 수 있는 공격자가 **우리가 그의 인증서를 고정하게**
    만들 수 있어, DANE가 막으려던 공격이 DANE를 통해 성립한다. 그래서 순서가:
    ① `packages/dns/src/dnssec.ts` — RRSIG 검증·DS 대조·키 태그(RSASHA256·ECDSAP256·Ed25519)
    ② `packages/dns/src/validating.ts` — 루트 앵커부터 위임을 따라 내려가는 **체인 검증**
       (EDNS0 DO 비트, DNSKEY 자체서명 확인 포함). 판정은 secure/insecure/**bogus** 3상태
    ③ `packages/mail-auth/src/dane.ts` — 인증서 대조(순수). DANE-EE는 말단만, DANE-TA는 체인 전체
    ④ `apps/server/src/dane-lookup.ts` → `MtaWorker.resolveTlsa` → `sendSmtp({dane})`
  - ⚠ **NSEC/NSEC3(부재 증명)는 넣지 않았다.** 그래서 "TLSA/DS가 없다"를 **안전하게 증명하지
    못한다**. 공격자가 DS를 지우면 우리는 `insecure`로 보고 DANE를 적용하지 않는다 — 즉
    **DANE 도입 이전 동작(opportunistic TLS)**으로 돌아갈 뿐이고, 같은 공격자는 TLSA를
    지우는 것으로도 같은 결과를 얻으므로 새로 생긴 구멍이 아니다. 반대 방향, 즉 **틀린 TLSA를
    신뢰하는 경로는 없다** — 그것이 이 구현이 지키는 성질이고 테스트가 겨냥하는 지점이다.
  - 조작 신호(`bogus`)는 "TLSA 없음"과 **다르게** 다룬다: 그 MX를 건너뛰고 지연시킨다.
    뭉개면 TLSA를 망가뜨리는 것만으로 DANE를 끌 수 있다.
- 스팸 판정: **자체 점수 엔진** (DNSBL 가중치 + 휴리스틱 룰 + Bayes) — ✅ 구현됨(`packages/spam`)
  - **§3과 §8의 충돌을 이렇게 풀었다**: §8이 금지하는 것은 **사람의 열람**이지 자동 처리가
    아니다(그렇지 않다면 스팸 판정도 검색 색인도 성립하지 않는다 — 둘 다 이미 본문을 다룬다).
    그 선을 코드로 지킨다:
    ① **토큰을 해시로만 저장**(HMAC + 계정별 솔트) — DB를 열어도 읽을 수 있는 단어가 없다
    ② **계정 경계를 넘지 않음**(PK가 `(account_id, token)`)
    ③ **학습은 사용자의 명시적 행동에서만** — 서버가 스스로 학습하면 오탐이 오탐을 낳는다
    휴리스틱 룰이 헤더·봉투만 보는 것은 그대로다(오탐 비용 때문이지 프라이버시만은 아니다).
- 바이러스 검사: 옵셔널 플러그인 훅만 제공(기본 비활성) — 시그니처 DB 생태계는 복제 불가

### SaaS 레이어
- 멀티테넌시 + 쿼터 + 사용량 미터링 — **데이터 모델에 처음부터 반영**
- 관리 REST API (계정/도메인/알리아스/큐 모니터링) + 관리 UI
- 웹훅/이벤트 시스템 (수신 메일 → HTTP 웹훅, Postmark inbound 스타일)
- SASL: PLAIN/LOGIN + OAUTHBEARER/XOAUTH2, 앱 비밀번호
- ACME 자동 TLS (도메인별 발급/갱신)
- Autoconfig/Autodiscover (Thunderbird/Outlook/iOS 자동 설정)
- 관측성: 구조화 로그, Prometheus/OTel 메트릭, 메시지 단위 추적

### 스코프 밖 (v2+)
CalDAV/CardDAV, 웹메일, 클러스터링/HA, 마이그레이션 도구(imapsync 대체), 저장 시 암호화(FTS와 충돌 — 트레이드오프 문서화 필요)

## 4. 아키텍처

```
ionosphere/ (npm workspace 모노레포 — 원안은 Bun workspace였다)
├─ packages/
│  ├─ proto-smtp/      # SMTP/Submission 파서 + 상태머신 (I/O 없음)
│  ├─ proto-imap/      # IMAP 파서 + 상태머신
│  ├─ proto-pop3/      # POP3
│  ├─ proto-jmap/      # JMAP over HTTP
│  ├─ proto-lmtp/      # 내부 배달
│  ├─ mime/            # RFC 5322/MIME 파싱·직렬화
│  ├─ mail-auth/       # SPF/DKIM/DMARC/ARC/SRS/MTA-STS
│  ├─ dns/             # 재귀 리졸버 (DNSBL 신뢰 조회용) + 캐시, 이후 DNSSEC/DANE
│  ├─ spam/            # 자체 점수 엔진: DNSBL 가중치 + 휴리스틱 + Bayes, AV 플러그인 훅
│  ├─ mta/             # 아웃바운드: 큐(DB), MX 조회, 재시도 백오프, 바운스(DSN), IP 풀
│  ├─ db/              # DB 추상화: 다이얼렉트 어댑터(SQLite/PG/MySQL/D1), 마이그레이션 러너
│  ├─ store/           # 메시지 스토어: 메타(db/ 위) + BlobStore(로컬 FS/S3) + SearchIndex(바이그램 역색인)
│  ├─ sieve/           # Sieve 인터프리터 + ManageSieve
│  ├─ core/            # 테넌트/계정/도메인 모델, SASL, 설정, TLS/ACME
│  └─ api/             # 관리 REST API + 웹훅 디스패처
├─ apps/
│  ├─ server/          # 전부 조립한 단일 프로세스 (Stalwart식 올인원)
│  └─ admin-ui/        # 관리 대시보드 ← ✗ 만들지 않았다. 콘솔은 @ionosphere/api가 서빙하고
│                      #   관리 명령의 정본은 @ionosphere/admin-cmd다(Phase 6)
```

### 설계 원칙
1. **프로토콜 패키지는 순수 파서/상태머신** — 소켓 I/O 없음. 런타임 중립 + 단위테스트 용이.
   소켓/TLS(STARTTLS 업그레이드 포함)는 얇은 어댑터 레이어가 담당.
2. **스토어가 중심 인터페이스** — IMAP/POP3/JMAP/웹훅은 전부 같은 스토어의 다른 뷰.
3. **IMAP + JMAP 요구사항을 스키마에 선반영** (상세: docs/PROTOCOLS.md §0):
   - **email↔mailbox 다대다** (JMAP 라벨 모델 — 폴더 1:N으로 짜면 JMAP에서 막힘)
   - UID 단조증가·재사용 금지, UIDVALIDITY, UIDNEXT
   - **타입별 modseq 변경로그 + expunge 툼스톤** — IMAP CONDSTORE/QRESYNC와
     JMAP /changes가 하나의 인프라를 공유 (Cyrus 검증 설계)
   - 불변 email_id/thread_id/mailbox_id (OBJECTID + JMAP), threadId는 수신 시점 계산
   - 콘텐츠 해시 blobId + 역참조 인덱스(GC·Blob/lookup 겸용)
   - savedate 컬럼, 증분 카운터(크기/건수/안읽음), 임의 키워드 플래그
4. **검색은 수신 시점 인덱싱** — MIME 파싱 → 텍스트 추출 → 바이그램 역색인 삽입.
   블롭은 검색 경로에서 절대 안 읽음. 재인덱싱은 배치 작업으로 별도 설계.
5. **멀티테넌시는 day-1** — 모든 테이블에 tenant 스코프 (JMAP accountId와 자연 결합).
6. **스토어 연산은 단일 원자 배치 단위** — "UID 할당 + 삽입 + modseq 증가 + 카운터 갱신"을
   한 번의 원자 배치로 정의. 다중 왕복 인터랙티브 트랜잭션을 인터페이스에서 금지 —
   D1(배치만 원자적)·SQLite(단일 writer)·PG/MySQL(배치를 트랜잭션으로 래핑) 전부 커버되는 교집합.
   DB별 SQL은 보수적 공통 부분집합 + 다이얼렉트 분기(upsert/returning 등)로.
7. **표준 세대교체 대응** — SMTP는 rfc5321bis 기준, DMARC는 RFC 9989/9990/9991(7489 폐기,
   DNS Tree Walk), DKIM 모듈은 DKIM2(2027 예상) 대비 교체 가능하게.

## 5. 로드맵

### Phase 0 — 뼈대와 최단 파이프라인
- 모노레포 셋업 (Bun workspace, 듀얼 테스트 CI)
- 스토어 스키마 v1 — 설계: [docs/SCHEMA.md](docs/SCHEMA.md)
- 블롭 추상화 (로컬 FS + S3)
- SMTP 수신 (25, STARTTLS) → 스토어 저장
- POP3 (110/995) → 꺼내기
- **완료 기준: 실제 메일 클라이언트로 메일 받고 POP3로 읽기**

### Phase 1 — 자체 MTA (발송)
- PG 기반 발송 큐, MX 조회, 재시도 백오프, 바운스/DSN 처리
- DKIM 서명, Submission(587) + SASL 인증
- suppression list 기초 (발송 레이트리밋은 §8 통제 ③으로 Phase 2 이관)
- **완료 기준: Gmail 수신함에 도달 (DKIM pass)**

### Phase 2 — 수신 인증 + 관리 API + SaaS 온보딩 통제
- SPF/DKIM/DMARC 검증 파이프라인, DNSBL, greylisting
- 관리 REST API (테넌트/계정/도메인/알리아스/큐 조회)
- PG FTS 인덱싱 파이프라인 (pg_bigm)
- **SaaS 신뢰 통제 (§8 참조 — 외부 도메인 고객을 받기 위한 전제):**
  1. **도메인 소유권 검증** — DNS TXT 토큰(`domains.verify_token`) 게시 확인 +
     SPF·MX 레코드 존재 검증. 통과해야 `domains.status=1(active)` + 발송 허용
  2. **미검증 도메인 아웃바운드 거부** — MTA enqueue/발송 게이트에서 발신 도메인의
     `status=1` + 유효 SPF/MX 확인. 미검증 도메인은 서버단에서 발송 거부 (submission 553)
  3. **계정별 레이트리밋** — 분/시/일 단위 발송 한도(`dedup_tracking` 계열 또는 전용
     카운터). 초과 시 submission 지연(4xx)·거부. 핫 계정·계정 탈취 발송 폭주 방어
  4. **AUP + abuse 대응** — 이용약관(스팸·대량 무단 메일 금지) 문서 + abuse@ 처리 흐름,
     스팸 신고율·바운스율 임계 모니터링 → 자동 발송 정지. **내용 미열람 원칙** —
     정당성은 콘텐츠가 아니라 위 구조적 통제로 강제 (프라이버시)
- **완료 기준: API로 테넌트 생성부터 메일 송수신까지 e2e + 미검증 도메인 발송 거부 검증**

### Phase 3 — IMAP (최대 난관, 기간 최대 배정)
- IMAP4rev1 코어 → IDLE → UIDPLUS/MOVE/SPECIAL-USE → CONDSTORE/QRESYNC
- Dovecot의 `imaptest` 호환성 테스트로 검증
- **완료 기준: Thunderbird/iOS Mail에서 정상 동작 + imaptest 통과**

### Phase 4 — JMAP, Sieve, 웹훅
- JMAP 코어 (Mailbox/Email/EmailSubmission), 검색 스니펫
- Sieve 인터프리터 + ManageSieve
- 수신 웹훅 디스패처 (재시도 포함)

### Phase 5 — 제품화
- 관리 UI, ACME 자동 TLS, Autoconfig/Autodiscover
- OAUTHBEARER/XOAUTH2, 앱 비밀번호
- ARC/SRS/MTA-STS, 관측성(메트릭/추적), 사용량 미터링

## 6. 리스크와 대응

| 리스크 | 대응 |
|---|---|
| IMAP 구현 복잡도 (상태머신·동시성·확장) | Phase 3에 기간 최대 배정. imaptest로 조기·상시 검증. WildDuck 소스 참고 |
| 아웃바운드 배달성 (IP 평판, 25번 포트 차단) | 개발 중엔 스테이징 도메인 + 테스트 수신함. 프로덕션 IP 워밍업 절차 문서화 |
| Bun의 TLS/소켓 엣지케이스 (STARTTLS 업그레이드 등) | node:net/tls만 사용, CI 듀얼 테스트. 문제 시 해당 컴포넌트만 Node 실행. **현실화됨(2026-07)**: Bun의 서버측 TLSSocket 업그레이드 미지원(oven-sh/bun#25044) — STARTTLS 핸드셰이크는 Node에서만 동작 확인. SMTP 리스너는 Bun 수정 전까지 Node 실행 권장 |
| 스토어 스키마 실수 → 대규모 마이그레이션 | Phase 0에서 IMAP/JMAP 요구사항(UID/MODSEQ) 선반영, 스키마 리뷰 별도 진행 |
| CJK 검색 품질 | 앱 레벨 바이그램 + 자체 역색인으로 시작, SearchIndex 추상화로 PG tsvector 가속·전용 엔진 교체 경로 확보 |
| DB 4종 지원 매트릭스 부담 (다이얼렉트 분기, 테스트 4배) | Phase 0은 SQLite+PG만. 스토어 연산을 원자 배치로 제한해 인터페이스를 D1 호환으로 먼저 고정 → MySQL/D1 어댑터는 Phase 2~에 추가. CI 매트릭스는 SQLite(전체) + PG(전체) + MySQL/D1(스토어 계약 테스트만)으로 비용 제어 |
| 외부 의존 최소화로 인한 범위 확대 (재귀 DNS 리졸버, 자체 스팸 엔진) | 리졸버는 DNSBL 정확성을 위해 어차피 필요 — Phase 2 진입 전 스파이크로 규모 검증. DNSSEC/DANE는 Phase 5로 분리. 스팸 룰 튜닝은 지속 운영 작업으로 인정하고 룰을 데이터 파일로 외부화 |
| 제3자 도메인 호스팅(SaaS) → 공유 IP 평판 오염 | 한 테넌트의 스팸이 IP 평판을 망가뜨려 전원 배달성 저하. §8 온보딩 통제(도메인 검증·미검증 발송 거부·레이트리밋)로 진입 차단 + 신고율/바운스율 임계 모니터링 → 자동 정지. 규모 확대 시 전용 IP·테넌트별 평판 격리(Phase 5 IP 풀) |
| 클라우드 25번 포트 차단 (Vultr 등) | 신규 인스턴스는 아웃바운드 25 기본 차단 — provider 티켓으로 해제(용도·물량·마케팅 여부·abuse 통제 소명). 해제 전엔 릴레이 경유 발송으로 개발. **PTR/rDNS는 해제와 별개로 IP에 선설정** (Gmail FCrDNS 요건) |

## 7. 테스트 전략
- 프로토콜 파서: 순수 함수라 단위테스트 중심 + 퍼징(잘못된 입력 내성)
- IMAP: Dovecot `imaptest` 스위트
- e2e: 실 클라이언트(Thunderbird headless / 스크립트된 IMAP 클라이언트) + swaks(SMTP)
- CI: ~~Bun + Node 듀얼 매트릭스~~ → **node 24 단일 잡**(postgres:17·mysql:8 서비스로 실연결 테스트).
  러너는 `node --test`이고 `@ionosphere/testkit`이 API를 잇는다

## 8. SaaS 신뢰·규정준수 모델

외부 도메인 고객(SaaS, 스코프 §3의 3번째 유형)을 받기 위한 전제. **핵심 원칙: 운영자는
사용자 메일 내용을 열람하지 않는다 — 정당성은 콘텐츠 검열이 아니라 구조적 통제로 강제한다.**
이는 Vultr 등 provider의 발송 심사, 그리고 대량 발송자 요건(PROTOCOLS §7) 양쪽의 답이기도 함.

| 통제 | 내용 | 구현 위치 | 상태 |
|---|---|---|---|
| ① 도메인 소유권 검증 | DNS TXT 토큰(`domains.verify_token`) 게시 확인 + SPF·MX 존재 검증 → `status=1` | api/domains.ts + dns/ | ✅ 완료 |
| ② 미검증 도메인 발송 거부 | enqueue·발송 게이트에서 발신 도메인 `status=1` + 유효 SPF/MX 확인, 아니면 거부(553) | mta/enqueue.ts | ✅ 완료 |
| ③ 계정별 레이트리밋 | 분/시/일 발송 한도 카운터, 초과 시 지연(4xx)·정지 — 계정 탈취 폭주 방어 | mta/ + store/ | ✅ 완료 |
| ④ AUP + abuse 대응 | 이용약관(스팸·대량 무단 금지) + abuse@ 흐름 + 신고율/바운스율 임계 → 자동 정지 | 문서 + mta/abuse.ts + mta/arf.ts | ✅ 완료(신고율 2026-08-07) |
| DKIM 서명 | 발신 도메인 키로 RSA-2048 + Ed25519 이중 서명 | mail-auth/ + mta/ | ✅ Phase 1 |
| suppression | 하드바운스·불만·수신거부 → 발송 억제 | mta/ | ✅ Phase 1 |

**내용 미열람과 통제의 양립**: 콘텐츠를 안 봐도 (a) 발송 자격을 도메인 검증으로 게이팅하고
(b) 물량을 레이트리밋으로 제한하며 (c) 결과 신호(신고율·바운스율)로 사후 정지하므로,
"통제 부재"가 아니라 "콘텐츠 비의존 통제"다. 이 4개 통제 완비 전에는 외부 도메인 고객을
받지 않는다 (자사 팀 메일 §3-1·2는 무관하게 사용 가능).
