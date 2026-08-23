# 프로토콜 기능 카탈로그

> 조사일: 2026-07-22 · 출처: IANA 레지스트리(SMTP/IMAP/POP3/Sieve/JMAP) 전수 + RFC 원문 + Gmail/Dovecot/Stalwart 실제 광고 capability 대조
>
> 티어 기준 — **MUST**: 없으면 실클라이언트 상호운용 깨짐 · **SHOULD**: 널리 쓰이고 실익 큼 · **NICHE**: 특정 요구 있을 때만 · **AVOID**: 폐기/보안 위험
>
> ⚠ **이 문서는 "무엇을 만들 가치가 있나"의 카탈로그이고, 티어·난이도·"후순위"는 조사 시점의
> 판단이다.** 지금 무엇이 구현돼 있는지는 여기서 읽지 말 것 — [STATUS.md](STATUS.md) §1·§2가
> 답한다. ✅ 표시가 붙은 항목은 이후 갱신하며 확인한 것이고, 표시가 없다고 미구현이라는 뜻은 아니다.
> (예: XOAUTH2·OAUTHBEARER는 표에 "후순위"로 적혀 있지만 **네 프로토콜에 구현돼 있다**.)
>
> 반면 **"넣지 않기로 했다"는 결정은 계속 유효하다**(CRAM-MD5·APOP·DIGEST-MD5·SMTP 콜아웃 검증).
> 되살리려면 그 자리에 적힌 근거부터 반박할 것.

---

## 0. 교차 발견사항 (스키마/아키텍처에 영향)

여러 프로토콜 조사가 **같은 인프라로 수렴**함. Phase 0 스키마에 반영할 것:

| 결정 | 근거 프로토콜 | 내용 |
|---|---|---|
| **email↔mailbox 다대다** | JMAP | JMAP은 라벨 모델 — Email이 여러 mailbox에 동시 소속. 폴더 모델(1:N)로 짜면 JMAP에서 막힘 |
| **타입별 modseq 변경로그 + 툼스톤** | IMAP CONDSTORE/QRESYNC + JMAP /changes | 하나의 변경로그가 IMAP 재동기화와 JMAP 델타 싱크를 모두 서빙 (Cyrus 검증된 설계) |
| **콘텐츠 해시 blobId** | JMAP + 스토어 | 블롭은 SHA 기반 주소, 역참조 인덱스(GC + Blob/lookup 겸용) |
| **불변 email_id / thread_id / mailbox_id** | IMAP OBJECTID + JMAP | 이동/리네임에도 불변. threadId는 수신 시점에 References/In-Reply-To로 계산 |
| **UID 기계장치** | IMAP/POP3 | 메일함별 단조증가 UID, UIDVALIDITY, UIDNEXT. POP3 UIDL도 여기서 파생 |
| **수신자별 트랜잭션** | LMTP | DATA 후 수신자별 개별 성공/실패 — 배달 파이프라인이 부분 성공을 지원해야 함 |
| **savedate 컬럼** | IMAP SAVEDATE | (message, mailbox) 삽입 시각, INTERNALDATE와 별개 |
| **증분 카운터** | IMAP STATUS=SIZE/QUOTA + JMAP Mailbox/Quota | 메일함·계정별 바이트/건수/안읽음 카운터를 트랜잭션으로 유지 |
| **임의 키워드 플래그** | IMAP RFC 8457 + JMAP keywords | 시스템 플래그 외 `$Junk`, `$label1` 등 자유 키워드 저장 |
| **accountId 네임스페이스** | JMAP + 멀티테넌시 | 모든 객체가 계정 스코프 — 테넌시 모델과 자연 결합 |

**표준 세대교체 주의**: SMTP 기준은 rfc5321bis(2025-07 rev44, 막바지), DMARC는 **RFC 9989/9990/9991**(2026-05, RFC 7489 폐기 — PSL 대신 DNS Tree Walk), DKIM2는 WG 진행 중(2027년 RFC 예상 — DKIM 코드를 교체 가능하게 설계).

---

## 1. SMTP (IANA 36개 키워드 전수 분류)

### MUST
| 기능 | RFC | 설명 | 난이도 |
|---|---|---|---|
| 베이스 ESMTP | 5321→bis | 상태머신, dot-stuffing, 응답코드, Received 헤더 | 중 |
| STARTTLS | 3207 | TLS 업그레이드. 업그레이드 후 상태 리셋 규칙이 버그 소굴 | 중 |
| AUTH (SASL) | 4954 | PLAIN+LOGIN 필수, XOAUTH2/OAUTHBEARER는 후순위 → ✅ **네 메커니즘 전부 구현**(+SCRAM-SHA-256 — §7 SASL) | 중 |
| SIZE | 1870 | 최대 크기 사전 선언 | 하 |
| PIPELINING | 2920 | 명령 배치. "early talker" 감지로 안티스팸 효과 덤 | 하-중 |
| 8BITMIME | 6152 | 8비트 본문 수용 | 하 |
| ENHANCEDSTATUSCODES | 2034/3463 | `250 2.1.5` 구조화 상태코드 | 하 |
| SMTPUTF8 | 6531-6533 | 국제화 주소(EAI). Gmail 기대 기준선 | 중-상 |
| Submission 프로파일 | 6409 | 587: AUTH 필수 + 메시지 fix-up. 25번과 정책 분리 | 중 |
| 암시적 TLS :465 | 8314 | submission 선호 포트. TLS≥1.2 | 하 |

### SHOULD
| 기능 | RFC | 설명 | 난이도 |
|---|---|---|---|
| DSN | 3461-3464 | NOTIFY/RET/ENVID/ORCPT + multipart/report 바운스 생성 | 상 |
| CHUNKING (BDAT) | 3030 | 길이 프리픽스 전송. MS/Google 광고, Exchange가 사용 | 중 |
| LIMITS | 9422 (2024) | EHLO에서 세션 한도 공지. 싸고 모던함 | 하 |
| REQUIRETLS | 8689 | TLS 강제 MAIL 파라미터. 채택 낮지만 표준 답안 | 중 |
| VRFY=252/EXPN 차단 | 5321 §7.3 | 사용자 열거 방지 — VRFY는 항상 252 | 하 |
| LMTP | 2033 | §4 참고. SMTP 엔진 95% 재사용 | 하(엔진 있으면) |

### NICHE
FUTURERELEASE 4865(예약발송 — **SaaS 기능으로 유용, 검토 가치**), BINARYMIME 3030, ETRN 1985, DELIVERBY 2852, MT-PRIORITY 6710, RRVS 7293, BURL 4468, XCLIENT/XFORWARD(무RFC, 프록시 뒤에 서면 필요)

### AVOID
TURN(메일 탈취 벡터), SEND/SOML/SAML(RFC 2821에서 제거), UTF8SMTP(→SMTPUTF8), CRAM-MD5/DIGEST-MD5/NTLM(약한 다이제스트), TLS<1.2, 평문 AUTH 광고

**2026 최소 신뢰 EHLO 세트**: 25번 `SIZE 8BITMIME PIPELINING ENHANCEDSTATUSCODES STARTTLS SMTPUTF8` / 587·465 `+AUTH LIMITS (CHUNKING DSN 선택)`

**리스너는 3프로파일 1엔진**: 25(릴레이: AUTH 없음, 수신자 검증 엄격) / 587(submission: TLS+AUTH 필수) / 465(암시적 TLS). LIMITS 값은 TLS/AUTH 전후로 다르게 광고 가능.

---

## 2. IMAP (IANA Capabilities 레지스트리 전수 분류)

### 전략: rev2 내부 엔진, rev1 호환 응답
IMAP4rev2(RFC 9051)는 Tier 1 확장 15개를 베이스에 흡수(ENABLE, IDLE, NAMESPACE, UNSELECT, UIDPLUS, ESEARCH, SEARCHRES, SASL-IR, LITERAL-, LIST-EXTENDED, LIST-STATUS, MOVE, SPECIAL-USE, STATUS=SIZE, BINARY-APPEND). **내부는 rev2 시맨틱**(\Recent 없음, ESEARCH 응답, 확장 LIST가 코어)으로 짜고, `ENABLE IMAP4REV2` 전까지 rev1 호환 응답(untagged SEARCH, LSUB) 방출. rev1+rev2 동시 광고. (rev2 광고하는 건 현재 Stalwart뿐 — 클라이언트 채택 얇음)

### MUST — 실질적 상호운용 하한선 (Gmail 광고 세트가 증거)
| Capability | RFC | 설명 | 난이도 | 스키마 |
|---|---|---|---|---|
| IDLE | 2177 | 실시간 푸시 | 하 | 세션 간 변경 알림 버스 |
| ENABLE | 5161 | 확장 옵트인 게이트 | 하 | — |
| NAMESPACE | 2342 | 네임스페이스/구분자 공지 | 하 | — |
| UIDPLUS | 4315 | APPENDUID/COPYUID — 동기화 정확성 핵심 | 하 | UID 기계장치 |
| MOVE | 6851 | 원자적 이동 | 하 | copy+delete 트랜잭션 |
| SPECIAL-USE (+CREATE-) | 6154 | \Sent \Trash 등 폴더 역할 자동감지 | 하 | 메일함 속성 컬럼 |
| LITERAL- | 7888 | 비동기 리터럴(4KB 캡 — 흐름제어 유지) | 하 | 파서만 |
| SASL-IR | 4959 | AUTH 왕복 절약 | 하 | — |
| ID | 2971 | 클라이언트 식별 (일부 클라이언트 요구) | 최하 | — |
| UNSELECT | 3691 | expunge 없는 닫기 | 최하 | — |
| CHILDREN | 3348 | \HasChildren — 트리 렌더링 | 하 | — |
| ESEARCH | 4731 | 압축 SEARCH 응답 | 하-중 | — |
| LIST-EXTENDED | 5258 | LIST 옵션 — **서버에서 가장 지저분한 파서** | 중 | — |
| LIST-STATUS | 5819 | LIST에 STATUS 인라인 (Thunderbird 헤비유저) | 하 | — |
| CONDSTORE | 7162 | MODSEQ/CHANGEDSINCE 플래그 재동기화 | 중-상 | **modseq 컬럼 + highestmodseq** |

### SHOULD
| Capability | RFC | 설명 | 난이도 | 스키마 |
|---|---|---|---|---|
| QRESYNC | 7162 | SELECT 한 방 재동기화 + VANISHED | 상 | **expunge 툼스톤 로그 (uid, 삭제시 modseq)** |
| OBJECTID | 8474 | 불변 EMAILID/THREADID/MAILBOXID | 중 | 불변 id (교차 발견 §0) |
| COMPRESS=DEFLATE | 4978 | 스트림 압축 — 모바일 대역폭 (zlib flush 시맨틱 주의) | 중 | — |
| STATUS=SIZE | 8438 | 메일함 크기 | 하 | 증분 카운터 |
| APPENDLIMIT | 7889 | 최대 APPEND 크기 공지 | 최하 | — |
| QUOTA | 9208 | 쿼터 조회/설정 (2087 폐기함 — 9208로 구현) | 중 | 쿼터 회계 |
| SEARCHRES | 5182 | `$` 검색결과 참조 | 하 | 세션 상태 |
| WITHIN | 5032 | YOUNGER/OLDER 검색 | 최하 | — |
| SORT / SORT=DISPLAY | 5256/5957 | 서버 정렬 — 웹메일용 | 중 | 봉투 필드 인덱스 |
| THREAD=REFERENCES | 5256 | JWZ 스레딩 | 중-상 | Message-ID/References 인덱스 |
| MULTIAPPEND | 3502 | 원자적 다중 APPEND (마이그레이션 도구) | 하-중 | — |
| BINARY | 3516 | 서버측 전송 인코딩 해제 | 중 | — |
| SAVEDATE | 8514 | 메일함 저장 시각 | 하 | savedate 컬럼 |
| PREVIEW | 8970 | 서버 생성 미리보기 — 모바일 큰 이득 | 중 | **수신 시 캐시 컬럼 권장** |
| UTF8=ACCEPT | 9755 | mUTF-7 대신 UTF-8 메일함명 | 중 | UTF-8 네이티브 저장 + mUTF-7 변환 |
| UNAUTHENTICATE | 8437 | 세션 재사용 | 하 | — |

### NICHE
ACL 4314(공유 메일함 — 팀 기능 시 필요, 난이도 상), METADATA 5464, NOTIFY 5465(클라이언트 거의 없음 — JMAP이 해결), CATENATE 4469, URLAUTH 4467, MULTISEARCH 7377, PARTIAL 9394(대형 메일함 페이징 — 신규), SEARCH=FUZZY 6203, REPLACE 8508(드래프트), UIDONLY 9586(신규 — 서버 단순화), INPROGRESS 9585, JMAPACCESS 9698(**JMAP 병행 서버니 최하 비용으로 광고 가치**), IMAPSIEVE 6785

### AVOID
LOGIN-REFERRALS/MAILBOX-REFERRALS(죽음), ANNOTATE-EXPERIMENT-1, CONVERT, UTF8=ALL/APPEND/USER(IANA OBSOLETE), UTF8=ONLY(레거시 클라이언트 차단), XLIST(SPECIAL-USE로 대체됨)

**capability 아니지만 필수**: RFC 5530 응답코드(OVERQUOTA, TRYCREATE 등 — 클라이언트 재시도 로직이 의존), RFC 8457 키워드($Junk/$NotJunk/$Important/$Phishing)

**권장 구현 순서**: Tier1 전부 → CONDSTORE → QRESYNC → {OBJECTID+SAVEDATE+STATUS=SIZE 스키마 배치} → COMPRESS/PREVIEW/QUOTA → SORT/THREAD(웹메일 시) → IMAP4REV2 광고

---

## 3. POP3

베이스 RFC 1939 + CAPA(RFC 2449). 와이어는 셋 중 최쉬움 — 어려움은 전부 스토어 시맨틱(maildrop 배타 잠금, UPDATE 상태 커밋, 영속 UIDL).

### MUST
CAPA, TOP, **UIDL**("서버에 남기기" 클라이언트 필수), USER/PASS, SASL(RFC 5034 — 1734 폐기함), STLS(2595, 핸드셰이크 후 상태 리셋+CAPA 재발급), **암시적 TLS :995**(8314 — 모던 클라이언트 기본), RESP-CODES(`[IN-USE]` `[SYS/TEMP]` 등)

### SHOULD
PIPELINING, AUTH-RESP-CODE(3206 — `[AUTH]`로 "비번 틀림 vs 서버 장애" 구분), IMPLEMENTATION, LOGIN-DELAY, EXPIRE

### NICHE / AVOID
UTF8+LANG(6856, EAI 연동 시), **APOP은 구현 금지**(MD5 + 평문 동등 비밀 저장 요구)

---

## 4. LMTP (RFC 2033)

- LHLO 인사(HELO/EHLO에 긍정 응답 금지), **DATA 종료 후 RCPT 순서대로 수신자별 개별 응답** — 큐 없는 배달 에이전트가 존재 이유
- 25번 포트 금지. 관례: TCP 24 또는 유닉스 소켓, 신뢰 네트워크 전용, 보통 무인증
- PIPELINING·ENHANCEDSTATUSCODES **MUST**, 8BITMIME SHOULD, CHUNKING/SIZE/SMTPUTF8/DSN 통상 지원
- **아키텍처 요점: Sieve 실행·쿼터 체크·중복 DB 갱신이 일어나는 지점** (Dovecot LMTP+Pigeonhole이 레퍼런스 모델)
- 구현: SMTP 엔진에 모드 플래그 — 신규 로직은 수신자별 부분 성공 트랜잭션뿐

---

## 5. Sieve + ManageSieve

### ManageSieve (RFC 5804)
- 포트 4190, IMAP풍 문법(태그 없음, 클라→서버 리터럴은 항상 `{n+}`)
- 명령: CAPABILITY/AUTHENTICATE/STARTTLS + PUTSCRIPT/LISTSCRIPTS/SETACTIVE/GETSCRIPT/DELETESCRIPT/RENAMESCRIPT/CHECKSCRIPT/HAVESPACE
- **결합 주의: PUTSCRIPT/CHECKSCRIPT가 서버측 Sieve 검증을 요구** — Sieve 파서 없이 ManageSieve 못 만듦
- 활성 스크립트는 유저당 정확히 1개. `SIEVE` capability 문자열이 클라이언트 UI를 결정(Roundcube가 지배적 클라이언트 — 서버가 광고하는 만큼 UI 적응)
- JMAP Sieve(RFC 9661)가 대안 관리 채널 — 우리는 둘 다 가능

### Sieve 언어 — MUST 확장 (Roundcube 생성 세트)
| 확장 | RFC | 설명 | 난이도 |
|---|---|---|---|
| 베이스 | 5228 | if/require/stop, keep/discard/redirect, 암묵적 keep | 중 |
| fileinto | 5228 | 폴더로 배달 — 최다 사용 액션 | 하 |
| envelope | 5228 | 봉투 테스트 (LMTP에서 봉투 전달 필요) | 하 |
| copy | 3894 | `:copy` — 암묵 keep 유지 사본 | 최하 |
| vacation (+seconds) | 5230/6131 | 자동응답 — **루프 방지·핸들별 추적 DB가 본체** | 중-상 |
| variables | 5229 | `${1}` 캡처 — 다수 확장의 전제 | 중 |
| relational | 5231 | `:value`/`:count` 숫자 비교 | 하 |
| imap4flags | 5232 | 배달 시 플래그 설정 | 하 |
| reject/ereject | 5429 | 거부 (ereject는 프로토콜 레벨 5xx 선호, 백스캐터 주의) | 중 |
| subaddress | 5233 | `user+detail@` 플러스 주소 | 하 |
| date/index | 5260 | 날짜 테스트 (타임존 주의) | 중 |
| duplicate | 7352 | Message-ID 중복 제거 — 만료되는 영속 ID DB 필요 | 중 |

### SHOULD
body 5173, mailbox 5490(`:create`), special-use 8579(**스팸 폴더링의 정도**), spamtest/virustest 5235(스캐너 점수 0-10 정규화), editheader 5293(기본 비활성 권장), environment 5183, include 6609, enotify 5435(mailto=5436), **regex(무RFC 영원한 드래프트지만 전원 구현 — ReDoS 방지로 RE2 계열/타임아웃 필수)**, fcc 8580, ihave 5463

### NICHE
extlists 6134(주소록 연동), mime/foreverypart 5703(난이도 상), **mailboxid 9042(id 기반 스토어면 공짜 승리 — 우리 해당)**, imapsieve 6785(난이도 상), processcalendar 9671(캘린더 시), convert 6558(스킵)

**참고**: Dovecot 기본 활성 세트 ≈ MUST+SHOULD 합집합. Stalwart는 레지스트리 거의 전부(28+).

---

## 6. JMAP

### RFC 현황 (2026-07)
| RFC | 내용 | 티어 |
|---|---|---|
| 8620 | Core — 세션/배치 호출/델타 싱크/푸시/블롭 | MUST |
| 8621 | Mail — Mailbox/Thread/Email/Identity/EmailSubmission/VacationResponse | MUST |
| 8887 | WebSocket 전송 + 푸시 | SHOULD (저비용 고효과) |
| 9749 | VAPID Web Push (2025) — PWA 웹메일 사실상 필수 | SHOULD |
| 9425 | Quotas | SHOULD |
| 9404 | Blob 관리 (업로드/범위조회/역참조 lookup) | SHOULD |
| 9661 | Sieve 스크립트 관리 | SHOULD (Sieve 엔진 있으면 저비용) |
| 9670 | Sharing/Principals — 공유 기능의 기반 | SHOULD-NICHE |
| 9007 | MDN | NICHE |
| 9219 | S/MIME 검증 (verify만 — 서명/암호화 드래프트는 죽음) | NICHE |
| 9610 | Contacts (JSContact RFC 9553) | v2 |
| Calendars | draft-27, IESG — RFC 임박이지만 **별도 프로젝트 규모** | v2 |
| filenode/emailpush/mail-sharing | 활성 드래프트 — 관찰 | watch |

### Core(8620) 구현 포인트
- `/get` `/set` `/changes` `/query` `/queryChanges` + 백레퍼런스(`#` JSON 포인터 해석기)
- **`/changes`가 스키마를 결정**: 타입별 state 문자열 + 변경로그(modseq+툼스톤) — IMAP과 공유 (§0)
- **`/queryChanges`는 최난도 — `cannotCalculateChanges` 응답으로 합법 회피 가능. 먼저 그렇게 출시**
- 푸시 3단: StateChange 계산 → SSE(EventSource) → PushSubscription(RFC 8030/8291/8292 Web Push)
- 블롭: 업로드/다운로드 URL, 고아 블롭 만료 GC
- `Core/echo`부터 (5분 작업, 파이프라인 검증)

### Mail(8621) 난이도 지도
- **Email이 괴물**: MIME→JSON bodyStructure, 헤더 5형식 파싱, textBody/htmlBody 휴리스틱(§4.1.4), keywords↔IMAP 플래그 매핑, Email/import·Email/parse. 나머지는 평이
- Thread: 서버가 스레딩 계산 의무(알고리즘은 자유 — References + 정규화 Subject 관례)
- EmailSubmission: `onSuccessUpdateEmail`(드래프트→보낸함 자동 이동), `undoStatus`(**발송 취소!**), `sendAt`(예약 발송) — SMTP FUTURERELEASE와 짝
- SearchSnippet: FTS 하이라이터에 위임

### 생태계 현실 (2026)
- 서버: Stalwart(최완성 — 컨포먼스 타깃), Cyrus/Fastmail(레퍼런스), Apache James/Twake
- 클라이언트: Fastmail 앱, Twake, aerc, meli, Ltt.rs(**최엄격 — 테스트 클라이언트로 사용 권장**)
- Thunderbird 아직 미지원이지만 Mozilla "Thundermail"이 JMAP 약속 — 시기적으로 좋은 베팅
- Apple Mail/Gmail/Outlook 미지원 → **IMAP/SMTP는 여전히 의무**

---

## 7. 인증/보안 스택

### 표준 세대교체 (2026-07 검증)
- **DMARC = RFC 9989/9990/9991 (2026-05)** — 7489 폐기. `pct` 제거(→`t=` 테스트 플래그), PSL 대신 **DNS Tree Walk**, `psd=`/`np=` 태그. 신규 구현은 9989 알고리즘으로
- **DKIM2**: draft-ietf-dkim-dkim2-spec-04 진행 중, RFC는 2027년경 — DKIM 모듈을 교체 가능하게 설계
- **BIMI**: 여전히 드래프트 (RFC 아님)
- **MS도 합류**: Outlook.com 2025-05부터 대량발송 요건 집행. Gmail은 2025-11부터 영구 거부로 격상

### 수신 경로
| 표준 | RFC | 티어 | 난이도 | 비고 |
|---|---|---|---|---|
| SPF 검증 | 7208 | MUST | 중 | 매크로 확장, 10-lookup 한도가 지저분. openspf 테스트 스위트 활용 |
| DKIM 검증 | 6376(STD76)+8301 | MUST | 중-상 | 정규화(relaxed/simple)가 본체. RSA≥1024 수용, sha1 거부 |
| DKIM Ed25519 | 8463 | SHOULD | 중 | ⚠`sign(null, data)`은 **원문**을 서명한다 — §3은 SHA-256 다이제스트를 서명하라고 정한다(STATUS §4-7) |
| DMARC 평가 | **9989** | MUST | 중 | Tree Walk 신규 구현 |
| Authentication-Results | 8601 | MUST | 하-중 | 자기 authserv-id 사칭 헤더 제거 필수 |
| ARC | 8617 | SHOULD | 상 | 포워딩/리스트 경유 보존. 검증→실링 순 |
| DSN 생성 | 3461-3464+6522 | MUST | 중 | |
| DNSBL/greylisting | §7.1 참고 | SHOULD | 하-중 | |

### 7.1 수신 방어 상세 (DNSBL/RBL 등)

**DNSBL** (= RBL — RBL은 MAPS사 상표라 표준 문서는 DNSBL로 부름). 조회 규약은 RFC 5782:
IP를 역순으로 존에 붙여 A 조회 (`2.0.0.127.zen.spamhaus.org`) → `127.0.0.x` 응답이면 등재,
x 값이 등재 사유 코드. TXT 조회로 사유 문자열도 얻음.

| 항목 | 내용 | 난이도 |
|---|---|---|
| IP DNSBL | 접속 IP 평판. 사실상 표준: **Spamhaus ZEN**(SBL+XBL+PBL 통합). 보조: Barracuda, SpamCop | 하 |
| DNSWL | 화이트리스트(dnswl.org) — 오탐 방지용 감점 | 하 |
| 도메인 DNSBL (RHSBL/DBL) | HELO·MAIL FROM·From 도메인 평판: Spamhaus DBL, SURBL | 하 |
| URI DNSBL | **본문 속 링크 도메인** 평판: SURBL, URIBL — 본문 파싱 후 단계라 배치가 다름 | 중 |
| greylisting | 초면 (IP, sender, rcpt) 트리플에 450 임시거부 → 정상 MTA는 재시도, 봇은 안 옴. 재시도 추적 DB 필요. SPF pass 발신자는 면제하는 게 요즘 관행 | 중 |
| 레이트리밋/tarpit | IP·발신자별 속도 제한, 위반 시 응답 지연 | 하-중 |
| SMTP 콜아웃 검증 | 발신자 존재 확인용 역방향 RCPT 시도 — **하지 말 것** (backscatter 유발, 대형 MTA들이 차단함) | — |

**구현 시 주의사항**:
- **자체 재귀 리졸버 필수** — Spamhaus 등 주요 DNSBL은 Google/Cloudflare 퍼블릭 리졸버 경유
  조회를 차단함(응답이 항상 미등재로 나옴 = 조용한 무력화). unbound 같은 로컬 리졸버를 끼거나
  상용 데이터피드 계약 필요. 무료 티어는 쿼리량 제한도 있음(Spamhaus ~30만/일).
- **차단 위치는 연결 직후** (RCPT 전) — DATA까지 받고 거부하면 대역폭 낭비. 단 URI DNSBL은
  본문 필요라 DATA 후.
- **하드 차단보다 점수제 권장** — 단일 리스트 오탐 리스크. ZEN 등재는 즉시 5xx 거부해도 되지만
  보조 리스트들은 가중치 합산이 안전. → **결정: 자체 점수 엔진으로 구현** (외부 의존 최소화 원칙,
  `spam/` 패키지 — DNSBL 가중치 + 휴리스틱 + Bayes, Stalwart 모델).
- 거부 응답에 등재 사유 URL 포함이 매너 (`554 5.7.1 Listed at https://check.spamhaus.org/...`).
- 캐싱: DNS TTL 준수 + 네거티브 캐시로 조회량 절감.

### 발송 경로 (SaaS 핵심)
| 표준 | RFC | 티어 | 난이도 | 비고 |
|---|---|---|---|---|
| DKIM 서명 | 6376 | MUST | 중 | RSA2048 + Ed25519 이중 서명 권장 (Ed25519 단독 금지). **고객 도메인 키 프로비저닝/로테이션 UI가 SaaS 코어 기능** |
| 바운스 파싱 + suppression | 3464 등 | MUST | 중-상 | **생성보다 실세계 쓰레기 바운스 파싱이 어렵고 가치 큼** |
| One-Click Unsub | **8058** | **MUST** | 하-중 | Gmail/Yahoo(2024-02)/MS(2025-05) 강제. 2일 내 처리. 서명 토큰 URL |
| List 헤더 | 2369/2919 | MUST | 하 | 8058의 전제 |
| MTA-STS 준수(발신측) | 8461 | SHOULD | 중 | 원격 정책 fetch/캐시/enforce 상태머신 |
| MTA-STS 게시(수신측) | 8461 | SHOULD | 최하 | HTTPS 정적 파일 |
| TLS-RPT 생성/파싱 | 8460 | SHOULD | 중/하 | 일일 JSON 리포트 |
| DANE 검증 | 7672 | SHOULD | 상 | ✅ 구현(`IONOSPHERE_DANE=1`). 자체 DNSSEC 체인 검증 위에. NSEC/NSEC3 부재 증명은 미구현 |
| DMARC 리포트 생성 | **9990** | SHOULD | 중 | 수신 규모 생기면 |
| DMARC 리포트 파싱 대시보드 | 9990 | SHOULD | 하-중 | **고객용 SaaS 기능 — 차별화 포인트** |
| FBL 소비 (ARF) | 5965 | MUST | 중 | Yahoo CFL, MS JMRP. Gmail은 FBL 없음 → Postmaster Tools API |
| SRS | 무RFC (죽은 2003 드래프트가 사실상 스펙) | 포워딩 제공 시 MUST | 하-중 | HMAC+타임스탬프, SRS0/SRS1, 64자 로컬파트 한도. ARC와 세트로 |
| Feedback-ID | Gmail 관례 | SHOULD | 최하 | 캠페인/고객별 스트림 식별 |

### 대량 발송자 요건 (Gmail/Yahoo/MS 공통, ≥5천통/일)
SPF+DKIM pass · From 도메인 정렬(SPF 또는 DKIM) · DMARC p=none 이상 · RFC 8058 원클릭 수신거부(2일 내 처리) · 스팸 신고율 <0.3%(목표 <0.1%) · FCrDNS/PTR · TLS 전송 · 유효한 From/Reply-To

**SaaS 아키텍처 함의**: 고객별 DKIM 키 CNAME 위임 플로우, 강제 커스텀 return-path 서브도메인(SPF 정렬), 바운스/FBL/수신거부 → suppression list 준실시간 반영, DMARC 없는 도메인 마케팅 발송 거부 게이트, Postmaster Tools/SNDS 연동 모니터링

### SASL (submission/IMAP/POP3 공통)
| 메커니즘 | 현실 (2026) | 판단 |
|---|---|---|
| PLAIN (4616) | 전 클라이언트 지원 | **MUST** — TLS 후에만 광고 |
| LOGIN (무RFC) | 구형 Outlook, 프린터/스캐너 | SHOULD — 20줄로 지원티켓 예방 |
| 앱 비밀번호 | 자체 도메인 서버의 2026년 표준 관행 | MUST (PLAIN 위에서) |
| XOAUTH2 / OAUTHBEARER (7628) | Thunderbird 128.4.1+ 등 | ✅ 구현(IMAP·POP3·SMTP, 자체발급 토큰 `kind=2`). 원래 판단이 "후순위"였던 이유는 그대로다 — **OAuth AS 운영이 진짜 비용**이라, 지금 있는 것은 자체발급 토큰이지 완전한 AS가 아니다 |
| SCRAM-SHA-256 (7677) | Thunderbird/Dovecot/Stalwart만. Apple Mail/Outlook 미지원 | ✅ 구현 — 네 프로토콜 전부. **PLAIN보다 앞에 광고**(아래) |
| CRAM-MD5/DIGEST-MD5 | 죽음 (6331 Historic) | 구현 금지 |

**SCRAM 배선에서 지킬 것 두 개** (둘 다 라이브에서 어긋난 적이 있다):

- **광고 순서**: `SCRAM-SHA-256`을 PLAIN **앞에** 놓는다. 다수 클라이언트가 광고 순서를 선호도로
  읽어서, PLAIN이 앞에 있으면 더 안전한 메커니즘을 두고도 평문을 고른다.
- **★실패도 기록·계수한다**: SCRAM 증명 검증은 순수 계산이라 백엔드 왕복이 없다. 그래서 실패가
  인증 액션을 거치지 않고 거절 응답만 내고 끝나기 쉽고, 그러면 어댑터의 스로틀·감사가 **아예
  실행되지 않는다** — 즉 SCRAM으로 무제한 대입이 무기록으로 가능해진다. 엔진은 실패를 반드시
  `{kind:"authFailed"}` 액션으로 내보내고, 어댑터가 그 자리에서 `recordFailure`와 `audit.record`를
  한다. 성공 액션(`authVerified`)을 재사용하면 실패가 성공 경로를 타므로 안 된다.

  광고 여부는 백엔드가 `scramKeys`·`scramAuthorize`를 **둘 다** 제공하는지로 정해진다. 그래서
  조립층이 인증 표면(submission·IMAP·POP3·ManageSieve)에만 넘겨야 한다 — relay(25)에 붙으면
  인증을 광고하지 않아야 할 표면이 SCRAM을 광고한다.

---

## 8. 로드맵 매핑 (PLAN.md Phase 기준)

| Phase | 이 카탈로그에서 가져갈 것 |
|---|---|
| **0** | §0 스키마 전부 · SMTP MUST(25번) · POP3 MUST · LMTP(SMTP 엔진 모드) |
| **1** | SMTP 587/465 + AUTH(PLAIN/LOGIN+앱비번) · DKIM 서명(RSA+Ed25519) · MX 발송 + DSN 파싱/생성 · RFC 8058+List 헤더 · suppression |
| **2** | SPF/DKIM/DMARC(9989) 검증 + Authentication-Results · DNSBL/greylisting · 관리 API · FTS 인덱싱 · FBL |
| **3** | IMAP Tier1 → CONDSTORE → QRESYNC → OBJECTID 배치 → COMPRESS/PREVIEW/QUOTA |
| **4** | JMAP core→mail (queryChanges 회피 출시) · WebSocket+VAPID · Sieve MUST 세트 → ManageSieve+RFC 9661 · 웹훅 |
| **5** | ARC/SRS · MTA-STS/TLS-RPT/DANE · DMARC 리포트 대시보드 · SORT/THREAD · OAuth/SCRAM · Quotas/Blob(JMAP) |
| **v2+** | JMAP Contacts/Calendars · ACL 공유 메일함 · BIMI 툴링 · DKIM2 대응 |
