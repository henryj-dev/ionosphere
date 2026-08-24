# 코드 전수 점검 보고서 재검토 의견

검토일: 2026년 8월 25일
검토 대상: [CODE_AUDIT_REPORT.md](./CODE_AUDIT_REPORT.md)
검토 기준: 보고서의 주장과 현재 코드의 실제 동작 대조

## 결론

보고서의 핵심 결론은 현재 코드와 대체로 일치합니다. 특히 메일 소실, 세션 범위를 벗어난 삭제,
SSRF, 쿼터 우회, JMAP 원자성 및 동기화 문제는 반박하기 어렵습니다.

다만 일부 수정 방향은 현재 프로젝트의 의존 방향과 맞지 않으며, 몇 가지 코드상 누락을 추가하는
것이 좋습니다.

## 반박하기 어려운 항목

다음 항목은 코드 근거가 명확합니다.

1. 같은 메일함으로의 IMAP `MOVE`가 원본 멤버십만 삭제하는 문제
2. POP3 `QUIT`가 세션 외의 `\Deleted` 메시지까지 `EXPUNGE`하는 문제
3. MTA-STS 정책 조회의 DNS 결과 검증 부재
4. IMAP `COPY`의 쿼터 검사 누락
5. JMAP `Email/set`의 부분 적용
6. JMAP `EmailSubmission` 거절 후 submission 행 잔류
7. Thread의 state/change 로그 누락
8. JMAP Session URL의 검증되지 않은 `Host` 사용 및 `http://` 고정
9. Cloudflare DNS API 페이지네이션 누락
10. Identity state/change 추적 미구현
11. RFC 2231 파라미터 확장 미지원
12. 비지원 charset의 부정확한 디코딩

## 정정 또는 표현 완화가 필요한 항목

### 1. MTA-STS 수정 방향

보고서의 “webhook 클라이언트를 `core`로 승격”이라는 처방은 수정하는 편이 좋습니다.

현재 가드된 HTTP 클라이언트는 `node:http`, `node:https`, `node:dns`에 의존하며,
`@ionosphere/webhook`은 이미 `@ionosphere/core`를 의존합니다.

- [packages/webhook/src/http-client.ts:20](./packages/webhook/src/http-client.ts:20)
- [apps/server/src/app.ts:29](./apps/server/src/app.ts:29)

따라서 해당 구현을 그대로 `core`로 옮기면 의존 방향과 패키지 책임이 불명확해집니다.
다음 중 하나가 더 적절합니다.

- `@ionosphere/http-client` 같은 하위 공용 패키지로 분리
- MTA-STS가 webhook의 가드된 클라이언트를 재사용하도록 공용 인터페이스 구성
- 앱 계층에 MTA-STS 전용 DNS 고정 HTTP 어댑터 추가

### 2. MySQL `INSERT IGNORE`

문제 제기는 유효하지만 실제 데이터 손상 여부는 각 호출자의 입력 검증 수준에 따라 달라집니다.
따라서 “항상 데이터 오류를 숨긴다”보다 “데이터베이스 오류 의미를 약화시킬 수 있는 조건부
하드닝 문제”로 표현하면 정확합니다.

### 3. 검증 결과의 현재 재현성

보고서의 `npm run verify` 통과 결과는 기준 실행 결과로 보존할 수 있습니다. 다만 이번 재검토에서
동일 명령을 다시 실행했을 때 `lint`와 `typecheck`는 통과했지만, 테스트 단계는 샌드박스의
`listen EPERM`으로 네트워크 리스너를 사용하는 테스트들이 실패했습니다.

따라서 보고서에는 다음을 명시하는 것이 안전합니다.

> 기준 실행에서는 전체 검증이 통과했다. 현재 검토 환경에서는 로컬 리스너 생성 권한 제한으로
> 전체 재현을 완료하지 못했다.

이 실패는 코드 결함으로 판정하지 않았습니다.

## 추가해야 할 코드상 문제

### 1. `thread_refs` 무한 누적

위치:

- [packages/store/src/store.ts:1304-1310](./packages/store/src/store.ts:1304)

마지막 메일함 멤버십이 삭제될 때 `thread_refs`를 삭제하지 않고, 예정된 보존 기간 GC도 구현되어
있지 않습니다. 결과적으로 삭제된 메일이 만든 thread reference가 계속 누적됩니다.

영향은 다음과 같습니다.

- 장기 운영 시 데이터베이스 크기 증가
- thread 해석 쿼리의 대상 증가
- 삭제된 메일과 관련된 메타데이터의 보존 기간 통제 실패

참조 행을 즉시 삭제할 수 없는 현재 스키마 제약은 보고서에 설명되어 있으므로, 별도 GC 작업 또는
참조 소유권을 식별할 수 있는 스키마 보강을 후속 조치로 제시하는 것이 좋습니다.

### 2. COPY 검색 부산물 복제 실패의 비복구성

`copySearchArtifacts()`는 핵심 메시지 복제 뒤에 실행되고, 실패를 기록하거나 재시도하지 않고
삼킵니다. 이 경우 사본은 존재하지만 검색 인덱스와 본문 검색 데이터가 영구적으로 누락될 수
있습니다.

이는 메일 자체의 소실은 아니지만, JMAP 검색 및 검색 기반 조회 결과가 실제 메일함과 달라지는
데이터 일관성 문제입니다. COPY 쿼터 항목 또는 Thread 동기화 항목의 관련 문제로 추가할 수
있습니다.

## 심각도 의견

- 같은 메일함 `MOVE`, POP3 `QUIT`, MTA-STS SSRF: 높음 유지
- COPY 쿼터, JMAP 원자성, Thread/Identity state: 중간 유지
- 보고서 집계 fallback, STARTTLS 프로브, D1 CI 공백, charset 및 RFC 2231: 낮음 또는 기능 공백
- `INSERT IGNORE`: 호출 경로에 따라 달라지는 조건부 중간/하드닝 이슈
- `thread_refs` 무한 누적: 운영 기간과 메일량에 따라 낮음~중간
- COPY 검색 부산물 복제 실패: 낮음~중간 데이터 일관성 이슈

## 공개 저장소 노출 검토

보고서 자체가 지적하듯 [CODE_AUDIT_REPORT.md](./CODE_AUDIT_REPORT.md)는 공개 저장소 루트에
있으며, 미수정 취약점의 위치와 재현 방법을 포함합니다.

운영 중인 서비스의 실제 취약점이라면 공개 저장소에 상세 재현 절차를 남기는 것이 적절한지 별도
판단해야 합니다. 필요하면 다음 중 하나를 선택해야 합니다.

- 공개 문서에서는 영향과 해결 상태만 요약
- 상세 재현 절차는 비공개 운영 저장소로 이동
- 수정 완료 후 공개 문서에 상세 내용을 반영

## 권장 후속 조치 순서

1. 같은 메일함 `MOVE`와 POP3 `EXPUNGE` 범위 회귀 테스트 추가
2. `COPY` 쿼터 검사와 검색 부산물 복구 전략 보완
3. MTA-STS용 DNS 고정 HTTP 클라이언트 적용
4. JMAP `Email/set` 및 `EmailSubmission` 원자성 보완
5. JMAP Session Host 및 스킴 검증
6. Thread·Identity state/change 로그 보완
7. `thread_refs` GC 또는 참조 소유권 스키마 설계
8. 보고서 집계 fallback 결과 확인 및 Cloudflare 페이지네이션 보완
