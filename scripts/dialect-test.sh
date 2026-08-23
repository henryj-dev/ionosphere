#!/usr/bin/env bash
# 방언 계약 테스트 로컬/CI 러너 — docker로 PostgreSQL + MySQL을 띄워
# apps/server/test/dialect-contract.test.ts를 실연결로 돌린다.
#   사용: ./scripts/dialect-test.sh
#   D1도 포함하려면: IONOSPHERE_TEST_D1_ACCOUNT=... IONOSPHERE_TEST_D1_TOKEN=... ./scripts/dialect-test.sh
# 컨테이너는 종료 시 자동 삭제(trap). SQLite는 게이트 없이 항상 함께 검증된다.
set -euo pipefail

PG_C=ionosphere-dialect-pg
MY_C=ionosphere-dialect-mysql
PG_PORT="${PG_PORT:-55432}"
MY_PORT="${MY_PORT:-33061}"

cleanup() { docker rm -f "$PG_C" "$MY_C" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "[1/3] 컨테이너 기동 (postgres:16, mysql:8)"
docker run -d --name "$PG_C" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=ionosphere -p "${PG_PORT}:5432" postgres:16 >/dev/null
docker run -d --name "$MY_C" -e MYSQL_ROOT_PASSWORD=test -e MYSQL_DATABASE=ionosphere -p "${MY_PORT}:3306" mysql:8 >/dev/null

echo "[2/3] 준비 대기"
for i in $(seq 1 30); do docker exec "$PG_C" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
for i in $(seq 1 60); do docker exec "$MY_C" mysqladmin ping -uroot -ptest >/dev/null 2>&1 && break; sleep 2; done

echo "[3/3] 계약 테스트 실행"
export IONOSPHERE_TEST_PG_URL="postgres://postgres:test@127.0.0.1:${PG_PORT}/ionosphere"
export IONOSPHERE_TEST_MYSQL_URL="mysql://root:test@127.0.0.1:${MY_PORT}/ionosphere"
# 어댑터 테스트(postgres/mysql.test.ts)도 같은 게이트를 쓰므로 **여기서 같이 돌려야 한다**.
# 예전엔 dialect-contract.test.ts만 돌렸고, 그 결과 어댑터 테스트는 CI의 PG job에서만 실행돼
# 마이그레이션 개수를 박아둔 단언이 001 시절 값(1)로 몇 달간 방치됐다(개수가 5가 되며 발각).
# 안 도는 테스트는 관리되지 않는다 — 러너가 게이트 대상을 전부 포함하게 둔다.
node --test --test-timeout=30000 apps/server/test/dialect-contract.test.ts packages/db/test/postgres.test.ts packages/db/test/mysql.test.ts
