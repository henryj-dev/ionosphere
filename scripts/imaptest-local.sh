#!/usr/bin/env bash
# 로컬 imaptest 실행 — Phase 3 완료 기준 검증(PLAN §5).
#
# 사전 준비:
#   1) dovecot core 빌드:   git clone --depth 1 https://github.com/dovecot/core dovecot-core
#                           cd dovecot-core && ./autogen.sh && ./configure && make
#   2) imaptest 빌드:       git clone --depth 1 https://github.com/dovecot/imaptest
#                           cd imaptest && ./autogen.sh && ./configure --with-dovecot=../dovecot-core && make
#   3) 테스트 mbox:         curl -fsSLO https://www.dovecot.org/tmp/dovecot-crlf
#
# 사용: IMAPTEST_BIN=<imaptest 바이너리> MBOX=<dovecot-crlf 경로> ./scripts/imaptest-local.sh [imaptest 추가 인자...]
# 예:  IMAPTEST_BIN=/tmp/imaptest/src/imaptest MBOX=/tmp/dovecot-crlf ./scripts/imaptest-local.sh secs=10
#
# 주의(SCHEMA §11 스파이크): copybox는 테스트 메일함과 다른 이름이어야 함(공유 키워드 모델).
set -euo pipefail

IMAPTEST_BIN=${IMAPTEST_BIN:?imaptest 바이너리 경로 필요}
MBOX=${MBOX:?dovecot-crlf mbox 경로 필요}
PORT=${PORT:-14300}
USER_EMAIL=${USER_EMAIL:-imaptest@test.local}
USER_PASS=${USER_PASS:-imaptest-pw}

WORK=$(mktemp -d)
trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT

cd "$(dirname "$0")/.."

# 계정 생성은 서버 정지 상태에서(SQLite 단일 라이터 — docs/STATUS.md §7)
IONOSPHERE_DB="$WORK/imaptest.db" node apps/server/src/cli.ts create-user "$USER_EMAIL" "$USER_PASS"

# 프로덕션과 동일하게 Node로 구동(STARTTLS/Bun 이슈와 무관하게 일관성)
IONOSPHERE_DB="$WORK/imaptest.db" IONOSPHERE_BLOBS="$WORK/blobs" IONOSPHERE_HOSTNAME=test.local \
  IONOSPHERE_SMTP_PORT=0 IONOSPHERE_POP3_PORT=0 IONOSPHERE_IMAP_PORT=$PORT IONOSPHERE_LOG_LEVEL=warn \
  node apps/server/src/main.ts &
SERVER_PID=$!
sleep 1.5

echo "=== imaptest → 127.0.0.1:$PORT (user=$USER_EMAIL) ==="
"$IMAPTEST_BIN" host=127.0.0.1 port=$PORT "user=$USER_EMAIL" "pass=$USER_PASS" \
  "mbox=$MBOX" no_pipelining copybox=CopyTarget "$@"
