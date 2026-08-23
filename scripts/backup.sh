#!/usr/bin/env bash
# ionosphere 백업 — DB(VACUUM INTO 스냅샷) + blobs를 타임스탬프 타르볼로 묶고 N일 보관.
# systemd(ionosphere-backup.timer)로 매일 실행하거나 수동 실행. 환경변수로 경로/보관일 조정.
#
# ★DB가 SQLite가 **아닌** 구성(IONOSPHERE_DB_URL=postgres://…)에서는 DB 스냅샷을 건너뛰고
# blobs만 묶는다. 그 경우 DB 백업은 서버 밖(예: k8s pg-backup CronJob)의 몫이다.
#
# 왜 이 분기가 필요한가(2026-08-02): PG로 전환한 뒤에도 이 스크립트가 `IONOSPHERE_DB`(SQLite 파일)를
# 그대로 떴다. 그 파일은 전환 시점에 **동결된 낡은 사본**인데 매일 "BACKUP OK"를 찍으니,
# 백업이 도는 것처럼 보이면서 실제로는 죽은 데이터를 쌓는다. 조용한 무백업보다 더 나쁘다 —
# 성공 메시지가 확인을 막는다. blobs는 PG로 옮겨지지 않고 계속 쓰이므로 **여전히 백업해야 한다**.
set -euo pipefail

# 타르볼 내용물은 DB 전체 + blobs = 전 테넌트 메일 본문·자격증명 해시·DKIM 개인키·웹훅 시크릿이다.
# 예전에는 umask도 chmod도 없어 0644로 떨어졌고, 서버의 비특권 로컬 계정이 그대로 읽을 수 있었다.
# 아래 명시적 chmod가 있어도 umask를 먼저 두는 이유: 생성과 chmod 사이의 창을 없애기 위해서다.
umask 077

DATA_DIR="${IONOSPHERE_DATA_DIR:-/var/lib/ionosphere}"
DB="${IONOSPHERE_DB:-$DATA_DIR/ionosphere.db}"
BACKUP_DIR="${IONOSPHERE_BACKUP_DIR:-$DATA_DIR/backups}"
RETAIN_DAYS="${IONOSPHERE_BACKUP_RETAIN_DAYS:-14}"
APP_DIR="${IONOSPHERE_APP_DIR:-/opt/ionosphere}"
NODE="${NODE:-/usr/local/bin/node}"

mkdir -p "$BACKUP_DIR"
# 이미 있던 디렉터리는 umask의 영향을 받지 않으므로 모드를 따로 맞춘다.
# 실패해도 백업 자체는 계속한다 — 소유자가 아니면 chmod가 거절되는데(백업은 linuxuser로 돈다),
# 실제 보호는 아래 파일 0600이 한다. 다만 조용히 넘어가면 안 되니 경고는 남긴다.
chmod 700 "$BACKUP_DIR" 2>/dev/null || echo "[warn] $BACKUP_DIR 모드를 700으로 못 바꿨습니다(소유자 확인 필요)"

TS="$(date +%Y%m%d-%H%M%S)"
SNAP="$BACKUP_DIR/ionosphere-$TS.db"
TARBALL="$BACKUP_DIR/ionosphere-$TS.tar.gz"

# 이 서버가 SQLite를 쓰는가 — IONOSPHERE_DB_URL이 원격 스킴이면 DB는 여기 있지 않다.
# 스킴 판정은 openDatabase(open.ts)와 같은 기준이다: postgres/postgresql/mysql = 원격.
case "${IONOSPHERE_DB_URL:-}" in
  postgres://*|postgresql://*|mysql://*) SQLITE_LOCAL=0 ;;
  *) SQLITE_LOCAL=1 ;;
esac

if [ "$SQLITE_LOCAL" = "1" ]; then
  # 1) DB 온라인 스냅샷(WAL 포함, 일관성 보장)
  "$NODE" "$APP_DIR/scripts/backup-db.ts" "$DB" "$SNAP"
  chmod 600 "$SNAP"

  # 2) DB 스냅샷 + blobs를 타르볼로(blobs 없으면 DB만)
  if [ -d "$DATA_DIR/blobs" ]; then
    tar czf "$TARBALL" -C "$BACKUP_DIR" "ionosphere-$TS.db" -C "$DATA_DIR" blobs
  else
    tar czf "$TARBALL" -C "$BACKUP_DIR" "ionosphere-$TS.db"
  fi
  rm -f "$SNAP"
else
  # 원격 DB 구성 — blobs만 묶는다. blobs가 없으면 **묶을 것이 없으므로 실패시킨다**:
  # 빈 타르볼을 만들고 "BACKUP OK"를 찍으면 그게 바로 조용한 무백업이다.
  if [ ! -d "$DATA_DIR/blobs" ]; then
    echo "[FAIL] 원격 DB 구성인데 blobs 디렉터리가 없습니다 — 백업할 대상이 없습니다" >&2
    echo "       DB 백업은 서버 밖(pg-backup 등)에서 도는지 확인하십시오." >&2
    exit 1
  fi
  echo "[info] 원격 DB(IONOSPHERE_DB_URL) 구성 — DB 스냅샷은 건너뛰고 blobs만 백업합니다."
  echo "       DB 백업은 서버 밖(예: k8s pg-backup CronJob)에서 돌아야 합니다."
  tar czf "$TARBALL" -C "$DATA_DIR" blobs
fi
chmod 600 "$TARBALL"

# 3) 보관 정책: N일 초과 타르볼 삭제
find "$BACKUP_DIR" -name 'ionosphere-*.tar.gz' -mtime "+$RETAIN_DAYS" -delete

echo "BACKUP OK: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
