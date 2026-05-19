#!/usr/bin/env bash
# Produce a control-plane Postgres logical backup through the operator-owned
# backup toolchain. The script never prints environment values.

set -euo pipefail

ENV_FILE="${YALLA_CONTROL_PLANE_ENV_FILE:-/etc/yalla/control-plane.env}"
API_BIN="${YALLA_API_BIN:-/usr/local/bin/yalla-api}"
WORKER_BIN="${YALLA_WORKER_BIN:-/usr/local/bin/yalla-worker}"
API_SERVICE="${YALLA_API_SERVICE:-yalla-api}"
WORKER_SERVICE="${YALLA_WORKER_SERVICE:-yalla-worker}"
PG_DUMP_BIN="${YALLA_PG_DUMP_BIN:-pg_dump}"
BACKUP_DIR="${YALLA_BACKUP_DIR:-/var/backups/yalla-control-plane}"
STATUS_FILE="${YALLA_BACKUP_STATUS_FILE:-}"
LOCK_FILE="${YALLA_BACKUP_LOCK_FILE:-/run/yalla/backup-database.lock}"
HEALTH_URL="${YALLA_HEALTH_URL:-http://127.0.0.1:8080/healthz}"
READY_URL="${YALLA_READY_URL:-http://127.0.0.1:8080/readyz}"
BACKUP_HEALTH_URL="${YALLA_BACKUP_HEALTH_URL:-http://127.0.0.1:8080/healthz/backup}"
MODE="dry-run"

usage() {
  cat <<'USAGE'
Usage:
  deploy/operations/backup-database.sh --dry-run
  deploy/operations/backup-database.sh --apply

Required environment values in the env file:
  YALLA_DATABASE_URL
  YALLA_BACKUP_STATUS_FILE

Optional environment values:
  YALLA_CONTROL_PLANE_ENV_FILE  default /etc/yalla/control-plane.env
  YALLA_API_BIN                 default /usr/local/bin/yalla-api
  YALLA_WORKER_BIN              default /usr/local/bin/yalla-worker
  YALLA_API_SERVICE             default yalla-api
  YALLA_WORKER_SERVICE          default yalla-worker
  YALLA_PG_DUMP_BIN             default pg_dump
  YALLA_BACKUP_DIR              default /var/backups/yalla-control-plane
  YALLA_BACKUP_LOCK_FILE        default /run/yalla/backup-database.lock
  YALLA_HEALTH_URL              default http://127.0.0.1:8080/healthz
  YALLA_READY_URL               default http://127.0.0.1:8080/readyz
  YALLA_BACKUP_HEALTH_URL       default http://127.0.0.1:8080/healthz/backup
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) MODE="dry-run" ;;
    --apply) MODE="apply" ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "backup-database: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

require_file() {
  if [[ ! -r "$1" ]]; then
    echo "backup-database: required file is not readable: $1" >&2
    exit 1
  fi
}

require_executable() {
  if ! command -v "$1" >/dev/null 2>&1 && [[ ! -x "$1" ]]; then
    echo "backup-database: required executable is not runnable: $1" >&2
    exit 1
  fi
}

redacted_env_plan() {
  env | sed -n 's/^\(YALLA_[A-Z0-9_]*\)=.*/\1=<redacted>/p' | sort
}

print_plan() {
  cat <<PLAN
backup-database dry-run plan:
  env_file: ${ENV_FILE}
  api_binary: ${API_BIN}
  worker_binary: ${WORKER_BIN}
  pg_dump_binary: ${PG_DUMP_BIN}
  backup_dir: <redacted>
  status_file: <redacted>
  lock: flock ${LOCK_FILE}
  verify_api_service: sudo systemctl is-active ${API_SERVICE}
  verify_worker_service: sudo systemctl is-active ${WORKER_SERVICE}
  health_probe: curl -fsS ${HEALTH_URL}
  readiness_probe: curl -fsS ${READY_URL}
  backup_probe_before: curl -fsS ${BACKUP_HEALTH_URL}
  run_backup: ${PG_DUMP_BIN} --format=custom --no-acl --no-owner --compress=9 --file <redacted>
  update_status: write RFC3339 UTC timestamp with mktemp then mv
  backup_probe_after: curl -fsS ${BACKUP_HEALTH_URL}
  logs: journalctl -u ${API_SERVICE} -u ${WORKER_SERVICE} -o json
  log_format: structured JSON
  env_preview:
PLAN
  redacted_env_plan | sed 's/^/    /'
}

if [[ "$MODE" == "dry-run" ]]; then
  print_plan
  exit 0
fi

require_file "$ENV_FILE"
require_executable "$API_BIN"
require_executable "$WORKER_BIN"
require_executable "$PG_DUMP_BIN"

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

if [[ -z "${YALLA_DATABASE_URL:-}" ]]; then
  echo "backup-database: YALLA_DATABASE_URL must be set by ${ENV_FILE}" >&2
  exit 1
fi
if [[ -z "${YALLA_BACKUP_STATUS_FILE:-}" ]]; then
  echo "backup-database: YALLA_BACKUP_STATUS_FILE must be set by ${ENV_FILE}" >&2
  exit 1
fi

STATUS_FILE="$YALLA_BACKUP_STATUS_FILE"
umask 077
mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOCK_FILE")"
mkdir -p "$(dirname "$STATUS_FILE")"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "backup-database: another backup is already running" >&2
  exit 1
fi

echo "backup-database: verifying API and worker services before backup" >&2
sudo systemctl is-active "$API_SERVICE" >/dev/null
sudo systemctl is-active "$WORKER_SERVICE" >/dev/null

echo "backup-database: probing /healthz, /readyz, and /healthz/backup" >&2
curl -fsS "$HEALTH_URL" >/dev/null
curl -fsS "$READY_URL" >/dev/null
curl -fsS "$BACKUP_HEALTH_URL" >/dev/null

stamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
backup_file="${BACKUP_DIR}/yalla-control-plane-${stamp}.dump"
tmp_backup="$(mktemp "${BACKUP_DIR}/.yalla-control-plane-${stamp}.XXXXXX.dump")"
tmp_status="$(mktemp "$(dirname "$STATUS_FILE")/.backup.status.XXXXXX")"

cleanup() {
  rm -f "$tmp_backup" "$tmp_status"
}
trap cleanup EXIT

echo "backup-database: running pg_dump --format=custom --no-acl --no-owner --compress=9 with redacted DSN" >&2
"$PG_DUMP_BIN" \
  --dbname "$YALLA_DATABASE_URL" \
  --format=custom \
  --no-acl \
  --no-owner \
  --compress=9 \
  --file "$tmp_backup"

mv "$tmp_backup" "$backup_file"
printf '%s\n' "$stamp" >"$tmp_status"
mv "$tmp_status" "$STATUS_FILE"
trap - EXIT

echo "backup-database: probing /healthz/backup after status update" >&2
curl -fsS "$BACKUP_HEALTH_URL" >/dev/null

echo "backup-database: completed; inspect structured JSON logs with journalctl -u ${API_SERVICE} -u ${WORKER_SERVICE} -o json" >&2
