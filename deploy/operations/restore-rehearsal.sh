#!/usr/bin/env bash
# Rehearse a control-plane database restore against a throwaway Postgres
# database. The script never prints environment values or restore DSNs.

set -euo pipefail

ENV_FILE="${YALLA_CONTROL_PLANE_ENV_FILE:-/etc/yalla/control-plane.env}"
API_BIN="${YALLA_API_BIN:-/usr/local/bin/yalla-api}"
WORKER_BIN="${YALLA_WORKER_BIN:-/usr/local/bin/yalla-worker}"
API_SERVICE="${YALLA_API_SERVICE:-yalla-api}"
WORKER_SERVICE="${YALLA_WORKER_SERVICE:-yalla-worker}"
PG_RESTORE_BIN="${YALLA_PG_RESTORE_BIN:-pg_restore}"
CANARY_BIN="${YALLA_CANARY_BIN:-scripts/canary.sh}"
REHEARSAL_DATABASE_URL="${YALLA_REHEARSAL_DATABASE_URL:-}"
SNAPSHOT="${YALLA_RESTORE_SNAPSHOT:-}"
REPORT_DIR="${YALLA_RESTORE_REHEARSAL_REPORT_DIR:-/var/log/yalla/restore-rehearsals}"
LOCK_FILE="${YALLA_RESTORE_REHEARSAL_LOCK_FILE:-/run/yalla/restore-rehearsal.lock}"
RESTORE_JOBS="${YALLA_RESTORE_JOBS:-4}"
HEALTH_URL="${YALLA_HEALTH_URL:-http://127.0.0.1:8080/healthz}"
READY_URL="${YALLA_READY_URL:-http://127.0.0.1:8080/readyz}"
BACKUP_HEALTH_URL="${YALLA_BACKUP_HEALTH_URL:-http://127.0.0.1:8080/healthz/backup}"
MODE="dry-run"
DATABASE_URL_ENV="YALLA_DATABASE_URL"

usage() {
  cat <<'USAGE'
Usage:
  deploy/operations/restore-rehearsal.sh --dry-run --snapshot <dump-file>
  deploy/operations/restore-rehearsal.sh --apply --snapshot <dump-file>

Required environment values in the env file for --apply:
  YALLA_REHEARSAL_DATABASE_URL  throwaway restore database DSN

Optional environment values:
  YALLA_RESTORE_SNAPSHOT               default from --snapshot
  YALLA_CONTROL_PLANE_ENV_FILE         default /etc/yalla/control-plane.env
  YALLA_API_BIN                        default /usr/local/bin/yalla-api
  YALLA_WORKER_BIN                     default /usr/local/bin/yalla-worker
  YALLA_API_SERVICE                    default yalla-api
  YALLA_WORKER_SERVICE                 default yalla-worker
  YALLA_PG_RESTORE_BIN                 default pg_restore
  YALLA_CANARY_BIN                     default scripts/canary.sh
  YALLA_RESTORE_REHEARSAL_REPORT_DIR   default /var/log/yalla/restore-rehearsals
  YALLA_RESTORE_REHEARSAL_LOCK_FILE    default /run/yalla/restore-rehearsal.lock
  YALLA_RESTORE_JOBS                   default 4
  YALLA_HEALTH_URL                     default http://127.0.0.1:8080/healthz
  YALLA_READY_URL                      default http://127.0.0.1:8080/readyz
  YALLA_BACKUP_HEALTH_URL              default http://127.0.0.1:8080/healthz/backup
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) MODE="dry-run" ;;
    --apply) MODE="apply" ;;
    --snapshot)
      if [[ $# -lt 2 ]]; then
        echo "restore-rehearsal: --snapshot requires a path" >&2
        exit 2
      fi
      SNAPSHOT="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "restore-rehearsal: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

require_file() {
  if [[ ! -r "$1" ]]; then
    echo "restore-rehearsal: required file is not readable: $1" >&2
    exit 1
  fi
}

require_executable() {
  if ! command -v "$1" >/dev/null 2>&1 && [[ ! -x "$1" ]]; then
    echo "restore-rehearsal: required executable is not runnable: $1" >&2
    exit 1
  fi
}

redacted_env_plan() {
  env | sed -n 's/^\(YALLA_[A-Z0-9_]*\)=.*/\1=<redacted>/p' | sort
}

print_plan() {
  cat <<PLAN
restore-rehearsal dry-run plan:
  env_file: ${ENV_FILE}
  api_binary: ${API_BIN}
  worker_binary: ${WORKER_BIN}
  pg_restore_binary: ${PG_RESTORE_BIN}
  canary_binary: ${CANARY_BIN}
  snapshot: <redacted>
  rehearsal_database_url: <redacted>
  report_dir: <redacted>
  lock: flock ${LOCK_FILE}
  verify_api_service: sudo systemctl is-active ${API_SERVICE}
  verify_worker_service: sudo systemctl is-active ${WORKER_SERVICE}
  health_probe: curl -fsS ${HEALTH_URL}
  readiness_probe: curl -fsS ${READY_URL}
  backup_probe: curl -fsS ${BACKUP_HEALTH_URL}
  restore_snapshot: ${PG_RESTORE_BIN} --clean --if-exists --no-owner --no-acl --jobs ${RESTORE_JOBS} --dbname <redacted> <redacted>
  apply_migrations: ${API_BIN} --migrate-only with ${DATABASE_URL_ENV}=<redacted>
  canary: ${CANARY_BIN} <redacted>
  report: write restore rehearsal report with mktemp then mv
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
require_executable "$PG_RESTORE_BIN"

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

REHEARSAL_DATABASE_URL="${YALLA_REHEARSAL_DATABASE_URL:-$REHEARSAL_DATABASE_URL}"
SNAPSHOT="${YALLA_RESTORE_SNAPSHOT:-$SNAPSHOT}"
CANARY_BIN="${YALLA_CANARY_BIN:-$CANARY_BIN}"

if [[ -z "$REHEARSAL_DATABASE_URL" ]]; then
  echo "restore-rehearsal: YALLA_REHEARSAL_DATABASE_URL must be set by ${ENV_FILE}" >&2
  exit 1
fi
if [[ -z "$SNAPSHOT" ]]; then
  echo "restore-rehearsal: snapshot path is required via --snapshot or YALLA_RESTORE_SNAPSHOT" >&2
  exit 1
fi
if [[ -n "${YALLA_DATABASE_URL:-}" && "$REHEARSAL_DATABASE_URL" == "$YALLA_DATABASE_URL" ]]; then
  echo "restore-rehearsal: rehearsal DSN must not match the primary control-plane DSN" >&2
  exit 1
fi

require_file "$SNAPSHOT"
require_executable "$CANARY_BIN"

umask 077
mkdir -p "$REPORT_DIR"
mkdir -p "$(dirname "$LOCK_FILE")"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "restore-rehearsal: another restore rehearsal is already running" >&2
  exit 1
fi

echo "restore-rehearsal: verifying API and worker services before rehearsal" >&2
sudo systemctl is-active "$API_SERVICE" >/dev/null
sudo systemctl is-active "$WORKER_SERVICE" >/dev/null

echo "restore-rehearsal: probing /healthz, /readyz, and /healthz/backup" >&2
curl -fsS "$HEALTH_URL" >/dev/null
curl -fsS "$READY_URL" >/dev/null
curl -fsS "$BACKUP_HEALTH_URL" >/dev/null

started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
started_epoch="$(date -u +"%s")"
report_file="${REPORT_DIR}/restore-rehearsal-${started_at}.json"
tmp_report="$(mktemp "${REPORT_DIR}/.restore-rehearsal-${started_at}.XXXXXX.json")"

cleanup() {
  rm -f "$tmp_report"
}
trap cleanup EXIT

echo "restore-rehearsal: running pg_restore into throwaway database with redacted DSN" >&2
"$PG_RESTORE_BIN" \
  --clean \
  --if-exists \
  --no-owner \
  --no-acl \
  --jobs "$RESTORE_JOBS" \
  --dbname "$REHEARSAL_DATABASE_URL" \
  "$SNAPSHOT"

echo "restore-rehearsal: applying embedded migrations with ${API_BIN} --migrate-only against throwaway database" >&2
(
  export "${DATABASE_URL_ENV}=$REHEARSAL_DATABASE_URL"
  "$API_BIN" --migrate-only
)

echo "restore-rehearsal: running canary suite against throwaway database" >&2
"$CANARY_BIN" "$REHEARSAL_DATABASE_URL"

finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
finished_epoch="$(date -u +"%s")"
duration_seconds="$((finished_epoch - started_epoch))"

cat >"$tmp_report" <<REPORT
{
  "schema_version": "yalla.restore_rehearsal.v1",
  "started_at": "${started_at}",
  "finished_at": "${finished_at}",
  "duration_seconds": ${duration_seconds},
  "snapshot": "[REDACTED]",
  "rehearsal_database_url": "[REDACTED]",
  "restore": "passed",
  "migrations": "passed",
  "canary": "passed",
  "health_checks": ["healthz", "readyz", "healthz/backup"],
  "log_format": "structured JSON"
}
REPORT
mv "$tmp_report" "$report_file"
trap - EXIT

echo "restore-rehearsal: completed; report written with redacted values; inspect structured JSON logs with journalctl -u ${API_SERVICE} -u ${WORKER_SERVICE} -o json" >&2
