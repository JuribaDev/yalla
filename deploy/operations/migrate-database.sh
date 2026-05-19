#!/usr/bin/env bash
# Apply Yalla Control Plane database migrations through the API binary's
# embedded migration runner. The script never prints environment values.

set -euo pipefail

ENV_FILE="${YALLA_CONTROL_PLANE_ENV_FILE:-/etc/yalla/control-plane.env}"
API_BIN="${YALLA_API_BIN:-/usr/local/bin/yalla-api}"
API_SERVICE="${YALLA_API_SERVICE:-yalla-api}"
WORKER_SERVICE="${YALLA_WORKER_SERVICE:-yalla-worker}"
HEALTH_URL="${YALLA_HEALTH_URL:-http://127.0.0.1:8080/healthz}"
READY_URL="${YALLA_READY_URL:-http://127.0.0.1:8080/readyz}"
MODE="dry-run"

usage() {
  cat <<'USAGE'
Usage:
  deploy/operations/migrate-database.sh --dry-run
  deploy/operations/migrate-database.sh --apply

Environment overrides:
  YALLA_CONTROL_PLANE_ENV_FILE  default /etc/yalla/control-plane.env
  YALLA_API_BIN                 default /usr/local/bin/yalla-api
  YALLA_API_SERVICE             default yalla-api
  YALLA_WORKER_SERVICE          default yalla-worker
  YALLA_HEALTH_URL              default http://127.0.0.1:8080/healthz
  YALLA_READY_URL               default http://127.0.0.1:8080/readyz
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
      echo "migrate-database: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

require_file() {
  if [[ ! -r "$1" ]]; then
    echo "migrate-database: required file is not readable: $1" >&2
    exit 1
  fi
}

require_executable() {
  if [[ ! -x "$1" ]]; then
    echo "migrate-database: required executable is not runnable: $1" >&2
    exit 1
  fi
}

redacted_env_plan() {
  env | sed -n 's/^\(YALLA_[A-Z0-9_]*\)=.*/\1=<redacted>/p' | sort
}

print_plan() {
  cat <<PLAN
migrate-database dry-run plan:
  env_file: ${ENV_FILE}
  api_binary: ${API_BIN}
  stop_worker: sudo systemctl stop ${WORKER_SERVICE}
  run_migrations: ${API_BIN} --migrate-only
  start_api: sudo systemctl start ${API_SERVICE}
  start_worker: sudo systemctl start ${WORKER_SERVICE}
  health_probe: curl -fsS ${HEALTH_URL}
  readiness_probe: curl -fsS ${READY_URL}
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

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

if [[ -z "${YALLA_DATABASE_URL:-}" ]]; then
  echo "migrate-database: YALLA_DATABASE_URL must be set by ${ENV_FILE}" >&2
  exit 1
fi

echo "migrate-database: stopping worker before schema changes" >&2
sudo systemctl stop "$WORKER_SERVICE"

echo "migrate-database: applying embedded migrations with ${API_BIN} --migrate-only" >&2
"$API_BIN" --migrate-only

echo "migrate-database: starting API and worker" >&2
sudo systemctl start "$API_SERVICE"
sudo systemctl start "$WORKER_SERVICE"

echo "migrate-database: probing /healthz and /readyz" >&2
curl -fsS "$HEALTH_URL" >/dev/null
curl -fsS "$READY_URL" >/dev/null

echo "migrate-database: completed; inspect structured JSON logs with journalctl -u ${API_SERVICE} -u ${WORKER_SERVICE} -o json" >&2
