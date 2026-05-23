#!/usr/bin/env bash
# Seed the initial Yalla Control Plane operator membership through the API
# binary's embedded maintenance command. The script never prints env values.

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
  deploy/operations/seed-admin.sh --dry-run
  deploy/operations/seed-admin.sh --apply

Required environment values in the env file:
  YALLA_DATABASE_URL
  YALLA_SEED_ADMIN_EMAIL
  YALLA_SEED_ADMIN_ORGANIZATION

Optional environment values:
  YALLA_SEED_ADMIN_ROLE          default owner
  YALLA_CONTROL_PLANE_ENV_FILE   default /etc/yalla/control-plane.env
  YALLA_API_BIN                  default /usr/local/bin/yalla-api
  YALLA_API_SERVICE              default yalla-api
  YALLA_WORKER_SERVICE           default yalla-worker
  YALLA_HEALTH_URL               default http://127.0.0.1:8080/healthz
  YALLA_READY_URL                default http://127.0.0.1:8080/readyz
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
      echo "seed-admin: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

require_file() {
  if [[ ! -r "$1" ]]; then
    echo "seed-admin: required file is not readable: $1" >&2
    exit 1
  fi
}

require_executable() {
  if [[ ! -x "$1" ]]; then
    echo "seed-admin: required executable is not runnable: $1" >&2
    exit 1
  fi
}

redacted_env_plan() {
  env | sed -n 's/^\(YALLA_[A-Z0-9_]*\)=.*/\1=<redacted>/p' | sort
}

print_plan() {
  cat <<PLAN
seed-admin dry-run plan:
  env_file: ${ENV_FILE}
  api_binary: ${API_BIN}
  verify_api_service: sudo systemctl is-active ${API_SERVICE}
  verify_worker_service: sudo systemctl is-active ${WORKER_SERVICE}
  run_seed: ${API_BIN} --seed-admin --seed-admin-email <redacted> --seed-admin-organization <redacted> --seed-admin-role <redacted>
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
  echo "seed-admin: YALLA_DATABASE_URL must be set by ${ENV_FILE}" >&2
  exit 1
fi
if [[ -z "${YALLA_SEED_ADMIN_EMAIL:-}" ]]; then
  echo "seed-admin: YALLA_SEED_ADMIN_EMAIL must be set by ${ENV_FILE}" >&2
  exit 1
fi
if [[ -z "${YALLA_SEED_ADMIN_ORGANIZATION:-}" ]]; then
  echo "seed-admin: YALLA_SEED_ADMIN_ORGANIZATION must be set by ${ENV_FILE}" >&2
  exit 1
fi

echo "seed-admin: verifying API and worker services before seeding" >&2
sudo systemctl is-active "$API_SERVICE" >/dev/null
sudo systemctl is-active "$WORKER_SERVICE" >/dev/null

echo "seed-admin: probing /healthz and /readyz" >&2
curl -fsS "$HEALTH_URL" >/dev/null
curl -fsS "$READY_URL" >/dev/null

echo "seed-admin: running ${API_BIN} --seed-admin with redacted operator identity" >&2
"$API_BIN" \
  --seed-admin \
  --seed-admin-email "$YALLA_SEED_ADMIN_EMAIL" \
  --seed-admin-organization "$YALLA_SEED_ADMIN_ORGANIZATION" \
  --seed-admin-role "${YALLA_SEED_ADMIN_ROLE:-owner}"

echo "seed-admin: completed; inspect structured JSON logs with journalctl -u ${API_SERVICE} -u ${WORKER_SERVICE} -o json" >&2
