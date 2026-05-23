#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  printf 'verify-yalla-skills: %s\n' "$*" >&2
  exit 1
}

if find skills -path '*dokploy*' -print -quit | grep -q .; then
  find skills -path '*dokploy*' -print >&2
  fail "skill paths must use yalla-only names"
fi

if rg -n -i 'dokploy|\.dokploy|your-dokploy|yalla-dokploy-deploy' skills; then
  fail "skill content must not expose private runtime naming"
fi

for dir in skills/claude/yalla-deploy skills/codex/yalla-deploy; do
  [[ -f "$dir/SKILL.md" ]] || fail "missing $dir/SKILL.md"
  rg -n '^name: yalla-deploy$' "$dir/SKILL.md" >/dev/null || fail "$dir/SKILL.md must declare name: yalla-deploy"
done

manifest="$(mktemp)"
trap 'rm -f "$manifest"' EXIT

/opt/homebrew/bin/go run ./cmd/yalla --json manifest > "$manifest"

required_paths=(
  "yalla project create"
  "yalla environment create"
  "yalla service create"
  "yalla service build set"
  "yalla service deploy"
  "yalla database backup run"
  "yalla database backup restore"
)

for path in "${required_paths[@]}"; do
  jq -e --arg path "$path" '.. | objects | select(.path? == $path)' "$manifest" >/dev/null \
    || fail "manifest missing documented command: $path"
done

printf 'verify-yalla-skills: all checks passed\n'
