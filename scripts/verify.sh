#!/usr/bin/env bash
# scripts/verify.sh — yalla local verification gate.
#
# Runs the minimum required checks (gofmt, go mod tidy, go vet,
# `go test ./...`, `go test -race ./...`) and the optional security gates
# (govulncheck, staticcheck, golangci-lint, goreleaser check) when those
# tools are installed. Missing optional tools are reported, never silently
# skipped — that mirrors the rule called out in CONTRIBUTING.md.
#
# Usage:
#   scripts/verify.sh                Required + optional checks (commit gate)
#   scripts/verify.sh --release      Adds `goreleaser release --snapshot --clean`
#   scripts/verify.sh --strict       Treats every missing optional tool as a failure
#   scripts/verify.sh --quiet        Suppresses per-step banners (CI-friendly)
#
# Exit codes:
#   0   all run checks passed
#   1   one or more required checks failed
#   2   --strict was set and an optional tool was missing

set -euo pipefail

release=0
strict=0
quiet=0
for arg in "$@"; do
  case "$arg" in
    --release) release=1 ;;
    --strict)  strict=1 ;;
    --quiet)   quiet=1 ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    *)
      echo "verify.sh: unknown flag: $arg" >&2
      exit 2
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

step() {
  if [[ "$quiet" -eq 0 ]]; then
    printf '\n=== %s ===\n' "$1" >&2
  fi
}

skipped_tools=()
required_failed=0

# 1. Required: formatting (gofmt -l should be empty)
step "gofmt -l ."
unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
  echo "gofmt: the following files are not formatted:" >&2
  echo "$unformatted" >&2
  required_failed=1
fi

# 2. Required: module hygiene
step "go mod tidy"
go mod tidy

# 3. Required: vet
step "go vet ./..."
if ! go vet ./...; then
  required_failed=1
fi

# 4. Required: tests
step "go test ./..."
if ! go test ./...; then
  required_failed=1
fi

# 5. Required: race detector
step "go test -race ./..."
if ! go test -race ./...; then
  required_failed=1
fi

# 6. Required: repository integration tests
step "go test ./internal/controlplane/store/..."
if ! go test ./internal/controlplane/store/...; then
  required_failed=1
fi

# 7. Optional: govulncheck (vulnerability scan)
step "govulncheck ./... (optional)"
if command -v govulncheck >/dev/null 2>&1; then
  if ! govulncheck ./...; then
    required_failed=1
  fi
else
  skipped_tools+=("govulncheck (install: go install golang.org/x/vuln/cmd/govulncheck@latest)")
fi

# 8. Optional: staticcheck
step "staticcheck ./... (optional)"
if command -v staticcheck >/dev/null 2>&1; then
  if ! staticcheck ./...; then
    required_failed=1
  fi
else
  skipped_tools+=("staticcheck (install: go install honnef.co/go/tools/cmd/staticcheck@latest)")
fi

# 9. Optional: golangci-lint
step "golangci-lint run ./... (optional)"
if command -v golangci-lint >/dev/null 2>&1; then
  if ! golangci-lint run ./...; then
    required_failed=1
  fi
else
  skipped_tools+=("golangci-lint (install: https://golangci-lint.run/welcome/install/)")
fi

# 10. Optional: goreleaser check (release config)
step "goreleaser check (optional)"
if command -v goreleaser >/dev/null 2>&1; then
  if ! goreleaser check; then
    required_failed=1
  fi
  if [[ "$release" -eq 1 ]]; then
    step "goreleaser release --snapshot --clean (optional)"
    if ! goreleaser release --snapshot --clean; then
      required_failed=1
    fi
  fi
else
  skipped_tools+=("goreleaser (install: https://goreleaser.com/install/)")
  if [[ "$release" -eq 1 ]]; then
    echo "verify.sh: --release requires goreleaser to be installed" >&2
    required_failed=1
  fi
fi

if [[ ${#skipped_tools[@]} -gt 0 ]]; then
  echo "" >&2
  echo "verify.sh: optional tools not installed (skipped, NOT silently — see CONTRIBUTING.md):" >&2
  for tool in "${skipped_tools[@]}"; do
    echo "  - $tool" >&2
  done
  if [[ "$strict" -eq 1 ]]; then
    echo "verify.sh: --strict was set; missing optional tools are a failure" >&2
    exit 2
  fi
fi

if [[ "$required_failed" -ne 0 ]]; then
  echo "" >&2
  echo "verify.sh: one or more checks failed" >&2
  exit 1
fi

echo ""
echo "verify.sh: all checks passed"
