#!/usr/bin/env bash
# Install this repository's tracked Git hooks.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

git config core.hooksPath .githooks

echo "Installed yalla Git hooks: core.hooksPath=.githooks"
