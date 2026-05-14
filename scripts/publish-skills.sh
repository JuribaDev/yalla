#!/usr/bin/env bash
# Publish the yalla agent skills to the public distribution repo
# (https://github.com/JuribaDev/yalla-skills).
#
# Why this script exists: the published repo is NOT a mirror of skills/. It has
# a transformed layout — the Claude variant is wrapped in a Claude Code plugin
# structure, the Codex variant sits at the top level, and there are injected
# metadata files (marketplace.json, plugin.json, README, LICENSE) that have no
# source in this repo. So syncing is a transform + version-stamp, not a push.
#
# The source of truth is this repo's skills/ tree. This script reads the working
# tree, applies the transform into a checkout of yalla-skills, bumps the version
# to match the yalla CLI version, and (with --push) commits, tags, and releases.
#
# Usage:
#   scripts/publish-skills.sh                          # dry run: transform + show diff, nothing pushed
#   scripts/publish-skills.sh --version v0.2.0         # stamp an explicit version
#   scripts/publish-skills.sh --version v0.2.0 --push  # commit + tag + push + GH release
#   scripts/publish-skills.sh --repo ../yalla-skills   # reuse an existing checkout instead of cloning
#
# Defaults:
#   --version : `git describe --tags --always` of this repo (skill version tracks CLI version)
#   --repo    : a fresh clone into a temp dir, cleaned up on exit
#
# Requirements: git, rsync, python3, and (for --push) the gh CLI authenticated
# with push access to JuribaDev/yalla-skills.

set -euo pipefail

# --- Config ---------------------------------------------------------------
DIST_REMOTE="https://github.com/JuribaDev/yalla-skills.git"
DIST_SLUG="JuribaDev/yalla-skills"
CLAUDE_SRC_REL="skills/claude/yalla-dokploy-deploy"
CODEX_SRC_REL="skills/codex/yalla-dokploy-deploy"
CLAUDE_DEST_REL="plugins/yalla-dokploy-deploy/skills/yalla-dokploy-deploy"
CODEX_DEST_REL="codex/yalla-dokploy-deploy"
# Files in the dist repo whose `version` field tracks the release:
MARKETPLACE_REL=".claude-plugin/marketplace.json"
PLUGIN_JSON_REL="plugins/yalla-dokploy-deploy/.claude-plugin/plugin.json"

# --- Args -----------------------------------------------------------------
VERSION=""
PUSH=false
DIST_DIR=""
CLONED_TMP=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --push)    PUSH=true; shift ;;
    --repo)    DIST_DIR="${2:-}"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "publish-skills: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

# --- Locate this repo -----------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

for tool in git rsync python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "publish-skills: '$tool' not found on PATH" >&2; exit 1; }
done

# --- Resolve version ------------------------------------------------------
if [[ -z "$VERSION" ]]; then
  VERSION="$(git describe --tags --always 2>/dev/null || echo "0.0.0-dev")"
fi
# Normalise: strip a leading 'v' for the JSON `version` field; keep a v-prefixed
# form for the git tag.
VERSION_NUM="${VERSION#v}"
VERSION_TAG="v${VERSION_NUM}"

YALLA_SHA="$(git rev-parse --short HEAD)"
echo "publish-skills: yalla @ ${YALLA_SHA}, publishing skill version ${VERSION_NUM}"

# Warn (don't block) if the skill source has uncommitted changes — provenance
# SHA in the commit message won't fully describe what was published.
if [[ -n "$(git status --porcelain -- "$CLAUDE_SRC_REL" "$CODEX_SRC_REL" 2>/dev/null)" ]]; then
  echo "publish-skills: WARNING — skills/ has uncommitted changes; the recorded" >&2
  echo "                provenance SHA (${YALLA_SHA}) will not reflect them." >&2
fi

# --- Get the dist repo into a working dir ---------------------------------
cleanup() { [[ -n "$CLONED_TMP" && -d "$CLONED_TMP" ]] && rm -rf "$CLONED_TMP"; }
trap cleanup EXIT

if [[ -z "$DIST_DIR" ]]; then
  CLONED_TMP="$(mktemp -d -t yalla-skills-publish.XXXXXX)"
  DIST_DIR="$CLONED_TMP/yalla-skills"
  echo "publish-skills: cloning ${DIST_SLUG} ..."
  git clone --quiet --depth 1 "$DIST_REMOTE" "$DIST_DIR"
else
  DIST_DIR="$(cd "$DIST_DIR" && pwd)"
  [[ -f "$DIST_DIR/$MARKETPLACE_REL" ]] || {
    echo "publish-skills: '$DIST_DIR' doesn't look like a yalla-skills checkout (no $MARKETPLACE_REL)" >&2
    exit 1
  }
  echo "publish-skills: using existing checkout at $DIST_DIR"
fi

# --- Transform: rsync the two variants into their published locations -----
# --delete keeps the dist tree in lockstep with source (removed source files
# disappear downstream). --exclude evals/ keeps the dev-only eval corpus out of
# the public package. The rsync targets are leaf skill dirs only, so the
# injected metadata files (marketplace.json, plugin.json, READMEs, LICENSE)
# are never touched here.
echo "publish-skills: syncing Claude variant  -> $CLAUDE_DEST_REL"
mkdir -p "$DIST_DIR/$CLAUDE_DEST_REL"
rsync -a --delete --exclude 'evals/' \
  "$REPO_ROOT/$CLAUDE_SRC_REL/" "$DIST_DIR/$CLAUDE_DEST_REL/"

echo "publish-skills: syncing Codex variant   -> $CODEX_DEST_REL"
mkdir -p "$DIST_DIR/$CODEX_DEST_REL"
rsync -a --delete --exclude 'evals/' \
  "$REPO_ROOT/$CODEX_SRC_REL/" "$DIST_DIR/$CODEX_DEST_REL/"

# --- Stamp the version into the metadata files ----------------------------
# Edits only the `version` fields; leaves the rest of each JSON intact.
python3 - "$DIST_DIR" "$VERSION_NUM" "$MARKETPLACE_REL" "$PLUGIN_JSON_REL" <<'PY'
import json, sys
dist, version, mp_rel, plugin_rel = sys.argv[1:5]

mp_path = f"{dist}/{mp_rel}"
with open(mp_path) as f: mp = json.load(f)
mp.setdefault("metadata", {})["version"] = version
for p in mp.get("plugins", []):
    p["version"] = version
with open(mp_path, "w") as f:
    json.dump(mp, f, indent=2, ensure_ascii=False); f.write("\n")

plugin_path = f"{dist}/{plugin_rel}"
with open(plugin_path) as f: plugin = json.load(f)
plugin["version"] = version
with open(plugin_path, "w") as f:
    json.dump(plugin, f, indent=2, ensure_ascii=False); f.write("\n")

print(f"publish-skills: stamped version {version} into marketplace.json + plugin.json")
PY

# --- Show what changed ----------------------------------------------------
cd "$DIST_DIR"
if git diff --quiet && git diff --cached --quiet; then
  echo "publish-skills: dist repo already in sync — nothing to publish."
  exit 0
fi

echo ""
echo "=== Changes staged for ${DIST_SLUG} ==="
git add -A
git --no-pager diff --cached --stat
echo ""

# --- Dry run stops here ---------------------------------------------------
if ! $PUSH; then
  echo "publish-skills: DRY RUN — nothing pushed."
  if [[ -n "$CLONED_TMP" ]]; then
    # The temp checkout is about to be cleaned up; surface a hint instead.
    echo "                Re-run with --push to commit, tag ${VERSION_TAG}, and release."
  else
    echo "                Changes are staged in $DIST_DIR — commit there, or re-run with --push."
    trap - EXIT  # keep the user's checkout intact
  fi
  exit 0
fi

# --- Push: commit, tag, release -------------------------------------------
git -c user.name="JuribaDev" -c user.email="Juribaalsiari@gmail.com" \
  commit --quiet -m "Sync skills from yalla@${YALLA_SHA} — ${VERSION_TAG}

Published from $(basename "$REPO_ROOT") working tree at commit ${YALLA_SHA}.
Skill content: skills/claude + skills/codex transformed into the plugin layout;
evals/ stripped; version stamped to ${VERSION_NUM}.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"

git push --quiet origin HEAD:main
echo "publish-skills: pushed commit to ${DIST_SLUG}@main"

# Tag + release only if this version isn't already released.
if git ls-remote --tags origin "refs/tags/${VERSION_TAG}" | grep -q "${VERSION_TAG}"; then
  echo "publish-skills: tag ${VERSION_TAG} already exists on the dist repo — skipping tag + release."
  echo "                (content was still synced and pushed to main.)"
else
  git tag -a "${VERSION_TAG}" -m "${VERSION_TAG} — synced from yalla@${YALLA_SHA}"
  git push --quiet origin "${VERSION_TAG}"
  echo "publish-skills: pushed tag ${VERSION_TAG}"

  if command -v gh >/dev/null 2>&1; then
    gh release create "${VERSION_TAG}" \
      --repo "${DIST_SLUG}" \
      --title "${VERSION_TAG}" \
      --notes "Synced from yalla CLI \`${YALLA_SHA}\`. See the [yalla repo](https://github.com/JuribaDev/yalla) for the matching CLI release.

Install:
\`\`\`sh
/plugin marketplace add ${DIST_SLUG}
/plugin install yalla-dokploy-deploy@yalla-skills
\`\`\`" >/dev/null
    echo "publish-skills: created GitHub release ${VERSION_TAG}"
  else
    echo "publish-skills: gh not found — tag pushed, but no GitHub release created."
  fi
fi

echo ""
echo "publish-skills: done. https://github.com/${DIST_SLUG}"
