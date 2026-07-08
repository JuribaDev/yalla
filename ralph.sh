#!/bin/bash
# Ralph Wiggum - Long-running AI agent loop
# Usage: ./ralph.sh [max_iterations_label]

set -e

MAX_ITERATIONS=${1:-10}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRD_FILE="$SCRIPT_DIR/ralph/prd.json"
PROGRESS_FILE="$SCRIPT_DIR/ralph/progress.txt"
ARCHIVE_DIR="$SCRIPT_DIR/ralph/archive"
LAST_BRANCH_FILE="$SCRIPT_DIR/ralph/.last-branch"

# Validate prd.json exists
if [ ! -f "$PRD_FILE" ]; then
  echo "Error: prd.json not found!"
  echo "Run '/ralph <prd-file>' first to create it."
  exit 1
fi

# Always archive existing prd.json + progress.txt before starting
if [ -f "$LAST_BRANCH_FILE" ]; then
  LAST_BRANCH=$(cat "$LAST_BRANCH_FILE" 2>/dev/null || echo "")
  if [ -n "$LAST_BRANCH" ]; then
    DATE=$(date +%Y-%m-%d-%H%M%S)
    FOLDER_NAME=$(echo "$LAST_BRANCH" | sed 's|^ralph/||')
    ARCHIVE_FOLDER="$ARCHIVE_DIR/$DATE-$FOLDER_NAME"

    echo "Archiving previous run: $LAST_BRANCH"
    mkdir -p "$ARCHIVE_FOLDER"
    [ -f "$PRD_FILE" ] && cp "$PRD_FILE" "$ARCHIVE_FOLDER/prd.json.bak"
    [ -f "$PROGRESS_FILE" ] && cp "$PROGRESS_FILE" "$ARCHIVE_FOLDER/"
    echo "   Archived to: $ARCHIVE_FOLDER"
  fi
fi

# Get branch name from prd.json
BRANCH_NAME=$(jq -r '.branchName' "$PRD_FILE")
if [ -z "$BRANCH_NAME" ] || [ "$BRANCH_NAME" = "null" ]; then
  echo "Error: branchName not found in prd.json"
  exit 1
fi

# Always ensure we're on the correct branch, created from main
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "$BRANCH_NAME" ]; then
  echo "Switching to branch: $BRANCH_NAME"

  # Stash any uncommitted changes
  git stash push -m "ralph-auto-stash" 2>/dev/null || true

  # Checkout main and pull latest
  git checkout main
  git pull origin main

  # Create or switch to feature branch from main
  if git show-ref --verify --quiet "refs/heads/$BRANCH_NAME"; then
    echo "Branch exists, switching to it"
    git checkout "$BRANCH_NAME"
  else
    echo "Creating new branch from main"
    git checkout -b "$BRANCH_NAME"
  fi
fi

# Track current branch
echo "$BRANCH_NAME" > "$LAST_BRANCH_FILE"

# Initialize progress file if it doesn't exist
if [ ! -f "$PROGRESS_FILE" ]; then
  echo "# Ralph Progress Log" > "$PROGRESS_FILE"
  echo "Started: $(date)" >> "$PROGRESS_FILE"
  echo "---" >> "$PROGRESS_FILE"
fi

echo "Starting Ralph - runs until all PRD stories pass"

i=1
while true; do
  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo "  Ralph Iteration $i"
  echo "═══════════════════════════════════════════════════════"

  # Run Claude Code with the ralph prompt
  PROMPT=$(cat "$SCRIPT_DIR/prompt.md")
  OUTPUT=$(claude -p --dangerously-skip-permissions "$PROMPT" 2>&1 | tee /dev/stderr) || true

  # Stop only when the PRD says every story is complete.
  REMAINING_STORIES=$(jq '[.userStories[] | select(.passes != true)] | length' "$PRD_FILE")
  if [ "$REMAINING_STORIES" -eq 0 ]; then
    echo ""
    echo "Ralph completed all tasks!"
    echo "Completed at iteration $i"
    exit 0
  fi

  echo "Iteration $i complete. Remaining stories: $REMAINING_STORIES. Continuing..."
  sleep 2
  i=$((i + 1))
done
