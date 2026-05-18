#!/bin/bash
# Ralph Codex - Long-running AI agent loop
# Usage: ./ralphcodex.sh [max_iterations_label]

set -e

MAX_ITERATIONS=${1:-10}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRD_FILE="$SCRIPT_DIR/ralph/prd.json"
PROGRESS_FILE="$SCRIPT_DIR/ralph/progress.txt"
ARCHIVE_DIR="$SCRIPT_DIR/ralph/archive"
LAST_BRANCH_FILE="$SCRIPT_DIR/ralph/.last-branch"
CODEX_OUTPUT_DIR="$SCRIPT_DIR/ralph/codex-output"
CODEX_TIMEOUT_SECONDS=${CODEX_TIMEOUT_SECONDS:-3600}
CODEX_POLL_SECONDS=${CODEX_POLL_SECONDS:-5}

# Validate prd.json exists
if [ ! -f "$PRD_FILE" ]; then
  echo "Error: prd.json not found!"
  echo "Run '/ralph <prd-file>' first to create it."
  exit 1
fi

# Detect whether the current PRD still has stories explicitly marked failed.
# If so, resume in place: skip archive + skip branch reset/creation from main.
FAILED_STORIES=$(jq '[.userStories[] | select(.passes == false)] | length' "$PRD_FILE")
if [ "$FAILED_STORIES" -gt 0 ]; then
  RESUME_MODE=true
  echo "Resuming previous run: $FAILED_STORIES stories have passes=false in prd.json"
else
  RESUME_MODE=false
fi

# Archive existing prd.json + progress.txt only on a fresh start
if [ "$RESUME_MODE" = false ] && [ -f "$LAST_BRANCH_FILE" ]; then
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

CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "$BRANCH_NAME" ]; then
  if [ "$RESUME_MODE" = true ]; then
    # Resume: switch to the existing branch without resetting from main
    if git show-ref --verify --quiet "refs/heads/$BRANCH_NAME"; then
      echo "Resuming on existing branch: $BRANCH_NAME"
      git stash push -m "ralph-auto-stash" 2>/dev/null || true
      git checkout "$BRANCH_NAME"
    else
      echo "Error: prd.json has $FAILED_STORIES stories with passes=false, refusing to create new branch $BRANCH_NAME"
      exit 1
    fi
  else
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
fi

# Track current branch
echo "$BRANCH_NAME" > "$LAST_BRANCH_FILE"

# Initialize progress file if it doesn't exist
if [ ! -f "$PROGRESS_FILE" ]; then
  echo "# Ralph Progress Log" > "$PROGRESS_FILE"
  echo "Started: $(date)" >> "$PROGRESS_FILE"
  echo "---" >> "$PROGRESS_FILE"
fi

echo "Starting Ralph Codex - runs until all PRD stories pass"
echo "Codex timeout per iteration: ${CODEX_TIMEOUT_SECONDS}s"
mkdir -p "$CODEX_OUTPUT_DIR"

i=1
while true; do
  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo "  Ralph Codex Iteration $i"
  echo "═══════════════════════════════════════════════════════"

  # Run Codex with the ralph prompt
  PROMPT=$(cat "$SCRIPT_DIR/prompt.md")
  TIMESTAMP=$(date +%Y%m%d-%H%M%S)
  ITERATION_NAME=$(printf "iteration-%06d-%s" "$i" "$TIMESTAMP")
  ITERATION_LOG="$CODEX_OUTPUT_DIR/$ITERATION_NAME.log"
  ITERATION_FINAL="$CODEX_OUTPUT_DIR/$ITERATION_NAME-final.md"
  ITERATION_STATUS="$CODEX_OUTPUT_DIR/$ITERATION_NAME.status.json"
  PENDING_BEFORE=$(jq '[.userStories[] | select(.passes == false)] | length' "$PRD_FILE")

  CODEX_PROMPT="$PROMPT

Codex runner note:
- You are running inside a non-interactive loop.
- Do not rely on chat output for progress. Update ralph/progress.txt.
- If you complete a story, update ralph/prd.json so that story has passes: true before exiting.
- Keep your final response short. Use <promise>COMPLETE</promise> only when every story is complete.
- If this run is interrupted by the runner timeout, the next run will pick the first unfinished story from ralph/prd.json."

  codex exec --cd "$SCRIPT_DIR" \
    --dangerously-bypass-approvals-and-sandbox \
    --output-last-message "$ITERATION_FINAL" \
    "$CODEX_PROMPT" >"$ITERATION_LOG" 2>&1 &

  CODEX_PID=$!
  START_EPOCH=$(date +%s)
  TIMED_OUT=0
  CODEX_STATUS=0

  while kill -0 "$CODEX_PID" 2>/dev/null; do
    NOW_EPOCH=$(date +%s)
    ELAPSED=$((NOW_EPOCH - START_EPOCH))

    if [ "$ELAPSED" -ge "$CODEX_TIMEOUT_SECONDS" ]; then
      TIMED_OUT=1
      CODEX_STATUS=124
      kill "$CODEX_PID" 2>/dev/null || true
      sleep 5
      kill -9 "$CODEX_PID" 2>/dev/null || true
      wait "$CODEX_PID" 2>/dev/null || true
      break
    fi

    sleep "$CODEX_POLL_SECONDS"
  done

  if [ "$TIMED_OUT" -eq 0 ]; then
    set +e
    wait "$CODEX_PID"
    CODEX_STATUS=$?
    set -e
  fi

  # Stop only when the PRD says every story is complete.
  REMAINING_STORIES=$(jq '[.userStories[] | select(.passes == false)] | length' "$PRD_FILE")
  PENDING_AFTER="$REMAINING_STORIES"
  ENDED_AT=$(date +%Y-%m-%dT%H:%M:%S%z)
  if [ "$TIMED_OUT" -eq 1 ]; then
    RUN_STATUS="timeout"
  elif [ "$CODEX_STATUS" -eq 0 ]; then
    RUN_STATUS="completed"
  else
    RUN_STATUS="failed"
  fi

  jq -n \
    --arg iteration "$i" \
    --arg status "$RUN_STATUS" \
    --arg exit_code "$CODEX_STATUS" \
    --arg ended_at "$ENDED_AT" \
    --arg pending_before "$PENDING_BEFORE" \
    --arg pending_after "$PENDING_AFTER" \
    --arg log_file "$ITERATION_LOG" \
    --arg final_file "$ITERATION_FINAL" \
    '{
      iteration: ($iteration | tonumber),
      status: $status,
      exit_code: ($exit_code | tonumber),
      ended_at: $ended_at,
      pending_before: ($pending_before | tonumber),
      pending_after: ($pending_after | tonumber),
      progress_made: (($pending_after | tonumber) < ($pending_before | tonumber)),
      log_file: $log_file,
      final_file: $final_file
    }' > "$ITERATION_STATUS"

  if [ "$REMAINING_STORIES" -eq 0 ]; then
    echo ""
    echo "Ralph Codex completed all tasks!"
    echo "Completed at iteration $i"
    exit 0
  fi

  echo "Iteration $i status=$RUN_STATUS exit=$CODEX_STATUS pending_before=$PENDING_BEFORE pending_after=$PENDING_AFTER status_file=$ITERATION_STATUS"
  sleep 2
  i=$((i + 1))
done
