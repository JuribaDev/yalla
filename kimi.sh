#!/bin/bash
# Ralph Kimi - Long-running AI agent loop
# Usage: ./ralphkimi.sh [max_iterations_label]

set -e

MAX_ITERATIONS=${1:-10}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRD_FILE="$SCRIPT_DIR/ralph/prd.json"
PROGRESS_FILE="$SCRIPT_DIR/ralph/progress.txt"
ARCHIVE_DIR="$SCRIPT_DIR/ralph/archive"
LAST_BRANCH_FILE="$SCRIPT_DIR/ralph/.last-branch"
KIMI_OUTPUT_DIR="$SCRIPT_DIR/ralph/kimi-output"
KIMI_TIMEOUT_SECONDS=${KIMI_TIMEOUT_SECONDS:-3600}
KIMI_POLL_SECONDS=${KIMI_POLL_SECONDS:-5}

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

echo "Starting Ralph Kimi - runs until all PRD stories pass"
echo "Kimi timeout per iteration: ${KIMI_TIMEOUT_SECONDS}s"
mkdir -p "$KIMI_OUTPUT_DIR"

i=1
while true; do
  if [ "$i" -gt "$MAX_ITERATIONS" ]; then
    echo "Reached MAX_ITERATIONS ($MAX_ITERATIONS). Exiting."
    exit 0
  fi

  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo "  Ralph Kimi Iteration $i"
  echo "═══════════════════════════════════════════════════════"

  PROMPT=$(cat "$SCRIPT_DIR/prompt.md")
  TIMESTAMP=$(date +%Y%m%d-%H%M%S)
  ITERATION_NAME=$(printf "iteration-%06d-%s" "$i" "$TIMESTAMP")
  ITERATION_LOG="$KIMI_OUTPUT_DIR/$ITERATION_NAME.log"
  ITERATION_FINAL="$KIMI_OUTPUT_DIR/$ITERATION_NAME-final.md"
  ITERATION_STATUS="$KIMI_OUTPUT_DIR/$ITERATION_NAME.status.json"
  PENDING_BEFORE=$(jq '[.userStories[] | select(.passes == false)] | length' "$PRD_FILE")

  KIMI_PROMPT="$PROMPT

Kimi runner note:
- You are running inside a non-interactive headless loop.
- Do not rely on terminal chat output for progress. Update ralph/progress.txt.
- If you complete a story, update ralph/prd.json so that story has passes: true before exiting.
- Keep your final response short.
- If this run is interrupted by the runner timeout, the next run will pick the first unfinished story from ralph/prd.json."

  # Run Kimi in a subshell to ensure it executes in SCRIPT_DIR
  (
    cd "$SCRIPT_DIR"
    kimi --print --yolo -p "$KIMI_PROMPT"
  ) >"$ITERATION_LOG" 2>&1 &

  KIMI_PID=$!
  START_EPOCH=$(date +%s)
  TIMED_OUT=0
  KIMI_STATUS=0

  while kill -0 "$KIMI_PID" 2>/dev/null; do
    NOW_EPOCH=$(date +%s)
    ELAPSED=$((NOW_EPOCH - START_EPOCH))

    if [ "$ELAPSED" -ge "$KIMI_TIMEOUT_SECONDS" ]; then
      TIMED_OUT=1
      KIMI_STATUS=124
      kill "$KIMI_PID" 2>/dev/null || true
      sleep 5
      kill -9 "$KIMI_PID" 2>/dev/null || true
      wait "$KIMI_PID" 2>/dev/null || true
      break
    fi

    sleep "$KIMI_POLL_SECONDS"
  done

  if [ "$TIMED_OUT" -eq 0 ]; then
    set +e
    wait "$KIMI_PID"
    KIMI_STATUS=$?
    set -e
  fi

  # Extract final output for the final.md file (replaces Claude's --output-last-message)
  tail -n 50 "$ITERATION_LOG" > "$ITERATION_FINAL"

  # Stop only when the PRD says every story is complete.
  REMAINING_STORIES=$(jq '[.userStories[] | select(.passes == false)] | length' "$PRD_FILE")
  PENDING_AFTER="$REMAINING_STORIES"
  ENDED_AT=$(date +%Y-%m-%dT%H:%M:%S%z)
  
  if [ "$TIMED_OUT" -eq 1 ]; then
    RUN_STATUS="timeout"
  elif [ "$KIMI_STATUS" -eq 0 ]; then
    RUN_STATUS="completed"
  else
    RUN_STATUS="failed"
  fi

  jq -n \
    --arg iteration "$i" \
    --arg status "$RUN_STATUS" \
    --arg exit_code "$KIMI_STATUS" \
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
    echo "Ralph Kimi completed all tasks!"
    echo "Completed at iteration $i"
    exit 0
  fi

  echo "Iteration $i status=$RUN_STATUS exit=$KIMI_STATUS pending_before=$PENDING_BEFORE pending_after=$PENDING_AFTER status_file=$ITERATION_STATUS"
  sleep 2
  i=$((i + 1))
done
