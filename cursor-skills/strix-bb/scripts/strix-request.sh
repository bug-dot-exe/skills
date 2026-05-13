#!/usr/bin/env bash
# Queue a Strix launch request. The watcher (strix-watcher.sh) picks it up and
# runs the launch on YOUR machine. Use from Cursor or anywhere.
#
# Usage: strix-request.sh <handle> [target]
#   handle: program handle (e.g. overwolf, nayya_health_bbp)
#   target: optional. Default "." (scope from instructions.md). Single URL only when explicitly provided.
#
# Requires: strix-watcher.sh running on your machine (start once in background).

set -e

HANDLE="${1:?Usage: strix-request.sh <handle> [target-url]}"
TARGET="${2:-.}"
BASE_DIR="${STRIX_RUNS_DIR:-$HOME/strix-runs}"
QUEUE_FILE="$BASE_DIR/.launch-queue"
LAUNCH_SCRIPT="${STRIX_LAUNCH_SCRIPT:-$HOME/.cursor/skills/strix-bb/scripts/strix-launch-tmux.sh}"

mkdir -p "$BASE_DIR"
echo "$HANDLE|$TARGET" > "$QUEUE_FILE"
echo "Queued: $HANDLE ($TARGET)"
echo "Watcher will launch on your machine. Attach with: tmux attach -t strix-$HANDLE"
