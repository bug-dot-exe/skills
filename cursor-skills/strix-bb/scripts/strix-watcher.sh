#!/usr/bin/env bash
# Watches for Strix launch requests and runs them on THIS machine.
# Start once (e.g. in background or on login) so Cursor/user requests get executed here.
#
# Usage: strix-watcher.sh [interval_seconds]
#   Run in background: strix-watcher.sh &
#   Or add to .bashrc: (strix-watcher.sh &)
#
# Queue file: ~/strix-runs/.launch-queue (format: handle|target)

BASE_DIR="${STRIX_RUNS_DIR:-$HOME/strix-runs}"
QUEUE_FILE="$BASE_DIR/.launch-queue"
LAUNCH_SCRIPT="${STRIX_LAUNCH_SCRIPT:-$HOME/.cursor/skills/strix-bb/scripts/strix-launch-tmux.sh}"
INTERVAL="${1:-5}"

mkdir -p "$BASE_DIR"

echo "Strix watcher started (checking every ${INTERVAL}s). Queue: $QUEUE_FILE"

while true; do
  if [[ -f "$QUEUE_FILE" ]] && [[ -s "$QUEUE_FILE" ]]; then
    line=$(cat "$QUEUE_FILE")
    > "$QUEUE_FILE"
    handle="${line%%|*}"
    target="${line#*|}"
    [[ -z "$target" ]] && target="."
    echo "[$(date +%H:%M:%S)] Launching strix-$handle ($target)"
    "$LAUNCH_SCRIPT" "$handle" "$BASE_DIR" "$target" || true
  fi
  sleep "$INTERVAL"
done
