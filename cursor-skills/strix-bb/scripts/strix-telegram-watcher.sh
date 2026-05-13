#!/usr/bin/env bash
# Poll run_dir every 5 min for new vulnerabilities. Send Telegram when found.
# Run in background BEFORE Strix — so you get notified while Strix is still running.
#
# Usage: strix-telegram-watcher.sh <run_dir> [interval_seconds]
#   run_dir: e.g. ~/strix-runs/overwolf
#   interval: default 300 (5 min)
#
# Run: strix-telegram-watcher.sh ~/strix-runs/overwolf &
# Then: strix -m standard ...

RUN_DIR="${1:?Usage: strix-telegram-watcher.sh <run_dir> [interval_sec]}"
INTERVAL="${2:-300}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOTIFY_SCRIPT="$SCRIPT_DIR/strix-telegram-notify.sh"
STATE_FILE="$RUN_DIR/.strix-telegram-last-count"

mkdir -p "$RUN_DIR"
last_count=0
[[ -f "$STATE_FILE" ]] && last_count=$(cat "$STATE_FILE" 2>/dev/null)

while true; do
  count=0
  if [[ -d "$RUN_DIR/strix_runs" ]]; then
    for vdir in "$RUN_DIR/strix_runs"/*/vulnerabilities; do
      [[ -d "$vdir" ]] || continue
      n=$(find "$vdir" -name 'vuln-*.md' 2>/dev/null | wc -l)
      count=$((count + n))
    done
  fi

  if [[ "$count" -gt "$last_count" ]] && [[ "$count" -gt 0 ]]; then
    "$NOTIFY_SCRIPT" "$RUN_DIR" 2>/dev/null || true
    last_count=$count
    echo "$last_count" > "$STATE_FILE"
  fi

  sleep "$INTERVAL"
done
