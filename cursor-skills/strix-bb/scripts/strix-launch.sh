#!/usr/bin/env bash
# Launch Strix in a tmux session for live viewing.
# Usage: strix-launch.sh <handle> [strix-runs-dir] [target-url]
#   handle: program handle (e.g. replit, shopify)
#   strix-runs-dir: base dir for runs (default: ~/strix-runs)
#   target-url: optional URL/domain for Strix (default: https://<handle>.com)

set -e

HANDLE="${1:?Usage: strix-launch.sh <handle> [strix-runs-dir] [target-url]}"
BASE_DIR="${2:-$HOME/strix-runs}"
TARGET="${3:-https://${HANDLE}.com}"
RUN_DIR="$BASE_DIR/$HANDLE"
SESSION="strix-$HANDLE"

if [[ ! -d "$RUN_DIR" ]]; then
  echo "Error: Run directory not found: $RUN_DIR"
  echo "Create it first and add instructions.md (e.g. via strix-bb skill)"
  exit 1
fi

if [[ ! -f "$RUN_DIR/instructions.md" ]]; then
  echo "Error: instructions.md not found in $RUN_DIR"
  exit 1
fi

if ! command -v strix &>/dev/null; then
  echo "Error: strix not found. Install with: curl -sSL https://strix.ai/install | bash"
  exit 1
fi

if ! command -v tmux &>/dev/null; then
  echo "Error: tmux not found. Install tmux first."
  exit 1
fi

# Kill existing session if it exists (optional - allows restart)
tmux kill-session -t "$SESSION" 2>/dev/null || true

# FIX: Tmux server caches env from when it was started. New sessions inherit STALE vars
# (e.g. STRIX_LLM=openai/gpt-5.2, no AZURE_*). We must update tmux server env first.
STRIX_ENV="${HOME}/.strix/env"
STRIX_CONFIG="${HOME}/.strix/cli-config.json"

if [[ -f "$STRIX_ENV" ]]; then
  source "$STRIX_ENV"
  for var in STRIX_LLM AZURE_API_KEY AZURE_API_BASE AZURE_API_VERSION; do
    [[ -n "${!var}" ]] && tmux set-environment -g "$var" "${!var}"
  done
elif [[ -f "$STRIX_CONFIG" ]] && command -v jq &>/dev/null; then
  while IFS=$'\t' read -r key value; do
    [[ -n "$key" && -n "$value" ]] && tmux set-environment -g "$key" "$value"
  done < <(jq -r '.env // {} | to_entries[] | "\(.key)\t\(.value)"' "$STRIX_CONFIG" 2>/dev/null)
fi

# Now create session — it inherits the updated env from tmux server
RUN_CMD="cd \"$RUN_DIR\" && strix -m standard --target \"$TARGET\" --instruction-file instructions.md; echo; echo 'Strix finished. Press Enter to close.'; read"
tmux new-session -d -s "$SESSION" -n strix "$RUN_CMD"

# Switch current tmux client to the new session, or print attach command
if tmux switch-client -t "$SESSION" 2>/dev/null; then
  echo "Strix running in tmux session '$SESSION'. Use prefix+W to switch sessions."
else
  echo "Strix running in tmux session '$SESSION'."
  echo "To watch live: tmux attach -t $SESSION"
fi
