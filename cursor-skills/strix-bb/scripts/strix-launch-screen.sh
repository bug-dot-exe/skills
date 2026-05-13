#!/usr/bin/env bash
# Launch Strix in a screen session for live interactive viewing.
# Usage: strix-launch-screen.sh <handle> [strix-runs-dir] [target] [mode]
#   handle: program handle (e.g. replit, shopify)
#   strix-runs-dir: base dir for runs (default: ~/strix-runs)
#   target: optional. Default "." (scope from instructions.md). Use single URL only when explicitly provided.
#   mode: optional. standard | deep (default: standard)

set -e

HANDLE="${1:?Usage: strix-launch-screen.sh <handle> [strix-runs-dir] [target-url] [mode]}"
BASE_DIR="${2:-$HOME/strix-runs}"
TARGET="${3:-.}"
MODE="${4:-standard}"
RUN_DIR="$BASE_DIR/$HANDLE"
SESSION="strix-$HANDLE"

if [[ ! -d "$RUN_DIR" ]]; then
  echo "Error: Run directory not found: $RUN_DIR"
  echo "Create it first and add instructions.md (e.g. via strix-prep or strix-bb skill)"
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

if ! command -v screen &>/dev/null; then
  echo "Error: screen not found. Install screen first."
  exit 1
fi

STRIX_ENV="${HOME}/.strix/env"
STRIX_CONFIG="${HOME}/.strix/cli-config.json"
CMDS_FILE="$RUN_DIR/.strix-paste.txt"
NOTIFY_SCRIPT="$HOME/.cursor/skills/strix-bb/scripts/strix-telegram-notify.sh"

# Build paste file (for interactive) or wrapper (for detached)
if [[ -f "$STRIX_ENV" ]]; then
  { cat "$STRIX_ENV"; echo ""; } > "$CMDS_FILE"
elif [[ -f "$STRIX_CONFIG" ]] && command -v jq &>/dev/null; then
  {
    echo 'export STRIX_LLM="azure/gpt-4"'
    jq -r '.env // {} | to_entries[] | "export \(.key)=\"\(.value)\""' "$STRIX_CONFIG" 2>/dev/null
    echo ""
  } > "$CMDS_FILE"
else
  echo "Warning: No ~/.strix/env or cli-config.json. Create ~/.strix/env with your Azure exports." >&2
  touch "$CMDS_FILE"
fi

WATCHER_SCRIPT="$HOME/.cursor/skills/strix-bb/scripts/strix-telegram-watcher.sh"
{
  echo "# Telegram watcher (run first, then cd and strix)"
  echo "\"$WATCHER_SCRIPT\" \"$RUN_DIR\" 300 &"
  echo "cd \"$RUN_DIR\""
  echo "strix -m $MODE --target $TARGET --instruction-file instructions.md"
} >> "$CMDS_FILE"

# Build runnable script
RUN_SCRIPT="$RUN_DIR/run.sh"
{
  echo "#!/usr/bin/env bash"
  echo "set -e"
  echo "RUN_DIR=\"$(cd "$RUN_DIR" && pwd)\""
  echo "cd \"\$RUN_DIR\""
  if [[ -f "$STRIX_ENV" ]]; then
    cat "$STRIX_ENV"
    echo ""
  elif [[ -f "$STRIX_CONFIG" ]] && command -v jq &>/dev/null; then
    echo 'export STRIX_LLM="azure/gpt-4"'
    jq -r '.env // {} | to_entries[] | "export \(.key)=\"\(.value)\""' "$STRIX_CONFIG" 2>/dev/null || true
    echo ""
  fi
  echo "\"$WATCHER_SCRIPT\" \"\$RUN_DIR\" 300 &"
  echo "exec strix -m $MODE --target $TARGET --instruction-file instructions.md"
} > "$RUN_SCRIPT"
chmod +x "$RUN_SCRIPT"

if [[ -t 0 ]]; then
  # Interactive terminal: start screen
  echo ""
  echo "=== In screen, run: cd $RUN_DIR && ./run.sh ==="
  echo ""
  echo "=== Starting screen session '$SESSION' ==="
  echo ""
  exec screen -R "$SESSION"
else
  # No TTY: DON'T create session — screen -dmS causes mouse error.
  # User creates session manually with screen -R (same as "screen -R test" that works).
  echo ""
  echo "Run this in YOUR terminal:"
  echo ""
  echo "  screen -R $SESSION"
  echo ""
  echo "Then run:"
  echo ""
  echo "  $RUN_SCRIPT"
  echo ""
  echo "Or paste from: $CMDS_FILE"
  echo "Detach: Ctrl+A, D"
fi
