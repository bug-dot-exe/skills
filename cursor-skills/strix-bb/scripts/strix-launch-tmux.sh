#!/usr/bin/env bash
# Launch Strix in a detached tmux session (auto-runs strix; attach to watch).
# Usage: strix-launch-tmux.sh <handle> [strix-runs-dir] [target] [mode]
#   handle: program handle (e.g. paradigm_connect)
#   strix-runs-dir: default ~/strix-runs
#   target: default "." ; use primary URL when hunting a single host
#   mode: standard | deep (default: standard)
#
# Per-run overrides: if ~/strix-runs/<handle>/strix-env.sh exists, it is sourced
# after ~/.strix/env (use for LLM_API_KEY, STRIX_LLM, etc.).

set -e

HANDLE="${1:?Usage: strix-launch-tmux.sh <handle> [strix-runs-dir] [target-url] [mode]}"
BASE_DIR="${2:-$HOME/strix-runs}"
TARGET="${3:-.}"
MODE="${4:-standard}"
RUN_DIR="$BASE_DIR/$HANDLE"
SESSION="strix-$HANDLE"

if [[ ! -d "$RUN_DIR" ]]; then
  echo "Error: Run directory not found: $RUN_DIR"
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

RUN_DIR_ABS=$(cd "$RUN_DIR" && pwd)
STRIX_ENV="${HOME}/.strix/env"
STRIX_CONFIG="${HOME}/.strix/cli-config.json"
WATCHER_SCRIPT="${HOME}/.cursor/skills/strix-bb/scripts/strix-telegram-watcher.sh"
TARGET_Q=$(printf '%q' "$TARGET")
MODE_Q=$(printf '%q' "$MODE")

RUN_INNER="$RUN_DIR/.strix-tmux-run.sh"
{
  echo "#!/usr/bin/env bash"
  echo "set -e"
  echo "cd $(printf '%q' "$RUN_DIR_ABS")"
  if [[ -f "$STRIX_ENV" ]]; then
    echo "if [[ -f \"\$HOME/.strix/env\" ]]; then"
    echo "  set -a"
    echo "  # shellcheck source=/dev/null"
    echo "  source \"\$HOME/.strix/env\""
    echo "  set +a"
    echo "fi"
  elif [[ -f "$STRIX_CONFIG" ]] && command -v jq &>/dev/null; then
    echo 'export STRIX_LLM="azure/gpt-4"'
    jq -r '.env // {} | to_entries[] | "export \(.key)=\"\(.value)\""' "$STRIX_CONFIG" 2>/dev/null || true
  else
    echo "echo \"Warning: no ~/.strix/env or cli-config.json — set keys in ~/strix-runs/$HANDLE/strix-env.sh\" >&2"
  fi
  echo "if [[ -f \"./strix-env.sh\" ]]; then"
  echo "  set -a"
  echo "  # shellcheck source=/dev/null"
  echo "  source \"./strix-env.sh\""
  echo "  set +a"
  echo "fi"
  echo "$(printf '%q' "$WATCHER_SCRIPT") $(printf '%q' "$RUN_DIR_ABS") 300 &"
  echo "set +e"
  echo "strix -m $MODE_Q --target $TARGET_Q --instruction-file instructions.md"
  echo "_strix_rc=\$?"
  echo "set -e"
  echo "echo \"\""
  echo "echo \"[strix-tmux] Strix exited (status \$_strix_rc). Interactive shell — type exit to close pane.\""
  echo "exec bash"
} > "$RUN_INNER"
chmod +x "$RUN_INNER"

# Optional paste reference (no secrets; inner script sources env files)
CMDS_FILE="$RUN_DIR/.strix-paste.txt"
{
  echo "# Detached tmux session already runs Strix. Attach with:"
  echo "#   tmux attach -t $SESSION"
  echo "# Inner runner: $RUN_INNER"
} > "$CMDS_FILE"

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "Replacing existing tmux session: $SESSION"
  tmux kill-session -t "$SESSION"
fi

tmux new-session -d -s "$SESSION" bash "$RUN_INNER"

echo ""
echo "Started tmux session: $SESSION"
echo "  Attach: tmux attach -t $SESSION"
echo "  Detach: Ctrl+B, then D"
echo "  Runner: $RUN_INNER"
echo ""
echo "Tip: Run this script on the same machine where you use tmux (e.g. your SSH shell on the VPS)."
echo "     Cursor/agents may use a different tmux server than your login session."
echo ""
