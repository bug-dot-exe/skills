#!/usr/bin/env bash
# Launch VulnAI in a detached tmux session (create session first; attach to watch).
#
# Usage:
#   vulnai-launch-tmux.sh <handle> [vulnai-runs-dir] [scan_mode] [-- extra vulnai args...]
#
#   handle: HackerOne program handle (e.g. fanduel)
#   vulnai-runs-dir: default ~/vulnai-runs
#   scan_mode: quick | standard | deep (default: deep)
#
# Per-run overrides: if ~/vulnai-runs/<handle>/vulnai-env.sh exists, it is sourced
# after ~/.vulnai/env (LLM keys, STRIX_LLM, etc.).
#
# Optional ~/vulnai-runs/<handle>/vulnai-launch.args — one CLI argument per line
# (lines starting with # and empty lines ignored). Injected first, then optional --h1.
#
# Optional ~/vulnai-runs/<handle>/vulnai-no-h1 — if this file exists (empty is fine),
# or env VULNAI_TMUX_NO_H1=1, the script does NOT pass --h1 (scope only from
# instructions.md; no H1 API scope fetch, no h1-brain MCP prepend). Example:
#   vulnai -t … -m deep --instruction-file instructions.md
#
# If `vulnai --help` does not list --h1 (older / non-H1 builds), --h1 is skipped
# automatically. Use vulnai-launch.args for `-t https://primary-in-scope.example.com`
# (or `-t .` for local code + instruction-file scope per vulnai examples).
#
# With --h1 (only when binary supports it and vulnai-no-h1 absent):
#   vulnai -t … --h1 HANDLE -m MODE … --instruction-file instructions.md
#
# Non-interactive: export VULNAI_NONINTERACTIVE=1 to add -n (no TUI).
#
# Same host as attach: run this from the shell where you use tmux (e.g. SSH on a VPS).
# Cursor/agent environments may use a different tmux server than your login session.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: vulnai-launch-tmux.sh <handle> [vulnai-runs-dir] [scan_mode] [-- extra vulnai args...]"
  exit 1
fi

HANDLE="$1"
shift
case $# in
  0)
    BASE_DIR="${VULNAI_RUNS_DIR:-$HOME/vulnai-runs}"
    MODE="deep"
    ;;
  1)
    if [[ -d "$1" ]]; then
      BASE_DIR="$1"
      MODE="deep"
    elif [[ "$1" =~ ^(quick|standard|deep)$ ]]; then
      BASE_DIR="${VULNAI_RUNS_DIR:-$HOME/vulnai-runs}"
      MODE="$1"
    else
      BASE_DIR="$1"
      MODE="deep"
    fi
    shift
    ;;
  *)
    BASE_DIR="$1"
    shift
    MODE="${1:-deep}"
    shift
    ;;
esac
if [[ "${1:-}" == "--" ]]; then shift; fi
EXTRA_ARGS=("$@")

RUN_DIR="$BASE_DIR/$HANDLE"
SESSION="vulnai-$HANDLE"
VULNAI_BIN="${VULNAI_BIN:-vulnai}"

if [[ ! -d "$RUN_DIR" ]]; then
  echo "Error: Run directory not found: $RUN_DIR"
  exit 1
fi

if [[ ! -f "$RUN_DIR/instructions.md" ]]; then
  echo "Error: instructions.md not found in $RUN_DIR"
  exit 1
fi

if ! command -v tmux &>/dev/null; then
  echo "Error: tmux not found. Install tmux before running VulnAI (required)."
  exit 1
fi

if ! command -v "$VULNAI_BIN" &>/dev/null; then
  echo "Error: '$VULNAI_BIN' not on PATH. Set VULNAI_BIN or install VulnAI."
  exit 1
fi

RUN_DIR_ABS=$(cd "$RUN_DIR" && pwd)
VULNAI_ENV="${HOME}/.vulnai/env"
VULNAI_CONFIG="${HOME}/.vulnai/cli-config.json"
HANDLE_Q=$(printf '%q' "$HANDLE")
BIN_Q=$(printf '%q' "$VULNAI_BIN")
MODE_Q=$(printf '%q' "$MODE")

# Optional: explicit -t / other leading args (see header comment)
FILE_ARGS=()
LAUNCH_ARGS_FILE="$RUN_DIR/vulnai-launch.args"
if [[ -f "$LAUNCH_ARGS_FILE" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    FILE_ARGS+=("$line")
  done < "$LAUNCH_ARGS_FILE"
fi

# Optional -n for automation
NI_FLAG=""
if [[ "${VULNAI_NONINTERACTIVE:-}" =~ ^(1|true|yes)$ ]]; then
  NI_FLAG="-n"
fi

VULNAI_LINE="$BIN_Q"
for a in "${FILE_ARGS[@]}"; do
  VULNAI_LINE+=" $(printf '%q' "$a")"
done
NO_H1=0
if [[ "${VULNAI_TMUX_NO_H1:-}" =~ ^(1|true|yes)$ ]] || [[ -f "$RUN_DIR/vulnai-no-h1" ]]; then
  NO_H1=1
fi
if [[ "$NO_H1" -eq 0 ]]; then
  if ! "$VULNAI_BIN" --help 2>&1 | grep -qE '(^|[[:space:]])--h1([[:space:]]|$)'; then
    NO_H1=1
    echo "Note: '$VULNAI_BIN' has no --h1 flag; skipping. Add -t via $LAUNCH_ARGS_FILE if needed." >&2
  fi
fi
if [[ "$NO_H1" -eq 0 ]]; then
  VULNAI_LINE+=" --h1 $HANDLE_Q"
fi
VULNAI_LINE+=" -m $MODE_Q"
[[ -n "$NI_FLAG" ]] && VULNAI_LINE+=" $NI_FLAG"
for a in "${EXTRA_ARGS[@]}"; do
  VULNAI_LINE+=" $(printf '%q' "$a")"
done
VULNAI_LINE+=" --instruction-file instructions.md"

RUN_INNER="$RUN_DIR/.vulnai-tmux-run.sh"
{
  echo "#!/usr/bin/env bash"
  echo "set -e"
  echo "cd $(printf '%q' "$RUN_DIR_ABS")"
  if [[ -f "$VULNAI_ENV" ]]; then
    echo "if [[ -f \"\$HOME/.vulnai/env\" ]]; then"
    echo "  set -a"
    echo "  # shellcheck source=/dev/null"
    echo "  source \"\$HOME/.vulnai/env\""
    echo "  set +a"
    echo "fi"
  elif [[ -f "$VULNAI_CONFIG" ]] && command -v jq &>/dev/null; then
    jq -r '.env // {} | to_entries[] | "export \(.key)=\"\(.value)\""' "$VULNAI_CONFIG" 2>/dev/null || true
  else
    echo "echo \"Warning: no ~/.vulnai/env — set keys in ~/vulnai-runs/$HANDLE/vulnai-env.sh\" >&2"
  fi
  echo "if [[ -f \"./vulnai-env.sh\" ]]; then"
  echo "  set -a"
  echo "  # shellcheck source=/dev/null"
  echo "  source \"./vulnai-env.sh\""
  echo "  set +a"
  echo "fi"
  echo "set +e"
  echo "$VULNAI_LINE"
  echo "_v_rc=\$?"
  echo "set -e"
  echo "echo \"\""
  echo "echo \"[vulnai-tmux] vulnai exited (status \$_v_rc). Interactive shell — type exit to close pane.\""
  echo "exec bash"
} > "$RUN_INNER"
chmod +x "$RUN_INNER"

CMDS_FILE="$RUN_DIR/.vulnai-tmux.txt"
{
  echo "# tmux session runs VulnAI. Attach with:"
  echo "#   tmux attach -t $SESSION"
  echo "# Inner runner: $RUN_INNER"
} > "$CMDS_FILE"

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "Replacing existing tmux session: $SESSION"
  tmux kill-session -t "$SESSION"
fi

tmux new-session -d -s "$SESSION" bash "$RUN_INNER"

echo ""
echo "Created tmux session: $SESSION"
echo "  Attach: tmux attach -t $SESSION"
echo "  Detach: Ctrl+B, then D"
echo "  Runner: $RUN_INNER"
echo ""
echo "Tip: Run this on the same machine where you attach to tmux (e.g. your SSH shell)."
echo "     Cursor/agents may use a different tmux server than your login session."
echo ""
