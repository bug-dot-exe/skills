#!/usr/bin/env bash
# Full Strix automation: create target folder, ensure instructions, start detached tmux (Strix runs automatically).
# Agent must create instructions.md with H1 data (hack + search_scopes) + bb-hunter-full BEFORE calling.
#
# Usage: strix-automate.sh <handle> [target_url] [mode]
#   handle: program handle (e.g. overwolf, mirantis)
#   target_url: optional. Default "." (scope from instructions). Single URL when provided.
#   mode: optional. standard | deep (default: standard)
#
# Flow:
#   1. Agent: hack(handle), search_scopes(handle)
#   2. Agent: create instructions.md with H1 data + strix-all-skills.md + bb-hunter-full.md
#   3. Agent: strix-automate.sh <handle> [url] [mode]
#   4. tmux session strix-<handle> starts Strix; attach: tmux attach -t strix-<handle>
#
# Screen + manual paste: STRIX_LAUNCH_SCRIPT=.../strix-launch-screen.sh strix-automate.sh ...

set -e

HANDLE="${1:?Usage: strix-automate.sh <handle> [target_url] [mode]}"
TARGET="${2:-.}"
MODE="${3:-standard}"
BASE_DIR="${STRIX_RUNS_DIR:-$HOME/strix-runs}"
RUN_DIR="$BASE_DIR/$HANDLE"
LAUNCH_SCRIPT="${STRIX_LAUNCH_SCRIPT:-$HOME/.cursor/skills/strix-bb/scripts/strix-launch-tmux.sh}"
METH_DIR="${STRIX_METHODOLOGY_DIR:-$HOME/.cursor/skills/strix-bb}"
ALL_SKILLS_MD="${STRIX_ALL_SKILLS_MD:-$METH_DIR/strix-all-skills.md}"
BB_FULL="${BB_HUNTER_FULL:-$METH_DIR/bb-hunter-full.md}"

mkdir -p "$RUN_DIR"

# If no instructions.md, create minimal (agent should have created with H1 data)
if [[ ! -f "$RUN_DIR/instructions.md" ]]; then
  echo "Creating minimal instructions.md (agent should create with H1 hack data)"
  cat > "$RUN_DIR/instructions.md" << EOF
# Target: $HANDLE

## Scope
Fetch from: https://hackerone.com/$HANDLE?view_policy=true
- In-scope assets
- Out-of-scope
- Policy / safe harbor / rate limits

## Test Credentials
Add from H1 policy page if provided.

## Instructions
You are an offensive security expert. Recon → Map → Test → Chain → Report.
Stay in scope. PoC or GTFO.

---
EOF
  [[ -f "$ALL_SKILLS_MD" ]] && cat "$ALL_SKILLS_MD" >> "$RUN_DIR/instructions.md"
  [[ -f "$BB_FULL" ]] && cat "$BB_FULL" >> "$RUN_DIR/instructions.md"
fi

exec "$LAUNCH_SCRIPT" "$HANDLE" "$BASE_DIR" "$TARGET" "$MODE"
