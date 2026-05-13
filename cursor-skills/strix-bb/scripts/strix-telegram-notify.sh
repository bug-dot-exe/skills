#!/usr/bin/env bash
# Send Telegram notification when Strix finds valid vulnerabilities.
# Called automatically after Strix exits (from strix-launch-screen.sh).
# Usage: strix-telegram-notify.sh <run_dir>
#
# Config: ~/.strix/telegram.env
#   TELEGRAM_BOT_TOKEN=your_bot_token
#   TELEGRAM_CHAT_ID=your_chat_id

RUN_DIR="${1:?Usage: strix-telegram-notify.sh <run_dir>}"

# Load config (never commit credentials)
if [[ -f "$HOME/.strix/telegram.env" ]]; then
  source "$HOME/.strix/telegram.env"
fi

[[ -z "$TELEGRAM_BOT_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]] && exit 0

# Find latest strix_runs subdir
STRIX_RUNS="$RUN_DIR/strix_runs"
[[ ! -d "$STRIX_RUNS" ]] && exit 0

LATEST=$(ls -td "$STRIX_RUNS"/*/ 2>/dev/null | head -1)
LATEST="${LATEST%/}"
[[ -z "$LATEST" ]] && exit 0

VULN_DIR="$LATEST/vulnerabilities"
[[ ! -d "$VULN_DIR" ]] && exit 0

COUNT=$(find "$VULN_DIR" -name 'vuln-*.md' 2>/dev/null | wc -l)
[[ "$COUNT" -eq 0 ]] && exit 0

# Build message
RUN_NAME=$(basename "$LATEST")
MSG="🔓 Strix found $COUNT valid vulnerability/vulnerabilities

Target: $RUN_NAME
Path: $VULN_DIR

"
# Add first 3 vuln titles (truncate for Telegram 4096 limit)
for f in "$VULN_DIR"/vuln-*.md; do
  [[ -f "$f" ]] || continue
  TITLE=$(head -1 "$f" | sed 's/^# //; s/\*\*//g')
  SEV=$(grep -m1 "^\*\*Severity:\*\*" "$f" 2>/dev/null | sed 's/.*: //')
  MSG+="• $TITLE [$SEV]
"
done

# Send (escape for JSON)
MSG_ESC=$(echo "$MSG" | jq -Rs . 2>/dev/null || echo "\"${MSG//\"/\\\"}\"")
curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
  -H "Content-Type: application/json" \
  -d "{\"chat_id\":\"${TELEGRAM_CHAT_ID}\",\"text\":${MSG_ESC},\"disable_web_page_preview\":true}" >/dev/null 2>&1 || true
