#!/usr/bin/env bash
# Backward-compatible alias: full automation now defaults to tmux in strix-automate.sh.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/strix-automate.sh" "$@"
