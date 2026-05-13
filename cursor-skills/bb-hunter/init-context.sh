#!/bin/bash
# Initialize agent context for a target (multi-agent mode)
# Usage: ./init-context.sh example.com
# Run from workspace root (bbrecon) or use absolute path for dir

target="${1:?Usage: $0 <target>}"
dir="output/$target"
ctx="$dir/.agent-context.json"
mkdir -p "$dir"

if [[ -f "$ctx" ]]; then
  echo "Context exists: $ctx"
  exit 0
fi

cat > "$ctx" << EOF
{
  "target": "$target",
  "scope": ["*.$target"],
  "phase": "recon",
  "created_at": "$(date -Iseconds)",
  "updated_at": "$(date -Iseconds)",
  "recon": {"subdomains": [], "live_urls": [], "tech_stack": {}, "attack_surface": []},
  "findings": [],
  "validated": [],
  "reports": [],
  "messages": []
}
EOF
echo "Created: $ctx"
