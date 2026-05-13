#!/usr/bin/env bash
# validate-cartography.sh — Validate a cartography file against the format spec.
# Checks frontmatter fields, required body sections, and reciprocal related links.
# Usage: validate-cartography.sh <cartography-file>
# Exits 0 if valid, 1 if errors found. Prints results to stderr.

set -euo pipefail

file="${1:-}"
if [ -z "$file" ] || [ ! -f "$file" ]; then
  echo "Usage: validate-cartography.sh <cartography-file>" >&2
  exit 1
fi

errors=0
warnings=0
passes=0

pass() {
  printf 'PASS\t%s\n' "$1" >&2
  passes=$((passes + 1))
}

fail() {
  printf 'FAIL\t%s\t%s\n' "$1" "$2" >&2
  errors=$((errors + 1))
}

warn() {
  printf 'WARN\t%s\t%s\n' "$1" "$2" >&2
  warnings=$((warnings + 1))
}

# --- Parse frontmatter ---
name=""
description=""
created=""
updated=""
related_raw=""
in_frontmatter=0
frontmatter_closed=0

# Section tracking
has_overview=0
has_entry_points=0
has_key_components=0
has_flow_sequence=0
has_security_notes=0
has_conditional=0
body_lines=0
current_section=""
referenced_paths=""

while IFS= read -r line; do
  if [ "$line" = "---" ]; then
    if [ "$in_frontmatter" -eq 0 ]; then
      in_frontmatter=1
      continue
    else
      frontmatter_closed=1
      continue
    fi
  fi

  if [ "$in_frontmatter" -eq 1 ] && [ "$frontmatter_closed" -eq 0 ]; then
    case "$line" in
      name:*)
        name="${line#name:}"
        name="${name# }"
        name="${name#\"}"
        name="${name%\"}"
        name="${name#\'}"
        name="${name%\'}"
        ;;
      description:*)
        description="${line#description:}"
        description="${description# }"
        description="${description#\"}"
        description="${description%\"}"
        description="${description#\'}"
        description="${description%\'}"
        ;;
      created:*)
        created="${line#created:}"
        created="${created# }"
        ;;
      updated:*)
        updated="${line#updated:}"
        updated="${updated# }"
        ;;
      related:*)
        related_raw="${line#related:}"
        related_raw="${related_raw# }"
        ;;
    esac
  fi

  if [ "$frontmatter_closed" -eq 1 ]; then
    # Count non-empty body lines
    if [ -n "$line" ]; then
      body_lines=$((body_lines + 1))
    fi

    # Check for required sections
    case "$line" in
      "## Overview"*) has_overview=1; current_section="overview" ;;
      "## Entry Points"*) has_entry_points=1; current_section="entry-points" ;;
      "## Key Components"*) has_key_components=1; current_section="key-components" ;;
      "## Flow Sequence"*) has_flow_sequence=1; current_section="flow-sequence" ;;
      "## Security Notes"*) has_security_notes=1; current_section="security-notes" ;;
      "## Conditional:"*) has_conditional=1; current_section="conditional" ;;
      "## "*) current_section="other" ;;
    esac

    # Collect file paths from Entry Points and Key Components
    if [ "$current_section" = "entry-points" ] || [ "$current_section" = "key-components" ]; then
      case "$line" in
        "- \`"*)
          path="${line#- \`}"
          path="${path%%\`*}"
          path="${path%%:*}"
          if [ -n "$path" ]; then
            referenced_paths="$referenced_paths $path"
          fi
          ;;
      esac
    fi
  fi
done < "$file"

# --- Validate frontmatter ---
if [ "$in_frontmatter" -eq 0 ]; then
  fail "frontmatter" "No frontmatter found (missing opening ---)"
elif [ "$frontmatter_closed" -eq 0 ]; then
  fail "frontmatter" "Frontmatter not closed (missing closing ---)"
else
  pass "frontmatter-structure"
fi

# Required fields
if [ -n "$name" ]; then
  pass "name"
else
  fail "name" "Missing required field: name"
fi

if [ -n "$description" ]; then
  pass "description"
else
  fail "description" "Missing required field: description"
fi

if [ -n "$created" ]; then
  if echo "$created" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
    pass "created"
  else
    fail "created" "Invalid date format: '$created'. Expected YYYY-MM-DD"
  fi
else
  fail "created" "Missing required field: created"
fi

if [ -n "$updated" ]; then
  if echo "$updated" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
    pass "updated"
  else
    fail "updated" "Invalid date format: '$updated'. Expected YYYY-MM-DD"
  fi
else
  fail "updated" "Missing required field: updated"
fi

# --- Validate sections ---
if [ "$has_overview" -eq 1 ]; then
  pass "overview-section"
else
  fail "overview-section" "Missing required section: ## Overview"
fi

if [ "$has_entry_points" -eq 1 ]; then
  pass "entry-points-section"
else
  fail "entry-points-section" "Missing required section: ## Entry Points"
fi

if [ "$has_key_components" -eq 1 ]; then
  pass "key-components-section"
else
  fail "key-components-section" "Missing required section: ## Key Components"
fi

if [ "$has_flow_sequence" -eq 1 ]; then
  pass "flow-sequence-section"
else
  fail "flow-sequence-section" "Missing required section: ## Flow Sequence"
fi

if [ "$has_security_notes" -eq 1 ]; then
  pass "security-notes-section"
else
  fail "security-notes-section" "Missing required section: ## Security Notes"
fi

# --- Validate referenced file paths ---
if [ -n "$referenced_paths" ]; then
  for path in $referenced_paths; do
    if [ -f "$path" ]; then
      pass "file-exists:$path"
    else
      warn "file-exists:$path" "Referenced file not found: $path"
    fi
  done
fi

# --- Validate reciprocal related links ---
if [ -n "$related_raw" ]; then
  # Extract slugs from flow-style [a, b] or bare list
  cleaned="${related_raw#\[}"
  cleaned="${cleaned%\]}"
  dir=$(dirname "$file")

  IFS=',' read -ra slugs <<< "$cleaned"
  for slug in "${slugs[@]}"; do
    slug=$(echo "$slug" | tr -d ' ')
    [ -z "$slug" ] && continue

    related_file="$dir/$slug.md"
    if [ -f "$related_file" ]; then
      # Check if the related file references this file back
      this_slug=$(basename "$file" .md)
      if grep -q "$this_slug" "$related_file" 2>/dev/null; then
        pass "reciprocal-link:$slug"
      else
        warn "reciprocal-link:$slug" "Related flow '$slug' does not link back to '$(basename "$file" .md)'"
      fi
    else
      warn "related-file:$slug" "Related flow file not found: $related_file"
    fi
  done
fi

# --- Body length warning ---
if [ "$body_lines" -gt 80 ] && [ "$has_conditional" -eq 0 ]; then
  warn "body-length" "Body has $body_lines non-empty lines (>80) with no conditional sections. Consider extracting sub-flows."
fi

# --- Summary ---
total=$((passes + errors + warnings))
echo "" >&2
if [ "$errors" -gt 0 ]; then
  echo "FAIL: $passes/$total passed, $errors error(s), $warnings warning(s) — $file" >&2
  exit 1
else
  if [ "$warnings" -gt 0 ]; then
    echo "PASS with $warnings warning(s): $passes/$total passed — $file" >&2
  else
    echo "PASS: $passes/$total passed — $file" >&2
  fi
  exit 0
fi
