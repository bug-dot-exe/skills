#!/usr/bin/env bash
# find-overlaps.sh — Detect overlapping cartography files by comparing Key Components.
# Outputs tab-separated: flow_A\tflow_B\toverlap_%\tshared_files
# Usage: find-overlaps.sh [directory] [threshold]
# Default directory: grimoire/cartography/  Default threshold: 40
# Exits 0 if no overlaps exceed threshold, 1 if any do.

set -euo pipefail

dir="${1:-grimoire/cartography/}"
threshold="${2:-40}"

if [ ! -d "$dir" ]; then
  echo "Directory not found: $dir" >&2
  exit 1
fi

tmpdir="${TMPDIR:-/tmp}/find-overlaps.$$"
mkdir -p "$tmpdir"
trap 'rm -rf "$tmpdir"' EXIT

# --- Extract Key Components from each cartography file ---
extract_components() {
  local file="$1"
  local outfile="$2"
  local in_components=0

  while IFS= read -r line; do
    # Enter Key Components section
    case "$line" in
      "## Key Components"*)
        in_components=1
        continue
        ;;
      "## "*)
        # Any other h2 heading exits the section
        if [ "$in_components" -eq 1 ]; then
          break
        fi
        continue
        ;;
    esac

    if [ "$in_components" -eq 1 ]; then
      # Extract file path from lines like: - `path/to/file.rs` — description
      # or: - `path/to/file.rs:symbol` — description
      case "$line" in
        "- \`"*)
          path="${line#- \`}"
          # Remove everything after the closing backtick
          path="${path%%\`*}"
          # Remove symbol suffix if present (e.g., :function_name)
          path="${path%%:*}"
          if [ -n "$path" ]; then
            echo "$path"
          fi
          ;;
      esac
    fi
  done < "$file" | sort -u > "$outfile"
}

# Extract name from frontmatter
extract_name() {
  local file="$1"
  local in_fm=0
  while IFS= read -r line; do
    if [ "$line" = "---" ]; then
      if [ "$in_fm" -eq 0 ]; then
        in_fm=1
        continue
      else
        break
      fi
    fi
    if [ "$in_fm" -eq 1 ]; then
      case "$line" in
        name:*)
          local name="${line#name:}"
          name="${name# }"
          name="${name#\"}"
          name="${name%\"}"
          echo "$name"
          return
          ;;
      esac
    fi
  done < "$file"
}

# --- Build component lists for all files ---
files=()
for file in "$dir"/*.md; do
  [ -e "$file" ] || continue
  basename=$(basename "$file")
  [ "$basename" = "_index.md" ] && continue

  slug="${basename%.md}"
  extract_components "$file" "$tmpdir/$slug.paths"
  files+=("$file")
done

count=${#files[@]}
if [ "$count" -lt 2 ]; then
  echo "Need at least 2 cartography files to compare. Found: $count" >&2
  exit 0
fi

# --- Pairwise comparison ---
found_overlap=0
pairs_checked=0
overlaps_found=0

for ((i=0; i<count; i++)); do
  for ((j=i+1; j<count; j++)); do
    file_a="${files[$i]}"
    file_b="${files[$j]}"
    slug_a=$(basename "$file_a" .md)
    slug_b=$(basename "$file_b" .md)

    paths_a="$tmpdir/$slug_a.paths"
    paths_b="$tmpdir/$slug_b.paths"

    # Skip if either has no components
    count_a=$(wc -l < "$paths_a" | tr -d ' ')
    count_b=$(wc -l < "$paths_b" | tr -d ' ')
    if [ "$count_a" -eq 0 ] || [ "$count_b" -eq 0 ]; then
      continue
    fi

    # Find shared components
    shared=$(comm -12 "$paths_a" "$paths_b" | wc -l | tr -d ' ')
    pairs_checked=$((pairs_checked + 1))

    if [ "$shared" -eq 0 ]; then
      continue
    fi

    # Calculate overlap: shared / max(count_a, count_b)
    if [ "$count_a" -gt "$count_b" ]; then
      max=$count_a
    else
      max=$count_b
    fi

    pct=$((shared * 100 / max))

    if [ "$pct" -gt "$threshold" ]; then
      name_a=$(extract_name "$file_a")
      name_b=$(extract_name "$file_b")
      shared_files=$(comm -12 "$paths_a" "$paths_b" | paste -sd ',' -)
      printf '%s\t%s\t%d%%\t%s\n' "${name_a:-$slug_a}" "${name_b:-$slug_b}" "$pct" "$shared_files"
      found_overlap=1
      overlaps_found=$((overlaps_found + 1))
    elif [ "$pct" -ge 20 ]; then
      name_a=$(extract_name "$file_a")
      name_b=$(extract_name "$file_b")
      printf 'INFO\t%s\t%s\t%d%%\n' "${name_a:-$slug_a}" "${name_b:-$slug_b}" "$pct" >&2
    fi
  done
done

# --- Summary to stderr ---
echo "" >&2
echo "Checked $pairs_checked pairs across $count flows (threshold: ${threshold}%)" >&2
if [ "$overlaps_found" -gt 0 ]; then
  echo "Found $overlaps_found pair(s) exceeding ${threshold}% overlap — consider gc-cartography" >&2
else
  echo "No overlaps exceed ${threshold}% threshold" >&2
fi

exit "$found_overlap"
