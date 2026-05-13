#!/usr/bin/env bash
# validate-poc.sh — Check a PoC file for required structural elements and
# warn on dangerous patterns.
#
# Usage: bash skills/write-poc/scripts/validate-poc.sh <poc-file>
#
# Checks (errors):
#   - Header block present (Title:, Affected:, Impact: in first 20 lines)
#   - At least one section header comment (// == [ or # == [)
#   - File has substantive content (>5 non-blank lines)
#
# Checks (warnings):
#   - Dangerous payload patterns (rm -rf, DROP TABLE, etc.)
#   - Hardcoded non-localhost URLs
#   - Missing success/failure output indicators
#
# Exit 0 if no errors, exit 1 if errors found. Warnings do not fail.

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <poc-file>" >&2
  exit 1
fi

FILE="$1"

if [ ! -f "$FILE" ]; then
  echo "FAIL: File not found: $FILE" >&2
  exit 1
fi

ERRORS=0
WARNINGS=0
CHECKS=0

pass() { CHECKS=$((CHECKS + 1)); echo "  PASS: $1"; }
fail() { CHECKS=$((CHECKS + 1)); ERRORS=$((ERRORS + 1)); echo "  FAIL: $1" >&2; }
warn() { CHECKS=$((CHECKS + 1)); WARNINGS=$((WARNINGS + 1)); echo "  WARN: $1" >&2; }

echo "Validating: $FILE"

# --- Substantive content ---
NON_BLANK=$(grep -c '[^[:space:]]' "$FILE" || true)
if [ "$NON_BLANK" -gt 5 ]; then
  pass "File has substantive content ($NON_BLANK non-blank lines)"
else
  fail "File has only $NON_BLANK non-blank lines (need >5)"
fi

# --- Header block ---
# Look for Title:, Affected:, Impact: in the first 20 lines
HEAD=$(head -20 "$FILE")

HAS_TITLE=$(echo "$HEAD" | grep -ci 'Title:' || true)
HAS_AFFECTED=$(echo "$HEAD" | grep -ci 'Affected:' || true)
HAS_IMPACT=$(echo "$HEAD" | grep -ci 'Impact:' || true)

if [ "$HAS_TITLE" -gt 0 ] && [ "$HAS_AFFECTED" -gt 0 ] && [ "$HAS_IMPACT" -gt 0 ]; then
  pass "Header block present (Title, Affected, Impact)"
else
  MISSING=""
  [ "$HAS_TITLE" -eq 0 ] && MISSING="${MISSING} Title:"
  [ "$HAS_AFFECTED" -eq 0 ] && MISSING="${MISSING} Affected:"
  [ "$HAS_IMPACT" -eq 0 ] && MISSING="${MISSING} Impact:"
  fail "Header block incomplete — missing:${MISSING}"
fi

# --- Section header comments ---
# Match // == [ ... ] == or # == [ ... ] ==
SECTION_HEADERS=$(grep -cE '(//|#)\s*==\s*\[' "$FILE" || true)
if [ "$SECTION_HEADERS" -gt 0 ]; then
  pass "Section header comments found ($SECTION_HEADERS)"
else
  fail "No section header comments (expected // == [ Name ] == or # == [ Name ] ==)"
fi

# --- Dangerous payloads ---
DANGEROUS=$(grep -niE 'rm\s+-rf|DROP\s+TABLE|FORMAT\s+C:|shutdown\s+(-s|-r|/s|/r)|deltree|:(){' "$FILE" || true)
if [ -z "$DANGEROUS" ]; then
  pass "No dangerous payload patterns detected"
else
  warn "Potential dangerous payload patterns found:"
  echo "$DANGEROUS" | sed 's/^/    /' >&2
fi

# --- Hardcoded non-localhost URLs ---
# Match http(s):// followed by something other than localhost, 127.0.0.1, [::1],
# or a variable/placeholder. Ignore comment-only lines that discuss URLs conceptually.
HARDCODED=$(grep -nE 'https?://' "$FILE" \
  | grep -vE 'localhost|127\.0\.0\.1|\[::1\]|\$\{|%s|TARGET|example\.com|169\.254\.169\.254' \
  | grep -vE '^\s*(//|#|/?\*)\s' \
  || true)
if [ -z "$HARDCODED" ]; then
  pass "No hardcoded non-localhost URLs in code"
else
  warn "Possible hardcoded target URLs (should be parameterized):"
  echo "$HARDCODED" | sed 's/^/    /' >&2
fi

# --- Success/failure output ---
OUTPUT_INDICATORS=$(grep -cE '\[\+\]|\[-\]|\[✓\]|\[✗\]|assert(Eq|Gt|Lt|True|False|Ge|Le)|require\(' "$FILE" || true)
if [ "$OUTPUT_INDICATORS" -gt 0 ]; then
  pass "Success/failure output indicators found ($OUTPUT_INDICATORS)"
else
  warn "No success/failure indicators ([+], [-], assert*, require) — output may be unclear"
fi

# --- Summary ---
echo ""
TOTAL=$((CHECKS))
PASSED=$((TOTAL - ERRORS - WARNINGS))

if [ "$ERRORS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
  echo "PASS: $TOTAL/$TOTAL checks passed — $FILE"
elif [ "$ERRORS" -eq 0 ]; then
  echo "PASS: $PASSED/$TOTAL passed, $WARNINGS warning(s) — $FILE"
else
  echo "FAIL: $PASSED/$TOTAL passed, $ERRORS error(s), $WARNINGS warning(s) — $FILE" >&2
fi

exit "$( [ "$ERRORS" -eq 0 ] && echo 0 || echo 1 )"
