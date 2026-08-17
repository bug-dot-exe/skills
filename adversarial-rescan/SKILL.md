---
name: adversarial-rescan
category: methodology
description: Mandates a second adversarial wave on first-wave endpoints with an exclusion list, so attention saturation does not hide sibling bugs in the same surface
depends_on: []
---

# Adversarial Re-Scan

After your first wave of workers reports back, the same endpoints almost always still hide bugs the first wave anchored past. LLM attention saturates on the first finding it confirms — once a worker has filed `missing-authz`, it stops noticing `mass-assignment` ten lines further down. The fix is structural: dispatch a second wave on the same high-value endpoints with an explicit exclusion list of what was already filed, told to find what the first wave missed.

This is distinct from VARIANT (same primitive, sibling endpoints), CHAIN (combine pairs), and COVERAGE GAP (unscanned endpoints). All four passes are mandatory before `finish_scan` on any non-cheap target.

## When to Run

- After every first-wave worker has reported (CONFIRM or REFUTE).
- BEFORE the VARIANT pass, so variant enumeration does not amplify first-wave blind spots.
- Iteration cap = 1. Do not run more than one adversarial re-scan wave per scan.

## How to Run

For each high-value endpoint that received a first-wave worker:

1. Build the exclusion brief — list every finding filed on that endpoint with its `finding_id` and one-sentence root cause.
2. Dispatch a single fresh worker via `create_agent` with a brief that:
   - Names the endpoint and its method.
   - Inlines the exclusion brief verbatim.
   - Tells the worker: "Same surface, fresh angle. Do not refile any finding above. Find what the first wave missed."
3. Cap the second wave at 5 workers per scan.

## Cheap-Target Exception

Skip adversarial re-scan when both:
- Total scanned endpoints ≤ 5.
- Total first-wave findings ≤ 3.

Cheap targets do not have enough surface for attention saturation to hide bugs. Proceed directly to VARIANT / CHAIN / COVERAGE GAP.

## When the Endpoint Scorer Has Not Shipped

If `target/ranked_endpoints.jsonl` does not exist, fall back to the set of endpoints that filed at least one first-wave finding (capped at 5). This keeps the layer shippable without the Scorer.

## What Counts As Success

A second-wave worker either:
- Files a new finding (different `root_cause` from anything on the exclusion list) — adversarial re-scan paid off.
- Returns CLEAN with a one-sentence explanation of what new angle it tried — also acceptable; the methodology demands the attempt, not a guaranteed find.

A worker that refiles an exclusion-list finding is a methodology violation — discard the duplicate; do not penalize the worker.

## Corpus-Derived Re-Scan Patterns

### Patch-Bypass Hunting (Highest ROI on Mature Platforms)

When a security fix ships (CVE patch, disclosed H1 fix, changelog "security improvement"):

1. **Read the patch diff** -- the commit localizes exactly where defenders looked
2. **Identify the input space the patch checks** vs the input space it does not
3. **Test the complement**: if the fix blocklists `<script>`, enumerate `<img onerror>`, `<svg onload>`, `<math>`, `<details/open/ontoggle>` and every other event-capable tag
4. **Test adjacent code paths**: the patch fixed `function_A()` but `function_B()` calls the same vulnerable internal helper without the new guard
5. **Test encoding bypass**: the fix checks the decoded form but the input arrives URL-encoded, double-encoded, Unicode-normalized, or mixed-encoding

Patch-bypass findings inherit the original severity (the root cause is still present, just incompletely fixed) and programs typically pay full bounty because the fix failed.

### Variant Hunting on Fixed Findings

After any fix is disclosed for a specific function or method:

1. **Enumerate every sibling** that delegates to the same underlying helper
2. **Enumerate every API endpoint** that accepts the same parameter class
3. **Test the same vulnerability class** on every entry point, not just the one that was patched
4. Sanitization fixes typically blocklist specific instances -- enumerate all instances the blocklist misses

### New-Feature Regression Hunting

1. **Subscribe to product changelogs**, release notes, and "What's New" feeds
2. When a new feature launches, test it within 48 hours -- new code has the highest defect density
3. **Map multi-state resources**: if a resource gained a new state (draft, archived, suspended), test whether existing security checks cover the new state
4. **Test whether the new feature interacts with old security boundaries**: new sharing feature + old ACL system = potential bypass

### Legacy and Regional Surface Enumeration

For mature programs with hardened main stacks:

1. **Enumerate regional/legacy/secondary domains**: China, India, Japan, Korea variants; legacy acquisition domains; regional CDNs
2. Test `m.`, `mobile.`, `api-legacy.`, `internal-` subdomains
3. Old codepaths on regional domains often lack the patches applied to the primary domain
4. Look for version skew: main domain on v3 API, regional domain still on v1

### Regression Corpus Testing

Maintain a corpus of historical PoCs for programs you regularly audit:

1. After each release, replay the corpus against the new version
2. Track which PoCs regress (fix reverted or new code path re-introduces the bug)
3. Regressions are nearly guaranteed acceptance -- the program already agreed the original was a valid finding

### Interpreter/Parser Shared-Invariant Audit

When a CVE fixes one code path that relies on a shared invariant:

1. Identify the invariant the fix assumes (e.g., "method_missing is always findable", "all inputs are UTF-8")
2. Enumerate every other code path that relies on the same invariant
3. Each path was likely implemented by a different developer and may violate the invariant differently
4. Test: does breaking the invariant via path B produce the same class of bug that was fixed in path A?

### Cross-Feature State-Persistence Regression

For any privacy or security setting (block user, disable sharing, revoke access):

1. Enumerate every feature that can reference the protected resource
2. Test whether the setting is enforced across all features: blocking a user should prevent them from appearing in search, notifications, shared documents, API responses, and export files
3. New features are most likely to miss the check -- they were built after the block mechanism but may not consult it

### Exclusion-List Bypass Techniques for Re-Scan Workers

When constructing re-scan worker briefs, instruct them to specifically test:

1. **Different HTTP methods** on the same path (GET vs POST vs PUT vs OPTIONS)
2. **Different content types** (JSON vs form-encoded vs XML vs multipart)
3. **Different auth contexts** (session cookie vs API key vs OAuth token vs no auth)
4. **Different parameter locations** (query string vs body vs header vs path)
5. **Error-path behavior** (malformed input, missing required fields, oversized payloads)
