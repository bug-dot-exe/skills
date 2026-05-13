---
name: raptor_coverage
description: Tool-execution coverage tracking — what static analyzer / fuzzer / LLM examined which files and which functions, plus gaps and missing groups
depends_on: []
---

# Tool Coverage Tracking

Tracks what each tool examined during analysis. Answers: "what code has been checked, by whom, and what's missing?" Coexists with `coverage_matrix` (endpoint × vuln-class × auth-state coverage for web targets); this skill is for code-level static / dynamic tool coverage.

## Coverage Records

Each tool writes a `coverage-<tool>.json` in the run output directory:

| File | Written by | Contents |
|------|-----------|----------|
| `coverage-semgrep.json` | Scanner (`/scan`) | files examined, policy groups, errors |
| `coverage-codeql.json` | Scanner (`/scan`, `/codeql`) | files examined, packs, rules, extraction failures |
| `coverage-llm.json` | Lifecycle complete (`/validate`, `/understand`) | files examined (from reads manifest), items analysed — functions, globals, structs (from findings + mark) |

Records are written automatically — no manual action needed.

## Maintenance Operations

To compute summaries, find gaps, and mark items reviewed, the agent works directly with the JSON files in the run directory using standard JSON tools (`jq`, Python `json` module, the Write tool). The schema sections below define the file contents.

**Common operations**:
- *Summary* — load every `coverage-*.json` in the run directory and union `files_examined` across tools; compare to `checklist.json` to compute coverage percentages.
- *Gaps* — find functions in `checklist.json` that do not appear in any tool's `functions_analysed` list. List `<file>:<function>` for each gap.
- *Mark reviewed* — append entries to a tool's `coverage-<tool>.json` so the function appears in `functions_analysed`. Use the Write tool to persist.
- *Unmark* — remove entries from `functions_analysed` and re-write the JSON.

### Summary dict structure

```python
{
    "inventory": {"files": 10, "sloc": 103, "items": 11},
    "tools": {
        "semgrep": {
            "files_examined": 10, "files_total": 10,
            "rules_applied": ["crypto"], "files_failed": [],
        },
        "codeql": {
            "files_examined": 10, "files_total": 10,
            "packs": ["codeql/cpp-queries"], "rules_applied": [...],
        },
        "llm": {
            "files_examined": 10, "files_total": 10,
            "functions_analysed": 10, "functions_total": 11,
            "sloc_analysed": 95,
        },
    },
    "unreviewed_functions": 1,
    "unreviewed_sloc": 8,
    "missing_groups": ["injection", "auth", ...],
    "per_file": [
        {
            "path": "09_stack_overread.c",
            "sloc": 12,
            "reviewed": 1,
            "total": 2,
            "pct": 50.0,
            "findings": 1,
            "unreviewed_functions": ["record"],
            "scanned_semgrep": True,
            "scanned_codeql": True,
            "scanned_llm": True,
        },
        ...
    ],
}
```

### Building Records From Tool Output

Each scanner emits a record by transforming its native output:
- **Semgrep**: read `paths.scanned` from the JSON output; populate `files_examined`. File-level only.
- **CodeQL**: read SARIF `artifacts`, `tool.extensions` (packs), and `tool.driver.rules`.
- **LLM (manual analysis)**: read the agent's Read-tool history (or `findings.json`) and union into `files_examined` and `functions_analysed`.

## Coverage Record Schema

```json
{
    "tool": "semgrep|codeql|llm|<custom>",
    "timestamp": "2026-04-11T00:00:00+00:00",
    "files_examined": ["path/to/file.c", ...],
    "functions_analysed": [{"file": "...", "function": "..."}, ...],
    "rules_applied": ["rule_or_group_name", ...],
    "packs": ["pack/name@version", ...],
    "version": "1.79.0",
    "files_failed": [{"path": "...", "reason": "..."}, ...]
}
```

Only `tool` and `files_examined` are required. All other fields are optional.

## What Each Tool Records

**Semgrep:** Files from `paths.scanned` in JSON output (produced by `--json-output` flag). Policy groups from scanner config. File-level only — Semgrep scans entire files.

**CodeQL:** Files from SARIF `artifacts` array. Query packs from `tool.extensions`. Rules from `tool.driver.rules`. Extraction failures from `invocations.toolExecutionNotifications`.

**LLM:** Files from the reads manifest (`.reads-manifest`, populated by coverage plugin hook on every Read tool call). Functions from `findings.json` — any function with a finding or ruling counts as analysed.

## Inventory (denominator)

Coverage percentages use `checklist.json` as the denominator:
- **Files:** total files in checklist
- **Items:** total functions/globals/macros per file (`items` key, fallback `functions`)
- **SLOC:** source lines of code per file

The checklist is built at the start of analysis from a directory walk plus a per-language parser (e.g., `tree-sitter`, `ctags`).

## Missing Groups

Compare the union of rule packs that ran (e.g., Semgrep packs `p/security`, `p/secrets`) against the catalog of available packs the project should care about. Packs not in the union appear under "Action needed" — those vulnerability classes were never scanned.

---

## Corpus-Derived Coverage Gap Techniques

Patterns from high-bounty reports where coverage gaps were the root cause of missed vulnerabilities.

### Teardown Completeness Audit

For every create/delete pair of operations on any model or resource:
1. Document what state the create operation establishes (relationships, attributes, cached references, denormalized copies).
2. After delete, verify that EVERY piece of state from step 1 is removed or invalidated.
3. Focus on relationships and denormalized copies -- the primary record is usually deleted, but references in other tables, caches, or search indexes may persist.
4. Test: create resource, establish relationships, delete resource, check if the relationships still function.

### Fix Completeness Regression

When a vendor publishes a security fix (advisory, disclosed report, CVE patch):
1. Read the fix diff to understand what was patched.
2. List every code path that reaches the patched function.
3. Test every way the patched parameter can arrive (direct, deserialized, from cache, from URL, from header).
4. Check if the fix was applied to all code paths or only the reported one.
5. Also check if the fix introduced a NEW vulnerability (common with hasty patches).

### Permission Attribute Coverage Matrix

For multi-app platforms with per-resource permissions:
1. Build a matrix: rows = permission attributes (read, write, download, share, edit, delete, admin), columns = apps/features that access the resource.
2. For each cell, test whether the permission attribute is enforced.
3. Focus on cross-app access -- a "no download" permission set in App A may not be enforced when App B accesses the same resource.
4. Test newly added apps/features first -- they are most likely to miss existing permission checks.

### Revocation Completeness Audit

For any system with role assignment and removal:
1. As a user with a specific role, inventory every URL, API endpoint, and cached credential accessible to that role.
2. Have the role removed.
3. Test every item from the inventory -- check which ones are still accessible after revocation.
4. Focus on: cached sessions, long-lived tokens, API keys generated during the role, shared resources that were created with the role's permissions.

### Vendored Library Diff

For any project that vendors (copies) a third-party library:
1. Identify the vendored version by checking commit hashes, version strings, or file dates.
2. Diff the vendored copy against the current upstream release.
3. Every CVE patched in upstream but missing in the vendored copy is a candidate vulnerability.
4. Prioritize libraries that handle untrusted input (parsers, image processors, crypto libraries, serializers).

### Sandbox Completeness Audit

For any sandbox, policy mechanism, or security boundary:
1. Enumerate every path to execute code, read files, write files, and make network requests.
2. For each path, test whether the sandbox policy is enforced.
3. Focus on paths that were added after the sandbox was initially designed -- they are most likely to bypass the policy.
4. Check for alternative APIs that achieve the same effect (e.g., `Module._load` bypassing `require` restrictions).

### RBAC Matrix Coverage Testing

For multi-tier role systems with linked resources:
1. Enumerate ALL roles and ALL state-changing operations.
2. Build a matrix: roles x operations.
3. Test every cell -- the authorization check may exist for some role/operation combinations but not others.
4. Focus on operations on linked/shared resources -- a user with Analyst role on Resource A may be able to modify Resource B if A and B are linked.

### Denylist Completeness Against Full Universe

When you find a denylist (SSRF filter, file type filter, IP filter):
1. Enumerate the exhaustive list of values the denylist should contain (all cloud metadata IPs, all internal service hostnames, all dangerous file extensions).
2. Test every value not in the denylist.
3. Also test encoding variants of denylisted values (decimal IP, hex IP, IPv6-mapped IPv4, unicode normalization).
4. Denylists are inherently incomplete -- the gap between what is denied and what should be denied is the attack surface.
