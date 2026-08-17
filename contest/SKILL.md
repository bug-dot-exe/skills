---
name: contest
description: >
  One-click audit contest pipeline. Takes a Code4rena/Sherlock/Cantina contest URL,
  clones the repo, reads scope, runs /web3 deep, formats findings for submission.
  Trigger on "/contest", "contest audit", "audit contest".
---

# Contest Audit Pipeline

You are an automated contest audit pipeline. Given a contest URL, you clone the repo, extract the scope, run a full multi-agent audit, and format findings for submission.

## Argument Parsing

Parse `$ARGUMENTS` for:
- **Contest URL**: Code4rena, Sherlock, Cantina, or Hats Finance contest page URL
- **Mode**: `quick`, `core`, `deep` (default: `deep` — contests warrant maximum coverage)
- **`--time-limit`**: optional hours limit (e.g., `--time-limit 4`)
- **`--submit-format`**: `c4` (Code4rena), `sherlock`, `cantina`, `hats` (auto-detected from URL if possible)

---

## Phase 0 — Contest Setup

### Step 1 — Detect Platform

From the URL, determine the platform:
- `code4rena.com` or `github.com/code-423n4` → Code4rena
- `audits.sherlock.xyz` or `github.com/sherlock-audit` → Sherlock
- `cantina.xyz` → Cantina
- `app.hats.finance` → Hats Finance

### Step 2 — Clone Contest Repo

```bash
# Extract repo URL from contest page or use directly if GitHub URL provided
git clone {repo_url} /tmp/contest-{contest_name} --depth 1
cd /tmp/contest-{contest_name}
```

### Step 3 — Extract Scope

Read the contest README, scope document, or `scope.txt`:

1. Look for `README.md` in repo root — parse "Scope" or "In Scope" section
2. Look for `scope.txt` or `.scope` file
3. If using MCP tools, fetch the contest page to read scope details

Extract:
- **In-scope files**: list of contract paths
- **Out-of-scope**: files/dirs to exclude
- **Known issues**: findings the sponsor already knows about (to avoid duplicates)
- **Prize pool**: total and per-severity breakdown (for prioritization)
- **Duration**: contest end date

Print scope summary:
```
Contest:    {name}
Platform:   {platform}
Scope:      {N} files, {N} lines
Prize Pool: ${amount}
Ends:       {date}
Known Issues: {N} listed
```

### Step 4 — Read Known Issues

If the contest lists known issues or previous audit findings, read them all. These are used in Phase 2 to avoid reporting duplicates.

---

## Phase 1 — Run /web3 Audit

Change to the contest directory and invoke the `/web3` orchestrator:

Read `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\web3/SKILL.md`. Spawn **one foreground Agent** with:
1. Full text of web3 SKILL.md
2. The scoped file list (not all files — only in-scope contracts)
3. Mode: as specified (default `deep`)
4. Additional scope notes: "Known issues to SKIP: {list of known issues}"
5. Instruction: write all output to `/tmp/contest-{contest_name}/audit/`

Wait for the full audit to complete.

---

## Phase 2 — Filter Against Known Issues

Read the audit findings. For each finding, check against the known issues list:
- If a finding matches a known issue (same root cause, same location): **REMOVE** it
- If a finding is adjacent to a known issue but distinct: **KEEP** but note the relationship

---

## Phase 3 — Format for Submission

Format each surviving finding according to the platform's template:

### Code4rena Format
```markdown
## [H-01] Title

### Summary
One-line summary.

### Vulnerability Detail
Detailed description with code references.

### Impact
What can an attacker do? Quantify if possible.

### Code Snippet
\`\`\`solidity
// vulnerable code
\`\`\`

### Tool used
Manual Review + AI-assisted audit (Claude Code /web3 deep)

### Recommendation
\`\`\`diff
- vulnerable code
+ fixed code
\`\`\`
```

### Sherlock Format
```markdown
# Title

## Summary
## Vulnerability Detail
## Impact
## Code Snippet
## Tool used
Manual Review
## Recommendation
```

### Cantina Format
```markdown
## Finding: Title

**Severity**: High
**Type**: [category]

### Description
### Impact
### Proof of Concept
### Recommended Mitigation
```

### Hats Finance Format
```markdown
**Title**: ...
**Severity**: High
**Description**: ...
**Attack Scenario**: ...
**Impact**: ...
**Recommendation**: ...
```

---

## Phase 4 — Output

Write formatted findings to `/tmp/contest-{contest_name}/submissions/`:
- One file per finding: `H-01.md`, `H-02.md`, `M-01.md`, etc.
- Summary file: `submissions-summary.md` with all findings listed

Print:
```
Contest audit complete.

Findings: {N} total
  Critical: {N}
  High:     {N}
  Medium:   {N}
  Low:      {N}

Output: /tmp/contest-{contest_name}/submissions/
Format: {platform}

{If PoCs were generated:}
Proven findings: {N}/{total C+H}

Ready for submission. Review each finding before submitting.
```

---

## Important Notes

- **Always review findings manually before submitting** — AI audits can have false positives
- **Check contest rules** — some contests require PoC, some don't
- **Time awareness** — if `--time-limit` is set, prioritize deeper analysis on high-value contracts (those with more external calls, higher TVL, or more complex logic)
- **Dedup against other submissions** — if you can see the contest's existing submissions, check for duplicates before submitting
