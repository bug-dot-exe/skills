---
name: benchmark
description: >
  Benchmark auditor skills against known-vulnerable contracts.
  Measures recall, precision, and false positive rate per auditor.
  Trigger on "/benchmark", "benchmark auditors", "eval auditors".
---

# Auditor Benchmark Harness

You benchmark security auditor skills against repos with **known vulnerabilities** to measure which auditors find what, what they miss, and their false positive rates.

## Argument Parsing

Parse `$ARGUMENTS` for:
- **Benchmark suite**: `defi-vuln` (DeFiVulnLabs), `dvd` (Damn Vulnerable DeFi), `contest:<url>` (past contest with known findings)
- **Auditors to test**: comma-separated list, or `all` (default: `all`)
- **`--quick`**: run only 2 auditors for speed comparison

If no suite specified, default to `defi-vuln`.

---

## Benchmark Suites

### Suite 1: DeFiVulnLabs (56 known vulnerabilities)

```bash
git clone https://github.com/SunWeb3Sec/DeFiVulnLabs /tmp/benchmark-defi-vuln 2>/dev/null || true
```

**Ground truth**: Each `.sol` file in `src/test/` is a vulnerability PoC. The vulnerability class is in the filename (e.g., `Reentrancy.sol`, `Overflow.sol`). Parse filenames to build the ground truth list.

### Suite 2: Damn Vulnerable DeFi v4

```bash
git clone https://github.com/theredguild/damn-vulnerable-defi /tmp/benchmark-dvd 2>/dev/null || true
```

**Ground truth**: Each challenge directory contains a known exploit. The README describes the vulnerability. Parse challenge names as ground truth.

### Suite 3: Past Contest (user-provided)

User provides a contest URL + ground truth findings file. The skill:
1. Clones the contest repo
2. Reads the findings file (usually `findings.md` or a JSON report)
3. Extracts: finding title, severity, location, root cause
4. Uses this as ground truth

---

## Evaluation Flow

### Step 1 — Setup

1. Clone/verify the benchmark repo
2. Parse ground truth (known vulnerabilities with locations + severities)
3. Print: "Benchmarking against {N} known vulnerabilities in {suite}"

### Step 2 — Run Each Auditor

For each auditor to benchmark, spawn a **foreground Agent** with:
1. The auditor's SKILL.md (read from `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\{name}/SKILL.md`)
2. The benchmark contract files as scope
3. Instruction: "Audit these contracts. Write findings to `/tmp/benchmark-{suite}/results-{auditor}.md` in the standard format."

Run auditors **sequentially** (not parallel) to get clean timing data. Time each run.

### Step 3 — Score

For each auditor's output, compare against ground truth:

- **True Positive (TP)**: Auditor found a vulnerability that matches a ground truth entry (same file + same vulnerability class)
- **False Positive (FP)**: Auditor reported a finding that doesn't match any ground truth entry
- **False Negative (FN)**: Ground truth vulnerability that the auditor missed

Calculate per auditor:
- **Recall** = TP / (TP + FN) — what % of real bugs did it find?
- **Precision** = TP / (TP + FP) — what % of its reports are real?
- **F1 Score** = 2 * (Precision * Recall) / (Precision + Recall)
- **Time**: how long the audit took

### Step 4 — Report

Print the leaderboard:

```markdown
# Auditor Benchmark Report

**Suite**: {suite_name}
**Ground Truth**: {N} known vulnerabilities
**Date**: {today}

## Leaderboard

| Rank | Auditor | Recall | Precision | F1 | TP | FP | FN | Time |
|------|---------|--------|-----------|-----|----|----|-----|------|
| 1 | krait | 78% | 85% | 0.81 | 14 | 3 | 4 | 4m |
| 2 | contract-auditor | 72% | 90% | 0.80 | 13 | 1 | 5 | 6m |
| ... | | | | | | | | |

## Bug Class Coverage

| Bug Class | contract-auditor | krait | code-sleuth | ... |
|-----------|-----------------|-------|-------------|-----|
| Reentrancy | FOUND | FOUND | - | |
| Access Control | FOUND | MISSED | - | |
| Oracle Manipulation | MISSED | FOUND | - | |
| Storage Collision | - | - | FOUND | |

## Recommendations

Based on this benchmark:
- **Best single auditor**: {name} (highest F1)
- **Best combo for recall**: {name1} + {name2} (covers {N}% of bugs)
- **Lowest FP rate**: {name} (highest precision)
- **Best for /web3 core mode**: {recommended 3 auditors}
```

### Step 5 — Save Results

Write the full report to `/tmp/benchmark-{suite}/benchmark-report.md`.

If the user wants to update `/web3`'s skill selection matrix based on results, suggest specific changes.

---

## Auditor Path Reference

| Auditor | SKILL.md Path |
|---------|--------------|
| contract-auditor | `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\contract-auditor/SKILL.md` |
| krait | `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\krait\.claude\skills/krait/SKILL.md` |
| kann-solidity-auditor | `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\kann-solidity-auditor/SKILL.md` |
| nemesis-auditor | `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\nemesis-auditor/SKILL.md` |
| tiny-auditor | `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\tiny-auditor/SKILL.md` |
| code-sleuth | `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\code-sleuth/SKILL.md` |
| monethic-maia | `C:\Users\pc\.config\opencode\vendor\conjure-3301-skills\monethic-maia/SKILL.md` |
