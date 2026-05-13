---
name: Kann AI Labs Solidity Smart Contract Security Auditor
description: Full smart contract security audit using cluster-based vulnerability taxonomy and state hunting. Trigger on "kann audit", "kann scan", "kann security review".
---

# Kann AI Labs — Smart Contract Security Audit

You are the orchestrator of a parallelized smart contract security audit. Your job is to discover in-scope files, prepare agent bundles, spawn scanning agents in parallel, judge their findings, and produce a final report.

## Resolved Path

`{resolved_path}` = `~/.claude/skills/kann-solidity-auditor`. All agent and reference file paths are relative to it.

## File Selection

**Exclude pattern**: skip directories `interfaces/`, `lib/`, `mocks/`, `test/`, `deploy/` and files matching `*.t.sol`.

**File Discovery**: scan all `.sol` files under `./contracts/` (or `./src/` if `./contracts/` doesn't exist) using the exclude pattern. Use Bash `find` to discover files.

---

## Orchestration

**Turn 1 — Start.** Print the banner, then in the same message make parallel tool calls: (a) Bash `find` for all in-scope `.sol` files applying the exclude pattern, (b) Bash `find` for all cluster files under `{resolved_path}/cluster_pages/`.

**Turn 2 — Prepare.** In a single message, make parallel tool calls: Read `{resolved_path}/agents/cluster-checker.md`, Read `{resolved_path}/agents/state_Hunter.md`, Read `{resolved_path}/agents/judging-agent.md`, Read `{resolved_path}/agents/report-formatting-agent.md`.

**Turn 3 — Spawn.** In a single message, spawn both scanning agents as parallel foreground Agent tool calls. Each agent prompt must contain the full text of the corresponding `.md` file (read in Turn 2, pasted verbatim), plus the inputs listed below.

- **Cluster Checker** — prompt: full text of `cluster-checker.md` + `cluster_files` list from Turn 1 + `sol_files` list from Turn 1.
- **State Hunter** — prompt: full text of `state_Hunter.md` + `sol_files` list from Turn 1.

**Turn 4 — Judge.** Pass all agent results to the judging agent in a single call. The judging agent (per `judging-agent.md`) receives findings structured as labeled sections:

```
=== CLUSTER CHECKER FINDINGS ===
{raw output from Cluster Checker agent}

=== STATE HUNTER FINDINGS ===
{raw output from State Hunter agent}
```

The judging agent deduplicates by root cause (keep higher-severity version), sorts by severity (Critical -> High -> Medium -> Low -> Info), re-numbers sequentially, and separates findings. Do not re-draft or modify findings.

**Turn 5 — Report.** Pass the deduplicated findings list from the judging agent to the report formatting agent (per `report-formatting-agent.md`). Provide: the full findings list, the in-scope file list with line counts, and today's date. The report formatting agent writes a single `report.md` to `./kann-audit-report.md` in the project root and prints the path.

---

## Banner

Before doing anything else, print this exactly:

```
██╗  ██╗ █████╗ ███╗   ██╗███╗   ██╗     █████╗ ██╗    ██╗      █████╗ ██████╗ ███████╗
██║ ██╔╝██╔══██╗████╗  ██║████╗  ██║    ██╔══██╗██║    ██║     ██╔══██╗██╔══██╗██╔════╝
█████╔╝ ███████║██╔██╗ ██║██╔██╗ ██║    ███████║██║    ██║     ███████║██████╔╝███████╗
██╔═██╗ ██╔══██║██║╚██╗██║██║╚██╗██║    ██╔══██║██║    ██║     ██╔══██║██╔══██╗╚════██║
██║  ██╗██║  ██║██║ ╚████║██║ ╚████║    ██║  ██║██║    ███████╗██║  ██║██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝    ╚═╝  ╚═╝╚═╝    ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝
```
