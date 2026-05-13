---
description: "Fetch HackerOne program scope/policies, write instruction file, launch bug.exe (bugdotexe) in tmux. Usage: /hunt-bugdotexe <hackerone_handle> [--mode quick|standard|deep] [--targets domain1,domain2] [--non-interactive]"
---

# /hunt-bugdotexe

Automated pipeline: HackerOne program intel → instruction file → bug.exe launch in tmux.

## What This Does

1. Fetches program scope, policies, and disclosed reports via HackerOne MCP tools
2. Creates `targets/<handle>/` directory with a comprehensive `instructions.md` file
3. Launches bug.exe in a named tmux session targeting the in-scope assets

## Usage

```
/hunt-strix rei
/hunt-strix rei --mode deep
/hunt-strix rei --targets rei.com,login.rei.com
/hunt-strix rei --non-interactive
```

## Arguments

- `<handle>` (required): HackerOne program handle (e.g., `rei`, `github`, `shopify`)
- `--mode`: bug.exe scan mode — `quick`, `standard`, or `deep` (default: `deep`)
- `--targets`: Comma-separated list of specific targets to hunt (overrides auto-selection from scope)
- `--non-interactive`: Pass `-n` to bug.exe (no TUI, exits on completion)

## Phase 1: Fetch Program Intel

### Step 1: Fetch scope and attack briefing

Call the `mcp__ultimate-bounty__hack` tool with the program handle. This returns:
- Program name, URL, response targets
- In-scope assets (domains, URLs, apps, cloud infra, etc.)
- Out-of-scope assets
- Bounty table / reward ranges
- Past disclosed reports and patterns

Save the full output — it's the primary data source for the instruction file.

### Step 2: Fetch detailed scopes

Call `mcp__ultimate-bounty__fetch_program_scopes` with the handle to get structured scope data:
- Asset identifiers
- Asset types (Domain, URL, iOS, Android, Other, etc.)
- Eligibility for bounty
- Max severity

### Step 3: Search disclosed reports for intel

Call `mcp__ultimate-bounty__search_disclosed_reports` with `program=<handle>` to find past public reports. Extract:
- Vulnerability types that paid bounties
- Endpoints that were previously vulnerable
- Bug classes the program cares about
- Average bounty amounts

### Step 4: Search for writeups (optional enrichment)

Call `mcp__ultimate-bounty__search_writeups` with `program=<handle>` to find community writeups about the target.

## Phase 2: Build Instruction File

Create directory: `targets/<handle>/`

Write `targets/<handle>/instructions.md` with this structure:

```markdown
# bug.exe Hunt Instructions: <Program Name>
# Generated: <date>
# HackerOne: https://hackerone.com/<handle>

## Program Overview
<Program name, type, response targets, safe harbor status>

## Scope

### In-Scope Assets
| Asset | Type | Max Severity | Bounty Eligible |
|-------|------|-------------|-----------------|
<populated from scope data>

### Out-of-Scope Assets
<list all out-of-scope assets and exclusions>

### Explicit Exclusions
<list any specific paths, features, or vulnerability types excluded>

## Program Rules & Policies
<key rules from the program policy that affect testing approach>
- Authentication requirements (e.g., "use @wearehackerone aliases")
- PoC requirements
- Credential handling rules
- Testing restrictions (no DoS, no social engineering, etc.)
- Consolidation rules (how they handle dupes/similar findings)
- Third-party exclusions

## Out-of-Scope Vulnerability Types
<list all vulnerability types the program does not accept>

## Bounty Information
<reward ranges by severity, any special payout rules>

## Intel from Disclosed Reports
### Past Findings
<summarize disclosed reports: which bug classes paid, which endpoints, amounts>

### Recommended Attack Vectors
Based on past reports and scope analysis:
1. <highest ROI attack vector with reasoning>
2. <second highest>
3. <third highest>

## Testing Instructions for bug.exe
- Focus on in-scope assets ONLY
- Do NOT test out-of-scope assets or excluded paths
- Do NOT perform DoS or DDoS attacks
- Do NOT access other users' accounts or data
- Prioritize bug classes that have paid bounties in the past
- For each finding: document exact reproduction steps and proof of concept
- <any program-specific testing instructions>
```

## Phase 3: Select Targets for bug.exe

### Auto-selection (default)

From the in-scope assets, select targets for bug.exe:
1. **Domains**: Use directly (e.g., `rei.com`, `login.rei.com`)
2. **URLs**: Use the base URL (e.g., `https://www.rei.com/learn/expert-advice`)
3. **Cloud/Other**: Skip these — bug.exe targets web assets
4. **Mobile apps**: Skip unless bug.exe supports mobile testing

Prioritize by:
- Bounty eligible = YES
- Max severity = Critical (highest reward potential)
- Most reports resolved (active attack surface — bugs exist here)
- Domains over URLs (broader attack surface)

### Manual override

If `--targets` is specified, use those instead of auto-selection.

## Phase 4: Launch bug.exe in tmux

### Step 1: Create tmux session

Session name: `bugdotexe-<handle>` (e.g., `bugdotexe-rei`)

### Step 2: Build bug.exe command

```bash
# Single primary target with instruction file
bugdotexe \
  -t <primary_target> \
  --instruction-file targets/<handle>/instructions.md \
  -m <mode> \
  [-n]

# Multiple targets (if several high-value domains)
bugdotexe \
  -t <target1> \
  -t <target2> \
  --instruction-file targets/<handle>/instructions.md \
  -m <mode> \
  [-n]
```

### Step 3: Launch in tmux

```bash
tmux new-session -d -s "bugdotexe-<handle>" \
  "bugdotexe -t <target> --instruction-file $(pwd)/targets/<handle>/instructions.md -m <mode>"
```

### Step 4: Confirm launch

```bash
tmux list-sessions | grep "bugdotexe-<handle>"
```

## Output

After completion, report to the user:
1. Instruction file path: `targets/<handle>/instructions.md`
2. Tmux session name: `bugdotexe-<handle>`
3. Targets being hunted (list each)
4. bug.exe scan mode used
5. How to attach: `tmux attach -t bugdotexe-<handle>`
6. Quick summary: number of in-scope assets, top attack vectors, bounty range

## Error Handling

- **MCP tool timeout**: If `hack()` or `fetch_program_scopes()` times out, fall back to asking the user to paste program scope manually
- **No disclosed reports**: Skip intel section, note "No public disclosures found — virgin attack surface or private program"
- **Tmux session exists**: Kill existing `bugdotexe-<handle>` session first (confirm with user), or append a number suffix
- **bug.exe not found**: Check `bugdotexe` is on PATH (or `uv run --project <repo> bugdotexe` works); suggest installation if missing
- **No bounty-eligible targets**: Warn user, still create instruction file but flag it

## Monitoring

After launch:
```bash
# Attach to watch bug.exe work
tmux attach -t bugdotexe-<handle>

# Detach without stopping: Ctrl+B, then D

# Check if bug.exe is still running
tmux list-sessions | grep bugdotexe

# Kill the session when done
tmux kill-session -t bugdotexe-<handle>
```
