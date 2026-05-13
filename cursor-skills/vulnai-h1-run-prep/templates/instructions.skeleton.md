# VulnAI run — `<HANDLE>` (HackerOne)

**Authorized bug bounty only.** Stay in scope; read policy before testing.

## Quick links

| Resource | URL |
|----------|-----|
| Program | https://hackerone.com/<HANDLE> |
| Policy | https://hackerone.com/<HANDLE>?view_policy=true |
| Hacktivity | https://hackerone.com/<HANDLE>/hacktivity |

## Data sources

- H1 Brain MCP: `hack`, `fetch_program_scopes`, `search_scopes` (note date + any failed calls).

## VulnAI — run inside tmux (required)

**Do not** start a long `vulnai` run without tmux (SSH drops lose the session).

**One command (creates detached session `vulnai-<HANDLE>`):**

```bash
~/.cursor/skills/vulnai-h1-run-prep/scripts/vulnai-launch-tmux.sh <HANDLE>
tmux attach -t vulnai-<HANDLE>
```

**Manual:**

```bash
tmux new -s vulnai-<HANDLE>
cd ~/vulnai-runs/<HANDLE>
vulnai --h1 <HANDLE> -m deep --instruction-file ./instructions.md
```

**Reference (same as inside tmux):**

```bash
vulnai --h1 <HANDLE> -m deep --instruction-file ~/vulnai-runs/<HANDLE>/instructions.md
```

```bash
vulnai --h1 <HANDLE> -n -m deep --instruction-file ~/vulnai-runs/<HANDLE>/instructions.md
```

## In-scope assets (from H1 MCP + cross-check)

| Asset | Type | Bounty | Max severity | Notes |
|-------|------|--------|--------------|-------|
| … | … | … | … | … |

## Out of scope — do not test

- …

## Policy & rules of engagement

**Read:** https://hackerone.com/<HANDLE>?view_policy=true

### Summary (optional — verify against live policy)

- …

## Credentials

- …

## H1 Brain attack briefing (from `hack()`)

*(Summarize; keep actionable vectors and priorities.)*

## Researcher directives

1. Only test in-scope assets; verify hostnames against scope.
2. PoC before any report; no real user data exfiltration.
3. Respect rate limits and program rules.
4. Use `mcp_call` to h1-brain during the run for `search_disclosed_reports`, `search_writeups`, `fetch_program_scopes` as needed.

---

<!-- Below: append full file contents in order: strix-all-skills.md then bb-hunter-full.md -->

## Methodology — full skill load

*(Insert contents of `~/.cursor/skills/strix-bb/strix-all-skills.md` here.)*

---

*(Insert contents of `~/.cursor/skills/strix-bb/bb-hunter-full.md` here.)*
