---
name: vulnai-h1-run-prep
description: When the user says "run vulnai for" a HackerOne handle, create ~/vulnai-runs/<handle>/ and instructions.md (H1 MCP scopes + full skills); require tmux before vulnai — use vulnai-launch-tmux.sh or manual tmux, then attach.
---

# VulnAI H1 run prep — folder + full `instructions.md`

## When to use

Phrases like:

- "run vulnai for `duel`"
- "prepare vulnai H1 `shopify`"
- "vulnai prep bug bounty `acme`"

## Goal

1. **Create** `~/vulnai-runs/<handle>/` (override if the user asks).
2. **Write** `instructions.md` that merges **H1 Brain MCP scope intelligence** with **full researcher methodology** (same skill load layer as Strix-BB: `strix-all-skills.md` + `bb-hunter-full.md`).
3. **Tell the user** how to launch **VulnAI** so structured H1 API scope, MCP briefing injection, and the file content stack correctly — **always inside tmux** (see §6).

## 1. Normalize the handle

Use the **exact HackerOne program handle** (as in `https://hackerone.com/<handle>`). If only a display name or nickname is given (e.g. “duel” → FanDuel), call **`search_programs`** and pick the right row or ask once. Folder name should match the **canonical handle** (e.g. `fanduel`, not `duel`).

## 2. Collect data from H1 Brain MCP (required for this skill)

Call **all** that succeed (in order):

| Call | Purpose |
|------|---------|
| **`hack(handle="<handle>")`** | Attack briefing, vectors, priorities, disclosed hints, scope context |
| **`fetch_program_scopes(handle="<handle>")`** | Fresh structured scope from the API backing the MCP |
| **`search_scopes(program="<handle>", bounty_only=false, limit=50)`** | Cross-check assets, eligibility, partial string matches |

Paste or **tightly summarize** into `instructions.md`:

- **In-scope assets** — table: identifier, type, bounty eligible, max severity, notes (from `search_scopes` / `fetch_program_scopes` / `hack` — dedupe).
- **Out of scope** — explicit bullets; **do not test**.
- **H1 Brain briefing** — summarized `hack()` (omit noise; keep actionable lines).

If an MCP call fails, note it under **Data sources** and continue with what remains. Never invent assets.

## 3. Policy and links (always)

Add:

- Program: `https://hackerone.com/<handle>`
- Policy: `https://hackerone.com/<handle>?view_policy=true`
- Hacktivity (optional): `https://hackerone.com/<handle>/hacktivity`

**Do not fabricate policy text.** If you cannot summarize safely, keep the policy URL and "read before testing."

## 4. Full skill / knowledge load (required)

After the program-specific sections, the agent writing `instructions.md` must **embed or concatenate** these files **in order** (same as Strix-BB):

1. `~/.cursor/skills/strix-bb/strix-all-skills.md` — phase routing, `strix-*` paths, bb-hunter / triage / report pointers.
2. `~/.cursor/skills/strix-bb/bb-hunter-full.md` — gates, bypass tables, methodology.

**Overrides (if the user uses them):** `STRIX_ALL_SKILLS_MD`, `BB_HUNTER_FULL`, `STRIX_METHODOLOGY_DIR`.

If a file is missing on disk, keep the paths in the doc as **required reading** and say "open these SKILL.md paths on the host."

## 5. How VulnAI uses this (important)

With **`vulnai --h1 <handle>`** and **`--instruction-file`**:

- VulnAI **fetches structured scope** via HackerOne API (`H1_USERNAME` + `H1_API_TOKEN`) and **prepends** it to merged instructions.
- VulnAI **registers h1-brain MCP** (when the server script is found and H1 env vars are set) and **prepends** the `hack()` briefing when the CLI starts.
- Your **`instructions.md`** should still contain **MCP-derived tables and narrative** so the run folder is **self-contained** for review, git, and reruns without Cursor; it also reinforces scope if API and MCP differ slightly.

**Without** H1 API tokens: omit `--h1`; set **one primary** `-t https://…` (or more if the user insists) and put **complete** scope from MCP in `instructions.md` only.

## 6. Launch — tmux required (do not start bare `vulnai` for real runs)

**Rule:** Create a **tmux** session first, run **`vulnai` inside that session** (detached or attached). Long scans survive disconnects; matches the Strix-BB workflow.

### Preferred: helper script (creates session + starts VulnAI)

```bash
~/.cursor/skills/vulnai-h1-run-prep/scripts/vulnai-launch-tmux.sh <handle>
# optional: base dir, mode, then extra vulnai args after --
#   vulnai-launch-tmux.sh fanduel ~/vulnai-runs deep -- -t https://primary.example.com
```

Then attach: `tmux attach -t vulnai-<handle>`

- Replaces an existing session with the same name (`vulnai-<handle>`).
- Per-run secrets: `~/vulnai-runs/<handle>/vulnai-env.sh` (sourced after `~/.vulnai/env`).
- Non-interactive: `VULNAI_NONINTERACTIVE=1 vulnai-launch-tmux.sh <handle>` (adds `-n`).

### Manual (same requirement)

```bash
tmux new -s vulnai-<handle>
cd ~/vulnai-runs/<handle>
vulnai --h1 <handle> -m deep --instruction-file ./instructions.md
# detach: Ctrl+B, D
```

### Inner command reference (what runs inside tmux)

**Interactive (default TUI):**

```bash
vulnai --h1 <handle> -m deep --instruction-file ~/vulnai-runs/<handle>/instructions.md
```

**Non-interactive:**

```bash
vulnai --h1 <handle> -n -m deep --instruction-file ~/vulnai-runs/<handle>/instructions.md
```

**Primary target override** (optional):

```bash
vulnai -t https://primary-in-scope.example.com --h1 <handle> -m deep \
  --instruction-file ~/vulnai-runs/<handle>/instructions.md
```

**Rate limits / URL fan-out:** VulnAI defaults to **`STRIX_BOUNTY_MAX_PASS_TARGETS=1`** when auto-filling many scope URLs under `--h1`. Mention raising to `2`–`3` only if program policy allows.

**LLM / config:** Remind to set `STRIX_LLM`, `LLM_API_KEY`, and optional `~/.vulnai/cli-config.json` (or `--config`).

**MCP server path:** If briefing is skipped at runtime, set `VULNAI_H1_MCP_SERVER` to the `server.py` of h1-brain / ultimate-bounty-mcp.

## 7. Reply to the user

Confirm:

- Folder path and `instructions.md` path.
- Whether scope tables came from `hack` / `fetch_program_scopes` / `search_scopes` (and any MCP failures).
- **tmux:** session name `vulnai-<handle>`, attach command, and either `vulnai-launch-tmux.sh` or the manual tmux steps.
- Reminder to open the **policy URL** before testing.

## Privacy

Do not put live API tokens or session cookies in `instructions.md`. Use `<no-mem>...</no-mem>` for secrets in chat; do not store credentials via `cursor-mem observe`.

## Template

Copy and fill: `~/.cursor/skills/vulnai-h1-run-prep/templates/instructions.skeleton.md`.
