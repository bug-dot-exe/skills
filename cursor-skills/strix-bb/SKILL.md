---
name: strix-bb
description: Automate Strix CLI — pull H1 scope/policy/out-of-scope, write full instructions (bb-hunter from claude-bug-bounty), start detached tmux (Strix runs automatically). Use when user says "run strix(X)", "automate strix X", or similar. For VulnAI use vulnai-h1-run-prep (run vulnai for HANDLE).
---

# Strix-BB: Full Automation

**Flow:** Pull H1 data → Write instructions (full bb-hunter) → `strix-automate.sh` starts detached **tmux** `strix-<handle>` and **runs Strix** (Telegram watcher in background). User attaches with `tmux attach -t strix-<handle>` to watch. For screen + manual paste, set `STRIX_LAUNCH_SCRIPT` to `strix-launch-screen.sh`.

## VulnAI (not Strix)

If the user says **run vulnai for `<handle>`** or wants the same H1 MCP + methodology stack under **VulnAI**: use **`~/.cursor/skills/vulnai-h1-run-prep/SKILL.md`**. It creates `~/vulnai-runs/<handle>/instructions.md` (scopes from `hack`, `fetch_program_scopes`, `search_scopes`). **Before `vulnai` runs, create tmux** — use **`~/.cursor/skills/vulnai-h1-run-prep/scripts/vulnai-launch-tmux.sh <handle>`** (detached session `vulnai-<handle>`) or `tmux new -s vulnai-<handle>` then run `vulnai` inside the pane.

## When to Use

- User says: `run strix for overwolf`, `automate strix mirantis`, `strix for X`
- User wants full prep: H1 scope/policy + bb-hunter methodology + tmux auto-launch + Telegram notifier

## Workflow

1. **Extract handle** from user message (e.g. `overwolf`, `mirantis`)

2. **Pull H1 data** — `mcp_h1-brain_hack(handle)` + `mcp_h1-brain_search_scopes(program=handle)`
   - In-scope assets, max severity
   - Out-of-scope (from hack output)
   - Policy URL: https://hackerone.com/{handle}?view_policy=true (MCP doesn't expose full policy — user adds if needed)
   - Test credentials (from hack if present; else placeholder)

3. **Create** `~/strix-runs/<handle>/`

4. **Write** `instructions.md` with:
   - **Full Scope** — In-scope (from hack + search_scopes), out-of-scope
   - **Policy** — Placeholder: "Fetch from https://hackerone.com/{handle}?view_policy=true"
   - **Test Credentials** — From hack or placeholder
   - **Hack briefing** — Attack vectors, your past findings, instructions from hack()
   - **Skill load layer** — Append `~/.cursor/skills/strix-bb/strix-all-skills.md` (phase→SKILL routing, all `strix-*` paths, bb-hunter/Caido pointers, triage/report paths). This is the “load every skill” orchestration block.
   - **bb-hunter-full.md** — FULL methodology from claude-bug-bounty (7-Question Gate, 4 gates, NEVER SUBMIT, conditionally-valid, bypass tables, hunting rules, security arsenal, report format). NOT minimal overlay.

   **Order:** program-specific body → `strix-all-skills.md` → `bb-hunter-full.md`.  
   `strix-automate.sh` does this automatically when it creates a **minimal** stub; if you author `instructions.md` by hand, concatenate in that order.

   **Overrides:** `STRIX_ALL_SKILLS_MD`, `BB_HUNTER_FULL`, `STRIX_METHODOLOGY_DIR` env vars.

5. **Run** `strix-automate.sh <handle> [target_url] [mode]`
   - Runs `strix-launch-tmux.sh`: detached tmux `strix-<handle>` executes watcher + `strix` immediately
   - Writes `.strix-tmux-run.sh` (sources `~/.strix/env` or `cli-config.json` via jq, then optional `strix-env.sh`)

6. **User:** `tmux attach -t strix-<handle>` to watch live (optional). Telegram notifier runs in background.

**Same tmux server:** Run `strix-launch-tmux.sh` / `strix-automate.sh` from the **same host and login** where you run `tmux attach` (e.g. your SSH shell on the VPS). Sessions started inside Cursor’s agent environment may not appear in your SSH tmux.

## Required MCP

- **h1-brain** — `hack(handle)` for scope and briefing. Must be configured and approved.

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/strix-automate.sh` | Full automation: prep + detached tmux (auto-starts Strix). Agent creates instructions first. |
| `scripts/strix-automate-tmux.sh` | Alias → `strix-automate.sh` |
| `scripts/strix-launch-tmux.sh` | Detached tmux; runs Strix without manual paste |
| `scripts/strix-launch-screen.sh` | Optional: screen + manual paste (`STRIX_LAUNCH_SCRIPT=...`) |
| `scripts/strix-telegram-watcher.sh` | Polls run_dir every 5 min for vulns, sends Telegram (run before Strix, in background) |
| `scripts/strix-telegram-notify.sh` | One-shot notify (used by watcher) |
| `scripts/strix-bb` | One-command: `strix-bb overwolf` (from your terminal) |
| `scripts/strix-request.sh` | Queue launch (Cursor → your machine via watcher) |
| `scripts/strix-watcher.sh` | Queue watcher (start once in background) |

## Automation (Cursor → Your Machine)

When Cursor runs the launch script, it executes in Cursor's environment — the screen session is created there, not on your SSH terminal. To automate:

1. **Start the watcher once** (on your machine, in background):
   ```bash
   ~/.cursor/skills/strix-bb/scripts/strix-watcher.sh &
   ```
   Or add to `~/.bashrc`: `(strix-watcher.sh &)` (starts on login)

2. **Cursor uses `strix-request.sh`** instead of direct launch:
   ```bash
   strix-request.sh overwolf https://creator.tebex.io
   ```
   This writes to `~/strix-runs/.launch-queue`. The watcher picks it up and runs the launch on your machine.

3. **Attach:** `tmux attach -t strix-overwolf`

## Fallback

If `hack(handle)` fails (e.g. program not found, MCP error):
- Check for existing `bbp/<handle>/instructions.md` and use that
- Or create minimal instructions with just the handle and ask user for scope

## Example Invocation

User: "run strix for overwolf" or "automate strix overwolf"

You:
1. `mcp_h1-brain_hack(handle="overwolf")` + `mcp_h1-brain_search_scopes(program="overwolf")`
2. Create `~/strix-runs/overwolf/`
3. Write `instructions.md` with: full scope, policy placeholder, credentials, hack briefing, **`strix-all-skills.md` + `bb-hunter-full.md`** (skill router + full methodology)
4. Run `strix-automate.sh overwolf [url] [mode]`
5. Reply: "Created ~/strix-runs/overwolf/. Strix is running in tmux `strix-overwolf` — attach: `tmux attach -t strix-overwolf`."
