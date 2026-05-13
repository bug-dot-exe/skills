---
name: strix-prep
description: Create Strix CLI target folder and instructions.md only. No launch. Use when user says "prepare strix for X", "strix prep target", or wants to set up a run they'll execute manually. For VulnAI-only prep use vulnai-h1-run-prep.
---

# Strix-Prep: Folder + Instructions Only

Create the target folder and `instructions.md` for Strix CLI. **Does not launch Strix.** User runs manually.

## VulnAI (no launch)

For **VulnAI** with the same “folder + instructions only” intent: use **`vulnai-h1-run-prep`** — default `~/vulnai-runs/<handle>/`, H1 MCP scope in the file, then user runs `vulnai --h1 … --instruction-file …` themselves.

## When to Use

- User says: `prepare strix for replit`, `strix prep shopify`, `create strix target for X`
- User wants folder + instructions only, will run `strix` themselves

## Workflow

1. **Extract target** from user message (handle, domain, or program name)
2. **If HackerOne program:** Call `mcp_h1-brain_hack(handle)` and `mcp_h1-brain_search_scopes(program=handle)` → scope, attack vectors, full asset list
3. **Create** `~/strix-runs/<target>/` directory
4. **Write** `instructions.md` with this structure:
   - **Scope** — Full in-scope assets from hack() + search_scopes. Out-of-scope if known.
   - **Policy** — Placeholder: "Fetch from https://hackerone.com/{handle}?view_policy=true — paste full policy (in-scope, out-of-scope, excluded bugs, rate limits)." H1 Brain MCP does not expose policy; user fetches manually.
   - **Test Credentials** — Placeholder: "If program provides test accounts on H1 policy page, add: email:password. Otherwise: create via signup." H1 Brain MCP does not expose credentials; user adds from program page.
   - **Hack briefing** — Attack vectors, your past findings, instructions from hack()
   - **`strix-all-skills.md`** — Skill load / phase routing (`~/.cursor/skills/strix-bb/strix-all-skills.md`)
   - **`bb-hunter-full.md`** — Gates, bypass tables, payloads (`~/.cursor/skills/strix-bb/bb-hunter-full.md`)
5. **Output** manual run instructions:
   ```
   Created ~/strix-runs/<target>/
   
   Run manually:
     cd ~/strix-runs/<target>
     strix -m deep --target . --instruction-file instructions.md
   
   Or launch in screen (interactive, detachable):
     ~/.cursor/skills/strix-bb/scripts/strix-launch-screen.sh <target>
   ```

## Parameters

- **target** — program handle (e.g. `replit`), domain, or identifier. Used for folder name and default URL.
- **base_dir** — optional, default `~/strix-runs`
- **target_url** — optional override for Strix `--target` (e.g. `https://immersivelabs.online` for immersive)

## Fallback (No H1 Brain)

If `hack()` fails or user provides non-H1 target:
- Create folder and minimal `instructions.md` with:
  - `# Target: <target>`
  - `## Scope` (placeholder: user adds in-scope assets)
  - `## Out of Scope` (placeholder)
  - `strix-all-skills.md` + `bb-hunter-full.md` (concatenate in that order)

## Files Created

```
~/strix-runs/<target>/
  instructions.md   # Scope + methodology for Strix
```

## Manual Run Options

After prep, user can run:

1. **Direct Strix:**
   ```bash
   cd ~/strix-runs/<target>
   strix -m deep --target <url> --instruction-file instructions.md
   ```

2. **Via launch script (screen):**
   ```bash
   ~/.cursor/skills/strix-bb/scripts/strix-launch-screen.sh <target> ~/strix-runs <target_url>
   ```
