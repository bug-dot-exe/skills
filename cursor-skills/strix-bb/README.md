# strix-bb

Automate Strix CLI — prep + launch with H1 Brain scope + bb-hunter methodology in a screen session.

## Usage

In Cursor, say:
- `run strix(replit)`
- `strix for shopify`
- `automate strix coinbase`

The agent will:
1. Call H1 Brain `hack(handle)` for scope and attack vectors
2. Create `~/strix-runs/<handle>/` with `instructions.md`
3. Launch Strix in screen session `strix-<handle>`

## Requirements

- **h1-brain MCP** — configured and approved
- **Strix CLI** — `curl -sSL https://strix.ai/install | bash`
- **screen** — for interactive detached sessions
- **Docker** — for Strix sandbox
- **~/.strix/cli-config.json** — LLM config (STRIX_LLM, AZURE_*)

## Watch the run

- Attach: `screen -r strix-<handle>`
- Detach: `Ctrl+A`, `D`

## Files

| File | Purpose |
|------|---------|
| `SKILL.md` | Cursor skill definition |
| `scripts/strix-launch-screen.sh` | Screen + Strix launcher |
| `scripts/strix-launch.sh` | Tmux alternative |
| `bb-hunter-overlay.md` | Full bb-hunter methodology (7-Question Gate, bypass tables, chains, hunting rules) |
| `instruction-template-enhanced.md` | Lighter fallback |
