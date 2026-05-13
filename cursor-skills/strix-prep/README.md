# strix-prep

Create Strix CLI target folder and `instructions.md` only. No launch.

## Usage

In Cursor, say:
- `prepare strix for replit`
- `strix prep shopify`
- `create strix target for coinbase`

The agent will:
1. Optionally call H1 Brain `hack(handle)` for scope
2. Create `~/strix-runs/<target>/`
3. Write `instructions.md` (scope + bb-hunter methodology)
4. Tell you how to run Strix manually

## Run Manually

```bash
cd ~/strix-runs/<target>
strix -m deep --target https://<target>.com --instruction-file instructions.md
```

Or with tmux:
```bash
~/.cursor/skills/strix-bb/scripts/strix-launch.sh <target>
```

## Files

| File | Purpose |
|------|---------|
| `SKILL.md` | Cursor skill definition |
| `instruction-minimal.md` | Fallback template when no H1 scope |
| `README.md` | This file |
