---
name: strix-h1-run-prep
description: When the user says "run strix for" a HackerOne handle (or similar), create a run folder and a full instructions.md with in-scope, out-of-scope, policy links, MCP briefing, and Strix launch commands. Use with h1-brain MCP and/or Strix platforms API. For VulnAI CLI use skill vulnai-h1-run-prep (run vulnai for HANDLE).
---

# Strix H1 run prep — folder + full `instructions.md`

## VulnAI instead of Strix

If the user wants **VulnAI** (`vulnai` from the vuln.ai project): follow **`~/.cursor/skills/vulnai-h1-run-prep/SKILL.md`**. Same MCP calls and methodology files; default folder `~/vulnai-runs/<handle>/`; launch with `vulnai --h1 <handle> -m deep --instruction-file ...`.

## When to use

Phrases like:

- "run strix for `shopify`"
- "prepare strix for H1 handle `truist_financial_bbp`"
- "strix prep hackerone `acme`"

## Preferred Strix launch (most researchers)

**Do not rely on `--h1`** unless H1 API tokens are set. The standard pattern is:

```bash
strix -t <primary_url_or_dot> -m deep --instruction-file ~/strix-runs/<handle>/instructions.md
```

- **`-t .`** — local source + everything else in the file.  
- **`-t https://…`** — one primary in-scope host; put **all** other URLs + policy + OOS in `instructions.md`.

## Goal

1. **Create** a dedicated directory for that program.
2. **Write** `instructions.md` that is **complete enough to paste into Strix** (`--instruction-file`) or to guide a hunt — not a one-line stub.

## 1. Parse the handle

- Normalize to the **exact HackerOne program handle** (lowercase, underscores as on the URL `hackerone.com/<handle>`).
- If the user gives a display name only, resolve the handle (search programs / ask once).

## 2. Create the folder

Default path (override if the user prefers):

```text
~/strix-runs/<handle>/
```

Create it if missing. Optional: also add `touch ~/strix-runs/<handle>/.gitkeep` if they version-control `strix-runs`.

## 3. Collect authoritative data (do all that apply)

### A. H1 Brain MCP (preferred when configured)

Call **`hack(handle="<handle>")`** for:

- In-scope / bounty context
- Suggested vectors, untouched assets, disclosed-report hints
- Any credential or testing notes returned

Call **`search_scopes(program="<handle>", bounty_only=false, limit=50)`** to cross-check assets and eligibility.

If MCP fails, note that in the doc and fall back to API (below).

### B. Strix HackerOne API (structured scopes + instruction block)

On the user’s machine, **H1_USERNAME** + **H1_API_TOKEN** (or **HACKERONE_***) must be set.

From a checkout where the `strix` package is importable (editable install or `PYTHONPATH`):

```bash
cd "${STRIX_REPO:-$HOME/strix}"
python3 <<'PY'
from strix.interface.platforms import fetch_program, build_instruction
handle = "REPLACE_HANDLE"
scope = fetch_program("hackerone", handle)
print(build_instruction(scope))
PY
```

Or run the helper (if present next to this skill):

```bash
python3 ~/.cursor/skills/strix-h1-run-prep/scripts/h1_scope_block.py REPLACE_HANDLE
```

**Important:** `fetch_hackerone` in Strix currently leaves **`policy` empty** in `ProgramScope`. The generated block covers **in-scope / out-of-scope** from structured scopes well, but **you must still add a Policy section manually** (see below).

### C. Policy (full rules of engagement)

HackerOne does not expose the full policy text via the same structured-scopes endpoint Strix uses. For every `instructions.md`:

1. Add the canonical **policy URL**:
   - `https://hackerone.com/<handle>?view_policy=true`
2. Instruct the researcher to read it before testing.
3. If you can **safely** summarize (browser MCP, user paste, or public policy mirror), add a **bullet summary** of:
   - Safe harbor / authorization
   - Prohibited actions (DoS, social engineering, physical, etc.)
   - Rate limits / request caps
   - Credential rules, duplicate rules, disclosure rules
   - Reward / severity table if visible on policy page

Never invent policy text — if unsure, keep only the link + "read before testing".

### D. Out of scope

- Include **everything** from `ProgramScope.out_of_scope` (from Strix `build_instruction` / API).
- If MCP or disclosures mention **implicit** OOS (e.g. "third-party widgets"), add under **Program-specific notes** with source.

## 4. Write `instructions.md`

Path:

```text
~/strix-runs/<handle>/instructions.md
```

### Required sections (in order)

1. **Title** — Program handle + one-line objective (authorized bug bounty only).
2. **Quick links**
   - Program: `https://hackerone.com/<handle>`
   - Policy: `https://hackerone.com/<handle>?view_policy=true`
   - Hacktivity / disclosures (if useful): `https://hackerone.com/<handle>/hacktivity`
3. **Environment**
   - Strix command templates (see §5).
   - Reminder: `H1_USERNAME` / `H1_API_TOKEN` for `--h1` scope fetch; LLM env (`STRIX_LLM`, keys, etc.).
4. **In-scope assets** — Table or bullet list:
   - Asset identifier
   - Type (URL, wildcard, mobile id, CIDR, …)
   - Bounty eligible (yes/no)
   - Max severity if known
   - Asset-level notes from API
5. **Out of scope** — Explicit list; **DO NOT TEST**.
6. **Policy & rules of engagement** — Link + summary (see §3C).
7. **Credentials / test accounts** — From MCP or "None provided — use only own test accounts; see policy."
8. **H1 Brain briefing** — Paste or summarize `hack()` output (vectors, priorities, untouched assets). Omit if MCP unavailable and say so.
9. **Researcher directives** — Short list: stay in scope, PoC before report, respect rate limits, no exfiltration of real customer data, etc.
10. **Optional methodology appendix** — Point to the user’s full methodology files instead of inlining megabytes, e.g.:
    - `~/.cursor/skills/strix-bb/strix-all-skills.md`
    - `~/.cursor/skills/strix-bb/bb-hunter-full.md`

Use clear Markdown headings (`##`, `###`) and tables where they improve readability.

## 5. Strix launch commands (put in the doc)

```bash
# Interactive (SSH terminal with TTY)
strix --h1 <handle> -m deep --instruction-file ~/strix-runs/<handle>/instructions.md

# Non-interactive / nohup
nohup strix --h1 <handle> -n -m deep --instruction-file ~/strix-runs/<handle>/instructions.md \
  > ~/strix-runs/<handle>/strix.log 2>&1 &
```

If they use a JSON CLI config:

```bash
strix --config ~/.strix/cli-config.json --h1 <handle> -m deep \
  --instruction-file ~/strix-runs/<handle>/instructions.md
```

## 6. Reply to the user

Short confirmation:

- Folder path
- Path to `instructions.md`
- Whether data came from MCP, Strix API, or both
- Reminder to open the **policy URL** if policy body is still thin
- **Rate limits:** Strix now defaults to **`STRIX_BOUNTY_MAX_PASS_TARGETS=1`** when `--h1` auto-fills many URLs (only one primary `--target`; rest queued in instructions). Mention if they should raise it (e.g. `2`–`3`) per program rules.

## Privacy

- Do not store live API tokens or session cookies inside `instructions.md`.
- Use `<no-mem>...</no-mem>` in chat if discussing secrets; do not `cursor-mem observe` credentials.
