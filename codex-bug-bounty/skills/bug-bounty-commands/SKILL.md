---
name: bug-bounty-commands
description: Bridge the original Claude Bug Bounty slash commands into Codex workflows. Use when the user references /recon, /hunt, /validate, /report, /scope, /triage, /intel, /resume, /surface, /autopilot, /remember, /chain, or /web3-audit from the Claude Bug Bounty repo.
---

# Bug Bounty Command Bridge

Codex does not execute Claude slash commands directly. When a user references one of the original commands, translate it into a normal Codex task and use the matching local docs, skills, and scripts from this plugin.

## Workflow

1. Identify the command the user is invoking.
2. Read the matching file in `../commands/` first.
3. Use the corresponding skill from `../skills/` when one exists.
4. Prefer the local helper script in `../tools/` when it fits the task.
5. Keep outputs in an explicit directory instead of assuming Claude-specific session state.

## Command Map

| Original command | Codex translation | Primary references |
| --- | --- | --- |
| `/recon target.com` | Run recon against the target and summarize the attack surface | `../commands/recon.md`, `../tools/recon_engine.sh`, `web2-recon` |
| `/hunt target.com` | Hunt a target for concrete, high-impact bugs | `../commands/hunt.md`, `../tools/hunt.py`, `bug-bounty`, `bb-methodology` |
| `/validate` | Apply the validation gates before reporting | `../commands/validate.md`, `../tools/validate.py`, `triage-validation` |
| `/report` | Draft a submission-ready report | `../commands/report.md`, `../tools/report_generator.py`, `report-writing` |
| `/scope asset` | Check whether a target asset is in scope | `../commands/scope.md`, `../tools/scope_checker.py` |
| `/triage` | Do a fast go/no-go pass on a potential finding | `../commands/triage.md`, `triage-validation` |
| `/intel target.com` | Pull disclosures, CVEs, and target-specific context | `../commands/intel.md`, `../tools/intel_engine.py`, `bug-bounty` |
| `/surface target.com` | Rank the attack surface from recon results | `../commands/surface.md`, `bug-bounty`, `bb-methodology` |
| `/resume target.com` | Rebuild context and continue a previous hunt | `../commands/resume.md`, `bb-methodology` |
| `/remember` | Persist a useful pattern or note from the current hunt | `../commands/remember.md`, `../memory/` |
| `/chain` | Look for a stronger B or C after bug A | `../commands/chain.md`, `bug-bounty` |
| `/autopilot target.com` | Run the hunt as staged checkpoints, not an uncontrolled loop | `../commands/autopilot.md`, `bb-methodology`, `bug-bounty` |
| `/web3-audit contract` | Run the smart-contract review workflow | `../commands/web3-audit.md`, `web3-audit`, `../web3/` |

## Codex-Specific Rules

- Treat slash-command text as intent, not literal syntax.
- Do not wait for Claude-only features like command palettes or built-in agent routing.
- For `/autopilot`, break work into explicit steps and checkpoint after each stage.
- If the repo offers both a skill and a script, use the skill for reasoning and the script for deterministic execution.
- If a command doc assumes unavailable tooling, say so and continue with the closest working path.

## Read As Needed

- `../README.md` for the overall workflow
- `../commands/*.md` for command-specific behavior
- `../rules/hunting.md` and `../rules/reporting.md` for guardrails
- `../docs/` and `../web3/` for deeper references
