# Runtime Progress Protocol

Use this protocol for all runtime progress output.
Keep human output minimal and professional; final deliverables are the 4 report files (see report writer prompt).

## Runtime verbosity modes

- `terse` (default): terminal shows stage start/end and one stage summary.
- `normal`: terminal also shows compact milestones.
- `debug`: terminal may show per-file/per-window details.

In `terse`, heartbeats should be written to debug artifacts only.

## Dual-channel output

Emit progress in two synchronized forms:

1. Human terminal line (mode-dependent)
2. Structured event line (JSONL) to `./.maia_auditor/events.ndjson` (optional debug artifact)

## Human output rules (strict)

- Do not print full JSON payloads or file contents to the terminal.
- Do not echo checklist items or long descriptions in terminal output.
- No narrative paragraphs; only short status lines.
- Prefer totals over per-item lists.
- Respect per-stage output limits in `references/output_budget.md`.

## Stage IDs

- `S01_BOOTSTRAP`
- `S02_RECON`
- `S03_CHECKLIST_PLAN`
- `S04_SCOPE_EVIDENCE`
- `S05_DEEP_SWEEP`
- `S06_CANDIDATES`
- `S07_ADVERSARIAL_VERIFY`
- `S08_REPORT`

## Event types

- `stage_start`
- `heartbeat`
- `metric`
- `decision`
- `stage_end`

## Required event envelope

```json
{
  "ts": "2026-03-17T08:10:00Z",
  "stage": "S05_DEEP_SWEEP",
  "type": "heartbeat",
  "msg": "Scanning window 3/9",
  "progress": {"current": 3, "total": 9, "percent": 33.3},
  "counters": {"files_done": 4, "windows_done": 27, "candidates": 13}
}
```

## Terminal line format (compact)

```text
[S05][27/120|22%] file=contracts/Vault.sol window=3/9 candidates=13 kept=9 dropped=4
```

For short stages:

```text
[S03] checklist parsed: categories=20 items=95 mapped=95 ai=0
```

## Minimum heartbeat cadence

- Emit at least every 3 seconds during long-running stages.
- In `terse`, write heartbeat events to `events.ndjson` only.
- In `normal`/`debug`, emit heartbeat lines to terminal as well.
- Always emit verifier `decision` events (terminal in `normal`/`debug`, file-only in `terse`).

## Final rollup file

Write `./.maia_auditor/progress.json` with latest counters (optional debug artifact):

```json
{
  "current_stage": "S08_REPORT",
  "stage_percent": 100,
  "files_total": 0,
  "files_done": 0,
  "windows_total": 0,
  "windows_done": 0,
  "candidates": 0,
  "valid": 0,
  "valid_downgraded": 0,
  "false_positive_dropped": 0
}
```
