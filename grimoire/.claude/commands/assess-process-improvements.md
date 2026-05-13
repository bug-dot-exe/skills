---
name: Assess Process Improvements
description: >-
  Analyze user feedback from the most recent gap-analysis or execute-plan run
  to identify systemic process improvements that would make that feedback
  unnecessary in the future.
user_invocable: true
---

# Assess Process Improvements

Study the conversation history to find every instance where the user corrected,
redirected, or refined Claude's work during the most recent gap-analysis or
execute-plan run. Then propose concrete changes to commands, skills, or
conventions so those corrections become unnecessary.

## Important Constraints

- This command operates on the current conversation context. It must be run in
  the same session as the gap-analysis or execute-plan run being assessed.
- Proposed changes target the process (commands, skills, CLAUDE.md, conventions),
  not the plugin implementation itself.
- The specification in `grimoire/grimoire/` is read-only. Never propose changes there.
- Use subagents for analysis to keep context clean.

## Subagent Tools

- **Step 1 subagent** (extract feedback): none needed (works from conversation context)
- **Step 2 subagent** (classify, Opus): `Read`, `Glob`
- **Step 3 subagent** (propose fixes, Opus): `Read`, `Glob`, `Grep`

## Workflow

### 1. Extract Feedback Events

Scan the full conversation history for the most recent `/gap-analysis` or
`/execute-plan` invocation and everything that followed it. Identify every
instance where the user:

- **Corrected** an output (e.g. "that's wrong", "no, it should be X")
- **Redirected** the approach (e.g. "don't do it that way", "use Y instead")
- **Added missing context** that Claude should have known or discovered
  (e.g. "you missed Z", "check the spec for W")
- **Refined quality** (e.g. "make this more detailed", "this is too verbose",
  "wrong format")
- **Repeated themselves** — gave the same feedback they've given before, meaning
  a prior improvement wasn't captured

For each event, record:
- **trigger** — what Claude did or produced that prompted the feedback
- **feedback** — what the user said (quote or close paraphrase)
- **resolution** — what Claude did in response
- **phase** — which step of the command workflow this occurred in

Present the extracted events to the user as a numbered list for confirmation
before proceeding. The user may add events that were missed or remove ones that
aren't worth addressing.

### 2. Classify Root Causes

For each confirmed feedback event, use an **Opus subagent** to determine the
root cause. The subagent should read the relevant command file(s) and classify
each event into one or more categories:

- **instruction_gap** — the command doesn't instruct this behavior; Claude had
  to be told. Fix: add explicit instruction to the command.
- **instruction_ambiguity** — the command says something but it's unclear or
  easily misinterpreted. Fix: clarify the instruction.
- **missing_convention** — the project has an unwritten convention that Claude
  violated. Fix: document the convention in CLAUDE.md or the relevant command.
- **missing_context** — Claude lacked information it needed and didn't know to
  look for it. Fix: add a search/read step to the command workflow.
- **quality_bar** — Claude's output met the letter of the instructions but not
  the user's quality expectations. Fix: add quality criteria or examples.
- **wrong_default** — Claude made a reasonable choice but the user prefers a
  different default. Fix: encode the preference.
- **tool_misuse** — Claude used the wrong tool or used a tool incorrectly.
  Fix: add tool guidance to the command.
- **scope_creep** — Claude did more or less than was asked. Fix: tighten scope
  boundaries in the command.

Present the classification to the user for confirmation.

### 3. Propose Process Changes

For each classified root cause, use an **Opus subagent** to draft a specific,
minimal change to the appropriate file. The subagent reads the target file and
proposes:

- **target_file** — which file to change (e.g. `.claude/commands/gap-analysis.md`,
  `CLAUDE.md`, a skill's `SKILL.md`)
- **change_type** — one of: `add_instruction`, `clarify_instruction`,
  `add_workflow_step`, `add_convention`, `add_quality_criteria`, `add_example`
- **location** — where in the file the change belongs (section name or after
  which line)
- **content** — the exact text to add or the before/after for a clarification
- **rationale** — one sentence explaining what feedback this prevents

Guidelines for proposals:
- Prefer the smallest change that prevents the feedback. Don't restructure
  entire commands to fix one issue.
- If multiple feedback events share a root cause, propose one change that
  addresses all of them.
- If a change would make a command significantly longer, consider whether a
  convention in CLAUDE.md would be better.
- Changes must be consistent with existing command style and conventions.

### 4. Present and Prioritize

Show the user:

1. **Feedback summary** — table with columns: #, Phase, Trigger (brief),
   Root Cause, Proposed Fix (brief)
2. **Proposed changes** — grouped by target file, each with full content and
   rationale
3. **Impact estimate** — for each change, how many feedback events it would
   have prevented

Sort proposals by impact (most feedback events prevented first).

### 5. Apply Approved Changes

Wait for the user to approve, modify, or reject each proposal. Then apply
all approved changes:

- Use `Edit` for modifications to existing files
- Use `Write` only for new files
- After applying, re-read each modified file to verify the change fits
  naturally in context

### 6. Update Memory

If any approved changes reveal stable patterns or preferences that apply
beyond a single command, note them in the auto memory directory so they
persist across sessions. Only record durable insights — not session-specific
fixes.

### 7. Commit

Stage all changes with `git add -A` and commit with a message like:
`process: incorporate feedback from [gap-analysis|execute-plan] session`

Don't push.
