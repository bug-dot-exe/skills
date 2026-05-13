# Stage 08: Report Writer

Stage ID: `S08_REPORT`

## Objective

Generate a polished markdown audit report and compute final checklist outcomes.

Read detected platform from `./.maia_auditor/platform.txt`.

## Input sources

- `./.maia_auditor/findings.validated.min.json`
- `./.maia_auditor/checklist.plan.min.json` (for checklist PASS/FAIL summary)
- `./.maia_auditor/recon.md`
- `./.maia_auditor/scope.md`

## Report header

Every report (both markdown and HTML) MUST begin with this header:

### Markdown reports

```markdown
# Monethic AI Auditor

```
 mmm  mmm     mm      mmmmmm      mm
 ###  ###    ####     ""##""     ####
 ########    ####       ##       ####
 ## ## ##   ##  ##      ##      ##  ##
 ## "" ##   ######      ##      ######
 ##    ##  m##  ##m   mm##mm   m##  ##m
 ""    ""  ""    ""   """"""   ""    ""

        Monethic AI Auditor
```

**[Monethic](https://monethic.io)** — Smart contract security audit engine | Coded by [0xluk3](https://x.com/0xluk3)

---
```

### HTML reports

The HTML `<header>` must render the ASCII banner in a `<pre>` block (monospace), followed by:

```
Monethic AI Auditor
Powered by Monethic (https://monethic.io) | Coded by 0xluk3 (https://x.com/0xluk3)
```

With `Monethic` linking to `https://monethic.io` and `0xluk3` linking to `https://x.com/0xluk3`. The ASCII banner should use a small monospace font so it fits nicely (about 10 lines).

## Report sections (in order)

1. **Header** — Monethic AI Auditor branding (see above)
2. **Audit metadata** — platform, date, mode, detector count
3. **Scope** — from `./.maia_auditor/scope.md`: platform, file list with line counts, exclusions
4. **Executive Snapshot** — 2-3 sentence summary of findings
5. **Severity Summary** — table of finding counts by severity
6. **Validated findings** — sorted by severity descending
7. **Checklist Summary** — PASS/FAIL/UNKNOWN counts
8. **Triage breakdown** — valid/downgraded/dropped counts
9. **Prioritized Remediation** — ordered fix list
10. **Footer** — "For professional smart contract audits, contact [Monethic](https://monethic.io/contact)" with clickable link

## Scope section

Include the full scope from `./.maia_auditor/scope.md`:

```markdown
## Scope

**Platform:** EVM (Solidity)
**Files in scope:** 12
**Total lines:** 3,847

| File | Lines |
|------|-------|
| contracts/Token.sol | 245 |
| contracts/Vault.sol | 412 |
| ... | ... |

**Excluded:** tests/, contracts/mocks/
```

This section tells the reader exactly what code was reviewed.

## Finding structure template

```
[SEVERITY-##] Brief technical description of the issue

Description + Vulnerability Details
[1-2 sentences explaining the vulnerability - state the reason, cause, and direct effect without exaggeration]
[Technical explanation of how the vulnerability works, referencing specific functions and state variables. Keep factual and precise.] Should contain reason, cause and effect as a confluent part of the text.

[FOR HIGH/MEDIUM ONLY: Insert unmodified code snippet showing the vulnerable code]

Impact
[1-2 sentences describing the concrete impact. Be specific about what can happen, avoid vague terms.]

Recommendation
[1-2 sentences with specific technical fix. Reference exact changes needed.]
```

## Severity categories

- **Critical**: CVSS 9+ like catastrophic issue with high likelihood of fatal damage to the protocol or application.
- **High**: Direct risk to funds, authentication bypass, or system compromise
- **Medium**: Indirect financial impact, DoS conditions, or data integrity issues
- **Low**: Best practice violations, minor issues with limited impact
- **Informational**: Code quality issues, typos, gas optimizations

## Refinement rules

- **Extract core issue**: Identify the actual vulnerability from findings
- **Remove speculation**: Convert "could potentially" → state what actually happens
- **Titles**: Rewrite to sentence case — NOTE: Sentence case means no all uppercase and no every first letter uppercase. Just SENTENCE CASE.
- **Simplify language**: Replace complex vocabulary with technical precision
- **Code snippets**: Add relevant unmodified code for High/Medium findings
- **Consolidate**: ONLY merge if findings share the SAME file, SAME function, AND SAME root cause. Do NOT merge findings across different files or functions even if they look similar.
- **Verify claims**: Ensure all statements can be proven from the code
- **Standardize format**: Apply consistent structure to all findings

## Code references

ALWAYS use code formatting (backticks) for function names (without parentheses), file names, line numbers, variable names, and module/contract names.

File and line reference format: `filename.sol:line` or `filename.move:line` or `filename:start-end`

## Checklist status resolution

- Direct mapping via `finding.checklist_item_ids`
- Fallback via `finding.rule_id` intersection with `item.rule_ids`

Status assignment:
- **FAIL**: >=1 validated finding maps to the item
- **PASS**: No validated finding maps to the item
- **UNKNOWN**: Checklist unavailable or incomplete metadata

## Content standards

- **Do NOT drop or merge findings. If the verifier passed it as `valid` or `valid_downgraded`, it MUST appear in the report. Every single validated finding gets its own entry.**
- Exclude `false_positive` dropped findings only
- For `valid_downgraded`, show original and final severity with rationale
- Each finding: ID, file:line, severity, confidence, description, code excerpt (for High/Medium), recommendation

## Output

Read platform from `./.maia_auditor/platform.txt` to determine file prefix.
Read report directory from `./.maia_auditor/report_dir.txt` (e.g., `report_maia_20260317_143022`).

Generate 4 report files inside the report directory:

1. **`{report_dir}/{platform}_audit.md`** — Selected findings report (validated findings only, excludes `false_positive`)
2. **`{report_dir}/{platform}_audit.html`** — HTML version of selected findings with inline CSS styling
3. **`{report_dir}/{platform}_audit_full.md`** — Full findings report (all findings including `false_positive` and `valid_downgraded` with annotations)
4. **`{report_dir}/{platform}_audit_full.html`** — HTML version of full findings

Where `{platform}` is `evm`, `move_aptos`, or `move_sui`.

The HTML versions MUST use a **dark theme** with inline CSS. Use these exact styles:

```css
body {
  background-color: #1e1e1e;
  color: #e0e0e0;
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  max-width: 960px;
  margin: 0 auto;
  padding: 2rem;
  line-height: 1.6;
}
h1, h2, h3 { color: #ffffff; }
a { color: #64b5f6; }
pre, code {
  background-color: #0d1117;
  color: #c9d1d9;
  border: 1px solid #30363d;
  border-radius: 6px;
  padding: 0.2em 0.4em;
  font-family: 'Fira Code', 'Consolas', monospace;
}
pre { padding: 1rem; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #30363d; padding: 0.5rem 0.75rem; text-align: left; }
th { background-color: #2d2d2d; color: #ffffff; }
tr:nth-child(even) { background-color: #252525; }
hr { border: none; border-top: 1px solid #30363d; margin: 2rem 0; }
.badge { display: inline-block; padding: 0.2em 0.6em; border-radius: 4px; font-weight: bold; font-size: 0.85em; }
.badge-critical { background-color: #d32f2f; color: #fff; }
.badge-high { background-color: #e65100; color: #fff; }
.badge-medium { background-color: #f9a825; color: #000; }
.badge-low { background-color: #1565c0; color: #fff; }
.badge-info { background-color: #546e7a; color: #fff; }
.banner { color: #64b5f6; font-size: 0.75em; }
.footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #30363d; color: #888; font-size: 0.9em; }
```

Additional HTML requirements:
- ASCII banner in a `<pre class="banner">` block
- Each severity label wrapped in `<span class="badge badge-{severity}">`
- Header: "Monethic AI Auditor" with links to monethic.io and x.com/0xluk3
- Footer in `<div class="footer">`: "For professional smart contract audits, contact [Monethic](https://monethic.io/contact)" — clickable link
- All CSS must be inline in `<style>` tag within `<head>` — no external stylesheets

## Terminal output (terse mode)

```
Audit complete
Findings: total=<n> (Critical=<n> High=<n> Medium=<n> Low=<n> Info=<n>)
Triage: valid=<n> downgraded=<n> dropped=<n>

📋 Open report in browser:
file://{absolute_path}/{report_dir}/{platform}_audit.html

All reports in {report_dir}/:
  {platform}_audit.md
  {platform}_audit.html
  {platform}_audit_full.md
  {platform}_audit_full.html
```

IMPORTANT: The `file://` link MUST use the absolute path to the HTML report (e.g., `file:///home/user/project/report_maia_20260317_143022/evm_audit.html`). Resolve the working directory to an absolute path. This is the primary output the user sees — make it easy to click and open in a browser.
