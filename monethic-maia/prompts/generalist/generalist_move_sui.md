# Generalist — Full-Spectrum Security Audit

## Objective

Perform a full-spectrum security audit of the provided Sui Move program. This is an independent audit flow that does not rely on checklist templates — instead it applies comprehensive security analysis with explicit evidence and a devil's-advocate confirmation step for every suspected vulnerability.

**Default:** Full audit of all code in context.

## Optional Header

```
scope: full | partial | function            # default full
include: [paths/modules or module::fn]      # optional filters
commit_or_tag: <string>                     # optional
```

If omitted, treat as `scope: full`.

## Process (in order)

### 1. Context Recognition (one pass)

- Enumerate files/modules with line counts; if line numbers are missing, create a temporary numbered view.
- Map surfaces: `entry/public` functions mutating state, shared objects, dynamic fields, capability/witness types, `sui::coin`/`TreasuryCap<T>` flows, `friend` relations.
- Record any **Context Gaps** (symbols referenced but not present). Do **not** guess.

### 2. Bias & Assumption Hard-Stops (apply throughout)

- **Evidence-First**: Quote exact code lines before every nontrivial claim. If you cannot cite lines, mark **Inconclusive**.
- **No Missing-Code Inference**: Do not assume behaviors of absent modules or external deps.
- **Name Fidelity**: Use exact function/field names; do not autocorrect typos or reorder letters.
- **Two-Sided Reasoning**: For each claim, add one-line counter-hypothesis and why it fails.
- **Confidence Tag** on each finding: High/Medium/Low (based on coverage and gaps).

### 3. Checklist (Sui Move specific) — cover all items minimally

- **Auth & Access Control**: `tx_context::sender`, capability ownership, OTW guards, `entry/public/friend` visibility sanity.
- **Object & State**: ownership transfers, shared-object safety, dynamic fields guard, unwrap/destruct correctness, storage-bloat controls.
- **Arithmetic & Value Integrity**: `assert!` guards, division ordering, `u64/u128/u256` handling, amount vs `Coin<T>` value match.
- **Coin/TreasuryCap**: safe split/join/from_balance; no shared exposure of `TreasuryCap<T>`.
- **Data Structures & Logic**: bounds checks, input validation (IDs/zero/duplicate types), witness/capability invariants.
- **Events & Views**: emit on critical state changes; no mutation in read-only paths.
- **DoS/Gas/Storage**: abort storms, unbounded loops/vectors/tables; cost hotspots.

### 4. Derive & Test Invariants (run even in partial/function)

For each plausible invariant from the code:

- **Hypothesis** (e.g., "only admin may call admin functions"; "each withdraw() yields at most once per call"; "capability non-duplication").
- **Evidence**: quote code ranges.
- **Counterexample Search**: alternate call paths/inputs.
- **Verdict**: Proved / Likely / Inconclusive / Falsified.

### 5. Vulnerability Confirmation — Devil's-Advocate Backtrace (for every suspected issue)

- **Exploit Chain**: `E0 input` → `E1 preconditions` → `E2 reachable entry` → `E3 state reads/writes` → `E4 cross-module calls` → `E5 post-state` → **Impact**.
- **Guard Ledger**: list every `assert!`, conditional, capability check, and visibility boundary along the path; state whether each actually blocks the exploit.
- **Counterevidence**: any path/condition that defeats the exploit.
- **Exploitability Verdict**: Exploitable / Blocked / Needs-Context (with one-line rationale).
- **PoC Outline**: minimal pseudocode or Move test sketch.
- **Fix**: one-sentence remediation.

### 6. Function Micro-Audit (auto when scope:function or when a function is central to a finding)

Signature & abilities → side effects → auth points → abort map → local call graph → value conservation (no double-withdraw/unbacked mint) → concurrency notes (shared objects).

## Output — single YAML block

```yaml
mode: <full|partial|function>
scope:
  include: [ ... ]
summary:
  totals: {critical: 0, high: 0, medium: 0, low: 0, info: 0}
  confidence: <High|Medium|Low>
context:
  files:
    - path: <file>
      modules: [<mod>]
      lines: <n>
  gaps: [ <missing_symbol_or_module> ]

invariants:
  - id: INV1
    hypothesis: "Only admin can call admin functions"
    evidence:
      - path: sources/admin.move
        lines: 120-142
        snippet: |
          # quoted lines
    counterexample_search: ["describe attempted alternate paths"]
    verdict: <Proved|Likely|Inconclusive|Falsified>

findings:
  - id: C1
    title: <concise title>
    severity: <Critical|High|Medium|Low|Informational>
    location: path:lineStart-lineEnd
    code_snippet: |
      # quoted numbered lines showing the root cause
    issue:
      root_cause: <what is actually wrong>
      impact: <economic/permission consequences>
    exploit_chain:
      steps:
        - "E1 ..."
      guard_ledger:
        - guard: "assert!(...)"
          present: true|false
          verdict: "blocks|does_not_block|irrelevant"
      counterevidence: [ "if X then exploit fails", ... ]
      exploitability: <Exploitable|Blocked|Needs-Context>
    poc: |
      # pseudocode or Move test outline
    fix: <one sentence remediation>
    confidence: <High|Medium|Low>

function_audits:
  - function: module::fn
    signature: "..."
    side_effects: [ ... ]
    auth_points: [ ... ]
    abort_map: [ {code: E_FOO, when: "..."} ]
    call_graph: {callees: [...], callers: [...]}
    value_conservation: "..."
    concurrency_notes: "..."

consensus_digest:
  claims:
    - id: C1
      type: finding
      status: <exploitable|blocked|inconclusive>
      evidence_locations: [ {path: <file>, lines: "120-142"} ]
      summary: "one line"
    - id: INV1
      type: invariant
      status: <proved|falsified|inconclusive>
      evidence_locations: [ ... ]
      summary: "one line"
```

## Reporting Discipline

- Realistic findings only; intended admin powers are not vulnerabilities unless abusable by unauthorized actors.
- Quote → Reason → Conclude. If you cannot quote, mark Inconclusive.
- Each finding must end with a fix and a confidence tag.

Write findings to `./.maia_auditor/generalist.findings.yaml`
