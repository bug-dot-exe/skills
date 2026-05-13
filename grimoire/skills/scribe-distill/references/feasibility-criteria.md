# Automation Feasibility Criteria

Guide for determining whether a confirmed finding can be encoded as automated detection and
which approach to use.

## Static Analysis (strongly preferred)

The pattern is **static-feasible** when:

- **Syntactic match:** The vulnerability involves a specific function call, keyword, import,
  or literal that can be grepped for directly. Examples: `debug_assert!` instead of `assert!`,
  `transfer()` before state update, `eval()` with user input.
- **Structural match:** The vulnerability involves a code shape that can be identified by AST
  pattern matching (function signature shape, modifier absence, inheritance pattern). Even if
  not grep-able, tools like semgrep can match these.
- **Low ambiguity:** Most matches of the search pattern are real issues, not benign uses. If
  the pattern has many benign matches, consider adding context constraints to narrow it.

Estimated false positive rate for static patterns should be under 20%. If higher, narrow the
detection or fall back to agentic.

## Agentic Check (fallback)

The pattern is **agentic-feasible** when:

- **Grep-able but context-dependent:** The pattern involves a searchable indicator (function
  call, import, annotation) but each match requires reading surrounding context to determine
  if it is a real issue. Example: `external` calls in Solidity are grep-able, but whether each
  constitutes a reentrancy risk depends on state update ordering.
- **Multi-file assessment:** Determining vulnerability requires checking 2-3 related files
  (e.g., interface vs implementation, config vs usage).
- **Severity depends on context:** The same code shape might be Critical in one context and
  Informational in another, requiring the agent to assess impact.

Agentic checks should still have concrete grep patterns as starting points. The assessment
section provides the reasoning framework the applying agent follows.

## Not Automatable (knowledge artifact)

The pattern is **not automatable** when:

- **Business logic dependency:** Understanding whether the code is vulnerable requires knowing
  the intended business rules, which are not expressed in code. Example: "the fee calculation
  is wrong" requires knowing the intended fee structure.
- **External state dependency:** Exploitation depends on oracle prices, off-chain state,
  governance decisions, or runtime configuration not visible in the source.
- **Full-codebase reasoning:** The vulnerability emerges from the interaction of many
  components and cannot be reduced to a local pattern. Example: "the protocol is economically
  exploitable via flash loans" requires understanding the full token flow.
- **One-off design flaw:** The issue is unique to this specific system's design choices and
  has no generalizable pattern.

For these, create a knowledge artifact: a reference document that describes what to look for
in natural language so the researcher remembers to investigate this class of issue in future
audits.

## False Positive Estimation

When proposing a detection approach, estimate the expected false positive rate:

| Rate   | Meaning | Action |
|--------|---------|--------|
| Low    | <5% of matches are benign  | Strong candidate for automation |
| Medium | 5-20% of matches are benign | Acceptable with assessment criteria |
| High   | >20% of matches are benign  | Narrow the pattern or downgrade to knowledge artifact |

A high-FP detection module wastes more researcher time than it saves. When in doubt, narrow
the detection pattern at the cost of missing some true positives.
