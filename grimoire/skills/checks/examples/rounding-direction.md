# Example Check: Rounding Direction (1 of 2)

This example demonstrates check splitting. The rounding vulnerability class is split into
two independent checks, each with focused reasoning. This check handles identification;
`rounding-inflation-attack.md` handles assessment of one specific exploitation path.

## Check File

```markdown
---
name: rounding direction
description: Identifies rounding operations and determines whether rounding favors the protocol.
languages: solidity
severity-default: informational
confidence: high
tools: [Grep, Read]
tags: [rounding, math, defi]
related-checks: [rounding-inflation-attack]
---

Look for these patterns:

- Division operations followed by multiplication (precision loss)
- Usage of `mulDiv`, `mulDivUp`, `mulDivDown` or similar helpers
- Explicit rounding: `Math.ceil`, `Math.floor`, `roundUp`, `roundDown`
- Integer division where the remainder is discarded

For each match:
1. Determine the rounding direction (up or down)
2. Determine who benefits from the rounding (protocol or user)
3. If rounding favors the user over the protocol, adjust severity to low

Do NOT assess exploitability here. That is handled by related checks.
```

## Why This Check Is Split

The spec discusses rounding as a case where splitting is essential:

- **Identification is easy, assessment is hard.** Finding rounding operations is a grep-able
  task with high confidence. Assessing whether rounding is exploitable requires deep reasoning
  about vault mechanics, deposit flows, and economic incentives.
- **Most rounding is benign.** Even rounding in the wrong direction is usually harmless. An
  agent that tries to assess both identification and exploitation in one pass will either
  skip important assessment steps (attention exhaustion) or over-report false positives.
- **Severity differs.** This scanning check defaults to informational because mere rounding is
  not a finding. The assessment check (rounding-inflation-attack) defaults to high because if
  the conditions are met, the impact is significant.
