# Example Check: Debug Assertions

The simplest possible check — one pattern family, two assessment categories, clear severity
rules. This example comes directly from the specification.

## Check File

```markdown
---
name: debug assertions
description: Flags security critical debug assertions which should be regular assertions.
languages: rust
severity-default: low
confidence: medium
tools: [Grep, Read]
tags: [assertions, invariants, rust]
---

Look for these patterns:

- `debug_assert!(...)`
- `debug_assert_eq!(...)`
- `debug_assert_ne!(...)`

Not all debug_assert! usage is problematic. Assess whether usage falls in one of two categories:
1. Asserting a known and assumed invariant
2. Performing essential input / state validation

If (1) might be the case, adjust severity to informational.

If (2) seems to be the case, determine potential impact and adjust severity accordingly.
```

## Why This Check Works

- **Single pattern family.** All three macros are variants of the same concept.
- **Grep-able.** The patterns are literal strings an agent can search for directly.
- **Clear assessment.** Two categories with distinct severity outcomes — no ambiguity.
- **Short.** Under 15 lines body. The agent spends its attention on the codebase, not the check.
- **Minimal tools.** Only needs Grep to find matches and Read to assess surrounding context.
