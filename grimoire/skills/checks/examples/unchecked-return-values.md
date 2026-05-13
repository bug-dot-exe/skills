# Example Check: Unchecked Return Values

A cross-language check demonstrating how the same concept maps to different patterns in C
and Go. Note: if the languages had very different assessment criteria, this should be split
into per-language checks.

## Check File

```markdown
---
name: unchecked return values
description: Flags function calls where error return values are ignored.
languages: [c, go]
severity-default: low
confidence: high
tools: [Grep, Read]
tags: [error-handling, reliability]
---

**C patterns:**
- Function calls whose return value is cast to `(void)` or not assigned
- Specifically: `close(`, `fclose(`, `write(`, `read(`, `malloc(` without NULL check

**Go patterns:**
- Error values discarded with blank identifier: `_, _ = someFunc()`
- Function calls without error capture where the function signature returns `error`

Not all unchecked returns are security-relevant. Prioritize:
1. Memory allocation (malloc, calloc) — adjust severity to high if unchecked
2. File/socket operations (read, write, close) — adjust severity to medium
3. Cleanup operations (close, free) — adjust severity to informational
```

## Why This Check Works

- **Cross-language with shared assessment.** Both C and Go share the same severity categories
  (allocation > I/O > cleanup). The patterns differ but the assessment logic is the same, so
  one check is appropriate.
- **When to split this instead.** If C needed different severity rules than Go (e.g., C
  unchecked malloc is critical because of null dereference, but Go has different failure
  modes), these should be separate checks with separate severity defaults.
- **High confidence.** The patterns are concrete and grep-able. Most matches are real unchecked
  returns — the question is severity, not validity.
