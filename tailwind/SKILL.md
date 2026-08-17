---
name: tailwind
description: Tailwind CSS attack surface: arbitrary value injection, JIT compiler RCE (build-time), purge gaps
depends_on: []
---

# Tailwind

Tailwind is utility-first CSS. Runtime bug surface is small. Build-time JIT compiler accepting user-controlled class names CAN execute Node.js (config functions) — usually only in dev.

## Common Bug Classes

- JIT-mode arbitrary value `[<expression>]` accepting CSS injection
- Purge / safelist gaps shipping unintended utility classes
- Plugin functions accepting build-time input from CMS

## Probe Targets

- Inspect Tailwind class names in HTML for arbitrary values
- Test class injection via user-content fields

## Cross-References

`xss`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
