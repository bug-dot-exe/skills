---
name: bootstrap
description: Bootstrap attack surface: data-* attribute injection, tooltip XSS, version-specific CVEs
depends_on: []
---

# Bootstrap

Bootstrap is CSS+JS components. Bug surface: data-* attribute injection (rendered as HTML), tooltip/popover XSS via `data-bs-content`, older versions with dompurify gaps.

## Common Bug Classes

- Tooltip/popover XSS via `data-bs-content` containing HTML
- Bootstrap <4.3 carousel data-* XSS
- Modal `data-target` allowing arbitrary selector

## Probe Targets

- Identify Bootstrap version from CSS comments
- Test injecting `data-bs-toggle="tooltip" data-bs-html="true" title="<img src=x onerror=alert(1)>"`

## Cross-References

`xss`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
