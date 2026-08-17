---
name: iis
description: Microsoft IIS attack surface: short-name disclosure, ASP.NET fallback, virtual directory abuse
depends_on: []
---

# Iis

IIS is enterprise Windows web server. Distinct bugs: 8.3 short-name disclosure (`~`), ASP.NET fallback handling, virtual directory traversal, WebDAV when accidentally enabled.

## Common Bug Classes

- 8.3 short-name disclosure via tilde requests: `/A~1.aspx`
- ASP.NET fallback route exposing `.cs` source files
- WebDAV enabled allowing PUT of .aspx for RCE
- IIS short-name → full-name brute force
- Trace.axd, ELMAH, debug.aspx exposed

## Probe Targets

- Probe `/A~1`, `/B~1.aspx`, `/A~1.css`
- Test `OPTIONS *` for WebDAV verbs
- Probe `/elmah.axd`, `/Trace.axd`

## Cross-References

`information_disclosure`, `path_traversal_lfi_rfi`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
