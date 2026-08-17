---
name: jquery
description: jQuery attack surface: CVE-rich versions, $.html/$.append XSS, JSONP abuse
depends_on: []
---

# Jquery

jQuery is legacy but everywhere. Older versions (<3.5) have known XSS in `.html()`. JSONP usage opens the page to arbitrary script execution from the JSONP endpoint.

## Common Bug Classes

- CVE-2020-11022/11023 — `.html()` XSS in jQuery <3.5
- `$.parseHTML(userInput)` rendering HTML from URL params
- `$.ajax({dataType:'jsonp'})` accepting attacker-controlled callback
- Older versions with `$.extend(true, target, userInput)` prototype pollution

## Probe Targets

- Identify jQuery version (`window.jQuery.fn.jquery`) and check CVE list
- Search bundle for `$.parseHTML`, `$.html`, dataType: jsonp

## Cross-References

`xss`, `prototype_pollution`, `information_disclosure`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
