---
name: flask
description: Flask attack surface: SSTI in Jinja2, weak session signing, debug PIN brute, blueprint scoping
depends_on: []
---

# Flask

Flask is minimal — security relies on developer choices. Jinja2 SSTI is the iconic Flask bug; `{{config}}`/`{{request}}`/`{{ ''.__class__.__mro__ }}` chains lead to RCE.

## Common Bug Classes

- Jinja2 SSTI via `render_template_string(user_input)`
- Weak `SECRET_KEY` allowing session forgery
- Werkzeug debug console reachable in prod (`/console`) — PIN bruteable
- Blueprint URL prefix leakage exposing internal routes
- Disabled CSRF via missing Flask-WTF on POST forms

## Probe Targets

- Test `{{7*7}}` and `${7*7}` in any reflected input
- Probe `/console`, `/-/console`, `/__debugger__/`
- Decode session cookies (Flask uses URL-safe base64) and check `_id` / `csrf` claims

## Cross-References

`ssti`, `session_security`, `csrf`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
