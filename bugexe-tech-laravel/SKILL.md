---
name: laravel
description: Laravel attack surface: APP_KEY reuse → RCE, Telescope exposure, mass assignment, queue payload tampering
depends_on: []
---

# Laravel

Laravel is the dominant PHP framework. Single most damaging bug: leaked `APP_KEY` (encrypts session cookies → forge session → impersonate any user; in older versions, deserialize → RCE).

## Common Bug Classes

- `APP_KEY` leak via `.env`, `phpinfo()`, debug pages → session forgery / RCE
- Telescope (`/telescope/`) exposed in prod showing all requests + queries
- Eloquent mass assignment via `$model->fill($request->all())` without `$fillable`
- Queue worker deserialization of attacker-controlled `payload` field
- Ignition debug page (`/_ignition/execute-solution`) — RCE in older Laravel
- Verbose validation errors leaking schema

## Probe Targets

- Probe `/.env`, `/phpinfo`, `/_ignition/health-check`
- Probe `/telescope/`, `/horizon/`
- Send full nested arrays in JSON to test mass assignment
- Check Laravel version (`<header X-Powered-By>` or comments) for known CVEs

## Cross-References

`mass_assignment`, `insecure_deserialization`, `information_disclosure`, `session_security`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
