---
name: phoenix
description: Phoenix Framework (Elixir) attack surface: LiveView socket abuse, Plug auth ordering, secret rotation
depends_on: []
---

# Phoenix

Phoenix is the dominant Elixir framework. LiveView introduces a stateful socket layer; auth assertions in mount functions can be bypassed by sending crafted events.

## Common Bug Classes

- LiveView event handlers without authorization checks
- Plug pipeline ordering: `:put_secret_key_base` after auth allowing forged tokens
- Channel topic subscription bypassing room-level authorization
- Verbose error pages in dev mode leaked to prod

## Probe Targets

- Open WebSocket to `/live/websocket` and inspect topic subscription
- Probe `/dev/`, `/dev/dashboard`, `/__debug__/`
- Look for `phoenix_live_view` chunks in JS

## Cross-References

`api_security`, `broken_function_level_authorization`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
