---
name: tech-rails
description: Ruby on Rails attack surface: deserialization (cookies/marshal), strong-parameters bypass, ActiveStorage SSRF
depends_on: []
---

# Rails

Rails relies on convention. `secret_key_base` reuse leads to session forgery (and historically RCE via marshalled cookies). Strong Parameters is opt-in per-controller — easy to forget.

## Common Bug Classes

- `secret_key_base` leak via `secrets.yml` or env exposure → session forgery
- Marshal deserialization in older cookie stores → RCE
- Strong Parameters bypass: nested `params.require(:user).permit(:name, role: {})` permits hash injection
- ActiveStorage SSRF via image-proxy URLs
- Mass assignment via `update_attributes(params)` (legacy)
- ERB SSTI in template strings concatenating user input

## Mass Assignment & PATCH-then-Promote

The highest-bounty Rails pattern ($50K+). When a service has multi-step approval workflows:

1. Enumerate all REST verbs on every resource (GET/POST/PUT/PATCH/DELETE)
2. Find endpoints accepting partial updates (PATCH especially)
3. Test adding privileged fields to PATCH body: `role`, `admin`, `verified`, `status`, `approved`
4. For multi-state objects (orders, KYC, ads, role assignments): test mass assignment at each state transition

**ORM setter injection:** Any Rails app accepting user-supplied JSON/YAML and calling `assign_attributes` (or equivalent) is vulnerable unless it uses strict `permit()`:

```ruby
# Vulnerable pattern — permits arbitrary nested hash
params.require(:user).permit(:name, metadata: {})

# Test: inject privileged fields via the permitted hash
PATCH /users/123 {"metadata": {"role": "admin"}}
```

## Sanitizer Bypass Patterns

Rails ships HTML sanitizers that are recurring XSS bypass targets:

- **Parser-differential:** List the parser the sanitizer uses (Nokogiri CRuby vs JRuby), then test content that parses differently between sanitizer-parse and browser-parse
- **Mode-changing tags:** `<svg>`, `<math>`, `<xmp>`, `<noscript>` switch the HTML5 parser into foreign content mode where different rules apply
- **`data:` URI injection:** For each allowlisted tag, test `data:text/html,<script>` in `href`/`src`/`action` attributes
- **Patch-sibling auditing:** When a sanitizer CVE is patched, find every other call site that exercises the same logic path with different input shapes

## Dynamic Setter SSRF

Gem-defined dynamic setters on models that flow through deserialization are SSRF gadgets:

1. List every model that accepts URL-typed attributes (`remote_*_url`, `source_url`, `attachment_url`)
2. Identify which attributes trigger server-side fetches (ActiveStorage, Carrierwave, Shrine)
3. Test with internal URLs: `http://169.254.169.254/`, `http://localhost:3000/admin/`
4. Check if import/export features (project import, CSV import) process URLs server-side

## Secret Token Auditing

When the obvious token is hardened, audit every other token signed by the same key:

- Rails uses a single `secret_key_base` for sessions, message verifiers, encrypted credentials, and signed URLs
- If the session cookie is JWT or properly rotated, check: password reset tokens, API tokens, signed ActiveStorage URLs, ActionText signed blobs
- Default/static signing key → forged sessions: check `config/secrets.yml`, `config/credentials.yml.enc`, leaked `RAILS_MASTER_KEY`

## Authorization Sweep Patterns

**Verb-asymmetric authorization:** For every restricted action on a resource:
1. Confirm the restriction on the action that triggers it
2. Test every OTHER verb on the SAME resource (`POST /resource` protected? Try `PATCH`, `DELETE`, `PUT`)
3. Test sibling endpoints: finding at `POST /resource/verb_A`? Immediately test `/resource/verb_B`, `/resource/verb_C`

**Discriminator-field scanning:** For shared endpoints handling multiple resource types:
1. Identify endpoints where different object types share the same route (`/issues` handling Issues + TestCases)
2. Test if permission checks are per-type or per-route
3. Submit requests as a lower-privilege role, changing the `type` parameter

## Error Message Schema Disclosure

Rails APIs with verbose error messages can reveal:
- Parameter names not documented in the API (`unknown attribute 'internal_field'`)
- Valid values for enum fields (`'status' must be one of: draft, pending, approved`)
- Internal model relationships via ActiveRecord error messages
- SQL structure via raw database errors when `rescue_from` is incomplete

## Timing-Based Token Attacks

For Rails apps using `find_by` with secret fields:

```ruby
# Vulnerable: string comparison timing leak
User.find_by(confirmation_token: params[:token])
```

1. Grep for `find_by(secret_field: params[...])`, `where(field: params[...]).first`
2. Test with batch requests varying one character at a time
3. Measure response time to infer correct characters
4. Check rate limiting on token-consuming endpoints

## Probe Targets

- Decode session cookie (default `_yourapp_session`); look for marshalled vs JSON serializer
- Test all controller params for nested-hash/array injection of privileged fields
- Probe `/rails/active_storage/disk/*` for SSRF
- Check `/rails/info/properties` and `/rails/info/routes`
- Test debug-mode paths: `/rails/info/`, `/rails/mailers/`
- Enumerate `*.json` and `*.xml` format variants on every endpoint
- Check for exposed `Gemfile.lock` revealing exact dependency versions

## Destructive-Action IDOR Mapping

Any endpoint with a destructive verb is a high-priority IDOR target:

- Map all `/wipe`, `/delete`, `/revoke`, `/cancel`, `/disable`, `/expire`, `/lock` endpoints
- Test each with another user's resource ID
- Destructive IDORs are often higher severity because the damage is irreversible
- Check `/remote_wipe`, `/device/delete`, `/session/revoke` endpoints specifically

## CLI Wrapper Command Injection

Rails apps that wrap CLI tools (ImageMagick, ffmpeg, wkhtmltopdf) via convenience APIs:

1. Map every wrapper API to its underlying CLI flags
2. Check if parameters can inject flags: `filename=--config=/etc/passwd`
3. Test Active Storage variants that pass user input to image processing
4. Check `send_file` / `send_data` for path injection

## Cross-References

`mass_assignment`, `ssrf`, `insecure_deserialization`, `session_security`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
- For mass assignment: show the privileged field actually changes server state, not just echoes back
- For SSRF: demonstrate server-side fetch with timing or out-of-band callback
