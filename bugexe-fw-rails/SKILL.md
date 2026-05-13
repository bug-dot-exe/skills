---
name: rails
description: Security testing playbook for Ruby on Rails covering strong params bypass, ActiveRecord injection, ERB SSTI, and credential management
depends_on: []
---

# Rails

Security testing for Ruby on Rails applications. Focus on secret_key_base compromise, mass assignment (strong params bypass), ERB/Slim template injection, ActiveRecord injection, Devise authentication weaknesses, asset pipeline leaks, and Action Cable authorization gaps.

## Attack Surface

**Secrets & Configuration**
- `secret_key_base`: signs/encrypts cookies, sessions, message verifiers, Active Storage URLs
- `config/credentials.yml.enc` (encrypted) + `config/master.key`
- `config/database.yml`, `config/storage.yml`, `.env` files
- Environment-specific configs: `config/environments/production.rb`

**Authentication & Authorization**
- Devise: registrations, sessions, confirmations, password resets, OmniAuth, rememberable, lockable
- Custom auth: `has_secure_password`, session-based, API tokens
- Authorization gems: Pundit (policies), CanCanCan (abilities)
- Action Policy, Rolify for role management

**Routing & Controllers**
- RESTful resources: `resources`, `resource`, nested routes, member/collection routes
- Constraints, namespaces, concerns
- Controller filters: `before_action`, `skip_before_action`, `prepend_before_action`
- `protect_from_forgery`: CSRF protection via authenticity tokens

**Data Layer**
- ActiveRecord: scopes, joins, `where()`, `find_by()`, `pluck()`, `order()`
- Raw SQL: `find_by_sql`, `execute`, `select`, `from`, Arel
- Strong Parameters: `require().permit()`, nested attributes, `permit!`

**Views & Templates**
- ERB: `<%= %>` (escaped), `<%== %>` or `raw()` (unescaped), `html_safe`
- Slim/Haml: interpolation and raw output modes
- Action View helpers: `link_to`, `image_tag`, `content_tag` with user input
- Turbo/Hotwire: Turbo Streams, Turbo Frames with server-side rendering

**Real-Time**
- Action Cable: WebSocket channels, authorization in `subscribed`, broadcasts
- Turbo Streams over Action Cable

**File Handling**
- Active Storage: direct uploads, service URLs, variants, mirror storage
- Paperclip/CarrierWave (legacy): file processing, path generation
- Asset Pipeline / Webpacker / Propshaft: compiled assets

## High-Value Targets

- `/rails/info/routes` (development route listing)
- `/rails/info/properties` (Rails version, environment info)
- `/rails/mailers` (mailer previews in development)
- `/admin`, `/admin/dashboard` (common admin panel paths)
- `config/master.key`, `config/credentials.yml.enc` in source/deployments
- Devise endpoints: `/users/sign_in`, `/users/password/new`, `/users/confirmation`
- Active Storage URLs: `/rails/active_storage/blobs/`, `/rails/active_storage/representations/`
- Action Cable mount: `/cable`
- Sidekiq web UI: `/sidekiq`
- Letter Opener: `/letter_opener` (development email viewer)

## Reconnaissance

**Rails Detection**
- `X-Request-Id` and `X-Runtime` response headers
- Cookie names: `_session_id`, `_app_session`
- CSRF meta tags: `<meta name="csrf-token" content="..."/>`
- Default 404/500 error pages with Rails styling

**Debug/Development Endpoints**
```
GET /rails/info/routes
GET /rails/info/properties
GET /rails/mailers
GET /rails/conductor/action_mailbox/inbound_emails
GET /sidekiq
GET /letter_opener
GET /assets/application.js
```

**Route Enumeration**
- Development route listing exposes all paths, HTTP methods, controller#action mappings
- Production: fuzz based on RESTful conventions (`/resources`, `/resources/:id`, `/resources/:id/edit`)
- Inspect JavaScript bundles for API paths and route helpers

## Key Vulnerabilities

### Secret Key Base Exposure

**Impact**
- `secret_key_base` encrypts/signs: session cookies, CSRF tokens, encrypted credentials, Active Storage URLs, Action Cable identifiers
- With key: forge sessions (admin access), generate valid CSRF tokens, decrypt credentials file
- Session cookie deserialization: Rails < 7 with Marshal serializer enables RCE via gadget chains

**Exposure Vectors**
- `config/master.key` committed to git or accessible via file read
- Environment variable leaks in error pages, CI/CD logs, Docker images
- `config/secrets.yml` (deprecated but may still exist) in plain text
- Heroku/PaaS config vars visible in admin panels

### Mass Assignment (Strong Params Bypass)

**Permit! Abuse**
```ruby
# Dangerous: permits all attributes
params.require(:user).permit!

# Insufficient: missing role/admin fields
params.require(:user).permit(:name, :email)  # But model has :is_admin, :role
```

**Nested Attributes**
```json
{
  "user": {
    "name": "attacker",
    "profile_attributes": { "admin_notes": "escalated" },
    "role_ids": [1]
  }
}
```
- `accepts_nested_attributes_for` with insufficient permit filtering
- Association IDs (`role_ids`, `team_ids`) permitted but not authorized
- `_destroy` parameter for nested records enabling unauthorized deletion

**Bypass Techniques**
- Different content types: JSON vs form-encoded may hit different permit paths
- API vs web controllers with different strong params definitions for the same model
- `update_columns` / `update_column` bypassing callbacks and validations

### ActiveRecord Injection

**String Interpolation in Queries**
```ruby
User.where("name = '#{params[:name]}'")              # SQL injection
User.where("role = ?", params[:role])                 # Safe (parameterized)
User.order(params[:sort])                             # Column injection
User.pluck(params[:field])                            # Column injection
User.select(params[:columns])                         # Select injection
User.from(params[:table])                             # Table injection
User.where(params[:conditions])                       # Hash injection
```

**Hash Condition Injection**
```ruby
# User-controlled hash to where()
User.where(params.permit(:name, :email).to_h)
# Attacker sends: { "password_digest.startswith" => "..." }
```

**Arel/Raw SQL**
```ruby
User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
ActiveRecord::Base.connection.execute("DROP TABLE users")
```

### ERB/Slim Template Injection

**Unescaped Output**
```erb
<%== user_input %>
<%= raw(user_input) %>
<%= user_input.html_safe %>
<%= content_tag(:div, user_input.html_safe) %>
```

**Server-Side Template Injection**
```ruby
# If user input reaches ERB.new or template compilation
ERB.new(user_input).result(binding)
```
Exploitation: `<%= system('id') %>`, `<%= File.read('/etc/passwd') %>`

**Indirect XSS**
- `link_to` with user-controlled URL: `javascript:` protocol
- `image_tag` / `stylesheet_link_tag` with user-controlled paths
- Turbo Stream responses with user-controlled HTML

### Devise Authentication

**Password Reset Poisoning**
- Host header injection: `Host: attacker.com` in password reset request
- Reset token in URL: leaked via Referer header to third-party resources
- Token reuse: verify tokens are single-use and time-limited

**Enumerable Accounts**
- Registration: different response for existing vs new email
- Password reset: timing or response differences revealing account existence
- Confirmation: resend endpoint disclosing registered emails

**OmniAuth Vulnerabilities**
- CSRF on OAuth callback (missing state parameter verification)
- Account linking without email verification
- Open redirect via callback URL manipulation

**Session Management**
- Rememberable token: predictability, scope, invalidation on password change
- Lockable: account lockout without notification enables silent brute force
- Timeoutable: session timeout enforcement on all paths

### Asset Pipeline Leaks

**Source Maps**
- `.map` files in production revealing full source code
- `assets/application.js.map`, `packs/application.js.map`

**Compiled Assets**
- CoffeeScript/TypeScript source in compiled bundles
- Environment-specific code branches visible in production bundles
- API keys, internal URLs, feature flags in JavaScript bundles

### Action Cable Authorization

**Missing Channel Auth**
```ruby
class ChatChannel < ApplicationCable::Channel
  def subscribed
    stream_from "chat_#{params[:room_id]}"  # No ownership check
  end
end
```

- Connection-level auth (in `ApplicationCable::Connection`) but no channel-level checks
- `stream_from` with user-controlled parameters enabling cross-tenant data access
- Broadcast actions without per-message authorization

### CSRF Issues

**skip_before_action :verify_authenticity_token**
- Applied to API controllers but those controllers also accept session cookies
- `protect_from_forgery with: :null_session` vs `:exception` behavior differences
- Turbo/Hotwire: CSRF token handling in Turbo Stream requests

## Bypass Techniques

- Content-type switching: `application/json` may bypass CSRF checks on older Rails
- Route constraint bypass: case sensitivity, trailing slashes, format extensions (`.json`, `.xml`)
- `skip_before_action` on specific actions removing auth filters inherited from parent controller
- Method override via `_method` parameter or `X-HTTP-Method-Override` header
- Active Storage signed URLs: expired or manipulated blob IDs

## Testing Methodology

1. **Secrets discovery** - Probe for `master.key`, `secrets.yml`, environment variable leaks in errors
2. **Debug endpoints** - Check `/rails/info/routes`, `/rails/mailers`, `/sidekiq`, `/letter_opener`
3. **Mass assignment** - Send extra attributes on create/update; test nested attributes and association IDs
4. **SQL injection** - Identify string interpolation in queries; test order/select/pluck with user input
5. **Template injection** - Search for `raw()`, `html_safe`, `<%== %>`; test SSTI in dynamic templates
6. **Auth boundaries** - Test Devise flows (reset, confirm, OmniAuth); check `skip_before_action` gaps
7. **Action Cable** - Test channel subscriptions with foreign IDs; verify per-channel authorization
8. **Asset audit** - Check for source maps, bundled secrets, internal URLs in compiled assets

## Corpus-Derived Attack Patterns

### PATCH-Then-Promote Workflow Bypass
Multi-step approval workflows (apply, pending, admin approves) are vulnerable to direct state manipulation:
1. Enumerate all REST verbs on approval-workflow resources (`PATCH /resource/:id`, `PUT /resource/:id`)
2. Test mass assignment on status/state fields: `{"status": "approved", "verified": true}`
3. Check if PATCH endpoint accepts fields that should only be writable during the admin approval step
4. `assign_attributes` or `update` with user-supplied JSON/YAML is vulnerable unless strong params explicitly exclude state-transition fields
5. Test both JSON and form-encoded content types -- they may hit different strong params definitions

### Error Message Schema Disclosure
Rails verbose error messages systematically leak internal schema:
- Submit invalid data types to every parameter and examine error responses
- Errors reveal: parameter names accepted by the model, expected types, column names, relationship names
- `ActiveRecord::RecordInvalid` messages expose validation rule structure
- `ActionController::UnpermittedParameters` in development mode lists all attempted extra parameters
- Use disclosed schema to craft mass assignment and injection payloads

### Sanitizer Parser-Differential XSS
Rails HTML sanitizers are bypassed via parser disagreement between the sanitizer and the browser:
1. Identify which parser the sanitizer uses (Nokogiri CRuby vs JRuby, Loofah)
2. Test foreign content tags (`<svg>`, `<math>`) that trigger different HTML5 parsing modes
3. `<select>` + `<style>` combinations: Nokogiri and browser parse these differently
4. `data:` URI content injection on allowlisted tags -- test `href`, `src`, `action` attributes
5. Patch-sibling auditing: when a sanitizer CVE is fixed, test every other call site exercising the same sanitization logic -- patches are often incomplete

### Discriminator-Field Privilege Scanning
Rails apps with shared endpoints handling multiple resource types:
1. Identify shared endpoints (`/issues` handling Issue, TestCase, Incident via `type` or `kind` parameter)
2. Test if permission checks are per-resource-type or only per-endpoint
3. Guest/low-privilege users may be allowed to create one type but the endpoint does not check the discriminator field
4. Send `{"type": "TestCase"}` on an endpoint where the user can create Issues but not TestCases

### Gem-Defined Dynamic Setter SSRF
Rails gems define dynamic attribute setters that accept URLs processed server-side:
1. List every model attribute defined by gems (ActiveStorage, Paperclip, CarrierWave, `remote_*_url` patterns)
2. For each URL-accepting attribute, test: direct internal URLs, DNS rebinding, redirect chains
3. `remote_attachment_url`, `remote_avatar_url`, `remote_image_url` are common SSRF surfaces
4. Import/export features using gem-defined URL attributes: the URL is fetched server-side during model save
5. Test redirect-following behavior: direct internal URL blocked, but redirect from allowed domain to internal target succeeds

### Verb-Asymmetric Authorization
Rails authorization often enforces permissions inconsistently across CRUD verbs for the same resource:
1. For every restricted action (webhooks, API keys, team settings), confirm the restriction on the triggering verb (POST/create)
2. Test sibling verbs: if POST is restricted, check PUT/PATCH (edit), DELETE (destroy), GET (show) for the same resource
3. `skip_before_action` on specific actions may remove auth filters inherited from the parent controller
4. When a finding lands at `POST /resource/action_A`, immediately test `POST /resource/action_B`, `PATCH /resource/action_A`, `DELETE /resource/action_A`

### Token Timing Attack on find_by
Rails apps using `find_by` with secret tokens are vulnerable to timing-based brute force:
- `Model.find_by(token: params[:token])` does string comparison at the database level
- Database string comparison may have timing side-channels on partial matches
- Batch array injection: `Model.where(token: params[:tokens])` with array parameter tests multiple tokens per request
- `confirmation_token`, `reset_password_token`, `unlock_token` in Devise are common targets
- Rate limiting on the endpoint counts requests, not tokens-per-request when arrays are accepted

### Destructive-Action IDOR
Destructive endpoints in Rails apps frequently lack ownership checks:
- Map all destructive verbs: `/wipe`, `/delete`, `/revoke`, `/cancel`, `/disable`, `/expire`, `/lock`
- These are often added later (after initial CRUD) and inherit less rigorous authorization
- `before_action :authenticate_user!` confirms login but not resource ownership
- Test: substitute another user's resource ID in the destructive action URL
- Remote wipe, session revocation, and API key deletion are highest-impact targets

## Validation Requirements

- Secret key: forged session cookie accepted by server (privilege escalation demonstrated)
- Mass assignment: privileged attribute (admin, role) persisted via create/update endpoint
- SQL injection: data extraction or error-based proof of query manipulation
- Template injection: server-side code execution or sensitive data extraction
- Devise bypass: account takeover via reset poisoning, OAuth CSRF, or enumeration
- Action Cable: unauthorized subscription receiving another user/tenant's broadcast data
- Asset leak: source map or compiled bundle exposing secrets, keys, or internal paths
