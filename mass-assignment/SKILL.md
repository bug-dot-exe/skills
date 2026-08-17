---
name: mass-assignment
description: Mass assignment testing for unauthorized field binding and privilege escalation via API parameters
depends_on: []
---

# Mass Assignment

Mass assignment binds client-supplied fields directly into models/DTOs without field-level allowlists. It commonly leads to privilege escalation, ownership changes, and unauthorized state transitions in modern APIs and GraphQL. Also known as: auto-binding, object injection, parameter injection, BOPLA write-side (OWASP API3:2023).

## Discovery Signals

Technology fingerprints indicating high mass assignment probability:

| Signal | Where to Find | Why Vulnerable |
|---|---|---|
| `new Model(req.body)` in Node.js | Source code, GitHub CodeSearch | Direct body-to-model binding, no built-in allowlist |
| `$fillable = []` or `$guarded = []` in Laravel | Source code, PHP files | Empty guard opens all fields to mass assignment |
| Meteor DDP `Collection.insert(obj)` | WebSocket frames, JS bundles | Client document inserted verbatim into MongoDB |
| `@ModelAttribute` in Spring Boot controllers | Java source, decompiled JARs | Binds all request params to POJO fields by default |
| Google `updateMask=` query parameter | API traffic, `pa.googleapis.com` | FieldMask tells server exactly which fields to patch |
| `accepts_nested_attributes_for` in Rails | Source code, schema.rb | Deep nesting bypasses strong_params when misconfigured |
| GraphQL input types mirroring DB models | Introspection `__schema` query | Input fields often match model columns 1:1, no per-field authz |
| `req.body` spread into ORM `.create()` | Express/Fastify source | Mongoose, Prisma, Sequelize accept all keys unless filtered |
| PATCH/PUT accepting whole-object body | API traffic, OpenAPI spec | Entire model merged server-side; partial update semantics missing |
| Multi-step approval workflow (apply/pending/approved) | UI flow observation | Status fields often writable via direct API PATCH |
| Admin/internal endpoints on public paths | Path scan: `/php/`, `/admin/`, `/internal/` | Internal CRUD often lacks auth; all fields writable |
| `options[verify_email]` or config-style params in forms | Hidden form fields, POST body | Server-side toggle exposed to client |

## Framework-Specific Attack Matrix

| Framework | Default Behavior | Dangerous Patterns | Bypass Technique |
|---|---|---|---|
| **Rails** | `strong_params` required since Rails 4 | `accepts_nested_attributes_for`, `.permit!`, `params.to_unsafe_hash` | Deep nesting: `user[profile_attributes][role]`; bypass via nested relation writes |
| **Django REST** | Serializer `fields` limits output; `read_only_fields` for input | `extra_kwargs` gaps, writable nested serializers, `partial=True` updates | Switch to `PATCH` (partial); add fields not in `read_only_fields`; nested serializer writes |
| **Express/Node** | No built-in protection; `req.body` is raw | `new Model(req.body)`, `Model.create(req.body)`, spread operator | No bypass needed -- attack is the default. Middleware validators often miss extra fields |
| **Laravel** | `$fillable` allowlist or `$guarded` denylist | `$guarded = []` (all writable), `$casts` mutating hidden fields | Hidden fields still writable if not in `$guarded`; `forceFill()` in admin routes |
| **Spring Boot** | `@ModelAttribute` binds all params to POJO | No field-level annotation enforcement by default | Add nested object params: `user.role=ADMIN`; dot notation binds to nested POJOs |
| **FastAPI/Pydantic** | Pydantic models validate declared fields | `model.dict()` spread into ORM, `exclude_unset` not used | Extra fields silently dropped by Pydantic but may pass through `**kwargs` to ORM |
| **ASP.NET** | Model binding from form/JSON/query | `[Bind]` attribute not applied, `TryUpdateModelAsync` with no filter | Include excluded fields via JSON body when controller expects form data |
| **Flask** | `request.json` is raw dict | Direct dict-to-ORM mapping, `db.session.merge()` | No bypass needed -- raw dict is the attack surface |
| **Meteor.js** | DDP methods receive arbitrary documents | `Collection.insert(doc)` without `check()` or schema validation | WebSocket frame manipulation; DDP format bypasses most WAFs |
| **Phoenix/Elixir** | `cast/4` requires explicit field list | `Ecto.Changeset.change/2` without `cast`, pipe `params` directly | Skip changeset; use `Repo.insert(struct(Model, params))` patterns |
| **ColdFusion** | `form` scope binds all POST params | `UserService.create(form.fields)` pattern | Inject new form fields not in the HTML; server accepts any POST param |

## High-Value Parameter Names

| Parameter | Impact | Common In |
|---|---|---|
| `role`, `roles[]`, `role_id`, `user_type` | Admin/staff privilege escalation | Every SaaS platform |
| `is_admin`, `isAdmin`, `admin`, `is_staff` | Boolean priv-esc; one-field ATO | Registration, profile update |
| `permissions[]`, `scopes[]`, `access_level` | Granular permission override | RBAC-based platforms |
| `email_verified`, `verified`, `is_verified` | Bypass email verification flow | Signup, account settings |
| `status`, `state`, `admin_approval` | Skip approval/review workflows | Ad platforms, KYC, onboarding |
| `plan`, `subscription_tier`, `tier`, `premium` | Feature/plan upgrade without payment | SaaS billing, freemium apps |
| `balance`, `credit`, `creditBalance` | Direct financial manipulation | Wallets, marketplace credits |
| `org_id`, `tenant_id`, `workspace_id` | Cross-tenant resource hijack | Multi-tenant SaaS |
| `owner_id`, `user_id`, `created_by` | Ownership reassignment | Any resource with ownership |
| `price`, `amount`, `currency`, `discount` | Payment/checkout manipulation | E-commerce, ad platforms |
| `features[]`, `flags[]`, `betaAccess` | Feature gate bypass | Feature-flagged products |
| `usageLimit`, `seatCount`, `maxProjects` | Quota/limit bypass | Usage-metered SaaS |
| `posAccess`, `canExport`, `can_moderate` | Function-level permission escalation | POS, admin tools, forums |
| `votes[]`, `score`, `karma`, `rating` | Aggregate/reputation manipulation | Community, marketplace |
| `effective_status`, `approved`, `active` | State machine bypass | Workflow-driven apps |
| `options[verify_email]`, `send_welcome_email` | Config toggle bypass | Signup flows, API gateways |
| `password_reset_token`, `recovery_email` | Account takeover chain | Account management |

## Content-Type Switching

Different parsers activate different code paths. Many validators only check one format.

| Original Content-Type | Switch To | Why It Bypasses |
|---|---|---|
| `application/json` | `application/x-www-form-urlencoded` | Form parser may skip JSON-specific field filters |
| `application/x-www-form-urlencoded` | `application/json` | JSON allows nested objects; form-encoded allowlist may not cover them |
| `application/json` | `multipart/form-data` | Multipart parser may use different binding logic entirely |
| `application/json` | `text/plain` | Some frameworks parse JSON from text/plain bodies (CORS preflight bypass) |
| Single content-type | Duplicate `Content-Type` headers | Parser confusion: first header parsed vs last header parsed |
| Standard encoding | `application/xml` or `text/xml` | XML parser may bind attributes and elements differently than JSON keys |

## Nested Object Injection

Flat parameter filtering often misses nested paths. Test every shape variant.

| Shape | Example | Targets |
|---|---|---|
| Bracket notation | `user[role]=admin` | Rails, PHP, Express (qs parser) |
| JSON nesting | `{"user":{"role":"admin"}}` | Any JSON API |
| Dot notation | `user.role=admin` | Spring Boot, .NET model binding |
| Array injection | `roles[]=admin&roles[]=user` | Array fields on models |
| Nested relation | `user[profile_attributes][admin]=true` | Rails `accepts_nested_attributes_for` |
| Duplicate keys | `{"role":"user","role":"admin"}` | Last-write-wins JSON parsers |
| JSON Patch path | `[{"op":"add","path":"/role","value":"admin"}]` | PATCH endpoints with JSON Patch support |
| JSON Merge Patch | `{"role":"admin"}` with `Content-Type: application/merge-patch+json` | RFC 7396 merge patch endpoints |

## API-Specific Mass Assignment

### GraphQL

- **Field expansion**: introspect schema, add fields to mutation inputs that the UI never sends. Fields present in schema but unused by UI are untested.
- **Response diffing**: query the mutated object immediately after mutation; overfetch all fields to detect hidden state changes.
- **Alias bypass**: `secret: sensitiveField` -- aliases may bypass naive field-name authz checks.
- **Batching/aliasing**: combine legitimate mutation with suspicious field mutation in one request; per-field checks may only fire on the first.
- **Fragment injection**: inline fragments can move sensitive fields into harder-to-grep query locations.
- **Permission differential**: for every mutation, test from each role. Watch for "Not found" vs "Access denied" -- "Not found" means the resolver ran (authz bypassed, only data scoping remains).

### gRPC / Protobuf

- **FieldMask manipulation**: `update_mask` or `field_mask` parameters control which fields the server updates. Add sensitive field names (e.g., `status`, `role`, `verified`) to the mask.
- **Unknown fields**: proto3 preserves unknown fields by default; inject field numbers not in the client's `.proto` but present on the server model.
- **Reflection API**: if gRPC reflection is enabled, enumerate all message types and their fields.

### PATCH vs PUT Behavior

- **PUT** replaces the entire resource -- server merges all supplied fields. Mass assignment via full-object replacement.
- **PATCH** updates specific fields -- but many implementations treat PATCH as PUT internally.
- **Test both verbs** on every endpoint. If only one is documented, try the other -- servers often accept both.

## Defense-Bypass Pairs

| Defense | Bypass Technique | Evidence |
|---|---|---|
| Rails `strong_params` (`.permit(:name, :email)`) | Nested attributes: `user[profile_attributes][role]=admin` | Rails strong_params bypass via `accepts_nested_attributes_for` |
| Django `read_only_fields` | Switch to PATCH with `partial=True`; `read_only` only enforced on full serialization | DRF partial update bypass |
| Laravel `$fillable` allowlist | `forceFill()` used in admin routes reachable by normal users | Admin route accessible without role check |
| JSON Schema validation | Send field not in schema -- many validators pass-through unknown properties (`additionalProperties: true` default) | JSON Schema permissive default |
| Frontend field filtering | Bypass frontend entirely; send raw HTTP request with extra fields | Every mass assignment bug ever |
| GraphQL input type restriction | Introspect for deprecated/hidden fields still accepted by resolvers | Schema drift between input type and resolver |
| Allowlist on one content-type | Switch content-type (JSON to form-encoded); different parser, different allowlist | Content-type switching (see table above) |
| Per-endpoint RBAC | Test admin-style mutations from low-priv sessions; watch for "Not found" vs "Denied" | Shopify billingChargesExport -- $1.9k |

## Chain Patterns

Mass assignment is rarely the final impact. It enables escalation chains.

| Chain | Mechanism | Real-World Example | Typical Bounty |
|---|---|---|---|
| Mass assignment -> privilege escalation | Set `role=admin` at registration | DoD webapp: self-grant admin, access all PII (SSNs) | $5k-50k+ |
| Mass assignment -> account takeover | Overwrite `email` or `recovery_email`, trigger password reset | Zomato: change merchant email, reset password, hijack payouts | $5k-25k |
| Mass assignment -> approval bypass | Set `admin_approval=APPROVED`, `status=ACTIVE` | Reddit ads: run ads without payment via status field overwrite -- $5k | $2k-10k |
| Mass assignment -> verification bypass | Set `email_verified=true` or `options[verify_email]=false` | api.data.gov: get API key without email verification | $500-5k |
| Mass assignment -> financial fraud | Modify `price`, `balance`, `creditBalance`, `amount` | WooCommerce/PayPal: modify checkout amount mid-flight | $2k-15k |
| Mass assignment -> cross-tenant access | Change `org_id`, `tenant_id`, `workspace_id` on owned resource | Move resources to another tenant's scope | $5k-25k |
| Mass assignment -> feature theft | Set `plan=enterprise`, `tier=premium`, `features[]=all` | Bypass paywall, access premium features | $500-5k |
| Mass assignment -> certification fraud | Set completion/credential fields directly | freeCodeCamp: acquire all certifications (6000+ hours) in one request | Reputation |

## Over-Serialization (Excessive Data Exposure)

The inverse of mass assignment: server returns fields the client should not see. Often found alongside writable mass assignment because both stem from missing field-level controls.

**Detection method**: for every API response, diff fields returned vs fields the UI renders. Hidden fields in the response are candidates for both read-leak and write-injection.

| Pattern | What Leaks | Impact |
|---|---|---|
| Rails `model.to_json` / `model.attributes` | All DB columns including tokens, hashes | GitLab: runner tokens leaked via Quick Actions -- $12k |
| DRF serializer without `fields` declaration | All model fields including internal state | Internal IDs, feature flags, admin notes |
| GraphQL type exposing all model fields | Every field queryable by any authenticated user | PII, financial data, internal flags |
| Error/validation responses returning full object | Sensitive fields in error context | Tokens, secrets, internal references |
| JSONP endpoints with legacy auth | Full object in callback response | Shopify: digital asset download URLs leaked -- $2.9k |

**Hunt pattern**: submit intentionally invalid data to trigger validation errors. Validation responses often return the full model (including sensitive fields) to show "what went wrong."

## Grep-Scale Hunting

Mass assignment has simple syntactic signatures. Hunt at scale across codebases.

| Language | Antipattern Grep Query | What It Finds |
|---|---|---|
| Node.js | `new Model(req.body)`, `Model.create(req.body)` | Direct body-to-model binding |
| Node.js | `Object.assign(model, req.body)`, `{...model, ...req.body}` | Spread-based field merge |
| Ruby/Rails | `params.permit!`, `to_unsafe_hash`, `accepts_nested_attributes` | Disabled strong_params |
| Python/Django | `serializer_class = ` + missing `read_only_fields` | Writable serializer gap |
| PHP/Laravel | `$guarded = []`, `forceFill(`, `$fillable = []` | Disabled mass assignment guard |
| Java/Spring | `@ModelAttribute` without `@InitBinder` allowlist | Unrestricted model binding |
| Go | `json.Unmarshal(body, &model)` without field tags | Direct JSON-to-struct binding |

**Wide-not-deep strategy**: use GitHub CodeSearch or grep.app to search the entire public corpus for these antipatterns. Filter by star count for maximum impact. This found mass assignment in freeCodeCamp (the most-starred GitHub project) leading to instant certification fraud.

## Testing Methodology

### Phase 1: Enumerate Attack Surface
1. Capture all create/update endpoints (REST, GraphQL mutations, WebSocket methods, gRPC calls).
2. For each endpoint, dump the full object via GET/query. Every field in the response is a candidate for write injection.
3. Introspect GraphQL schemas, read OpenAPI/Swagger docs, inspect hidden form fields, reverse mobile app bundles.
4. Map approval/review workflows -- identify every state-transition field (`status`, `state`, `approved`, `verified`).
5. Enumerate internal/admin-style paths: `/php/`, `/admin/`, `/internal/`, `/tools/`, `/api/internal/`. These often share backend implementations with public endpoints but skip auth.

### Phase 2: Build Sensitive-Field Dictionary
Per resource: role/permission fields, ownership fields, status/state fields, billing fields, feature flags, verification booleans, aggregate counters. Use the High-Value Parameter Names table above.

Add resource-specific fields discovered from:
- GET response bodies (all returned fields are write candidates)
- GraphQL introspection (full field list per type)
- Mobile app decompilation (hardcoded field names in request builders)
- JavaScript bundles (API client code, form builders, mutation strings)
- OpenAPI/Swagger specs (all properties per schema object)

### Phase 3: Inject and Observe
1. Add sensitive fields alongside legitimate updates, one field at a time.
2. Try all shape variants: flat, nested, bracket, dot notation, duplicate keys.
3. Test across content-types: JSON, form-encoded, multipart.
4. For GraphQL: expand mutation input selection set; test with aliases and fragments.
5. For each endpoint, test from every available role (anonymous, user, staff, admin). Same endpoint, different sessions.

### Phase 4: Verify Persistence
1. After injection, re-fetch the object (GET or GraphQL query). Confirm the field value persisted.
2. Test from a different session/account to confirm the change is visible (not just local echo).
3. For state fields: verify the downstream effect (e.g., approval email sent, feature unlocked, payment status changed).
4. Check if the write persisted but the response was filtered -- some APIs return sanitized responses while writing unsanitized data.

### Phase 5: Test Bypass Variants
1. If blocked on one content-type, try another.
2. If blocked on flat params, try nested/bracket/dot notation.
3. If blocked on single updates, try batch/bulk endpoints.
4. If blocked on direct write, try race condition: two concurrent updates, one with forbidden field.
5. Strip parameters one at a time from legitimate requests -- empty/missing auth params sometimes trigger "default to most recent" fallback behavior.
6. Try the update from a pre-confirmation account state (signed up but not email-verified). Fewer validations often run in this state.
7. If the UI only sends POST, try PATCH and PUT on the same resource path. Undocumented verbs often have weaker field filtering.

## Validation

1. Show a minimal request where adding a sensitive field changes persisted state for a non-privileged caller.
2. Provide before/after evidence (response body, subsequent GET, or GraphQL query) proving the forbidden attribute value.
3. Demonstrate the chain impact: if `role=admin` was set, show admin-only actions succeeding. If `email` was changed, show password-reset to attacker-controlled address.
4. For nested/bulk: show that protected fields are written within child objects or array elements.
5. Quantify impact: role flip, cross-tenant move, financial amount, quota increase, certification count.

## False Positives

- Server recomputes derived fields (plan/price/role) ignoring client input -- verify via re-fetch
- Fields marked read-only and enforced consistently across ALL content-types and encodings
- Only UI-side changes with no persisted server-side effect
- Server accepts the field but applies authorization separately (returns 200 but value unchanged)
- GraphQL returns the field in response but it was not actually written (read-through from existing data)

## High-Value Endpoint Patterns

Endpoints where mass assignment pays the most, ordered by typical bounty:

| Endpoint Type | Why High Value | Fields to Target | Typical Impact |
|---|---|---|---|
| Registration / signup | No existing session to validate against | `role`, `is_admin`, `user_type`, `verified` | Instant admin -- DoD Critical |
| Profile / account update | Existing object with many writable fields | `email`, `role`, `permissions`, `org_id` | ATO or priv-esc |
| Approval / review workflows | State machine fields often writable | `status`, `admin_approval`, `effective_status` | Skip review -- Reddit $5k |
| Billing / subscription | Direct financial impact | `plan`, `price`, `balance`, `trial_end` | Financial fraud |
| API key / token creation | Config toggles exposed in form | `options[verify_email]`, `scopes[]`, `roles[]` | Verification bypass |
| Batch / bulk operations | Per-item validation often skipped | Any field -- hidden in large arrays | Scale multiplier |
| Partner / merchant portals | Multi-step approval, generic CRUD | `status`, `verified`, `tier` | Google Nest $50k |
| Internal / admin endpoints on public paths | Often no auth at all | Everything | Full model write |

## Client-Supplied Permission Claims

A variant of mass assignment where the client sends its own permission flags and the server trusts them. Not about model binding -- about the server reading authorization from request parameters instead of computing it server-side.

| Pattern | Example | Where Found |
|---|---|---|
| Permission JSON in request body | `extended_data.topic_permissions.can_moderate=1` | Steam Community forums -- $500 |
| Role field in form data | `userType=ADMINISTRATOR` injected into registration POST | DoD webapp -- Critical |
| Config toggle in hidden field | `options[verify_email]=false` flipped in signup | api.data.gov API gateway |
| Action parameter controlling behavior | `action=update-merchant` with no auth check | Zomato `/php/merchant_details.php` |

**Detection**: look for `can_*`, `is_admin`, `role`, `permissions`, `auth_level`, `tier`, `accessLevel` in any request body or query string. If the server reads these to make authorization decisions, flip them to elevated values.

## Pro Tips

1. **Build a per-resource sensitive-field dictionary** and fuzz systematically. Do not guess -- enumerate from GET responses and schema introspection.
2. **Always try shapes the UI never sends.** The most impactful mass assignment bugs come from injecting NEW parameters, not modifying existing ones. The form shows 5 fields; the model has 20.
3. **Watch the differential signal.** On GraphQL: "Not found" vs "Access denied" tells you whether authz was bypassed. "Not found" means the resolver ran.
4. **Check approval workflows end-to-end.** Walk the legitimate flow, observe what fields the server sets at each state transition, then try to set them yourself via the update API.
5. **Inspect hidden form fields and config-style params.** Parameters like `options[verify_email]` and `send_welcome_email` are server-side toggles exposed to the client. Flip them.
6. **For Google APIs: always test `updateMask`** with sensitive field names. Without `updateMask`, PATCH may silently drop your changes, leading you to falsely conclude the field is protected.
7. **Test from the unconfirmed/uninitialized state.** Many mass assignment bugs require the account to be in a pre-confirmation state where fewer validations run.
8. **Compound your findings.** Mass assignment alone is Medium; chain it with privilege escalation, ATO, or financial fraud for High/Critical. Always map: what can I DO with the field I just set?
9. **Target Node.js/Express over Rails.** Rails solved this in 2012 with strong_params. The Node.js ecosystem has no equivalent built-in -- higher hit rate for the same effort.
10. **Construct the server-side model, not the form-side model.** Forms are a UI; servers maintain the truth. Anything the server's model has is reachable via mass assignment unless explicitly blocked.
11. **Test every REST verb on every resource.** If the submit flow only uses POST, try PATCH and PUT. The submit-form code path may validate; the generic PATCH may not.
12. **After finding one writable field, test all others.** A single mass-assignment-vulnerable endpoint typically accepts multiple privileged fields. Report each distinct impact separately.

## Summary

Mass assignment is eliminated by explicit mapping and per-field authorization. Treat every client-supplied attribute -- especially nested, batch, or config-style inputs -- as untrusted until validated against an allowlist and caller scope. The bug persists across every framework generation because each new ecosystem reinvents model binding without built-in field-level protection.
