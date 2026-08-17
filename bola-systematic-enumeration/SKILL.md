---
name: bola-systematic-enumeration
category: vulnerabilities
description: Systematic BOLA enumeration beyond basic IDOR — access matrix construction, role-sweep methodology, automated enumeration at scale, defense-bypass pairs, and cross-product authorization drift patterns from $50K-$1.3M disclosed reports
depends_on: [idor]
---

# BOLA Systematic Enumeration

This skill covers the SYSTEMATIC part of BOLA hunting — the structured methodology that
turns ad-hoc ID-swapping into exhaustive coverage. For basic IDOR theory, ID format
fingerprinting, bypass techniques, and transport-level attacks, see `idor.md`. This skill
assumes you already know how to swap an ID; it teaches you how to ensure you have swapped
EVERY ID on EVERY endpoint for EVERY role.

## When to Load This Skill

- Target has 3+ roles or multi-tenant architecture
- API surface has 20+ endpoints with object references
- You need structured proof that every endpoint was tested (role-sweep gate)
- Prior IDOR testing was ad-hoc and you suspect gaps

## Access Matrix Construction

The access matrix is not a concept — it is a literal artifact you build and maintain
throughout the hunt. Every cell is a test. Empty cells are untested attack surface.

### Step 1: Enumerate Principals

List every distinct identity the target recognizes. Not just "user A / user B" — every
role tier, every tenant, every API key scope:

| Principal | Type | How Obtained | Auth Mechanism |
|-----------|------|--------------|----------------|
| Unauth | None | N/A | No headers |
| Free user (Account A) | Horizontal | Self-signup | Bearer JWT |
| Free user (Account B) | Horizontal | Self-signup | Bearer JWT |
| Paid user | Vertical | Upgrade A | Bearer JWT |
| Admin | Vertical | Invite/provision | Bearer JWT + MFA |
| API key (read) | Scoped | Dashboard | X-API-Key header |
| API key (write) | Scoped | Dashboard | X-API-Key header |
| Service account | Internal | Config leak / SSRF | Basic auth |
| Tenant A operator | Cross-tenant | Signup on tenant A | Cookie + X-Tenant |
| Tenant B operator | Cross-tenant | Signup on tenant B | Cookie + X-Tenant |

### Step 2: Enumerate Objects

For each resource type, collect at least one ID owned by each principal:

| Resource | Owner | ID | ID Format | Obtained Via |
|----------|-------|----|-----------|-------------|
| /users/{id} | Account A | 42 | Sequential int | GET /me |
| /users/{id} | Account B | 43 | Sequential int | GET /me |
| /orders/{id} | Account A | ord_abc | Prefixed slug | POST /orders |
| /orgs/{id} | Tenant A | org_123 | Prefixed slug | GET /org |
| /files/{id} | Admin | f_001 | Prefixed slug | Admin panel |

### Step 3: Build the Matrix

Cross every principal against every object with every action (R/W/D):

```
              | A's user | B's user | Admin's user | A's order | B's order | Admin file |
Unauth READ   |    ?     |    ?     |      ?       |     ?     |     ?     |     ?      |
Unauth WRITE  |    ?     |    ?     |      ?       |     ?     |     ?     |     ?      |
User A READ   |    OK    |    ?     |      ?       |    OK     |     ?     |     ?      |
User A WRITE  |    OK    |    ?     |      ?       |    OK     |     ?     |     ?      |
User B READ   |    ?     |    OK    |      ?       |     ?     |    OK     |     ?      |
API-key READ  |    ?     |    ?     |      ?       |     ?     |     ?     |     ?      |
Tenant B op   |    ?     |    ?     |      ?       |     ?     |     ?     |     ?      |
```

Each `?` is a test to run. Each `OK` is baseline (expected to succeed).
Mark results: `OK` (expected access), `BOLA` (unauthorized access), `403` (blocked), `404` (not found).

### Step 4: Systematic Sweep

For EVERY `?` cell, send the request. Use the bugdotexe access-matrix tracker:
- `record_access_probe(target, endpoint, method, role, status_code)` after each probe
- `get_access_matrix(target)` every ~10 probes to see gaps
- `get_authz_anomalies(target)` to surface role-privilege inversions

## Automated Enumeration Techniques

| # | Technique | Scale | Tool | Where It Works |
|---|-----------|-------|------|----------------|
| 1 | Sequential ID sweep (N-1000 to N+1000) | 2000 reqs | ffuf with generated wordlist | Any sequential integer endpoint |
| 2 | GraphQL alias batching (100+ lookups per request) | 100-10K per req | Custom GraphQL query | GraphQL APIs without per-alias rate limits ($50K Google Polish course) |
| 3 | Batch endpoint array injection | 100-1000 per req | curl with JSON array body | `/api/batch`, `/api/bulk`, any endpoint accepting ID arrays |
| 4 | UUIDv1 timestamp prediction | ~100 candidates | Python uuid module: `uuid.UUID(known).time` + offset | Any API using UUIDv1 (check `uuid.UUID(x).version == 1`) |
| 5 | Base64-encoded ID regeneration | Unlimited | `echo -n "User:N" \| base64` for N in range | GraphQL Relay node IDs, any base64-wrapped sequential ID |
| 6 | Dual-ID substitution (plaintext + "encrypted") | Per-endpoint | Manual decode + re-encode | APIs with `userId` + `userIdEncrypt` pairs ($50K Google WeChat) |
| 7 | FieldMask parameter mutation | Per-endpoint | curl with `?updateMask=status` | Google AIP-style APIs, any API with field projection ($50K Nest, $313K Search Console) |
| 8 | Client-side disabled-attribute removal | Per-control | DevTools: remove `disabled=""` | SPAs with role-gated UI buttons ($313K Google Search Console) |
| 9 | Batchexecute RPC ID substitution | Per-RPC | Burp replay with modified IDs | Google products using batchexecute ($313K Google Chat Spaces) |
| 10 | Search-index ACL drift probing | Per-query | Search with filters on restricted content | Products with search + direct-read paths ($500K Google Groups) |
| 11 | Boolean flag mutation (`includeSuspended`, `includeArchived`) | Per-endpoint | curl with flag=true on every GET | APIs where edge-case flags bypass response masking ($1.3M YouTube) |
| 12 | `updateMask` / mass-assignment on status fields | Per-endpoint | PATCH with `updateMask=status` | Multi-stage approval workflows ($50K Nest Pro Portal) |

## Defense-Bypass Pairs

| # | Defense | Bypass | Real-World Reference |
|---|---------|--------|---------------------|
| 1 | "Encrypted" user ID in request body | Decode (base64/hex), substitute, re-encode | $50K Google WeChat Mini-Program |
| 2 | Dual-ID validation (plaintext + encoded) | Both are client-supplied; regenerate both | $50K Google WeChat — neither rooted in session |
| 3 | FieldMask response shaping (only return requested fields) | Boolean flag (`includeSuspended=true`) bypasses mask | $1.3M YouTube Content ID chain |
| 4 | UI-disabled buttons for role-gated actions | Remove `disabled` attr in DevTools; server has no role check | $313K Google Search Console bulk export |
| 5 | Per-request rate limit on lookups | GraphQL alias batching: 100 lookups in 1 request | $50K Google Polish course platform |
| 6 | Sequential ID replaced with UUIDv4 | Leak UUIDs from list/search/export endpoints, then IDOR | Structural — UUIDs are not authorization |
| 7 | "Admin-only" API endpoints (docs say restricted) | Test with lower-privilege tokens; docs often lie | $1.3M YouTube Content ID API (docs said CMS-only) |
| 8 | Search results show only "authorized" content | Search index has stale ACLs; snippet-walk reconstructs full message | $500K Google Groups search ACL drift |
| 9 | PATCH endpoint validates org ownership | Accepts `updateMask=status` — validates WHO but not WHICH FIELDS | $50K Nest Pro Portal mass assignment |
| 10 | Anti-CSRF token on state-changing RPCs | Attacker uses their OWN anti-CSRF token; bug is missing authz, not CSRF | $313K Google Chat Spaces |

## Cross-Product Authorization Drift

The highest-paying BOLA bugs are not simple ID swaps — they exploit authorization
inconsistency between two access paths to the same data:

| Path A (Enforced) | Path B (Broken) | Why Drift Exists | Example |
|-------------------|-----------------|------------------|---------|
| Direct resource read | Search results | Search index has stale/missing ACLs | $500K Google Groups |
| Current API version (v3) | Legacy API version (v1) | Auth added to v3 only | Structural — always test v1/v2/beta |
| Web UI action | Underlying RPC endpoint | UI hides button; server trusts UI | $313K Search Console |
| Single-item endpoint | Batch/bulk/export endpoint | Batch skips per-item auth check | Structural — batch is the backdoor |
| Normal response mask | Response with edge-case flag | Alternate code path ignores mask | $1.3M YouTube `includeSuspended` |
| API A (returns opaque ID) | API B (resolves opaque ID to PII) | API B's access control is wider than intended | $1.3M YouTube two-API chain |
| GA direct user view | GA filtered aggregate report | k-anonymity fails at k=1 segment | $500K Google Analytics |

## Chain Patterns

| Base Finding | Chain With | Combined Impact | Reference |
|-------------|-----------|-----------------|-----------|
| Read BOLA on user profile | Leaked Stripe customer ID in response | Payment data correlation, billing abuse | $50K Google Polish course |
| FieldMask bypass (read extra fields) | Second API resolving opaque IDs to email | Mass de-anonymization of YouTube creators | $1.3M YouTube |
| UI-disabled export bypass | Persistent pipeline to attacker's BigQuery | Data exfil continues after access revocation | $313K Search Console |
| Activation token format reuse | Session token with same signing oracle | Mint session for any username via registration | $50K VirusTotal |
| Member-removal RPC IDOR | Gaia ID leak from collaborator list | Remove any user (including managers) from any space | $313K Google Chat |
| Search ACL drift | Snippet-walking (last word as next query) | Full message reconstruction from search snippets | $500K Google Groups |
| BOLA on restricted group | BOLA on group admin actions | Read + write access to restricted organizational data | Structural |
| Batch endpoint IDOR | Export/download endpoint IDOR | Bulk data exfiltration across accounts | Structural |

## Pro Tips

1. **Build the matrix as an artifact, not a mental model.** Use the bugdotexe access-matrix tracker or a spreadsheet. Empty cells are untested surface. The matrix IS your coverage proof.
2. **Decode EVERY "encrypted" or "opaque" ID before testing.** Base64, hex, URL-safe base64, double-encoding. The $50K Google WeChat bug was "encrypted" IDs that were just base64. 90% of the time it is encoding, not encryption.
3. **Test every boolean flag on every endpoint.** `includeSuspended`, `includeArchived`, `includeDeleted`, `expand`, `verbose`, `withMetadata`, `complete` — each flag potentially selects a different code path with weaker authorization. The $1.3M YouTube bug was one boolean.
4. **Always test the batch/bulk/export variant** of any endpoint where single-item access is locked. Batch endpoints are the most reliably un-authed surface in API security.
5. **For Google AIP-style APIs, always try PATCH with `updateMask` on every field.** The field-level write authorization is often missing even when entity-level auth works. The $50K Nest bug was PATCH with `updateMask=status`.
6. **Two-API chaining: when API A leaks an opaque ID, find API B that resolves it.** Opaque IDs are not authorization. The $1.3M YouTube bug chained a content owner ID leak with a Content ID API email lookup.
7. **Test search/filter/list endpoints separately from direct-read endpoints.** Search indexes have stale ACLs. The $500K Google Groups bug was search returning content that direct read denied.
8. **For SPAs, inspect every disabled/hidden UI control.** Remove `disabled`, force-click, capture the RPC. If the server accepts it, the role check is client-side only. The $313K Search Console bug was one DevTools edit.
9. **Role-sweep before reporting.** Ensure every operator-provided role has at least one 2xx/3xx probe recorded. The submission gate requires this.
10. **Persistent integration actions (export to BigQuery, webhook setup) are the highest-severity BOLA.** They create ongoing data flow that survives access revocation. Always test these with lower-privilege roles.

## Summary

Systematic BOLA is a coverage problem, not a cleverness problem. Build the access matrix, fill every cell, decode every opaque ID, test every boolean flag, probe every alternate access path (search, batch, legacy API, RPC), and record every result. The highest bounties come from cross-product authorization drift and multi-API chaining, not from swapping `123` to `124`.
