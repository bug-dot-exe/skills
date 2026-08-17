---
name: triage-validity
category: methodology
description: Pre-report validation checklist ensuring findings meet submission quality before writing
depends_on: []
---

# Triage Validity

Every finding must pass all 7 questions before report writing begins. A single NO kills or downgrades.

## When to Use

- After a finding passes kill signal checks
- Before starting to write a formal report

## 7-Question Gate

| # | Question | If NO |
|---|----------|-------|
| 1 | **Reproducible?** Can you trigger it right now, on demand, at least twice? | Drop or demote to informational |
| 2 | **Impact real?** Can you state the harm in one sentence without "could" or "might"? | Reconsider severity or drop |
| 3 | **Affects real users?** Would normal users encounter this, not just a contrived setup? | Downgrade severity |
| 4 | **Not a duplicate?** No prior report with the same root cause on this platform? | Drop unless you add a new bypass or impact |
| 5 | **Severity correct?** Matches criteria below without inflation? | Adjust before writing |
| 6 | **Evidence complete?** Full HTTP pairs, curl repro, timestamps, labeled accounts? | Fill gaps first |
| 7 | **Reproducible by others?** Can a triage analyst with no context follow your steps? | Evidence is incomplete |

## Severity Reference

| Severity | Criteria |
|----------|----------|
| Critical | ATO, RCE, auth bypass, mass data breach |
| High | Significant data access, privesc, stored XSS on sensitive pages, supply chain compromise |
| Medium | Limited data exposure, CSRF on state-changing actions, IDOR on non-sensitive data |
| Low | Info disclosure with minimal impact, reflected XSS requiring unusual interaction |
| Info | Best practice violation, no direct security impact |

When in doubt, submit one tier lower than your gut says.

## Evidence Checklist

- [ ] Full HTTP request for every exploitation step (method, URL, headers, body)
- [ ] Full HTTP response showing the vulnerability (status, headers, body)
- [ ] Two accounts demonstrating the boundary violation (if authz issue)
- [ ] Standalone curl command reproducing the core finding
- [ ] Timestamps consistent and sequential
- [ ] Attacker vs victim tokens clearly labeled (never ambiguous)
- [ ] Sensitive data in evidence is from test accounts only

## Quick Evidence Template

```
=== Step N: [what this does] ===
REQUEST:
[METHOD] [PATH] HTTP/1.1
Host: [target]
Authorization: Bearer <ATTACKER_TOKEN>
[body]

RESPONSE:
HTTP/1.1 [STATUS]
[relevant body proving the vulnerability]
```

## Final Gate

All 7 questions YES + evidence checklist complete = ready to write. Any borderline answer = strengthen evidence or downgrade first.

---

## Corpus-Derived Validity Patterns

Techniques from high-bounty reports that address the gap between "found something" and "valid submission." These patterns catch bugs that pass the 7-question gate but miss subtle validity traps.

### Validate-and-Use Mismatch Detection

When a string flows through any system, the validation step may parse it differently from the consumption step. Before reporting, verify the mismatch is real:

1. Capture the exact bytes the validator sees (URL-decoded, charset-normalized, canonicalized).
2. Capture the exact bytes the consumer sees after the validator approves.
3. If they differ, you have a finding. The mismatch IS the vulnerability — show both interpretations in evidence.
4. Common mismatch surfaces: URL parsers (validation vs redirect), HTML sanitizers (parse vs render), filename validators (check vs filesystem), JSON schema validators (validate vs deserialize).

### Patch-Adjacent Retesting

Every accepted finding is a signal that the entire flow is under-tested. After a bug is fixed:

1. Re-enumerate every mutation primitive in the same feature (edit-profile, change-email, update-password, delete-account).
2. Test each primitive with the same attack class that worked on the fixed one.
3. Check that the fix is not method-conditional — if CSRF protection was added to POST, test PUT, PATCH, DELETE on the same endpoint.
4. Test that the fix covers all product variants — regional domains, mobile API, legacy API versions.

### Filter-vs-Resolver Disagreement (SSRF/Redirect)

For any input that undergoes both validation and resolution:

1. Identify the filter (regex, allowlist, blocklist) and the resolver (DNS lookup, HTTP client, URL parser).
2. Test: does the filter check the string while the resolver follows redirects, re-resolves DNS, or normalizes the URL differently?
3. Six-layer SSRF bypass before declaring safe: (a) direct internal target, (b) DNS rebinding, (c) redirect chain, (d) IPv6 mapping, (e) URL scheme tricks, (f) parser-specific edge cases (backslash, null byte, Unicode normalization).

### Parser-Differential Sanitizer Bypass

When the target uses an HTML sanitizer, Markdown renderer, or rich-text processor:

1. Identify the parser library and version.
2. Feed edge-case inputs from the relevant spec: empty comments (`<!---->`), processing instructions, namespace prefixes, CDATA sections, entity-encoded payloads.
3. If the sanitizer produces output that re-parses differently in the browser, the differential is exploitable. Show both the sanitizer's interpretation and the browser's interpretation in evidence.

### E2E-Encrypted Channel Client Auditing

When a feature uses end-to-end encryption, server-side validation is absent by design. The client becomes the trust boundary:

1. Identify what metadata the client processes without server validation — filenames, MIME types, content format, link previews.
2. Test path traversal in filenames, script injection in preview rendering, and format confusion in MIME handling.
3. The threat model shifts entirely to the client's parser — test it as you would test server-side input handling.

### State-Machine Adversarial-Order Testing

For every multi-step flow (signup, email change, password change, payment, delete-account):

1. Map the intended step order: A -> B -> C -> D.
2. Test every permutation: B -> A -> C -> D, A -> C -> B -> D, skip B entirely, repeat A twice.
3. Test mutation between steps: change the email/owner-id/scope after step A but before step C consumes it.
4. Race the critical transition: send steps B and C simultaneously. If the authority check in B has not completed when C executes, the check is bypassed.

### Cross-Service Settlement Idempotency

For any system where money, balance, or state changes via a multi-service workflow:

1. Identify the idempotency key and where it is generated vs where it is checked.
2. Test: can you replay the settlement request with the same key but different parameters? Can you replay with a new key for the same logical transaction?
3. If the idempotency boundary ends at one service but the settlement continues through another, the gap between services is exploitable.

### Privilege-Plus-Silence Audit

For any multi-party platform (bug bounty, code review, support, marketplace):

1. Enumerate every action a privileged user can take on another user's content.
2. For each action, check: is the content owner notified?
3. Any action that modifies content WITHOUT notification is a finding — the privilege is expected, the silence is the bug.

### Asymmetric Field Validation

When a feature accepts multiple input fields:

1. Map the validation strictness of each field (which characters are allowed, length limits, encoding checks).
2. Find the least-validated field and test it with payloads appropriate for its rendering context.
3. Fields added later in a product's lifecycle often have weaker validation than the original fields.

### Cache-Invalidation Predicate Auditing

For every cached response:

1. Identify what the cache uses as the key (URL, headers, cookies, query params).
2. Identify what the cache uses as the invalidation signal.
3. Test: can you poison the cache by supplying attacker-controlled values in unkeyed headers or parameters?
4. Test: can you prevent cache invalidation by manipulating the invalidation predicate's inputs?
