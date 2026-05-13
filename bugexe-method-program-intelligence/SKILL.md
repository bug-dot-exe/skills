---
name: program_intelligence
category: methodology
description: Bug bounty program intelligence gathering for scope analysis, reward optimization, disclosed report patterns, and policy quirks
depends_on: []
---

# Program Intelligence

Before hunting, study the program. Understanding scope nuances, reward structures, disclosed reports, and triager behavior turns hours of blind testing into targeted exploitation.

## When to Use

- Before starting work on any new bug bounty program
- When deciding which program to invest time in
- After a rejection to recalibrate your approach
- When comparing multiple programs for ROI optimization

## Methodology

### Step 1: Scope Deep Dive

Read the scope page line by line. Extract:

- **In-scope assets**: domains, IPs, mobile apps, APIs, source code repos
- **Out-of-scope assets**: explicitly excluded domains, third-party services, specific paths
- **Out-of-scope vuln types**: often self-XSS, clickjacking, missing headers, rate limiting
- **Testing restrictions**: no automated scanning, no DoS, no social engineering, production vs staging
- **Special rules**: bonus scopes, time-limited additions, VDP vs bounty distinction

Map the scope boundary precisely. Ambiguous scope means wasted reports.

### Step 2: Reward Structure Analysis

| Factor | What to Extract |
|--------|----------------|
| Base ranges | Min/max per severity tier |
| Bonus multipliers | Impact-based bonuses, asset-specific bonuses, seasonal bonuses |
| Severity criteria | Program-specific severity definitions (may differ from CVSS) |
| Payment terms | Time to payout, currency, minimum threshold |
| Reputation impact | Points/ranking system, invitation criteria |

Calculate expected value: `P(accepted) * avg_reward * frequency` per vuln class.

### Step 3: Disclosed Report Analysis

Read every disclosed report on the program. Extract:

- **Accepted vuln classes**: what they actually pay for (vs what scope says)
- **Severity calibration**: how they rate Medium vs High vs Critical in practice
- **Preferred reporting style**: terse technical or detailed business impact?
- **Common findings**: if 10 reports are XSS, the low-hanging fruit is picked
- **Gaps**: vuln classes with zero disclosures (either not present or not yet found)
- **Triager comments**: reveal what the team cares about and how they evaluate impact

### Step 4: Response Time and Triage Quality

Track or research:

- **Time to first response**: hours vs days vs weeks
- **Time to triage**: how fast findings move from new to triaged
- **Time to bounty**: from submission to payment
- **Triage quality**: do they engage technically or template-respond?
- **Dispute handling**: how they handle severity disagreements

Fast, technical triage teams are worth investing in. Slow, template-driven triage wastes your time on edge cases.

### Step 5: Policy Quirks

Every program has unwritten rules discovered through experience or community knowledge:

- Do they accept chained findings or require each step separately?
- Do they pay for duplicates found via different attack vectors?
- Do they accept findings on staging/dev environments?
- Safe harbor language: how strong is their legal protection?
- Retesting policy: do they pay for regressions?

### Step 6: Build Program Profile

Compile into a decision-ready profile:

```
Program: [name]
Platform: [H1/Bugcrowd/Intigriti/Immunefi/VDP]
Reward range: [Low: $X | Medium: $X | High: $X | Critical: $X]
Response time: [fast/medium/slow]
Top vuln classes accepted: [list from disclosures]
Auto-reject list: [from scope + rejection patterns]
Hunt strategy: [deep logic / surface scan / source review / chain building]
ROI assessment: [high/medium/low]
```

## Program Comparison Matrix

When choosing between programs:

| Factor | Weight | Program A | Program B |
|--------|--------|-----------|-----------|
| Reward per hour | 30% | | |
| Acceptance rate | 25% | | |
| Scope size | 15% | | |
| Competition level | 15% | | |
| Triage quality | 15% | | |

## Corpus-Derived High-Value Hunting Patterns

### Multi-Surface Authorization Audit

Multi-surface platforms (web, mobile, API, CLI, SDK, embedded) enforce the same permission model across different code paths written by different teams. The highest-bounty findings come from testing the same operation across every surface:

1. **Enumerate all surfaces** that expose the same resource (web UI, REST API, GraphQL, mobile deeplink, CLI, SDK, browser extension, embedded iframe)
2. **Capture the authorized request** on the most-privileged surface (usually admin web UI)
3. **Replay against every other surface** with a lower-privilege token
4. One surface almost always has a weaker authorization check -- the team that built the mobile API did not talk to the team that built the web middleware

### Search-vs-Direct ACL Split

For any platform with both a "list/search/filter" endpoint AND a "direct read by ID" endpoint for the same resource: test whether the search endpoint respects ACLs that the direct-read endpoint does not (or vice versa). Concrete steps:

1. Create a private resource as User A
2. As User B, search for it (should return empty)
3. As User B, request it directly by ID (often returns the resource)
4. Reverse: if direct-read is locked, test whether the search index still leaks field values in facets, counts, or suggestions

### OAuth Scope Capability Enumeration

Do not trust the consent screen to describe what a scope can do. For any OAuth provider with many scopes:

1. Request the least-privileged scope
2. Enumerate every API endpoint the token can reach (not just what docs say)
3. Test cross-scope operations: can a `read:profile` token call `write:settings`?
4. Test deprecated scopes: old scope names often map to broader permissions than current equivalents
5. Test scope upgrade paths: can a token request additional scopes without user re-consent?

### Platform Fingerprinting to Known-Misconfiguration Checklist

Every web app runs on identifiable infrastructure. Recognize the platform, then apply its known-misconfiguration checklist:

| Platform Signal | Check |
|----------------|-------|
| Firebase/Firestore JS SDK | Test Firestore rules: `GET /v1/projects/{id}/databases/(default)/documents/{collection}` without auth |
| Salesforce Experience Cloud | Test guest user API access, `aura` endpoints, SOQL injection in `@AuraEnabled` methods |
| ServiceNow | Test `table_api` ACLs, `sys_` table exposure, `glide.security` bypass |
| AWS Amplify + Cognito | Test identity pool unauthenticated role permissions, GraphQL resolver authorization |
| Hasura | Test role-based permission bypass via `x-hasura-role` header manipulation |

### Acquired-Company Infrastructure Audit

For every company acquisition in the target's history:

1. Enumerate the acquired company's original domains, IP ranges, and cloud accounts
2. Test for: dangling DNS pointing to decommissioned infra, SSO integration gaps (acquired users may have broader access), shared credentials or API keys that bridge old and new systems
3. Acquired domains are rarely re-hardened to the acquirer's security standard -- they are among the softest targets in large scopes

### Inter-Property Auth Token Graph

For multi-property platforms (Google, Microsoft, Meta, Amazon): map every location where one property's auth token is accepted by another property. Test:

1. Token issued by Property A used on Property B's API
2. Cookie scope overlaps between subdomains of different properties
3. SSO session propagation: does logging out of one property invalidate tokens on the other?
4. Downscoped token accepted where it should not be

### Privilege-Tier Request Replay

On any platform with multiple privilege flows (public vs owner, customer vs admin, free vs enterprise):

1. Capture the legitimate privileged request (admin action, enterprise feature)
2. Replay with a lower-privilege session token
3. If rejected: mutate the request (strip headers, change content-type, URL-encode differently) and replay
4. Test at the parameter level: can a free-tier user send the `enterprise_feature=true` parameter and have it honored?

### Aggregated-Demographics Cohort Leakage

Wherever an analytics or reporting platform claims to show "aggregated" demographic data: test whether you can filter to a cohort of 1:

1. Find the privacy threshold (minimum group size before data is shown)
2. Build filter combinations that isolate a single user (rare location + rare interest + rare age range)
3. If the platform shows data for a cohort of 1, it is leaking individual user information

### JSONP/postMessage Proxy Infrastructure Audit

Large platforms maintain proxy iframes that bridge first-party APIs to third-party contexts. Enumerate these:

1. Search JS bundles for `postMessage`, `receiveMessage`, `__JSONP__`, `callback=`
2. For each proxy endpoint: test whether it validates the requesting origin, whether the callback parameter is injectable, and whether the response contains sensitive data
3. Chain: XSS on any same-origin page + unsanitized postMessage listener = full account takeover

## Red Flags

- Programs that take 30+ days to triage with no communication
- Scope that excludes nearly every useful vuln class
- History of downgrading severity without technical justification
- No disclosed reports despite being live for 12+ months
- VDP with no bounty disguised as a bounty program
