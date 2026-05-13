---
name: reward_prioritization
category: methodology
description: Testing prioritization based on reward potential — high-bounty vuln classes, effort-to-reward ratio, and scope timing
depends_on: []
---

# Reward-Aware Testing Prioritization

Time is finite. Prioritize testing paths that maximize expected payout per hour invested. Not all bugs are equal and not all programs reward equally.

## When to Use

- Planning a hunting session and choosing where to start
- Deciding between multiple programs or targets
- Allocating time across different vulnerability classes
- Evaluating whether to continue or switch targets mid-session

## Methodology

### Step 1: Rank Vulnerability Classes by Reward

Historical data across major platforms shows consistent reward tiers:

| Tier | Vuln Class | Typical Severity | Avg Payout Range |
|------|-----------|------------------|------------------|
| S | RCE, auth bypass to admin, full DB dump | Critical | $5K-$50K+ |
| A | SSRF to cloud creds, SQLi with data access, ATO chains | Critical/High | $2K-$20K |
| B | Stored XSS on sensitive pages, IDOR on PII, privilege escalation | High/Medium | $1K-$5K |
| C | CSRF on state changes, open redirect in OAuth, race conditions | Medium | $500-$2K |
| D | Reflected XSS, info disclosure, missing headers | Low/Info | $50-$500 |

### Step 2: Calculate Effort-to-Reward Ratio

For each target and vuln class, estimate:

```
Expected Value = P(finding) * P(accepted) * avg_reward
Hourly Value   = Expected Value / estimated_hours
```

| Factor | Low Effort | High Effort |
|--------|-----------|-------------|
| Recon required | Minimal, scope is clear | Extensive, complex infrastructure |
| Vuln complexity | Single request, obvious | Multi-step, logic-dependent |
| PoC difficulty | Screenshot sufficient | Custom tooling, environment setup |
| Report writing | Template, quick | Detailed chain, business impact |

### Step 3: Program-Specific Bonus Areas

Many programs have higher payouts for specific targets:

- **Newly added scope**: programs often announce new assets with bonus multipliers
- **Critical assets**: payment systems, auth infrastructure, admin panels
- **Specific vuln types**: some programs explicitly bonus for certain classes
- **Impact tiers**: programs paying based on demonstrated impact, not just vuln class

Check program pages and announcements for active bonuses.

### Step 4: Timing Optimization

| Timing Factor | Strategy |
|---------------|----------|
| New scope added | Hunt within 24-48 hours before competition saturates |
| Program launch | First week has lowest duplicate rate |
| After major update | New features = new bugs, old bugs reintroduced |
| Holiday periods | Fewer hunters active, slower triage but less competition |
| After disclosed reports | Study what was found, hunt adjacent areas |

### Step 5: Session Planning

Structure hunting sessions around reward tiers:

1. **First 30 min**: Quick wins on new scope or known high-value targets
2. **Next 2 hours**: Tier A/B vuln hunting on primary targets
3. **Remaining time**: Deep logic bugs, chains, or pivot to secondary targets

Re-evaluate every 2 hours: are you making progress toward a payout?

### Step 6: Portfolio Diversification

Do not put all time into one program:

- **Primary** (60% time): high-reward program with your best skill match
- **Secondary** (30% time): backup program for when primary is dry
- **Exploratory** (10% time): new programs for future pipeline

## Quick Decision Table

| Situation | Action |
|-----------|--------|
| New scope on high-reward program | Drop everything, hunt immediately |
| Found Low-severity bug | Submit fast, pivot to higher-value targets |
| 3 hours with no leads | Pivot program or vuln class |
| Found potential chain starter | Invest time to complete the chain |
| Duplicate on submitted report | Analyze what was duplicated, hunt adjacent areas |
| Program announced bonus | Re-prioritize toward bonus target |

## Anti-Patterns

- Spending 8 hours on a Low-severity finding that pays $100
- Perfecting a report for a minor info disclosure instead of hunting more
- Only hunting one vuln class regardless of program and target
- Ignoring program announcements and scope changes
- Never tracking time-per-finding to optimize future sessions

---

## Corpus-Derived Reward Maximization Patterns

Strategies from the highest-paying disclosed reports that reveal where the real money concentrates.

### Patch-Bypass as Highest-ROI Strategy

When a vendor fixes a security issue, the fix itself is a roadmap:

1. Read the patch carefully. Identify what it blocks and what it does not.
2. Test: does the fix cover all code paths, or only the reported one? Does it handle all encodings, all methods, all content types?
3. Bypass payouts often match or exceed the original finding because they prove the fix was incomplete — this signals systemic risk to the vendor.
4. Maintain a list of disclosed bugs on your target programs. After each major release, retest PoCs against the patched area. Regressions are common during refactors.

### Parser-Differential Discovery (Highest Bounty Class)

Context-aware escaping libraries and HTML sanitizers are the highest-paying XSS surface:

1. Read the library's source. Identify the specific characters it escapes per context (HTML body, attribute, script, CSS, URL).
2. Craft inputs that are benign in the escape context but become active when the output is consumed in a different context.
3. The gap between what the sanitizer thinks the context is and what the browser actually renders is the exploit.
4. Test with HTML specification edge cases: entity-encoded payloads, CDATA in SVG/MathML, processing instructions, BOM characters.

### EVM-Equivalent L2 Differential Auditing

For blockchain programs with L2 scope:

1. Enumerate every EVM opcode that mutates state.
2. Build a differential test: execute the same transaction on L1 and L2, compare all state diffs.
3. Any divergence is a candidate for consensus-breaking or fund-draining bugs.
4. Focus on opcodes with special handling: `SELFDESTRUCT`, `CREATE2`, `DELEGATECALL`, precompiles.

### Legacy Subdomain and Internal Tool Hunting

Large organizations have thousands of subdomains. The high-value targets are:

1. Internal-flavored subdomains (staging, dev, admin, internal, ops) that are accidentally internet-accessible.
2. Deprecated services still running on old stacks with known vulnerabilities.
3. Admin interfaces with default credentials or no authentication on non-standard ports.
4. Any service exposing a debug, monitoring, or management interface to the public internet.

### Inter-Property Token Graph Mapping

For large multi-property platforms:

1. Map every place where one product passes an auth token to another product (OAuth handoffs, SSO, API gateways, internal RPCs).
2. Test each handoff: does the receiving product validate the token's scope, or does it accept any valid token from the platform?
3. A token scoped to Product A that works on Product B is an authorization bypass with severity proportional to Product B's sensitivity.

### CVE-Sweep Recon on Internet-Facing Services

When high-severity CVEs drop on perimeter products (VPN, load balancer, CMS, email gateway):

1. Subscribe to vendor advisories, NVD, and exploit databases.
2. Use Shodan/Censys to find instances of the vulnerable product across your target programs' infrastructure.
3. The window between CVE publication and patching is the exploit window — speed of response determines whether you get the bounty or the duplicate.

### Escalate Dismissed Findings

When an initial finding is dismissed or classified as low severity:

1. Use the dismissed finding as a foothold for deeper enumeration — the access it provides often reveals higher-severity bugs.
2. Path traversal dismissed as "only reads /etc/passwd"? Enumerate what else is readable: config files with credentials, internal API endpoints in reverse proxy configs, database connection strings.
3. The second submission with escalated impact often converts a rejected Low into a paid High.

### HMAC Canonicalization Exploitation

For any request signed with HMAC or similar:

1. Find the canonicalization code (source-side or via behavior probing).
2. Identify whether canonicalization uses delimiters that appear in the values (ampersands in query strings, commas in headers).
3. Test parameter smuggling: `amount=100&currency=USD` signed the same as `amount=100%26currency=X&currency=USD` if the canonicalizer URL-decodes before signing but the server parses after.
