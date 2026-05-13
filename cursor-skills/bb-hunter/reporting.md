# Reporting Reference

The report is the product. Write for a competent developer who doesn't specialize in security.

## Generic Report Template

```markdown
# [Vuln Type] in [Component] at [target] leads to [Impact]

## Summary
[2-3 sentences: what the vulnerability is, where it exists, what an attacker can achieve]

## Affected Endpoint(s)
| URL | Method | Parameter |
|-----|--------|-----------|
| https://target.com/api/endpoint | POST | `user_id` |

## Steps to Reproduce
1. [Exact step with URL]
2. [Exact step with payload]
3. [Observe: what happens]
4. [Repeat with variation if needed]

## HTTP Request/Response
[Raw request — copy-pasteable]

POST /api/endpoint HTTP/2
Host: target.com
Content-Type: application/json

{"user_id": "victim_id"}

[Raw response — showing the vulnerability]

## Impact
[Business language, not just technical. Who is affected? What data is exposed?
 What actions can an attacker take? What's the blast radius?]

## CVSS / Severity
[Score with justification. Link to calculator if helpful.]

## Remediation
[Specific, actionable fix. Not "validate input" — say exactly what validation.]
```

## Vuln-Class Report Templates

### IDOR / BOLA

```markdown
# IDOR in [endpoint] allows [attacker action] on other users' [resource]

## Summary
The `[parameter]` in `[endpoint]` is not validated against the authenticated
user's session. By changing `[parameter]` to another user's value, an attacker
can [read/modify/delete] any user's [resource].

## Steps to Reproduce
1. Log in as User A (attacker). Note your [resource_id] is `123`.
2. Send the following request, changing [resource_id] to `456` (User B):
   [raw HTTP request]
3. Observe: User B's [resource] is returned/modified in the response.
4. Repeat with sequential IDs to confirm enumeration is possible.

## Impact
Any authenticated user can [read/modify/delete] any other user's [resource].
This affects all [N] users. Leaked data includes: [specific fields].
Combined with [other finding], this enables [escalated impact].
```

### XSS (Stored / Reflected / DOM)

```markdown
# [Stored/Reflected/DOM] XSS in [component] at [target] enables [impact]

## Summary
User input in `[parameter]` at `[endpoint]` is rendered without sanitization
in [context: HTML body / attribute / JavaScript / etc.]. An attacker can execute
arbitrary JavaScript in the victim's browser session.

## Steps to Reproduce
1. [For stored: inject payload] / [For reflected: craft URL]
   Payload: `[exact payload]`
2. [For stored: visit the page where content renders] /
   [For reflected: victim clicks crafted URL]
3. Observe: JavaScript executes (demonstrated with [cookie exfil / DOM manipulation / API call]).

## Payload
[The exact payload that works, with encoding if needed]

## HTTP Request (injection point)
[Raw request showing the payload being submitted]

## HTTP Response (render point)
[Raw response showing the payload rendered in the page — highlight the exact line]

## Impact
An attacker can execute arbitrary JavaScript in the context of any user who
[views the page / clicks the link]. This enables:
- Session hijacking via `document.cookie` theft
- Account takeover via API calls using the victim's session
- [Additional impact: data exfiltration, UI manipulation, phishing]
Affects: [who — all users, admins only, users who view X]

## Proof of Concept
[Weaponized PoC showing real impact, not just alert(1).
 E.g., script that sends victim's cookies to attacker server,
 or performs an admin action via fetch()]
```

### SSRF

```markdown
# SSRF in [feature] at [target] allows [internal access / cloud metadata / etc.]

## Summary
The `[parameter]` in `[endpoint]` accepts user-controlled URLs and the server
fetches them without restriction. An attacker can access internal services,
cloud metadata, and potentially execute actions on internal infrastructure.

## Steps to Reproduce
1. Send the following request with an internal URL:
   [raw HTTP request with `http://169.254.169.254/latest/meta-data/`]
2. Observe: server responds with [cloud metadata / internal service response].
3. [Additional steps showing escalation: IAM creds, internal API access, etc.]

## Impact
An attacker can:
- Access cloud metadata and extract IAM credentials
- Reach internal services not exposed to the internet
- [Specific escalation: read S3 buckets, invoke Lambda, etc.]

## Blind SSRF Evidence (if applicable)
[If blind: show DNS callback / timing difference / error differential
 proving the server made the request]
```

### Authentication Bypass / OAuth Misconfiguration

```markdown
# [Auth bypass type] in [component] at [target] leads to [impact]

## Summary
[Describe the authentication flaw: missing auth, broken OAuth, JWT weakness, etc.]

## Steps to Reproduce
1. [Discovery step — how you found the flaw]
2. [Exploitation step — exact request to bypass auth]
3. [Verification — prove you have access you shouldn't]

## OAuth-Specific Sections (when applicable)

### Server Metadata
[Include relevant output from /.well-known/oauth-authorization-server or
 /.well-known/openid-configuration showing the misconfiguration]

### Client Registration (if applicable)
[Request/response showing unauthenticated client registration with
 dangerous parameters: none auth method, broad scopes]

### Token Exchange
[Request/response showing token obtained without proper authentication]

### Scope Validation
[Evidence that requested scopes were granted without validation]

## Impact
An attacker can [specific auth bypass impact]:
- Access any user's account without credentials
- Register malicious OAuth clients that appear legitimate
- Obtain tokens with elevated privileges
- [Downstream impact: data access, admin actions, etc.]

## Architectural Analysis
[For complex auth bugs: explain WHY the flaw exists at an architectural level.
 Reference relevant RFCs. This helps triage understand severity and helps the
 dev team fix the root cause, not just the symptom.]
```

### Race Condition

```markdown
# Race condition in [feature] at [target] leads to [financial impact / state corruption]

## Summary
The `[endpoint]` does not use atomic operations or proper locking for
[state-changing operation]. Sending concurrent requests allows [double-spend /
duplicate action / state corruption].

## Steps to Reproduce
1. Set up: [preconditions — account balance, coupon available, etc.]
2. Send [N] concurrent requests to [endpoint]:
   [raw HTTP request]
3. Use the following script to send requests simultaneously:
   [Python/curl script for concurrent execution]
4. Observe: [specific result — balance debited once but credited twice, etc.]

## Timing
[Number of concurrent requests, timing window, success rate]

## Impact
An attacker can [specific financial/logical impact]:
- Transfer $X but receive $2X (demonstrated with [evidence])
- Redeem coupon [N] times instead of once
- [Quantified impact: $/transaction × scale]
```

### Mass Assignment

```markdown
# Mass assignment in [endpoint] at [target] leads to privilege escalation

## Summary
The `[endpoint]` accepts and processes fields not exposed in the UI.
By adding `[field]` to the request body, an attacker can [escalate privilege /
modify protected attributes].

## Steps to Reproduce
1. Log in as a normal user.
2. Send the normal update request: [original request]
3. Add extra field(s) to the request body:
   [modified request with `"role": "admin"` or similar]
4. Observe: [field was accepted — verify via profile, permissions, or behavior change]

## Impact
Any authenticated user can [escalate to admin / modify billing / etc.]
by adding hidden fields to standard API requests.
```

## Impact Statements That Pay

Same vuln, different framing:

**Weak:** "XSS on the settings page"

**Strong:** "Stored XSS in the user profile bio field allows an attacker to execute arbitrary JavaScript in the context of any user who views the profile. This enables session hijacking, account takeover via cookie theft, and phishing within the trusted application domain. Affects all 2M+ active users."

### Formula
```
[Vuln type] allows [attacker action] affecting [who/how many], enabling [concrete impact].
```

## Severity Escalation

When triage undervalues your finding:

1. **Reframe in business terms** — "This isn't just an open redirect, it enables full account takeover via OAuth token theft"
2. **Show the chain** — demonstrate the full attack path, not just the individual bug
3. **Reference precedent** — link to similar reports on the same program that were rated higher
4. **Provide realistic attack scenario** — describe how a real attacker would exploit this, step by step
5. **Demonstrate the error differential** — show server behavior that proves the vuln is real (different error messages for valid vs invalid inputs)
6. **Be professional** — adversarial tone gets you nowhere; make the triager's job easy

### Language That Works
- "The impact is not [vuln class] in isolation, but rather [full attack scenario]"
- "An attacker with [minimal/no] authentication can [specific action] affecting [scope]"
- "This bypasses [specific control] that was designed to prevent [specific threat]"

### When to Push Back
- When you have concrete evidence of higher impact
- When similar bugs on the same program were rated higher
- When the triager misunderstood the finding

### When to Accept
- When you've made your case clearly and they disagree on a judgment call
- When the severity difference is one level (medium vs. high) not two (low vs. critical)
- When arguing further would damage the relationship

## Common Report Mistakes

| Mistake | Fix |
|---------|-----|
| "I found XSS" as title | "[Stored XSS] in profile bio at target.com enables account takeover" |
| Screenshot of alert(1) only | Include raw HTTP request + response + impact chain |
| "Steps are obvious" | Write for someone who never saw the app |
| Submitting before chain explored | Spend 1 day trying to escalate, then submit |
| Sitting on finding for weeks | Submit what you have, note chain potential in impact |
| Missing HTTP requests | Always include copy-pasteable requests AND screenshots |
| Generic remediation | Specific fix: "add authorization check comparing `resource.owner_id` to `session.user_id`" |
| No evidence of impact | Show the actual data leaked, action performed, or privilege gained |

## Source
https://bugbounty.info/Reporting/
