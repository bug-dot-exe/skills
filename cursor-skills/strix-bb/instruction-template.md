---

## bb-hunter Methodology (apply during testing)

### Validation
- **PoC or GTFO** — Never claim a finding without a working proof-of-concept. Confirm user input reaches the sink, credentials are attached, or the parameter is exploitable.
- **Triage detections** — A pattern match (DOM sink, CORS header, SSRF param) is a detection. A finding requires confirmation.

### Chain Thinking
Every finding is a pivot. Ask: **what does this let me reach next?**
- Open Redirect → OAuth redirect_uri manipulation → Account Takeover
- SSRF → Cloud metadata 169.254.169.254 → RCE / Infra Compromise
- XSS (stored) → Admin renders user content → Privilege Escalation
- IDOR → PII → password reset → Account Takeover

### Report Format
- **Title:** `[Vuln Type] in [component] at [target] leads to [impact]`
- **Include:** Raw HTTP request AND response. Exact repro steps. Impact in business language.
- **Impact formula:** `[Vuln type] allows [attacker action] affecting [who/how many], enabling [concrete impact].`

### Rate Limits
Respect program rate limits (e.g. ≤10 req/s). Do not brute-force.
