# bb-hunter Methodology + Bounty Intel (apply during testing)

---

## Validation Rules

- **PoC or GTFO** — Never claim a finding without a working proof-of-concept. Confirm user input reaches the sink, credentials are attached, or the parameter is exploitable.
- **Triage detections** — A pattern match (DOM sink, CORS header, SSRF param) is a detection. A finding requires confirmation.
- **7-Question Gate** — Before reporting: Can attacker use it RIGHT NOW? In scope? Real impact? Not known/design? Prove impact beyond "technically possible"? Not on never-submit list? One wrong answer = kill it.
- **Avoid what pays $0:** Broken link hijacking, self-XSS without chain, missing security headers alone, scanner output without validation, GraphQL introspection alone, open redirect alone, SSRF DNS-only.

---

## Chain Thinking

Every finding is a pivot. Ask: **what does this let me reach next?**

| Initial Finding | Bridge | Final Impact |
|-----------------|--------|--------------|
| Open Redirect | OAuth redirect_uri manipulation | Account Takeover |
| SSRF | Cloud metadata 169.254.169.254 | RCE / Infra Compromise |
| XSS (stored) | Admin renders user content | Privilege Escalation |
| IDOR | PII → password reset | Account Takeover |
| Subdomain Takeover | Cookies scoped to *.domain.com | Session Hijack |
| Race Condition | Payment/transfer/reward flow | Financial Impact |

**Two mediums chained = critical = $5k-$50k.** Don't stop at standalone.

---

## Sibling Rule

If `/api/admin/users` has auth, check `/api/admin/export`, `/api/admin/delete`, `/api/admin/reset`. Missing middleware on sibling endpoints = ~30% of paid IDOR/auth bugs.

## High-ROI Attack Paths (from paid reports)

1. **URL parsing differential SSRF** — Bypass allowlists with `allowed\@attacker`, `%5C`, userinfo, fragment. Test: image proxy, URL preview, webhook, import.
2. **Unauthenticated admin/OAuth endpoints** — `/api/admin/oauth/*`, `/oauth/configure`. Accept `server`/`host` param → SSRF to OAST, then metadata.
3. **Forgotten subdomain + setup token** — Metabase, Grafana, Redash. Check `/api/session/properties`, `/api/admin/settings`
4. **Weaponized patch** — After CVE patch, test the patch itself. Double bypass chars: `?raw??` if `?raw` was blocked.
5. **IDOR on unauthenticated pages** — Application pages with tokens in URL; often no auth required.

---

## Campaign Prioritization

Score paths by risk. Test first:

| Path pattern | Priority | Why |
|-------------|----------|-----|
| `/graphql`, `/auth`, `/admin`, `/debug` | 9 | Highest value |
| `/api/`, `/upload`, `/webhook`, `/payment` | 8 | Critical business logic |
| `/user`, `/search`, `/export`, `/invite` | 7 | Data access + collaboration |
| + POST body | +3 | State-changing |
| + Query params | +2 | Parameter-based attacks |

---

## Report Format

- **Title:** `[Vuln Type] in [component] at [target] leads to [impact]`
- **Include:** Raw HTTP request AND response. Exact repro steps. Impact in business language.
- **Impact formula:** `[Vuln type] allows [attacker action] affecting [who/how many], enabling [concrete impact].`

---

## Subagent Skill Selection

When spawning attacking subagents, pass skills matching the attack surface. Prioritize:

- **APIs:** idor, mass_assignment, broken_function_level_authorization, sql_injection
- **User input:** xss, ssrf, path_traversal_lfi_rfi, insecure_file_uploads
- **Auth flows:** authentication_jwt, csrf, open_redirect
- **Business logic:** business_logic, race_conditions
- **Tech-specific:** strix-nextjs, strix-fastapi, strix-graphql, strix-supabase, strix-firebase-firestore

---

## Rate Limits

Respect program rate limits (e.g. ≤10 req/s). Do not brute-force.
