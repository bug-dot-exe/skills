---
name: surface_discovery_pipeline
category: methodology
description: Universal recon pipeline — spec extraction + content discovery + crawl + parameter fuzzing + historical URLs + tech fingerprint
depends_on: []
---

# Surface Discovery Pipeline

Recon depth determines the ceiling on findings. Reading only the OpenAPI
spec misses 50-80% of attack surface on real targets. Methodology: run the
universal recon stack, append all discoveries to shared state, then attack-
class workers consume it.

## When to Use

- FIRST dispatch in every scan, before any attack-class worker
- Any time root suspects undocumented surface (legacy versions, hidden admin paths, beta features)
- After authentication: re-run as authenticated principal to capture auth-only surface

## Inputs (all runtime-derived)

- **TARGET** = `scan_config.target_url`
- **AUTH_BUNDLE** = `/workspace/auth_sessions.json` (if any credentials provided)
- **WORDLISTS** = Sandbox-installed wordlists (SecLists, fuzz4bounty). Resolve at runtime; skip if missing.

## The Pipeline (run sequentially, append all results to /workspace/discoveries.jsonl)

### 1. SPEC EXTRACTION

Probe known spec endpoints. Save any that return 200:

```
for path in /openapi.json /swagger.json /api-docs /v3/api-docs /redoc \
            /api/swagger.json /api/openapi.json /api/v1/openapi.json \
            /api/spec /spec.json /docs/api.json \
            /.well-known/openapi /graphql:
  curl -s {target}{path} -o /workspace/spec_{path//\//_}.json
  # If 200 + valid JSON, parse for endpoints
```

GraphQL specifically:
```
curl -X POST {target}/graphql -H "Content-Type: application/json" \
     -d '{"query":"{__schema{queryType{fields{name}}mutationType{fields{name}}}}"}'
```

For each spec found, extract endpoints + methods + parameters. Append to
discoveries.jsonl with `surface_type: "endpoint_from_spec"`.

### 2. CONTENT DISCOVERY (unauthenticated)

Run ffuf with a generic API wordlist. Resolve the wordlist path from the
sandbox — fall back gracefully if a specific wordlist isn't installed:

```
WORDLIST=$(find /usr/share/wordlists /usr/share/seclists -name 'api-endpoints*' -o -name 'common-api*' 2>/dev/null | head -1)
[ -z "$WORDLIST" ] && WORDLIST=$(find /usr/share/wordlists -name 'common*.txt' | head -1)
ffuf -w "$WORDLIST" -u "{target}/FUZZ" -mc 200,301,302,401,403,500 -t 40 -of json -o /workspace/ffuf.json
```

Append all responses with `surface_type: "endpoint_from_fuzz"`, including the
status (401/403 reveal hidden but auth-required endpoints).

### 3. CRAWL — unauthenticated AND authenticated

```
katana -u {target} -d 5 -jc -kf all -fs fqdn -o /workspace/crawl_unauth.txt
```

Then per credential (using auth bundle):
```
TOKEN=$(jq -r ".sessions[\"{role}\"].access_token" /workspace/auth_sessions.json)
katana -u {target} -d 5 -jc -kf all -H "Authorization: Bearer $TOKEN" -o /workspace/crawl_{role}.txt
```

Append all URLs as `surface_type: "url_from_crawl"`.

### 4. PARAMETER DISCOVERY

For each endpoint discovered above, run arjun:

```
for endpoint in $(jq -r '.[]?.path?' /workspace/discoveries.jsonl | sort -u); do
  arjun -u "{target}{endpoint}" -m GET,POST -t 10 -oJ /workspace/arjun_{slug}.json
done
```

Append discovered parameters as `surface_type: "param"`.

### 5. HISTORICAL URLs

```
HOST=$(echo {target} | sed 's|^https\?://||' | cut -d/ -f1)
gau "$HOST" 2>/dev/null | grep -E "^https?://[^/]*${HOST//./\.}" \
  | sort -u > /workspace/gau.txt
```

If `gau` isn't installed, try `waymore`:
```
waymore -i "$HOST" -mode U -oU /workspace/waymore.txt
```

Append as `surface_type: "url_from_historical"`.

### 6. KNOWN-CVE / EXPOSURE SCAN

```
nuclei -u {target} -t cves -t exposures -t default-logins \
       -severity critical,high,medium -j -o /workspace/nuclei.json
```

Append matches as `surface_type: "nuclei_finding"`.

### 7. TECH FINGERPRINT

```
httpx -u {target} -tech-detect -title -status-code -ip -j -o /workspace/httpx.json
```

Also probe for version disclosure on common headers:
```
curl -sI {target} | grep -iE "server:|x-powered-by:|x-aspnet|x-php"
```

Append findings as `surface_type: "tech_fingerprint"` with the detected
framework, server, language.

### 8. JS BUNDLE EXTRACTION

For each JS file in the crawl output:
```
for js in $(grep -E '\.js(\?|$)' /workspace/crawl_unauth.txt | sort -u); do
  curl -s "$js" -o "/workspace/js/$(basename $js)"
done
```

Then run extractors (resolve from PATH; skip if missing):
```
which jsluice && jsluice urls -i /workspace/js/ > /workspace/jsluice.txt
which linkfinder && linkfinder -i /workspace/js/*.js -o /workspace/linkfinder.html
which secretfinder && secretfinder -i /workspace/js/ -o cli > /workspace/secrets.txt
```

Fall back to grep if extractors aren't installed:
```
grep -hoE '"[/][a-zA-Z0-9_/-]+"' /workspace/js/*.js | sort -u
grep -hiE 'api[_-]?key|secret|token|password' /workspace/js/*.js | head -50
```

Append as `surface_type: "endpoint_from_js"` or `surface_type: "secret_from_js"`.

## Output — append to /workspace/discoveries.jsonl

Schema (one JSON object per line):

```json
{
  "finder_agent_id": "<agent_id>",
  "surface_type": "endpoint_from_spec | endpoint_from_fuzz | url_from_crawl | url_from_historical | param | nuclei_finding | tech_fingerprint | endpoint_from_js | secret_from_js",
  "data": {
    "method": "GET|POST|...",
    "path": "/...",
    "params": [...],
    "status": 200,
    "evidence": "...",
    "source": "ffuf|katana|gau|nuclei|jsluice|..."
  }
}
```

Root reads this file each iteration and uses entries to inform attack-class
worker dispatch. Do NOT skip writing entries — root depends on this file
for surface inventory.

## Anti-Patterns

- **Stop at /openapi.json**: this is the most common recon failure. Spec
  is INCOMPLETE. Always run content discovery + crawl + JS extraction.
- **Skip auth crawl**: anonymous crawl misses 50%+ of surface. Always re-crawl per role.
- **Hardcode wordlist path**: resolve at runtime from `find` so we work on
  any sandbox image.
- **Hardcode tool path**: `which tool` first, fall back gracefully.
- **Skip JS extraction**: SPAs hide their entire admin surface in lazy-loaded
  bundles. Extract every URL pattern from JS.
- **Skip historical URLs**: gau/waymore find deleted-but-reachable endpoints,
  staging leaks, and pre-fix versions.

## Composability

- `auth_matrix_systematic` — consumes the endpoint inventory this skill produces
- `boundary_spec_violation` — consumes the parameter inventory this skill produces
- `frontend_backend_parity` — consumes the JS bundles this skill captures
- `cross_tenant_isolation` — consumes the URL patterns this skill discovers

This skill is the FOUNDATION; all other methodology skills depend on its output.

---

## Corpus-Derived Surface Discovery Techniques

High-bounty patterns for finding attack surface that standard recon tools miss.

### Alternate-Surface Authorization Audit

Multi-surface platforms (document editors, cloud consoles, collaboration tools) expose the same data through multiple interfaces:
1. Enumerate every surface that can access the same resource: primary UI, mobile API, embed/preview endpoint, export API, search API, sharing API, revision history API.
2. Test authorization independently on each surface -- the primary UI may enforce access controls that an alternate API does not.
3. Focus on surfaces added later (mobile, export, search widget) -- they are most likely to have weaker authorization.
4. Check read-only surfaces (preview, thumbnail, search result snippet) for data that should be access-controlled.

### Blind XSS on Internal Review Surfaces

Customer-facing forms (support, abuse report, feedback, contact) render submissions on internal admin/review dashboards:
1. Identify every form that accepts user input and is reviewed by staff.
2. Inject XSS payloads that call back to your collector (interactsh or similar).
3. Internal dashboards often have weaker CSP and higher privilege than the public-facing site.
4. Payloads may fire days later when a support agent opens the ticket -- use persistent callbacks.

### Static Asset Path Traversal

Modern security audits focus on dynamic endpoints and overlook static asset handlers:
1. Probe static prefixes (`/assets`, `/static`, `/public`, `/_next/static`, `/_app/`) with path traversal payloads.
2. If a static handler serves from a base directory, `../` may escape to parent directories.
3. Test double-encoding (`%2e%2e%2f`), null bytes, and OS-specific separators.
4. Static asset handlers often bypass WAF rules because they are expected to serve only safe content.

### Patch Bypass Discovery

When a vendor publishes a security advisory with a fix:
1. Read the patch commit diff to understand exactly what was fixed.
2. Identify the boundaries of the fix -- what inputs does it now validate that it did not before?
3. Test inputs that are adjacent to the fix boundary but not covered by it.
4. Check if the same vulnerable pattern exists elsewhere in the codebase (the patch may fix one instance but leave others).
5. This is one of the highest expected-value strategies in bug bounty -- the vendor has confirmed the bug class exists.

### CI/CD Runner Reconnaissance

For any target with public repositories:
1. Pull workflow run logs (`gato`, GitHub API, or manual log download) to identify self-hosted runner labels.
2. Search for `pull_request_target` triggers that check out PR code with write permissions.
3. Check `issue_comment` triggers for shell injection via comment body.
4. Identify any workflow that downloads and executes artifacts from untrusted sources.
5. Self-hosted runners on public repos are a canonical RCE surface.

### Multi-Render-Surface Data Leak

For every feature that stores user data, enumerate ALL surfaces where that data is rendered:
1. Primary view, list/table view, search results, notification emails, webhook payloads, API responses, export files, audit logs, admin dashboards, analytics dashboards.
2. Test XSS and injection on each render surface independently -- a sanitizer may protect the primary view but not the email template or webhook payload.
3. Focus on surfaces where the renderer is different from the primary (email uses a different template engine, export uses a different serializer).

### Pipeline Parity Audit

When a platform has a global policy (strip EXIF, resize images, transcode video, sanitize HTML):
1. Enumerate every upload path: primary upload, import, API upload, mobile upload, paste, drag-and-drop, bulk upload.
2. Test whether the policy is enforced on every path -- bulk and API paths are most commonly missed.
3. Check whether the policy is applied before or after storage -- if after, a race condition may allow access to the unprocessed version.

### Port Scanning for Forgotten Infrastructure

Large organizations own vast IP ranges with forgotten services:
1. Scan IP ranges (from ASN data, certificate transparency, or DNS enumeration) for non-standard ports.
2. Focus on management interfaces (8080, 8443, 9090, 3000, 8888) and database ports (3306, 5432, 27017, 6379).
3. Check TLS certificates on raw IPs -- the CN/SAN fields reveal which service is running.
4. Admin interfaces on non-standard ports frequently lack authentication or use default credentials.
