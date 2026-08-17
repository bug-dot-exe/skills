---
name: parameter-discovery
category: reconnaissance
description: Discover hidden parameters via arjun, historical URL mining, JS extraction, and manual probing for injection targets
depends_on: []
---

# Parameter Discovery

## When to Use
- After endpoint discovery, before injection testing
- When endpoints return different responses with unknown parameters
- To find hidden debug/admin parameters not in documentation
- To build the parameter → injection testing matrix

## Methodology

### Phase 1: Historical Parameter Extraction

Parameters from historical URLs are high-confidence — the target actually used them:

```bash
# Extract all parameter names from historical URLs
cat all_historical.txt 2>/dev/null | grep "?" | \
  unfurl -u keys 2>/dev/null | sort | uniq -c | sort -rn > params_historical.txt

# Extract full key=value pairs (reveals expected formats)
cat all_historical.txt 2>/dev/null | grep "?" | \
  unfurl -u keypairs 2>/dev/null | sort | uniq -c | sort -rn > params_with_values.txt

echo "[+] $(wc -l < params_historical.txt) unique parameter names from history"
```

### Phase 2: Automated Parameter Discovery

```bash
# arjun — brute-force hidden parameters (GET + POST)
arjun -u "$TARGET/api/endpoint" -m GET POST -oJ arjun_results.json 2>/dev/null

# x8 — faster alternative with custom wordlists
x8 -u "$TARGET/api/endpoint" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -X GET POST 2>/dev/null

# paramspider — mine parameters from web archives
paramspider -d "$DOMAIN" 2>/dev/null
```

### Phase 3: Manual High-Value Parameter Probing

Test parameters that commonly lead to vulnerabilities:

```bash
# IDOR parameters (test with different IDs)
for param in id user_id uid account_id org_id team_id project_id file_id doc_id order_id; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/api/endpoint?$param=1" --max-time 5)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "[IDOR] $param → HTTP $CODE"
done

# SSRF/Redirect parameters (test with external URL)
for param in url redirect next return_to callback continue dest destination forward ref uri; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET?$param=https://example.com" --max-time 5)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "[SSRF/REDIRECT] $param → HTTP $CODE"
done

# File/Path parameters (test with known file)
for param in file path filename template include page view resource src; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET?$param=/etc/passwd" --max-time 5)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "[LFI] $param → HTTP $CODE"
done

# Injection parameters (test with special chars)
for param in search query q filter sort cmd exec command input data; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET?$param=test'%22%3E" --max-time 5)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "[INJECTION] $param → HTTP $CODE"
done

# Debug/Admin parameters
for param in debug test admin verbose trace log mode env config internal dev; do
  for val in true 1 yes on; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET?$param=$val" --max-time 3)
    [ "$CODE" = "200" ] && echo "[DEBUG] $param=$val → HTTP $CODE"
  done
done
```

### Phase 4: JS Parameter Extraction

```bash
# Extract parameter names from JS fetch/axios calls
grep -rohP '(params|data|body)\s*[:=]\s*\{[^}]+\}' js_download/ 2>/dev/null | \
  grep -oP '"([a-zA-Z_]+)"' | tr -d '"' | sort -u > params_from_js.txt

# Extract query string construction
grep -rohP '[\?&]([a-zA-Z_]+)=' js_download/ 2>/dev/null | \
  sed 's/[?&]//;s/=//' | sort -u >> params_from_js.txt
```

## Parameter → Vulnerability Mapping

After discovering parameters, map them to vulnerability classes:

- `id`, `user_id`, `account_id` → **IDOR** (change values, check access control)
- `url`, `redirect`, `next` → **SSRF / Open Redirect** (inject external URLs)
- `file`, `path`, `template` → **LFI / Path Traversal / SSTI** (inject paths/templates)
- `search`, `query`, `filter` → **SQLi / XSS** (inject payloads)
- `cmd`, `exec`, `command` → **RCE** (inject OS commands)
- `debug`, `admin`, `test` → **Info Disclosure** (toggle hidden features)
- `callback`, `jsonp` → **XSS** (inject JavaScript)
- `format`, `output` → **XXE** (request XML format)

---

## Advanced Parameter Discovery Techniques

The following techniques extend the core methodology with parameter discovery patterns from high-value disclosed reports. Standard parameter brute-forcing finds the obvious params; these patterns find the ones that pay bounties.

### Phase 5: Deep JS Bundle Parameter Mining

JavaScript bundles contain the client-side contract of what parameters the API accepts. Mining them systematically reveals parameters that automated tools miss.

```bash
# Download all JS files
katana -u "$TARGET" -jc -d 3 -ef css,png,jpg,svg 2>/dev/null | grep '\.js$' | sort -u > js_urls.txt
mkdir -p js_download
while read url; do
  fname=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -s "$url" -o "js_download/$fname" --max-time 10
done < js_urls.txt

# Extract API route definitions (React Router, Vue Router, Express routes)
grep -rohP '(path|route|url|endpoint)\s*[:=]\s*["\x27]/[^"\x27]+' js_download/ 2>/dev/null | \
  sed "s/.*['\"]//;s/['\"].*//" | sort -u > routes_from_js.txt

# Extract fetch/axios request bodies — reveals expected parameter shapes
grep -rohP '(fetch|axios\.(get|post|put|patch|delete))\s*\([^)]+' js_download/ 2>/dev/null | \
  grep -oP '(params|data|body|headers)\s*[:=]\s*\{[^}]*\}' | sort -u > request_shapes.txt

# Extract GraphQL operation names and variables
grep -rohP '(query|mutation)\s+\w+\s*\([^)]*\)' js_download/ 2>/dev/null | sort -u > graphql_ops.txt

# Extract internal API hostnames and base URLs
grep -rohP '(https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}(/[a-zA-Z0-9._/-]*)?)' js_download/ 2>/dev/null | \
  sort -u > internal_urls_from_js.txt
```

**Key technique**: diff JS bundles across application versions. Newly added parameters in a recent deploy are under-tested. Use Wayback Machine or APKMirror to obtain older JS bundles, then diff parameter names.

### Phase 6: Parameter Pollution and Duplicate Parameter Handling

When the same parameter name appears multiple times in a request, different components handle it differently. This confusion is exploitable.

1. **Test duplicate parameter behavior**: send `?param=valueA&param=valueB`. Which value does the server use? First? Last? Both? Array?
2. **Test cross-location pollution**: send the same parameter in the query string AND the POST body AND a header. Different frameworks merge these differently:
   - Express.js: query params override body params (by default)
   - PHP: last value wins for `$_REQUEST`, but `$_GET` and `$_POST` are separate
   - Java servlets: `getParameter()` returns first, `getParameterValues()` returns all
   - ASP.NET: comma-joins duplicate values
3. **Test WAF/app disagreement**: if a WAF checks `param=safe` in the query string but the app reads `param=malicious` from the body (or vice versa), the WAF is bypassed
4. **Test array parameter injection**: `?id[]=1&id[]=2` vs `?id=1,2` vs `?id=1&id=2`. Some frameworks auto-parse array syntax, creating injection opportunities when the app expects a scalar

```bash
# Test duplicate parameter handling
echo "[*] Testing duplicate param handling on $TARGET"
for endpoint in $(cat endpoints.txt | head -20); do
  RESP1=$(curl -s "$endpoint?test=FIRST&test=SECOND" --max-time 5)
  if echo "$RESP1" | grep -q "FIRST"; then echo "[FIRST-WINS] $endpoint"
  elif echo "$RESP1" | grep -q "SECOND"; then echo "[LAST-WINS] $endpoint"
  fi
done
```

### Phase 7: Content-Type Switching and Format Confusion

Changing the Content-Type of a request can bypass validation, trigger different parsers, or unlock hidden functionality.

1. **JSON to XML**: send the same data as XML with `Content-Type: application/xml` or `text/xml`. If the server parses XML, it may be vulnerable to XXE. Add a DOCTYPE with an external entity
2. **JSON to form-urlencoded**: change `Content-Type: application/json` to `application/x-www-form-urlencoded` and restructure the body. This can bypass CSRF protections that only check for JSON content types
3. **Form to multipart**: switch from `application/x-www-form-urlencoded` to `multipart/form-data`. Multipart parsers handle parameter boundaries differently, enabling injection in boundary strings or filename fields
4. **Test content-type header variations**: `application/json`, `application/json;charset=utf-8`, `text/json`, `application/vnd.api+json`, `application/csp-report` — some WAFs only check specific content type strings
5. **Check for accept-based routing**: change the `Accept` header to `application/xml`, `text/csv`, `application/pdf`. Some APIs return different formats based on Accept, and the alternate serializer may leak additional data or lack output encoding

```bash
# Test Content-Type switching for XXE
for endpoint in $(cat post_endpoints.txt); do
  echo "[*] Testing XML parsing on $endpoint"
  RESP=$(curl -s -X POST "$endpoint" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root><data>&xxe;</data></root>' \
    --max-time 5)
  [ -n "$RESP" ] && echo "$RESP" | head -5 && echo "---"
done
```

### Phase 8: API Versioning Parameter Discovery

API versioning creates parallel attack surfaces. Older versions frequently lack security controls added in newer versions.

1. **Enumerate version indicators**: check URL path (`/v1/`, `/v2/`, `/api/v3/`), query param (`?version=2`, `?api-version=2024-01`), headers (`Api-Version: 1`, `Accept: application/vnd.api.v1+json`), and subdomain (`v1.api.target.com`)
2. **Test every discovered endpoint against every version**: an endpoint secured in v3 may be unprotected in v1 if the v1 API is still live. Automate this with URL rewriting
3. **Check for version fallback**: what happens when you request a nonexistent version? Some APIs fall back to the oldest version (which has the least security controls)
4. **Test mixed-version requests**: use v1 authentication with v3 endpoints. Some APIs validate auth at the version router but apply business logic from the requested version
5. **Map deprecation status vs availability**: deprecated API versions may still respond to requests even when documentation says they are retired. "Deprecated" means "less monitored," not "turned off"

```bash
# Enumerate API versions
for ver in v1 v2 v3 v4 v5 api/v1 api/v2 api/v3; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$ver/" --max-time 5)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "[VERSION] /$ver/ → HTTP $CODE"
done

# Test version header variants
for ver in 1 2 3 "2024-01-01" "2023-01-01" "2022-01-01"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/api/endpoint" \
    -H "Api-Version: $ver" --max-time 5)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "[VERSION-HEADER] Api-Version: $ver → HTTP $CODE"
done
```

### Phase 9: Token Scope and Client ID Auditing

On platforms with multiple OAuth clients, each client's scope grants are a parameter discovery surface.

1. **Enumerate client IDs**: inspect OAuth login flows across the target's products. Each product may use a different `client_id` with different scope grants
2. **Map scopes per client**: capture the OAuth authorization URL for each client. Extract the `scope` parameter — each scope is a capability that may expose additional API parameters
3. **Test scope escalation**: request scopes assigned to Client A using Client B's flow. If the authorization server does not enforce per-client scope restrictions, you can escalate privileges
4. **Mine scope-gated parameters**: some API parameters only function when the token has specific scopes. Enumerate parameters from API docs, then test each with tokens of varying scope levels

### Phase 10: Redacted-Display Reconstruction and Search Parameter Mining

When a UI redacts data (masked emails, partial phone numbers, starred card numbers) but the underlying query layer is searchable, the search parameters become an oracle for reconstructing hidden data.

1. **Identify redacted displays**: look for masked values in the UI (`j***@example.com`, `****1234`, `+1***555****`)
2. **Find the search/filter endpoint**: identify the API endpoint that powers search, filtering, or autocomplete for the redacted data
3. **Test character-by-character search**: if the search endpoint accepts partial matches, use binary search on each character position to reconstruct the full value
4. **Check export endpoints**: data exports (CSV, PDF, API bulk endpoints) may return unredacted values even when the UI display is masked
5. **Test different parameter names for the same data**: the UI may show the redacted version via one parameter, but the API may accept an unredacted lookup via a different parameter name (e.g., `display_email` vs `email`, `masked_phone` vs `phone`)
