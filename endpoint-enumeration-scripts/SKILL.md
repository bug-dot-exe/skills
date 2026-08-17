---
name: endpoint-enumeration-scripts
category: reconnaissance
description: Custom scripted endpoint discovery — JS bundle extraction, target-aware wordlist generation, response diffing, and API path inference
depends_on: []
---

# Endpoint Enumeration Scripts

## When to Use
- Standard wordlists produce too many 404s (target uses custom routing)
- Target is a SPA with all routes defined in JavaScript
- You need a target-specific wordlist built from the target's own content
- After initial recon, to go deeper on a specific service

## Methodology

### Script 1: Build Wordlist from JS Bundles

Extract real API paths from the target's own JavaScript:

```bash
# Collect all JS files (from crawl + historical)
cat crawl_*.txt urls_*.txt 2>/dev/null | grep -iE "\.js(\?|$)" | sort -u > all_js.txt

# Download and extract API paths
mkdir -p js_download
for js in $(head -100 all_js.txt); do
  FNAME=$(echo "$js" | md5sum | cut -c1-8).js
  curl -s "$js" -o "js_download/$FNAME" --max-time 10 2>/dev/null
done

# Extract quoted paths (API routes)
grep -rohP '["'"'"'][/][a-zA-Z0-9_/\-\.{}\:]+["'"'"']' js_download/ 2>/dev/null | \
  tr -d '"'"'"'' | sort -u > js_api_paths.txt

# Extract fetch/axios/XMLHttpRequest URLs
grep -rohP '(fetch|axios\.\w+|\.open)\s*\(\s*["'"'"'`][^"'"'"'`]+' js_download/ 2>/dev/null | \
  grep -oP '["'"'"'`][^"'"'"'`]+' | tr -d '"'"'"'`' | sort -u >> js_api_paths.txt

# Extract template literals with API paths
grep -rohP '`[^`]*/(?:api|v[0-9]+|auth|admin|user)[^`]*`' js_download/ 2>/dev/null | \
  tr -d '`' | sort -u >> js_api_paths.txt

sort -u -o js_api_paths.txt js_api_paths.txt
echo "[+] $(wc -l < js_api_paths.txt) paths extracted from JS"
```

### Script 2: Build Wordlist from Historical URLs

```bash
# Extract path components from all historical URLs
cat all_historical.txt 2>/dev/null | unfurl -u paths 2>/dev/null | \
  sed 's|^/||' | sort -u > historical_wordlist.txt

# Extract directory structure (for recursive fuzzing)
cat historical_wordlist.txt | tr '/' '\n' | sort | uniq -c | sort -rn | \
  awk '$1 > 1 {print $2}' > directory_components.txt

echo "[+] $(wc -l < historical_wordlist.txt) paths from historical URLs"
echo "[+] $(wc -l < directory_components.txt) common directory names"
```

### Script 3: Response Diffing for Hidden Endpoints

Detect endpoints that return different responses than the default 404:

```bash
# Get baseline 404 response size
BASELINE=$(curl -s "$TARGET/definitely-not-a-real-path-$(date +%s)" -o /dev/null -w "%{size_download}")

# Fuzz and filter by response size difference
ffuf -u "$TARGET/FUZZ" \
  -w custom_wordlist.txt \
  -fs "$BASELINE" \
  -mc all \
  -t 30 -o diff_results.json -of json

# Alternative: use wfuzz with response code + size filtering
# wfuzz -u "$TARGET/FUZZ" -w custom_wordlist.txt --hc 404 --hh $BASELINE
```

### Script 4: API Version & Path Permutation

```bash
# Given a known endpoint, discover variations
BASE_PATH="/api/users"

# Version permutation
for ver in "" /v1 /v2 /v3 /v4 /beta /staging /internal /private; do
  FULL="$TARGET${ver}${BASE_PATH}"
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$FULL" --max-time 3)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "[+] $FULL → $CODE"
done

# Method permutation on discovered endpoint
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$TARGET$BASE_PATH" --max-time 3)
  echo "$method $BASE_PATH → $CODE"
done
```

### Script 5: Combine All Sources into Master Wordlist

```bash
# Merge: JS paths + historical paths + generic wordlist + known endpoints
cat js_api_paths.txt historical_wordlist.txt 2>/dev/null | sort -u > target_wordlist.txt

# Enrich with common suffixes
while read path; do
  echo "$path"
  echo "${path}/"
  echo "${path}.json"
  echo "${path}.xml"
  echo "${path}?format=json"
done < target_wordlist.txt | sort -u > enriched_wordlist.txt

echo "[+] Master wordlist: $(wc -l < enriched_wordlist.txt) entries"
echo "[+] This wordlist is TARGET-SPECIFIC — far more effective than generic wordlists"

# Final ffuf pass with enriched target-aware wordlist
ffuf -u "$TARGET/FUZZ" -w enriched_wordlist.txt \
  -mc 200,201,301,302,401,403,405,500 -t 40
```

## Corpus-Derived Hunting Patterns

### Client-Side Path Traversal (CSPT) Discovery

Any URL-bar parameter that becomes a path segment in a same-origin API call is a CSPT candidate. For every JS fetch/XHR call found in Script 1 that constructs a URL from window.location or URL parameters:
1. Identify the parameter that controls the path segment
2. Inject `../` sequences to traverse into sibling API routes
3. Test whether the traversed route returns data the original route would not
This is the client-side analog of SSRF and has produced payouts exceeding $1M.

### Search-vs-Direct ACL Split Testing

For any platform with both a "list/search/filter" endpoint AND a "direct read" endpoint for the same data:
1. Find resources via the search endpoint (which applies visibility filters)
2. Note the IDs of returned objects
3. Access the direct-read endpoint with IDs of resources NOT in search results
4. If direct-read returns data the search hid, the ACL is only on the search layer

### Method Swap Matrix

For every endpoint discovered, systematically test auth enforcement per HTTP method:
1. **Method swap**: if GET requires auth, try POST/PUT/PATCH/DELETE (and vice versa)
2. **Content-Type swap**: send the same body as `application/json`, `application/x-www-form-urlencoded`, and `multipart/form-data`
3. **CSRF enforcement check**: for every destructive action, test if the endpoint accepts a non-canonical method and if CSRF validation is method-conditional

### GraphQL Schema Mining

For any GraphQL endpoint:
1. Acquire the schema via introspection or client-side `.graphql`/`.gql` files
2. For every query/mutation that takes an object identifier, test authorization on the resolver -- not the query gateway
3. Check for field-level auth gaps: a query may authorize the top-level object but leak sensitive nested fields
4. Test union/inline-fragment type confusion to access fields from types you should not see

### Import/Deserialization Privilege Boundaries

For any platform with import/export of complex data (projects, organizations, sites, templates):
1. Export a legitimate object and inspect the serialized format
2. Modify internal references to point to resources in other tenants
3. Import the modified payload and observe whether cross-tenant references resolve
4. Test whether import bypasses validation that the UI enforces (file size, allowed types, field restrictions)

### Deployment Artifact Auditing

Audit deployment configuration files in OSS repos, not just application code. Web app security depends on reverse-proxy/WAF/ingress configuration as much as on the code itself:
1. Search for `nginx.conf`, `apache.conf`, `.htaccess`, Kubernetes ingress YAMLs in the target's public repos
2. Look for `alias` directives in nginx (classic `alias` traversal when `location` lacks trailing slash)
3. Check `proxy_pass` rules for path normalization mismatches between the proxy and the backend

### Metadata-Derived Filename Tracing

For any feature that extracts data from uploaded files and uses it for naming or storage:
- Image uploads: EXIF `Artist`, `Copyright`, `ImageDescription` fields
- Archives: internal file paths in ZIP/TAR entries
- Documents: metadata `Title`, `Author`, `Subject` fields
- Packages: `name` field in `package.json`, `pom.xml`, `setup.py`
If any extracted value becomes a filesystem path or URL path segment, test path traversal through the metadata field.

## Key Insight

Generic wordlists contain 100K+ entries with <1% hit rate. A target-aware wordlist built from the target's own JS + historical URLs has 50-500 entries with 10-30% hit rate. Quality over quantity.
