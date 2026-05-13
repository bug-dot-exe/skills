---
name: bbrecon-parameter-discovery
description: Deep parameter and endpoint discovery for bug bounty recon. Use after bbrecon crawl/post_assets, when mapping API attack surface, or when gf/arjun/paramspider return few results. Covers JS-extracted params, Wayback param mining, response-based inference, and high-value parameter patterns.
---

# bbrecon Parameter Discovery

Finds hidden parameters that drive IDOR, SSRF, XSS, and injection.

## When to Use

- Param discovery returns few results
- Testing API endpoints (need all params)
- Target has heavy JS (params in client code)
- Wayback has old URLs with different params

## 1. bbrecon Integration

bbrecon runs `param_discovery` in POST_ASSET_INTEL. Output:

- `ACTIVE/PARAMS/all.params.txt` — paramspider + arjun results
- `ACTIVE/PARAMS/` — per-endpoint param files

This skill extends those results.

## 2. JavaScript Parameter Extraction

Params in JS often not in HTML forms.

```bash
# From downloaded JS (getJS, crawl)
grep -rohE "(params|query|body)\s*[=:]\s*\{[^}]*\}" JS/*.js | head -50

# Common patterns
grep -rE "(param|query|searchParams|getParam|urlParam)\(['\"]?([a-zA-Z_][a-zA-Z0-9_]*)['\"]?" JS/ | grep -oE "[a-zA-Z_][a-zA-Z0-9_]*" | sort -u

# React/Vue: useSearchParams, $route.query, router.query
grep -rE "(useSearchParams|route\.query|router\.query|params\.)" JS/ | grep -oE "[a-zA-Z_][a-zA-Z0-9_]*" | sort -u
```

## 3. Wayback Parameter Mining

Old URLs often have params removed from current UI.

```bash
# Get all URLs
waybackurls target.com | sort -u > .tmp/wayback.txt

# Extract params
cat .tmp/wayback.txt | grep -oE "[?&]([a-zA-Z_][a-zA-Z0-9_]*)=[^&]*" | cut -d'=' -f1 | tr -d '?&' | sort -u > ACTIVE/PARAMS/wayback_params.txt

# High-value param names
grep -iE "(id|user|admin|redirect|url|callback|file|path|cmd|exec|debug)" ACTIVE/PARAMS/wayback_params.txt
```

## 4. Response-Based Inference

Server error messages or behavior reveal param names.

```bash
# Send invalid param, check error
curl -s "https://target.com/api/user?id=invalid" 
# If error says "user_id must be..." → try user_id

# Arjun with response diff
arjun -u https://target.com/endpoint -m GET -o arjun_results.json
# Arjun detects params by response length/body changes
```

## 5. High-Value Parameter Patterns

| Category | Params | Vuln Class |
|----------|--------|------------|
| ID reference | id, user_id, account_id, order_id | IDOR |
| URL/redirect | url, redirect, return_to, next, callback | Open redirect, SSRF |
| File | file, path, document, attachment | Path traversal, LFI |
| Command | cmd, exec, command, query | RCE, SQLi |
| Debug | debug, trace, verbose, log | Info disclosure |
| Auth | token, key, secret, session | Auth bypass |

```bash
# Merge with custom wordlist
cat ACTIVE/PARAMS/all.params.txt wordlists/params_highvalue.txt | sort -u > ACTIVE/PARAMS/extended.txt
```

## 6. API Parameter Discovery

REST/GraphQL params differ from web params.

```bash
# From OpenAPI/Swagger
curl -s https://target.com/swagger.json | jq -r '.paths[].parameters[].name' | sort -u

# From GraphQL schema
jq -r '.data.__schema.types[].fields[]?.name' graphql_schema.json | sort -u

# From request capture (Caido)
# Export requests, grep for param names in query/body
```

## 7. gf Integration

bbrecon uses gf for vuln categorization. Param discovery feeds gf:

```bash
# After param discovery
cat ACTIVE/PARAMS/all.params.txt | while read p; do
  echo "https://target.com/page?$p=PAYLOAD"
done | gf idor
```

## 8. Wordlist Sources

- SecLists: `Discovery/Web-Content/burp-parameter-names.txt`
- Assetnote: `http-parameters`
- Custom: params from similar programs (disclosed reports)

## Output Convention

- `ACTIVE/PARAMS/all.params.txt` — merged params
- `ACTIVE/PARAMS/wayback_params.txt` — Wayback-derived
- `ACTIVE/PARAMS/js_params.txt` — JS-extracted

## References

- bbrecon: modules/post_assets/param_discovery
- bb-hunter: recon.md (arjun, paramspider)
- strix-idor, strix-ssrf — param-specific testing
