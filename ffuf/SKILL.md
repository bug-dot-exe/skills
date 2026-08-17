---
name: ffuf
description: ffuf fuzzing syntax with matcher/filter strategy and non-interactive defaults.
depends_on: []
---

# ffuf CLI Playbook

Official docs:
- https://github.com/ffuf/ffuf

Canonical syntax:
`ffuf -w <wordlist> -u <url_with_FUZZ> [flags]`

High-signal flags:
- `-u <url>` target URL containing `FUZZ`
- `-w <wordlist>` wordlist input (supports `KEYWORD` mapping via `-w file:KEYWORD`)
- `-mc <codes>` match status codes
- `-fc <codes>` filter status codes
- `-fs <size>` filter by body size
- `-ac` auto-calibration
- `-t <n>` threads
- `-rate <n>` request rate
- `-timeout <seconds>` HTTP timeout
- `-x <proxy_url>` upstream proxy (HTTP/SOCKS)
- `-ignore-body` skip downloading response body
- `-noninteractive` disable interactive console mode
- `-recursion` and `-recursion-depth <n>` recursive discovery
- `-H <header>` custom headers
- `-X <method>` and `-d <body>` for non-GET fuzzing
- `-o <file> -of <json|ejson|md|html|csv|ecsv>` structured output

Agent-safe baseline for automation:
`ffuf -w wordlist.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403,405 -ac -t 20 -rate 50 -timeout 10 -noninteractive -of json -o ffuf.json`

Common patterns:
- Basic path fuzzing:
  `ffuf -w /path/wordlist.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403 -ac -t 40 -rate 200 -noninteractive`
- Vhost fuzzing:
  `ffuf -w vhosts.txt -u https://target.tld -H 'Host: FUZZ.target.tld' -fs 0 -ac -noninteractive`
- Parameter value fuzzing:
  `ffuf -w values.txt -u 'https://target.tld/search?q=FUZZ' -mc all -fs 0 -ac -t 30 -noninteractive`
- POST body fuzzing:
  `ffuf -w payloads.txt -u https://target.tld/login -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=admin&password=FUZZ' -fc 401 -noninteractive`
- Recursive discovery:
  `ffuf -w dirs.txt -u https://target.tld/FUZZ -recursion -recursion-depth 2 -ac -t 30 -noninteractive`
- Proxy-instrumented run:
  `ffuf -w wordlist.txt -u https://target.tld/FUZZ -x http://127.0.0.1:48080 -mc 200,301,302,403 -ac -noninteractive`

Critical correctness rules:
- `FUZZ` must appear exactly at the mutation point in URL/header/body.
- If using `-w file:KEYWORD`, that same `KEYWORD` must be present in URL/header/body.
- Always include `-noninteractive` in agent/script execution to prevent ffuf console mode from swallowing subsequent shell commands.
- Save structured output with `-of json -o <file>` for deterministic parsing.

Usage rules:
- Prefer explicit matcher/filter strategy (`-mc`/`-fc`/`-fs`) over default-only output.
- Start conservative (`-rate`, `-t`) and scale only if target tolerance is known.
- Do not use `-h`/`--help` during normal execution unless absolutely necessary.

Failure recovery:
- If ffuf drops into interactive mode, send `C-c` and rerun with `-noninteractive`.
- If response noise is too high, tighten `-mc/-fc/-fs` instead of increasing load.
- If runtime is too long, lower `-rate/-t` and tighten scope.

If uncertain, query web_search with:
`site:github.com/ffuf/ffuf <flag> README`

## SecOpsAgentKit contributions

Additional patterns sourced from SecOpsAgentKit's `appsec/dast-ffuf/SKILL.md`. Use these when bug.exe's tighter CLI playbook above doesn't already cover the surface you need.

### Fuzzing Modes

ffuf supports three input-iteration modes when multiple wordlists are wired in via `KEYWORD` placeholders:

- **clusterbomb** (default) — Cartesian product of all wordlists. Tests every combination:
  `ffuf -u https://target.tld/FUZZ1/FUZZ2 -w dirs.txt:FUZZ1 -w files.txt:FUZZ2 -mode clusterbomb`
- **pitchfork** — parallel iteration; pairs wordline-1 of A with wordline-1 of B, etc. Stops at the shortest list:
  `ffuf -u https://target.tld/login -X POST -d "u=FUZZ1&p=FUZZ2" -w users.txt:FUZZ1 -w passwords.txt:FUZZ2 -mode pitchfork`
- **sniper** — single wordlist iterated across multiple positions:
  `ffuf -u https://target.tld/FUZZ -w wordlist.txt -mode sniper`

### Auth-Endpoint Patterns

- **Username discovery via differential response**:
  `ffuf -u https://target.tld/login -X POST -d "username=FUZZ&password=test" -w users.txt -mr "Invalid password|Incorrect password"`
  The `-mr` regex matches responses indicating a valid username (different error than for invalid users).
- **Password spray on confirmed user**:
  `ffuf -u https://target.tld/login -X POST -d "username=admin&password=FUZZ" -w passwords.txt -fc 401,403`

### Cookie / Header Fuzzing

- Cookie value fuzzing: `ffuf -u https://target.tld/dashboard -b "session=FUZZ" -w session-tokens.txt -mc 200`
- Custom header value fuzzing: `ffuf -u https://target.tld/admin -H "X-Forwarded-For: FUZZ" -w ips.txt -mc 200`
- Cookie name fuzzing: `ffuf -u https://target.tld/admin -b "FUZZ=admin" -w cookie-names.txt`

### OWASP WSTG Mapping

| ffuf use case | OWASP WSTG ID | Description |
|---|---|---|
| Backup file discovery | WSTG-CONF-04 | Old backup and unreferenced files |
| Admin interface enumeration | WSTG-CONF-05 | Infrastructure and admin interfaces |
| HTTP method fuzzing | WSTG-CONF-06 | HTTP methods |
| Directory traversal probes | WSTG-ATHZ-01 | Directory traversal / file include |
| Reflected XSS via parameter fuzz | WSTG-INPVAL-01 | Reflected XSS |

## Corpus-Derived Advanced Techniques

### Routing-Layer Path Confusion

Fuzz URL paths with special characters to detect misrouting between load balancers, CDNs, and backends:
```bash
# Characters that trigger path-confusion between intermediary and origin
ffuf -w path-specials.txt:FUZZ -u 'https://target.tld/FUZZadmin/config' \
  -mc all -fc 404 -ac -noninteractive -o path_confusion.json -of json
# Wordlist contents: @, \, ;, .., %00, %2f, %2e%2e, leading -, %0a, %0d
```
Monitor for different responses (403 vs 200, different server headers, different body sizes) that reveal the frontend and backend disagree on path routing.

### Subdomain x Admin-Path Matrix Scan

Combine subdomain enumeration with admin-path fuzzing for exposed management interfaces:
```bash
# Two-keyword mode: subdomain x path
ffuf -w subdomains.txt:SUB -w admin-paths.txt:PATH \
  -u 'https://SUB.target.tld/PATH' \
  -mc 200,301,302,401,403 -ac -t 30 -rate 100 -noninteractive \
  -mode clusterbomb -o matrix.json -of json
```

### Debug and Backup Endpoint Discovery

Probe for framework-specific debug endpoints and file backups:
```bash
# Framework debug endpoints
ffuf -w debug-endpoints.txt -u 'https://target.tld/FUZZ' \
  -mc 200,500 -ac -noninteractive
# Wordlist includes: Trace.axd, Elmah.axd, /_layouts/15/start.aspx,
# /actuator, /debug, /phpinfo.php, /_debugbar, /telescope, /__debug__/
```
For every discovered script file, fuzz backup extensions:
```bash
ffuf -w backup-exts.txt:EXT -u 'https://target.tld/config.phpEXT' \
  -mc 200 -noninteractive
# Extensions: .bak, .old, .orig, .save, .swp, ~, .copy, .tmp, .dist, .0
```

### Cache Poisoning Header Fuzzing

Brute-force unkeyed headers to identify cache poisoning vectors:
```bash
ffuf -w unkeyed-headers.txt:HDR -u 'https://target.tld/' \
  -H 'HDR: evil.attacker.tld' -mc all -ac -noninteractive \
  -o cache_poison.json -of json
# After run: diff responses where unkeyed header value appears reflected
# Key headers: X-Forwarded-Host, X-Original-URL, X-Rewrite-URL,
# X-Forwarded-Scheme, X-Forwarded-Proto
```

### WebSocket Event Fuzzing

Fuzz WebSocket message types after enumerating event schemas via traffic interception:
```bash
# Fuzz WebSocket endpoint parameters discovered during crawl
ffuf -w ws-events.txt -u 'https://target.tld/ws?event=FUZZ' \
  -mc all -ac -noninteractive
```

### Data-Store Fingerprint Then Fuzz

Fingerprint the backend data store before choosing injection payloads:
```bash
# Solr/Lucene detection (faceted responses, q/fq parameters)
ffuf -w solr-payloads.txt -u 'https://target.tld/search?q=FUZZ' \
  -mc 200 -ac -noninteractive -fr 'error'
# GraphQL variable fuzzing for IDOR
ffuf -w graphql-vars.txt -u 'https://target.tld/graphql?query={user(id:FUZZ){email}}' \
  -mc 200 -ac -noninteractive
```
