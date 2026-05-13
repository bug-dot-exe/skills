---
name: zap
description: OWASP ZAP DAST scanner — passive baseline + active scan + API spec testing for XSS/SQLi/SSRF, runnable via Docker for sandbox-friendly automation
depends_on: []
---

# OWASP ZAP DAST

ZAP (Zed Attack Proxy) is OWASP's flagship DAST tool. It acts as a manipulator-in-the-middle proxy, spiders the application, performs passive checks on every observed response, then optionally runs active scanners that send real exploit payloads. For autonomous agents, the Docker-packaged automation modes (`zap-baseline.py`, `zap-full-scan.py`, `zap-api-scan.py`) are the highest-leverage entry points.

## Prerequisites

- Docker (install: `apt install docker.io`, ensure the agent's runtime can spawn containers — bug.exe's sandbox supports this when the agent has `docker` access)
- 4GB+ RAM for full-scan mode
- Network egress to the target

For headless installs without Docker:
- ZAP CLI via Java 11+: download release ZIP from https://www.zaproxy.org/download/, run `zap.sh -daemon -port 8080`

## Canonical Syntax (Docker)

`docker run -t zaproxy/zap-stable <script>.py [flags]`

Three primary scripts:
- `zap-baseline.py` — passive scan only (safe to run against production with permission)
- `zap-full-scan.py` — passive + active scan (sends real attack payloads — get authorization)
- `zap-api-scan.py` — API-specification-driven scan (OpenAPI/GraphQL/SOAP)

## High-Signal Flags (`zap-baseline.py` / `zap-full-scan.py`)

- `-t <url>` target URL (required)
- `-r <file>` HTML report output
- `-J <file>` JSON report output
- `-x <file>` XML report output
- `-w <file>` Markdown report output
- `-a` include alpha-grade passive checks
- `-j` use Ajax spider (for SPAs/heavy-JS apps)
- `-d` debug mode (verbose log)
- `-m <mins>` spider time cap in minutes (default 1)
- `-T <mins>` total time cap in minutes (default unlimited; use `-T 60` for safety)
- `-z "-config <key>=<val>"` raw ZAP config overrides (e.g., proxy headers, scope regex)
- `-l <level>` minimum alert level: `INFO`, `LOW`, `MEDIUM`, `HIGH`
- `-I` do not return non-zero exit code on warnings (warnings only)

## High-Signal Flags (`zap-api-scan.py`)

Adds:
- `-f openapi|graphql|soap` API spec format (required)
- `-d <path>` path to spec file (mounted into container)

## Agent-Safe Baseline (Docker, mounted output dir)

```bash
mkdir -p zap-out
docker run --rm -t \
  -v "$(pwd)/zap-out:/zap/wrk:rw" \
  zaproxy/zap-stable zap-baseline.py \
    -t https://target.tld \
    -J /zap/wrk/zap.json \
    -r /zap/wrk/zap.html \
    -m 5 \
    -T 30 \
    -l MEDIUM
```

This runs a 30-minute-capped passive scan with a 5-min spider, dumps JSON+HTML to `./zap-out/`, and returns non-zero on MEDIUM-and-above findings.

## Common Patterns

- **Quick passive baseline (CI gate)**:
  `docker run -t zaproxy/zap-stable zap-baseline.py -t https://staging.target.tld -J zap.json -m 2 -T 10`

- **Full active scan against staging only** (NEVER against production without authorization):
  ```bash
  docker run --rm -t -v "$(pwd):/zap/wrk:rw" zaproxy/zap-stable zap-full-scan.py \
    -t https://staging.target.tld \
    -r /zap/wrk/zap.html -J /zap/wrk/zap.json \
    -T 120 -l LOW
  ```

- **API spec-driven scan**:
  ```bash
  docker run --rm -t -v "$(pwd):/zap/wrk:rw" zaproxy/zap-stable zap-api-scan.py \
    -t https://api.target.tld \
    -f openapi -d /zap/wrk/openapi.yaml \
    -r /zap/wrk/zap-api.html -J /zap/wrk/zap-api.json
  ```

- **Ajax spider for SPAs** (Vue/React/Angular):
  `docker run -t zaproxy/zap-stable zap-baseline.py -t https://spa.target.tld -j -m 10 -T 60`

- **Authenticated scan**: ZAP supports form auth, scripted auth, OAuth via context files. Use `-z "-config <auth_config_keys>=<values>"` or pass a pre-built ZAP context XML via `-n /zap/wrk/auth-context.xml`.

## Sandbox / Network Concerns for Autonomous Agents

- ZAP needs outbound network egress to the target. If the bug.exe sandbox restricts egress, ensure the target is allow-listed.
- ZAP active scans send real exploit payloads — confirm the target is in scope and authorization exists before triggering `zap-full-scan.py`.
- Docker-in-Docker (DinD): if running ZAP from inside another container, use `--network=host` only when target is local; otherwise prefer host-side `docker run`.
- Containers exit with code 0 by default unless any rule is fired; use `-l MEDIUM` to gate CI on real findings.

## Output Formats

| Flag | Format | Best for |
|---|---|---|
| `-r` | HTML | Human review, embedded screenshots |
| `-J` | JSON | Automation, downstream parsing |
| `-x` | XML | Legacy CI tools (JUnit-style integrations) |
| `-w` | Markdown | PR-friendly summary |

JSON schema preserves alert metadata: `name`, `risk`, `confidence`, `cweid`, `wascid`, `url`, `param`, `evidence`, `solution`, `references`.

## Critical Correctness Rules

- ALWAYS pass `-T <mins>` to cap total runtime — ZAP has no default ceiling and can run for hours on dynamic apps.
- The "baseline" script never sends attack payloads, but it DOES make many requests during spidering. If the target has rate limits, throttle via `-z "-config spider.maxDuration=N -config spider.threadCount=2"`.
- The `-a` (alpha checks) flag enables experimental scanners — useful for exploration, may produce more false positives.
- The active scan WILL send SQLi, XSS, command-injection payloads to every input it spiders. Confirm scope before running.

## Failure Recovery

- If the container exits immediately with no report: check Docker has the image (`docker pull zaproxy/zap-stable`), and verify volume permissions if the script can't write to `/zap/wrk`.
- If the scan finds zero alerts on a known-vulnerable target: increase spider time (`-m 30`), enable Ajax spider (`-j`), or pre-seed the URL list with `-z "-config spider.startingFile=/zap/wrk/seeds.txt"`.
- For 401/403 responses on every URL: configure authenticated context (form auth, OAuth) before scanning — passive-mode auth-walls report nothing useful.

## OWASP Top 10 Coverage

ZAP's active scanner covers most of OWASP Top 10:
- A01 Broken Access Control: limited (better via authenticated session-replay)
- A02 Cryptographic Failures: TLS/cookie checks (passive)
- A03 Injection: SQLi, XSS, command, LDAP, XPath (active)
- A04 Insecure Design: limited (passive checks for missing security headers)
- A05 Security Misconfiguration: header/cookie/version-disclosure (passive + active)
- A06 Vulnerable Components: passive version checks via fingerprints
- A07 Authentication Failures: weak-password, session-fixation (active in authed scans)
- A08 Data Integrity Failures: limited
- A09 Logging Failures: not covered (server-side concern)
- A10 SSRF: active probe via header injection

## SecOpsAgentKit contributions

Sourced from SecOpsAgentKit's `appsec/dast-zap/SKILL.md` (Docker-mode invocations, three-script split, OWASP Top 10 coverage matrix, time-cap and authentication patterns). Adapted to bug.exe's CLI-playbook format.

## Corpus-Derived Advanced Techniques

### Parser-Differential Request Smuggling

Use ZAP as the request-crafting proxy for HTTP desync testing between CDN/LB and origin:
```bash
# Step 1: passive scan to fingerprint intermediary (Server header, Via header)
docker run --rm -t -v "$(pwd)/zap-out:/zap/wrk:rw" zaproxy/zap-stable \
  zap-baseline.py -t https://target.tld -J /zap/wrk/fingerprint.json -m 2 -T 5
# Step 2: manual request-smuggling payloads via ZAP's requester
# Test bare CR (\r without \n), CL/TE conflicts, HTTP/2-to-HTTP/1.1 downgrade
# RFC corner cases: "MAY contain X" or "SHOULD reject Y" — test the gap
```
Protocol-translating proxies (HTTP/2 frontend, HTTP/1.1 backend) are high-value targets. Check for `h2` in response ALPN, then test request-line injection via pseudo-headers.

### Deployment Artifact Auditing

Scan for reverse-proxy and ingress misconfigurations that live outside application code:
```bash
# Nginx alias traversal: /assets../etc/passwd
docker run --rm -t -v "$(pwd)/zap-out:/zap/wrk:rw" zaproxy/zap-stable \
  zap-full-scan.py -t https://target.tld \
  -z "-config spider.seedList=https://target.tld/assets../,https://target.tld/static../" \
  -r /zap/wrk/alias_traversal.html -T 30
```
Check OSS deployment manifests (Helm charts, Dockerfiles, nginx.conf in repos) for misconfigured `alias`, `proxy_pass`, and `location` directives.

### Mobile-App GraphQL Endpoint Discovery

Proxy mobile traffic through ZAP to discover GraphQL endpoints invisible from web:
```bash
# Configure device/emulator to proxy through ZAP
docker run --rm -t -p 8080:8080 -v "$(pwd)/zap-out:/zap/wrk:rw" zaproxy/zap-stable \
  zap-baseline.py -t https://api.target.tld \
  -z "-config api.disablekey=true -config network.localServers.mainProxy.port=8080" \
  -J /zap/wrk/mobile_graphql.json -T 60
```
After capturing, replay each GraphQL query with modified authorization and variable values.

### Tool-as-Victim Attack Surface

Security tools that fetch attacker-controlled content are themselves targets:
- ZAP rendering engine, Burp Scanner, screenshot tools, link-preview bots
- Plant XSS/clickjacking payloads on attacker-controlled pages
- If scanning tools render JS: test for local file read, SSRF via the tool itself

### Redirect-Following Proxy Audit

Test server-to-server redirect behavior for token leakage:
```bash
# ZAP active scan with redirect-following enabled
docker run --rm -t -v "$(pwd)/zap-out:/zap/wrk:rw" zaproxy/zap-stable \
  zap-full-scan.py -t https://target.tld \
  -z "-config spider.handleODataParametersVisited=true" \
  -r /zap/wrk/redirect_audit.html -J /zap/wrk/redirect_audit.json -T 60
```
Check: does the proxy forward `Authorization` headers through 3xx redirects to a different origin?

### Host Header Poisoning on Authenticated Endpoints

```bash
# Pre-seed ZAP with auth endpoints and test Host header behavior
docker run --rm -t -v "$(pwd)/zap-out:/zap/wrk:rw" zaproxy/zap-stable \
  zap-full-scan.py -t https://target.tld/graphql \
  -z "-config replacer.full_list(0).description=HostSwap \
       -config replacer.full_list(0).matchtype=REQ_HEADER \
       -config replacer.full_list(0).matchstring=Host \
       -config replacer.full_list(0).replacement=evil.attacker.tld" \
  -r /zap/wrk/host_header.html -T 30
```
If the response reflects the injected Host value, test for password-reset poisoning and cache key manipulation.
