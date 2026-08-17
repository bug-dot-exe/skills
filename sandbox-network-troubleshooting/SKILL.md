---
name: sandbox-network-troubleshooting
category: methodology
description: When naabu / nmap / masscan returns 0 results, the target is not necessarily dead — it's usually the sandbox. This skill maps each failure mode to its root cause (CAP_NET_RAW, egress filter, IP reputation block, DNS, MTU) and provides the exact fallback command to run.
depends_on: []
---

# Sandbox Network Troubleshooting

A scanner returning 0 open ports is ambiguous. It could mean:

- The target is genuinely silent (no open ports / offline / filtered)
- The sandbox lacks the kernel capability for the scan mode the tool uses
  (naabu defaults to SYN which needs `CAP_NET_RAW`)
- The sandbox's egress IP is on the target's WAF / Shield blocklist
- DNS inside the container resolves to the wrong IP
- MTU mismatch silently drops the scan packets
- Rate limiting at the container runtime quietly discarded most packets

Never dismiss a target as "no ports open" until you've diagnosed WHICH of
these is true. The `diagnose_sandbox_network` tool runs the full ladder
automatically; this skill is the reference for interpreting its output
and for acting without the tool when you want to check something
specific.

## When to Use

- naabu / nmap / masscan returned 0 open ports against a target you
  expect to have some (any web host has 80 or 443)
- A scan says "all hosts probably down" but you can `curl` the site from
  your machine
- `ping` fails but `curl` succeeds (or vice versa)
- The target is a known-live program asset yet the scanner says nothing
- Before concluding "no attack surface" on a target

## First Move: Run the Diagnostic Ladder

Call `diagnose_sandbox_network(target, port=<optional>)`. It returns a
structured diagnosis with:

- `likely_root_cause`: one of `dns_failure`, `missing_cap_net_raw`,
  `egress_blocked`, `ip_reputation_block`, `icmp_blocked_but_tcp_ok`,
  `target_offline`, `unknown`
- `recommended_fallbacks`: the literal commands to run next
- Per-step booleans (`dns_ok`, `tcp_80_ok`, `http_status`, etc.) so you
  can reason about unusual patterns

Skip to the section matching the returned `likely_root_cause` below.

## Per-Root-Cause Fallbacks

### `missing_cap_net_raw` — TCP works but raw-socket scans fail

Symptoms: `tcp_80_ok: true`, `tcp_443_ok: true`, `cap_net_raw: false`,
naabu returned 0 results.

Naabu defaults to SYN scans (`-s s`) which require raw sockets. The
container doesn't have `CAP_NET_RAW`, so the syscall fails silently and
the tool reports no open ports.

```bash
# Forced TCP-connect naabu — works without raw sockets.
naabu -host {target} -s c -silent

# Nmap explicit TCP connect, no ping required.
nmap -sT -Pn -n --top-ports 1000 {target}

# Masscan full-range TCP connect.
masscan -p1-65535 --rate 1000 -sT {target}

# httpx for HTTP service discovery — always works without CAP_NET_RAW.
httpx -l hosts.txt -silent -status-code -title -tech-detect -json

# Single-port probe via bash /dev/tcp (no tools needed).
timeout 3 bash -c '(exec 3<>/dev/tcp/{target}/{port}) && echo OPEN'
```

If all of these still return empty, the target really is silent on
those ports. Move on.

### `egress_blocked` — ICMP works but no TCP ports respond

Symptoms: `icmp_ok: true`, `tcp_80_ok: false`, `tcp_443_ok: false`,
`http_ok: false`.

Either the sandbox egress is filtering outbound TCP (uncommon but
happens on restricted runtimes) or the target is aggressively dropping
SYN from this IP range.

```bash
# Confirm via explicit TCP connect to 80 — if this fails, it's not just
# a scanner issue.
timeout 3 bash -c '(exec 3<>/dev/tcp/{target}/80) && echo OPEN'

# Pivot to HTTP probes through upstream proxies.
httpx -l hosts.txt -silent -status-code -title -tech-detect -json

# Check if ANY outbound TCP works from this sandbox.
curl -sk -o /dev/null -w '%{http_code} %{remote_ip}\n' --max-time 5 https://google.com/

# If google.com works but target.com doesn't, target is filtering by
# source IP. Switch to passive recon + a different egress (Cloudflare
# frontend, external runner).
```

### `ip_reputation_block` — target's WAF recognises the sandbox IP

Symptoms: `http_status: 403` / 406 / 451 / repeated Cloudflare block
pages. ICMP + TCP handshake usually succeed, then the HTTP response
itself is the block.

Your sandbox is on a cloud-provider IP range that the target's WAF has
tagged as a bot / scanner. No tool-level fallback will fix this — the
egress IP is the problem.

```bash
# Verify: curl with a normal User-Agent + full headers
curl -v -H 'Accept: text/html,*/*' -H 'User-Agent: Mozilla/5.0 ...' https://{target}/ 2>&1 | head -30

# Pivot to passive recon — the data you can't fetch from the sandbox
# you can probably pull from Shodan / urlscan / wayback.
# Call the dorking skills instead.

# If the bounty program allows it, use httpx with a proxy that comes
# from a residential / non-cloud IP.
```

**Important**: do NOT dismiss findings because of this. If you already
have a vulnerability candidate confirmed from elsewhere (code audit,
JS-mined endpoint, prior disclosure), a WAF block on active probing
does not refute it — see `block_bypass_strategies.md`.

### `dns_failure` — container can't resolve the target name

Symptoms: `dns_ok: false`, `resolved_ips: []`.

```bash
# Inspect container resolver
cat /etc/resolv.conf

# Force a public resolver
dig @8.8.8.8 {target}
dig @1.1.1.1 {target}

# If resolution only works via a public resolver, tell the scanner to
# use it directly.
naabu -host {target} -s c --system-dns -silent
# or: getent the IP once and feed the raw IP to the scanner.
TARGET_IP=$(dig +short @8.8.8.8 {target} | head -1)
naabu -host "$TARGET_IP" -s c -silent
```

### `icmp_blocked_but_tcp_ok` — NORMAL, keep going

Symptoms: `icmp_ok: false`, but `tcp_80_ok` or `tcp_443_ok` is true.

Most cloud hosts block ICMP. This is not a problem — it just means
host-discovery scans based on ping will skip the target. Disable host
discovery and continue.

```bash
nmap -Pn -sT -n --top-ports 1000 {target}
naabu -host {target} -s c -silent       # naabu skips ICMP by default
```

### `target_offline` — nothing at all responds

Symptoms: ICMP, TCP/80, TCP/443, HTTP all fail.

Either the target really is down, or EVERYTHING from this egress is
blocked. Before dismissing, check from outside the sandbox:

```bash
# Is the sandbox egress working for any host?
curl -sk --max-time 5 https://example.com/

# If yes, the target is specifically unreachable. Confirm externally
# (shodan, urlscan, previous DNS records) before marking the target
# dead.
```

### `unknown` — basic reachability works, scan returns empty

Rare. Usually means the specific scan mode you used didn't land — try
the conservative fallbacks:

```bash
naabu -host {target} -s c -rate 200 -silent    # slow + connect scan
nmap -sT -Pn -n -p 80,443,22,8080,8443 {target}
httpx -l hosts.txt -silent -status-code -title -tech-detect -json
```

## Per-Tool Fallback Cheat-Sheet

| Primary tool | Typical failure | Fallback command |
|---|---|---|
| `naabu` (default SYN) | 0 open ports, no error | `naabu -host H -s c -silent` |
| `nmap` (default `-sS`) | "0 hosts up" | `nmap -sT -Pn -n --top-ports 1000 H` |
| `masscan` | "0 ports open" | `masscan -p1-65535 --rate 1000 -sT H` |
| `rustscan` | "no open ports" | `rustscan -a H -r 1-65535 --ulimit 5000 -- -sT` |
| `httpx` | "no hosts live" | re-check URL list format (one per line, http/https scheme); `httpx -status-code -follow-redirects` |
| `subfinder` | "no subdomains" | check API keys; try `amass enum -passive -d H` as a second opinion |
| port-check one-liner (no tools) | — | `timeout 3 bash -c '(exec 3<>/dev/tcp/H/P) && echo OPEN'` |

## HTTP-Only Service Discovery

When TCP scans are blocked but HTTP works, use the HTTP probe as a
service discovery mechanism. `httpx` is always the safest bet because
it does a standard HTTP handshake that almost always survives WAFs /
egress filters / rate limits.

```bash
# Generate a subdomain list (from subfinder / passive sources), then:
httpx -l subs.txt \
      -silent \
      -status-code \
      -title \
      -tech-detect \
      -web-server \
      -follow-redirects \
      -timeout 5 \
      -rate-limit 100 \
      -json > http_alive.jsonl

# Summarise with the scanner output parser:
summarize_scanner_output(tool='httpx', file_id=<the_digest_id>, top_n=50)
```

## Do Not Dismiss Until

- You've called `diagnose_sandbox_network` AND tried the recommended
  fallback
- You've confirmed the target is also unreachable from an outside probe
  (or confirmed it's reachable and the issue is egress-specific)
- You've at least tried the HTTP-probe service-discovery swap
- If you had a vulnerability candidate ALREADY (from code, from JS,
  from a prior disclosure), a scanner returning 0 ports does NOT
  invalidate it — that's the scan-path that's broken, not the finding

---

## Corpus-Derived Network and Sandbox Exploitation Techniques

Patterns from high-bounty reports involving network-layer, proxy-layer, and sandbox-bypass exploitation.

### HTTP Request Smuggling via Parser Differentials

When a CDN, load balancer, or reverse proxy sits in front of the application:
1. Identify the HTTP intermediary (CDN vendor, proxy software, API gateway).
2. Test RFC-violation parser differentials: bare CR without LF, chunked encoding edge cases, Content-Length vs Transfer-Encoding disagreement.
3. A request that the proxy interprets as one request but the backend interprets as two enables cache poisoning, auth bypass, and request hijacking.
4. Also test: HTTP/2 downgrade to HTTP/1.1 (header injection via pseudo-headers), oversized headers, and duplicate headers.

### Cache Poisoning via Unkeyed Inputs

For every CDN or cache layer in front of the target:
1. Identify which request components are part of the cache key (URL, query params, Host header) and which are not (custom headers, cookies, User-Agent).
2. Test whether unkeyed inputs influence the response body (X-Forwarded-Host, X-Original-URL, X-Rewrite-URL).
3. If an unkeyed input is reflected in the response, send a request with a malicious value -- the poisoned response is cached and served to all subsequent visitors.
4. Test with `Pragma: no-cache` and `Cache-Control: no-cache` to control when the cache is populated.

### WebView JavaScript Bridge Exploitation

For any mobile app that exposes a WebView with a JavaScript bridge:
1. Decompile and find `@JavascriptInterface` (Android) or `postMessage`/`evaluateJavaScript` handlers (iOS).
2. Identify what functions the bridge exposes to JavaScript (file access, token retrieval, native API calls).
3. Find any domain that the app trusts to load in the WebView -- XSS on that domain gives access to the bridge.
4. Check if the bridge validates the origin of messages -- many implementations trust any page loaded in the WebView.

### Cloud IDE and Remote Development Security

Cloud IDEs (remote development environments, browser-based editors, hosted notebooks) share a common threat model:
1. Map the boundary between the user's workspace and the host infrastructure.
2. Check for debug endpoints, DevTools proxies, and internal APIs exposed on the workspace domain.
3. Test whether the workspace's token or session cookie can access other users' workspaces.
4. Check if the workspace domain's CSP and CORS policies are permissive enough to allow cross-origin data exfiltration.

### PRNG Audit for Network-Visible Identifiers

For any system that generates externally observable identifiers:
1. Identify the PRNG used for: session IDs, TCP initial sequence numbers, DNS transaction IDs, CSRF tokens, API keys, file upload names.
2. Collect multiple samples and test for predictability (sequential, timestamp-seeded, weak entropy source).
3. If the PRNG is predictable, compute future values to hijack sessions, predict tokens, or forge identifiers.
4. Check if the PRNG is seeded per-process or globally -- a per-process seed means observing one process's output predicts all its future output.

### Reverse Proxy Path Normalization Bypass

When a reverse proxy routes requests to backend services based on URL path:
1. Test whether the proxy and backend normalize paths differently.
2. Common differentials: `/api/admin/..%2f../public` may be routed to the admin backend by the proxy but resolved to `/public` by the backend.
3. Test: trailing slashes, double slashes, encoded slashes, path parameters (`;param`), and dot segments.
4. Also test: case sensitivity differences between proxy and backend on case-insensitive filesystems.

### Deployment Artifact Security

Web application security is determined by deployment configuration, not just code:
1. Check reverse proxy configs (nginx `alias` directive misuse, Apache `Alias` + `Directory` mismatches).
2. Search for deployment manifests in public repositories (Kubernetes manifests, Terraform configs, Docker Compose files) that expose internal service names, ports, or credentials.
3. Test Ingress/Route configurations for path-based routing bypasses that expose backend services not intended to be publicly reachable.

### Dependency Confusion in Package Manifests

For any target whose package manifests (Gemfile, package.json, requirements.txt, go.mod) reference internal package names:
1. Search the target's public repos, Docker images, and error pages for internal package names.
2. Check if the package manager is configured to check the public registry before the private one.
3. Register the internal package name on the public registry with a higher version number.
4. If the build system pulls from the public registry, the attacker's package executes during the build.

---

## Cross-References

- `methodology/block_bypass_strategies.md` — when the block is at the
  WAF / application layer rather than network layer
- `reconnaissance/fast_recon.md` — the proper recon order
- `tooling/naabu.md`, `tooling/nmap.md`, `tooling/httpx.md` — per-tool
  reference
