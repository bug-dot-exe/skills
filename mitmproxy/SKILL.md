---
name: mitmproxy
description: mitmproxy/mitmweb/mitmdump TLS-capable intercepting proxy — capture, modify, replay HTTP/1/2/3 + WebSockets with Python addon API for automation
depends_on: []
---

# mitmproxy

mitmproxy is an interactive TLS-capable HTTP proxy with three CLIs: `mitmproxy` (curses-style TUI), `mitmweb` (browser UI), and `mitmdump` (headless, addon-driven). For autonomous agents, `mitmdump` plus a Python addon script is the canonical pattern: capture traffic, mutate on the fly, persist a flow file for later analysis.

## Prerequisites

- Python 3.9+
- mitmproxy (install: `pip install mitmproxy` — provides all three binaries)

For HTTPS interception:
- The mitmproxy CA cert must be trusted by the client (browser, mobile device, thick client). On first run, the cert is auto-generated under `~/.mitmproxy/`. To install in the system trust store: `cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt && update-ca-certificates`.

## Canonical Syntax

`mitmdump [flags]` — headless interception. Flags also work for `mitmproxy` (TUI) and `mitmweb` (browser UI).

## High-Signal Flags

- `--mode regular|transparent|reverse:<url>|upstream:<url>|socks5` — operating mode (default `regular`)
- `-p, --listen-port <port>` listen port (default 8080)
- `--listen-host <addr>` bind address (default 0.0.0.0)
- `-w, --save-stream-file <file>` save all flows to `.flow` file
- `-r, --rfile <file>` replay from `.flow` file
- `-s, --scripts <file>` Python addon script
- `--set <key>=<value>` runtime option override (e.g., `--set ssl_insecure=true`)
- `--set hardump=<file>` export to HAR format on shutdown
- `-q, --quiet` suppress per-flow log
- `-n, --no-server` script-only mode (no proxy listener; pair with `-r`)
- `--anticache` strip If-None-Match / If-Modified-Since headers
- `--view-filter <expr>` filter displayed flows (e.g., `~d api.target.tld`, `~m POST`, `~c 401`)
- `--modify-headers <expr>` rewrite headers via expression
- `--modify-body <expr>` rewrite response body via expression

## Filter Expressions

mitmproxy supports a rich filter DSL:
- `~d <regex>` domain match (`~d api.target.tld`)
- `~m <method>` method match (`~m POST`)
- `~c <code>` status code (`~c 401`)
- `~s` server-side (response)
- `~q` client-side (request)
- `~b <regex>` body content match
- `~h <regex>` header match
- `&` AND, `|` OR, `!` NOT (`~d api & ~m POST`)

## Agent-Safe Baseline

Headless capture of all traffic to a flow file:

```bash
mitmdump --listen-host 0.0.0.0 --listen-port 8080 \
  -w /tmp/traffic.flow \
  --set hardump=/tmp/traffic.har \
  -q
```

Configure the target client to use `http://<agent-ip>:8080` as its HTTP/HTTPS proxy. After capture, kill mitmdump (SIGINT) — the `.flow` and `.har` files are written.

## Operating Modes

- **Regular** (default) — client must be configured to use mitmproxy as proxy:
  `mitmdump --mode regular --listen-port 8080`

- **Reverse** — mitmproxy fronts a single target server (no client-side proxy config needed):
  `mitmdump --mode reverse:https://api.target.tld --listen-port 443`

- **Transparent** — invisible to the client, requires kernel-level packet redirection (iptables/pf):
  `mitmdump --mode transparent --listen-port 8080`

- **Upstream** — chain through another proxy:
  `mitmdump --mode upstream:http://corporate-proxy:3128`

- **SOCKS5** — speak SOCKS5 instead of HTTP:
  `mitmdump --mode socks5 --listen-port 1080`

## Python Addon Skeleton

mitmproxy's automation power comes from Python addons. Save as `addon.py`, run with `mitmdump -s addon.py`.

```python
from mitmproxy import http
import json

class APITester:
    def __init__(self):
        self.tokens = []
        self.findings = []

    def request(self, flow: http.HTTPFlow) -> None:
        # Hook on every outgoing request — modify here
        if "api.target.tld" not in flow.request.pretty_url:
            return

        # Capture auth tokens for replay testing
        auth = flow.request.headers.get("authorization", "")
        if auth and auth not in self.tokens:
            self.tokens.append(auth)

        # Test for IDOR by replacing a numeric ID with 1
        if "/users/" in flow.request.path:
            new_path = flow.request.path.split("/users/")[0] + "/users/1"
            self.findings.append({
                "test": "idor",
                "original": flow.request.path,
                "modified": new_path,
            })

    def response(self, flow: http.HTTPFlow) -> None:
        # Hook on every response — analyze here
        if flow.response.status_code == 200 and "admin" in flow.response.text.lower():
            self.findings.append({
                "test": "privilege_disclosure",
                "url": flow.request.pretty_url,
                "evidence": flow.response.text[:200],
            })

    def done(self):
        # Called once when mitmdump exits
        with open("/tmp/findings.json", "w") as f:
            json.dump({"tokens": self.tokens, "findings": self.findings}, f, indent=2)

addons = [APITester()]
```

Run: `mitmdump -s addon.py -w /tmp/traffic.flow`

## Common Patterns

- **Replay a captured flow against a fresh server (regression test)**:
  `mitmdump -nc -r /tmp/traffic.flow`

- **Domain-scoped capture only**:
  `mitmdump --view-filter "~d target.tld" -w /tmp/scoped.flow`

- **HAR export after capture (for Burp / browser devtools tools)**:
  `mitmdump --set hardump=/tmp/out.har -w /tmp/out.flow`

- **SSL pinning bypass via reverse mode** — when the mobile app pins certs, point its API calls at mitmproxy in reverse mode and modify `/etc/hosts` / DNS to make `api.target.tld` resolve to the proxy:
  `mitmdump --mode reverse:https://api.target.tld --listen-port 443`

- **WebSocket interception** — same addon pattern, hook `websocket_message`:
  ```python
  def websocket_message(self, flow):
      message = flow.messages[-1]
      if message.from_client:
          message.content = message.content.replace(b"user", b"admin")
  ```

## Critical Correctness Rules

- The agent MUST install the mitmproxy CA cert into the target client's trust store before HTTPS interception will work — otherwise the client refuses the connection.
- Reverse mode terminates TLS at the proxy and re-initiates it to the upstream — useful for testing servers that don't trust client-side proxies.
- mitmproxy auto-saves flow state to `~/.mitmproxy/` even without `-w`. For air-gapped runs or multi-tenant agents, set `--set confdir=/tmp/mitm-<scan-id>` to isolate.
- `--set ssl_insecure=true` skips upstream TLS verification — use only when the upstream is known broken/self-signed; otherwise it weakens the test.

## Failure Recovery

- If the proxy listener won't bind: another process is on port 8080 (`ss -tlnp | grep 8080`). Use `-p 8081`.
- If clients show "ERR_CERT_AUTHORITY_INVALID": CA cert not trusted by the client. Re-install with the platform-specific recipe at `http://mitm.it`.
- If addon's `request()` hook isn't firing: ensure the client is actually proxied (check `--quiet` is OFF and watch the flow log; verify `HTTPS_PROXY` env var or system proxy setting on the client).
- If HTTP/2 / HTTP/3 capture is empty: enable explicitly with `--set http2=true` or `--set http3=true` (latter is experimental as of 10.x).

## OWASP API Top 10 Test Surface

mitmproxy is the foundation tool for nearly every OWASP API Top 10 test:
- API1 BOLA — modify object IDs in `request()` hook, observe responses
- API2 Broken Auth — drop the `Authorization` header, replay flow
- API3 BOPLA — fuzz extra properties in JSON request bodies
- API4 Resource Consumption — replay-loop a costly endpoint, measure rate-limit response
- API5 BFLA — replay an admin request with a low-privilege token
- API7 SSRF — modify URL parameters with internal addresses
- API8 Misconfiguration — passive scan of response headers for missing CSP/HSTS
- API10 Unsafe Consumption — modify upstream API responses via reverse mode, observe how the consumer handles bad data

## SecOpsAgentKit contributions

Sourced from SecOpsAgentKit's `appsec/api-mitmproxy/SKILL.md` (Docker-free addon patterns, OWASP API Top 10 mapping, certificate-pinning bypass via reverse mode, HAR export workflow). Adapted to bug.exe's CLI-playbook format.

## Corpus-Derived Advanced Workflows

Patterns extracted from 295 disclosed reports ($5.8M total bounty). These show HOW top researchers use traffic interception to find real bugs.

### Cloud Extension/Webhook Proxy Auditing ($3.1M pattern)

For any cloud platform feature that proxies requests or handles webhooks, intercept the full lifecycle in reverse mode and write an addon that recursively flattens JSON request bodies to log every field matching auth/credential/token/key/secret/password:

```bash
mitmdump --mode reverse:https://deployment-manager.googleapis.com \
  --listen-port 443 -w /tmp/cloud_proxy.flow -s cloud_auth_audit.py
```

The addon's `request()` hook parses JSON bodies, flattens nested keys, and logs any key containing auth-related terms to `/tmp/auth_fields.log`. This surfaces authentication fields buried in nested schemas that manual review misses.

### Parser-Differential Request Smuggling ($500K+ pattern)

Test for HTTP request smuggling by placing mitmproxy between a CDN and origin to observe parsing differences. Use reverse mode with `ssl_insecure=true` and write an addon that logs raw request bytes (method, path, headers, body) for offline comparison against the CDN's interpretation:

```bash
mitmdump --mode reverse:https://origin.target.tld \
  --listen-port 443 --set ssl_insecure=true -s smuggling_probe.py
```

Focus on: bare CR in headers, chunk extensions, Transfer-Encoding variants, Content-Length disagreement.

### IoT Account Linking Interception ($107K pattern)

For IoT devices that support account linking, use transparent mode to intercept LAN traffic and inspect the linking handshake for trust based on LAN-presence alone, missing mutual authentication, and OAuth tokens transmitted without pinning:

```bash
mitmdump --mode transparent --listen-port 8080 -w /tmp/iot_linking.flow --set ssl_insecure=true
```

### HTTP/2 Downgrade and Protocol Translation ($2.4K+ pattern)

Every front-end that downgrades HTTP/2 to HTTP/1.1 is a smuggling candidate. Enable H2 interception and write an addon that logs `:authority` vs `Host` header mismatches during downgrade:

```bash
mitmdump --listen-port 8080 --set http2=true -w /tmp/h2_traffic.flow -s h2_downgrade.py
```

For protocol-translating proxies (HTTP/AJP, HTTP/gRPC, HTTP/FCGI), use reverse mode and modify headers that have different semantics in the upstream protocol (Content-Length handling, Transfer-Encoding support).

### Mobile App TLS Validation Testing ($2.1K pattern)

Route mobile app traffic through mitmproxy WITHOUT installing the CA cert on the device. If traffic flows and decrypts, the app does not validate TLS certificates -- all auth tokens are exfiltrable:

```bash
mitmdump --listen-port 8080 -w /tmp/mobile_traffic.flow
# On device: set proxy to <agent-ip>:8080, do NOT trust the CA
```

### Chaining mitmproxy with Other Tools

1. **mitmproxy -> nuclei**: captured flows reveal API structure for targeted template scanning
2. **mitmproxy -> semgrep**: intercepted JS reveals API endpoints for source-code analysis
3. **subfinder -> mitmproxy**: discovered API subdomains become reverse-proxy targets
4. **mitmproxy -> spectral**: captured traffic converted to HAR then OpenAPI for linting
