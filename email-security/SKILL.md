---
name: email-security
category: vulnerabilities
description: DNS-level email authentication (SPF/DKIM/DMARC) exploitation, mail infrastructure attacks, relay abuse, and domain verification gaps — the infrastructure layer beneath email header injection
depends_on: []
---

# Email Security

This skill covers EMAIL INFRASTRUCTURE security: SPF/DKIM/DMARC configuration exploitation,
mail relay abuse, domain verification gaps, MTA-level attacks, and DNS-based email
authentication bypass. For SMTP header injection, template injection, Host header reset
poisoning, and email-to-ATO chains, see `email_header_injection.md`. For OAuth email
verification bypass, see `authentication_jwt.md`. This skill focuses on what happens at the
DNS and mail transport layer — the foundation that makes spoofing possible or impossible.

## When to Load This Skill

- Target uses email for auth flows (password reset, verification, MFA)
- Target is a high-trust domain (financial, government, healthcare)
- Scope includes subdomains that send transactional email
- Prior testing focused on header injection but did not audit DNS records

## DNS-Level Email Security Matrix

| # | Record / Config | Misconfiguration | Impact | Test Command |
|---|----------------|------------------|--------|-------------|
| 1 | SPF missing entirely | No TXT record with `v=spf1` | Full domain spoofing (anyone can send as domain) | `dig TXT example.com +short \| grep spf1` |
| 2 | SPF `+all` | Explicitly allows all senders | Full spoofing — even receivers that check SPF will pass | Same as above; look for `+all` terminator |
| 3 | SPF `~all` + DMARC `p=none` | Softfail + no enforcement | Spoofed email delivers; DMARC only reports | Check both: `dig TXT example.com` + `dig TXT _dmarc.example.com` |
| 4 | SPF >10 DNS lookups | Exceeds RFC 7208 limit; `permerror` | SPF breaks entirely; treated as no SPF by receivers | Count `include:`, `a:`, `mx:`, `ptr:`, `redirect=` (nested includes too) |
| 5 | SPF stale `include:` (dead provider) | Former SaaS provider's IP range in SPF | Attacker who controls that IP range can spoof | Resolve each `include:` and check if the service is still active |
| 6 | SPF `include:sendgrid.net` (shared pool) | Any SendGrid customer can send as domain | Spoof from any account on shared infrastructure | Sign up for free SendGrid trial; send as target domain |
| 7 | DMARC missing entirely | No `_dmarc.example.com` TXT record | No policy instructs receivers to reject spoofs | `dig TXT _dmarc.example.com +short` |
| 8 | DMARC `p=none` | Reports only; no enforcement | Spoofed email delivers to inbox | Check for `p=none` in DMARC record |
| 9 | DMARC `sp=none` with `p=reject` | Subdomains inherit `sp=none` | Apex locked; subdomains wide open for spoofing | Check `sp=` tag in DMARC; if absent, subdomains inherit `p=` |
| 10 | DMARC `pct=0` or low `pct` | Only N% of messages get enforcement | Most spoofed messages bypass enforcement | Check for `pct=` tag; `pct=0` means zero enforcement |
| 11 | DMARC relaxed alignment (`aspf=r` or `adkim=r`) | Sibling subdomain alignment passes DMARC | Spoof from `anything.example.com` passes alignment | Check `aspf=` and `adkim=` tags; `r` = relaxed |
| 12 | DKIM key <1024 bits | Factorable key weakens DKIM | Attacker can sign as domain after factoring | `dig TXT default._domainkey.example.com` and check key length |
| 13 | DKIM `t=y` in production | Testing flag; receivers may ignore | DKIM signature treated as advisory, not enforced | Check for `t=y` in DKIM TXT record |
| 14 | DKIM published but not signing | Record exists; outbound mail unsigned | DKIM check fails; combined with weak DMARC = spoof | Send yourself a legit email; check `Show Original` for DKIM-Signature header |
| 15 | Subdomain with no SPF/DKIM/DMARC | Common on `mail.`, `mg.`, `em.`, sending subs | Subdomain spoofable even if apex is locked | Enumerate sending subs; check each independently |
| 16 | MTA-STS missing or expired | No `_mta-sts.example.com` TXT or stale policy | MITM on SMTP delivery; downgrade TLS to plaintext | `dig TXT _mta-sts.example.com` + fetch `https://mta-sts.example.com/.well-known/mta-sts.txt` |
| 17 | BIMI without enforced DMARC | Brand logo in inbox without `p=reject` | Visual trust indicator without actual anti-spoofing | Check BIMI record but verify DMARC `p=reject` is prerequisite |
| 18 | Null MX (`MX 0 .`) mishandled | Some MTAs still deliver to null-MX domains | Bypass MX-based validation assumptions | `dig MX example.com` — if null MX, test delivery anyway |

## Defense-Bypass Pairs

| # | Defense | Bypass | Real-World Pattern |
|---|---------|--------|-------------------|
| 1 | SPF `-all` on apex | Spoof from subdomain without its own SPF | `sp=none` or missing subdomain DMARC; most common paid finding |
| 2 | DMARC `p=reject` on apex | Relaxed alignment (`aspf=r`) + sibling subdomain auth | Send from `attacker-sub.example.com`; org-domain match passes |
| 3 | DKIM signature required | DKIM replay: capture legit DKIM-signed email, modify unsigned headers, resend | `h=` field does not cover From display name or Reply-To |
| 4 | DMARC `p=reject` | SMTP smuggling: `\n.\n` vs `\r\n.\r\n` parsing differential | Pre-patch Postfix CVE-2023-51764; second message bypasses all auth |
| 5 | All email auth on apex | ARC header injection from "trusted" intermediary | Inject fake ARC chain to override DMARC failure at receiver |
| 6 | SPF via dedicated sending IP | Shared provider pool in SPF `include:` | Any customer on same provider (SendGrid/Mailgun/SES) can send as domain |
| 7 | Email gateway appliance scanning | Deeply nested MIME multipart exceeds scanner recursion | Payload bypasses email security gateway |
| 8 | SPF + DKIM + DMARC all enforced | Envelope MAIL FROM diverges from Header From with relaxed alignment | SPF checks envelope; user sees Header From; alignment relaxed = spoof |
| 9 | Subdomain DMARC inherits `p=reject` | Register expired/dangling MX target hostname | Receive all mail for subdomain; intercept rather than spoof |
| 10 | Internal email treated as trusted | Inject via open port 587 (unauthenticated SMTP submission) | Internal-origin phishing bypasses all external detection ($300 SideFX) |

## Mail Infrastructure Attacks

| # | Target | Attack | How to Test | Impact |
|---|--------|--------|-------------|--------|
| 1 | Port 587 open to internet | Unauthenticated SMTP submission to internal addresses | `nmap -p 587 target.com` then telnet + `RCPT TO: employee@target.com` | Internal phishing that bypasses external gateways ($300 SideFX) |
| 2 | Open mail relay | Relay email through target's SMTP to external recipients | `swaks --to external@gmail.com --from ceo@target.com --server mail.target.com` | Spam relay using target's IP reputation; SPF passes |
| 3 | Autodiscover dangling CNAME | `autodiscover.target.com` CNAME to expired/claimable host | `dig CNAME autodiscover.target.com`; if dangling, register target | Outlook clients send credentials automatically on startup |
| 4 | MX to shared/expired hosting | Subdomain MX points to claimable hostname | `dig MX sub.target.com`; check if target hostname is registrable | Full email interception for affected subdomain |
| 5 | IMAP/POP3 without STARTTLS | Plaintext mail retrieval | `nmap -sV -p 110,143,993,995 mail.target.com`; check STARTTLS support | Passive credential and email content sniffing |
| 6 | Exchange/OWA exposed | ProxyLogon/ProxyShell/ProxyNotShell CVEs | Scan for `/owa`, `/ecp`, `/autodiscover`, `/mapi` | RCE on mail server; read all org email |
| 7 | Client-side email relay endpoint | SPA POSTs to `/api/mail` with arbitrary From/To/Body | Find relay endpoint in JS; POST with spoofed headers | DKIM-signed phishing from target domain (DoD reports) |
| 8 | Transactional provider API key leak | SendGrid/Mailgun/SES key in client JS or `.env` | Grep JS bundles for `SG.`, `api-key`, `SENDGRID_API_KEY` | Full send-as capability from any machine |

## Subdomain Spoofing — The Consistent Money Spot

Apex domain (`example.com`) almost always has `p=reject`. The payable surface is subdomains:

**Enumeration checklist** — check EACH of these for independent SPF/DKIM/DMARC:
`mail`, `email`, `send`, `smtp`, `marketing`, `hr`, `careers`, `security`, `support`,
`noreply`, `notifications`, `invoices`, `alerts`, `m`, `em`, `mg`, `bounces`,
`mail2`, `mailer`, `transactional`, `campaigns`

**Test delivery** (the proof that converts Informational to Medium+):
```bash
# Confirm subdomain lacks DMARC
dig TXT _dmarc.mg.example.com  # expect NXDOMAIN

# Deliver spoofed email
swaks --to you@gmail.com \
      --from "Security Team <security@mg.example.com>" \
      --ehlo "mg.example.com" \
      --header "Subject: Urgent: Password Reset Required" \
      --header "Reply-To: attacker@evil.com" \
      --body "Your account has been compromised. Reset: https://evil.com/reset" \
      --server mx-of-gmail.com

# Verify in Gmail: "Show original" -> check SPF/DKIM/DMARC results + inbox placement
```

## Chain Patterns

| # | Base Finding | Chain With | Combined Impact | Severity Uplift |
|---|-------------|-----------|-----------------|-----------------|
| 1 | Subdomain spoofable (no DMARC) | BEC-style phishing to finance team | Credential theft / wire transfer fraud | Info -> High |
| 2 | Shared provider in SPF | Sign up for same provider; send as target | Phishing with valid SPF + DKIM | Low -> Medium |
| 3 | Open port 587 to internal | Spoof internal sender (CEO to finance) | Internal phishing bypassing all external controls | Low -> High |
| 4 | Expired MX hostname claimable | Register hostname; intercept all subdomain email | Full email interception including password resets | Medium -> Critical |
| 5 | Autodiscover dangling CNAME | Register host; capture Outlook auto-sent credentials | Mass credential harvest from all domain users | Medium -> Critical |
| 6 | DKIM replay (modify unsigned headers) | Change display name + add Reply-To attacker | Legitimate DKIM signature + spoofed identity | Low -> Medium |
| 7 | SMTP smuggling on target's MTA | Inject second message bypassing all auth | Full spoofing despite SPF+DKIM+DMARC reject | N/A -> High |
| 8 | API key leak (SendGrid/SES) | Send DKIM-signed email as any target address | Branded phishing at scale from attacker machine | Info -> High |
| 9 | `p=none` on domain | Working spoof to Gmail Primary inbox (not Spam) | Proven deliverability elevates from "config issue" | Info -> Medium |
| 10 | Relaxed DMARC alignment | Envelope/Header From divergence + subdomain auth | SPF passes on envelope; user sees spoofed Header From | Low -> Medium |

## Testing Methodology

1. **DNS inventory**: `dig TXT example.com`, `dig TXT _dmarc.example.com`, `dig MX example.com`, and repeat for EVERY sending subdomain (discovered via DMARC `rua=`, SPF `include:` resolution, email headers from legitimate messages, or subdomain enumeration)
2. **Per-domain scoring**: For each domain/subdomain: SPF (missing/soft/hard), DKIM (missing/weak/present), DMARC (missing/none/quarantine/reject), subdomain policy (`sp=`), alignment mode (`aspf=`/`adkim=` r or s)
3. **SPF lookup count**: Count all `include:`, `a:`, `mx:`, `ptr:`, `redirect=` mechanisms including nested includes. >10 = `permerror` = broken SPF
4. **Stale include audit**: Resolve every `include:` in SPF. Check if the SaaS provider is still active. Dead includes = potential IP takeover
5. **Shared provider test**: For each `include:sendgrid.net`, `include:spf.protection.outlook.com`, etc. — sign up for a free trial on that provider and attempt to send as the target domain
6. **Port scan**: `nmap -p 25,465,587,110,143,993,995 mail.target.com` — check for open SMTP submission (587), open relay (25), unencrypted retrieval (110/143)
7. **MX and Autodiscover takeover check**: `dig MX target.com`, `dig CNAME autodiscover.target.com` — check if any target hostname is dangling/registrable
8. **Deliver a spoof**: Use `swaks` to send a spoofed email to your Gmail/Outlook. Check `Show Original` for SPF/DKIM/DMARC pass/fail results AND inbox placement (Primary tab vs Spam). Inbox placement is the proof.
9. **DKIM replay test**: Capture a legitimately DKIM-signed email from the target. Modify unsigned headers (display name, Reply-To). Resend. Check if DKIM still passes.
10. **Verify with real inbox**: ALWAYS test delivery to Gmail + Outlook. Inbox acceptance is the report-worthy outcome, not just DNS findings.

## False Positives

- `p=none` alone is reported constantly and usually marked Informational — elevate ONLY with a working spoof to Primary inbox
- SPF softfail without DMARC enforcement — prove inbox placement before reporting
- "Spoof" that only reaches Spam folder — low value unless target is high-trust (bank, gov, healthcare)
- Subdomain spoofing where the subdomain is obviously not a sending domain (`test.example.com`) — triagers will reject
- `~all` with `p=reject` and strict alignment — softfail is overridden by DMARC reject
- Triager pushback: "Email spoofing is not in scope" — preempt with a BEC-style PoC showing specific harm (credential theft scenario, wire redirect) rather than generic "I can send email as you"

## Pro Tips

1. **Always enumerate subdomains first** (`subfinder`, `amass`, DMARC aggregate reports). The spoofable targets hide there; apex is usually locked. Mailgun/SES sending subdomains (`mg.`, `em.`, `bounces.`) are the #1 payable surface.
2. **Use `dmarcian.com`, `mxtoolbox.com`, `easydmarc.com` for quick triage.** They surface `sp=` inheritance issues, alignment modes, and lookup count problems automatically.
3. **The most payable finding is a working spoof into Gmail Primary — not a DNS screenshot.** Always deliver. `swaks` is the universal email-injection CLI.
4. **Count SPF DNS lookups including nested includes.** A common finding: the SPF record itself has 8 mechanisms but the nested `include:` chains push total past 10, causing `permerror` that silently breaks all SPF enforcement.
5. **Audit every `include:` for dead SaaS providers.** Companies change email providers but leave old `include:sendgrid.net` in SPF. If you can obtain an IP in that range (free SendGrid trial), you can send as the target domain with SPF pass.
6. **SMTP smuggling (CVE-2023-51764 class) bypasses everything.** If the target runs Postfix/Sendmail/Exim, test `\n.\n` vs `\r\n.\r\n` end-of-data sequence differential. The second injected message bypasses all SPF/DKIM/DMARC.
7. **Port 587 open to internet without AUTH = internal phishing weapon.** Internal-origin email bypasses Mimecast/Proofpoint/Defender because it originates from the company's own SMTP infrastructure. This is higher impact than external spoofing.
8. **Pair every DNS finding with a delivery proof.** A DMARC `p=none` screenshot pays $0. A DMARC `p=none` + spoofed email in Gmail Primary inbox with "Show Original" proof pays $500-$5000 depending on domain trust level.
9. **Check Autodiscover CNAME for subdomain takeover.** Outlook clients auto-send credentials to `autodiscover.target.com`. If that CNAME is dangling, registering the target gives you passive credential collection from every domain user.
10. **For DeFi/crypto targets, email spoofing impact is amplified.** Phishing leads directly to wallet drains. Frame impact as "attacker spoofs domain -> phishing email -> victim approves malicious transaction -> irreversible fund loss."

## Summary

Email infrastructure security pays when you deliver a spoofed message to a real inbox, not when you screenshot a DNS record. The attack surface is DNS (SPF/DKIM/DMARC misconfiguration and subdomain gaps), mail transport (open relays, unauthenticated SMTP submission, MTA parsing differentials), and infrastructure (dangling MX/Autodiscover, leaked provider API keys, shared SPF pools). Hunt subdomains without DMARC, count SPF lookups, audit stale includes, test shared provider spoofing, and always prove delivery with a real inbox screenshot.
