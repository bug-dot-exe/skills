---
name: twilio
description: Twilio integration attack surface: API credential leak, webhook validation, Studio Flow injection
depends_on: []
---

# Twilio

Twilio is messaging/voice infra. Bugs are in the integrator: API credentials leaked, webhook signature unchecked allowing spoofed inbound messages, Studio Flow widgets accepting injected liquid templates.

## Common Bug Classes

- Twilio Account SID + Auth Token leaked -> SMS/voice abuse on victim's bill
- X-Twilio-Signature header validation skipped on inbound webhooks
- Studio Flow Liquid template injection via inbound message body
- Phone-number enumeration via verification flow timing
- SMS/OTP rate limit absence enabling brute-force or cost abuse
- TURN/STUN credential exposure in API responses enabling SSRF
- Channel-binding IDOR (attacker receives victim's SMS/WhatsApp notifications)

## Credential Exposure (54 reports, $640K corpus)

### API Key Discovery
1. Grep JS bundles, mobile app binaries, and public repos for Twilio Account SID pattern: `AC` followed by 32 hex characters
2. Search for Auth Token alongside SID — they are often in the same config block
3. Check environment variable references: `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_API_KEY`
4. Inspect error messages and debug responses — Twilio client libraries may log credentials in verbose mode
5. Impact of `SID + Auth Token` leak: full account access — send/receive SMS and calls, access call logs, modify configuration, incur charges

### Infrastructure-Leak Observation
Every outbound message the application sends (email, SMS, push, webhook) is an evidence surface:
1. Trigger a password reset, signup email, verification SMS
2. Inspect the FROM number, message body, and any embedded URLs
3. If the message contains internal URLs, staging hostnames, or debug information, that is an information disclosure
4. If the SMS verification flow uses a Twilio-hosted URL, check if it leaks the Account SID in the URL path

## Webhook Signature Bypass

### Missing X-Twilio-Signature Validation
1. Identify the inbound webhook URL (common paths: `/twilio/webhook`, `/sms/receive`, `/voice/callback`, `/api/twilio`)
2. Send a POST request with a valid Twilio webhook structure but NO `X-Twilio-Signature` header — does the server process it?
3. Send with an invalid signature — does the server reject it?
4. If the server processes unsigned webhooks, an attacker can spoof inbound SMS/calls:
   - Inject arbitrary inbound messages triggering application logic
   - If the app processes commands via SMS (balance check, account actions), execute them as any user

### Webhook Event Confusion
1. If signature validation exists, test if the handler verifies the `To` and `From` phone numbers
2. Can you send a webhook claiming to be FROM the target's own Twilio number? (self-message injection)
3. Test if the handler processes status callbacks (`MessageStatus`, `CallStatus`) without verifying they reference legitimate message/call SIDs

## SMS/OTP Rate Limit and Cost Abuse

### Rate Limit Testing
For every endpoint that triggers an SMS (verification, 2FA, password reset):
1. Send 50-100 rapid requests to the same phone number — is there a per-number rate limit?
2. Test per-IP rate limit separately (use different source IPs)
3. Test per-account rate limit (different user accounts, same phone number)
4. If no rate limit exists: each SMS costs the target ~$0.01-0.08 — 10K requests = $100-800 in charges
5. After hitting a rate limit, wait for the throttle window to expire and test again — some limits are too short

### OTP Brute-Force
1. If the OTP is 4-6 digits, test if there is a lockout after N failed attempts
2. Test if the OTP is reusable (submit the same code twice)
3. Test if requesting a new OTP invalidates the previous one
4. Test timing oracle: does a valid vs invalid OTP produce different response times?

## TURN/STUN Credential Exposure

When the application uses Twilio for WebRTC (voice/video calls):
1. Monitor API responses during call setup for `iceServers` configuration
2. TURN server credentials in the response are SSRF primitives — TURN proxies TCP/UDP to arbitrary destinations
3. Test: use the TURN credentials to proxy traffic to `169.254.169.254` (cloud metadata), `localhost:*` (internal services), or internal network ranges
4. TURN credential lifetime is typically short (hours) but renewed on every call setup

## Channel-Binding and Notification IDOR

### SMS/WhatsApp Notification Hijacking
1. Find endpoints that bind a phone number to notifications (order updates, security alerts, login codes)
2. Test if binding requires ownership verification: can you bind the victim's phone number to your session?
3. Test if the binding endpoint accepts phone numbers belonging to other users
4. "Verify the side-effect, not the response" — even if the API returns success for your own number, check if the victim's notifications actually redirect

### Verification Flow Abuse
1. Find the phone verification endpoint
2. Test with empty values, partial numbers, international format variations
3. Test if you can verify a phone number you do not own by manipulating the verification callback
4. Test if completed verification on one account can be transferred to another account

## Studio Flow and Template Injection

### Liquid Template Injection
If the application uses Twilio Studio Flows that process inbound message content:
1. Send SMS with Liquid template syntax: `{{ 7*7 }}`, `{% if true %}yes{% endif %}`
2. If templates evaluate, test object access: `{{ flow.data }}`, `{{ trigger.message }}`
3. Escalate to data exfiltration: craft template expressions that leak Studio Flow variables (API keys, connection strings stored in Flow config)

### TwiML Injection
If the application constructs TwiML responses from user input:
1. Test for XML injection in `<Say>`, `<Message>`, `<Redirect>` elements
2. If you can inject `<Redirect>`, redirect the call/SMS flow to your own TwiML endpoint
3. If you can inject `<Record>`, start recording the call and send the recording to your URL

## Multi-Channel Command Surface Audit

For applications with SMS-driven commands (chatbots, SMS-based account management):
1. Map every command available via SMS
2. Test if the same access controls apply via SMS as via the web interface
3. SMS channels often lack: session management, CSRF protection, rate limiting, 2FA enforcement
4. Test if a command via SMS can bypass web-only restrictions (e.g., SMS password reset skipping email verification)

## DNS Rebinding on Webhook Callbacks

### Two-Resolution TOCTOU
When the application validates webhook callback URLs before fetching:
1. The pattern is: `validate(hostname)` then `fetch(hostname)` with independent DNS resolution for each
2. Set up a DNS record that alternates between a safe IP and `169.254.169.254` (cloud metadata)
3. First resolution (validation) returns safe IP -> passes the allowlist check
4. Second resolution (fetch) returns internal IP -> SSRF
5. This bypasses Twilio URL blocklists and application-level SSRF filters

## Outbound Communication Domain Audit

For every email, SMS, and push notification the target sends via Twilio:
1. Trigger the notification (password reset, verification, order confirmation)
2. Extract every URL and domain referenced in the message body
3. Verify each domain is registered and controlled by the target — expired or unclaimed domains in notification URLs are a takeover vector
4. Check if shortened URLs (bit.ly, t.co) in SMS messages resolve to expected destinations
5. Test if notification URLs contain session tokens or other sensitive data in query parameters
6. Long field values in user profiles may truncate differently in SMS vs email — test if truncation exposes an injection point

## Supply Chain and Installation Integrity

### Twilio SDK and Helper Library Audit
1. Check which version of the Twilio SDK the target uses — older versions may have known vulnerabilities
2. If the application uses Twilio's helper libraries for webhook signature validation, verify the library is up-to-date
3. Test if the application's dependency lock file pins the Twilio SDK version or allows automatic upgrades (supply chain risk)
4. Check for forks or unofficial Twilio SDK packages that may contain malicious code

## Probe Targets

- Grep bundle / public repos for `AC` (Account SID prefix) + 32 hex chars
- Send unsigned webhook payloads to common Twilio webhook paths
- Test verification SMS for timing oracle on valid vs invalid numbers
- Test SMS sending endpoint for rate limits (per-IP, per-number, per-account)
- Monitor WebRTC call setup for TURN credentials in API responses
- Test notification binding endpoints for phone number IDOR
- Send Liquid/TwiML injection payloads via inbound SMS
- Check SMS commands for authorization bypass vs web interface
- Test OTP endpoint for brute-force protection and code reuse

## Cross-References

`api_security`, `signature_replay`, `ssti`, `public_credential_disclosure`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
