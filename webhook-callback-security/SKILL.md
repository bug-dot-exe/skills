---
name: webhook-callback-security
description: Webhook signature bypass, callback URL SSRF, notification injection, and event replay attacks
depends_on: [ssrf]
---

# Webhook & Callback Security

Webhooks, callbacks, and notification pipelines are bidirectional trust boundaries where the target controls one side of a signed exchange. Signature bypass turns payment confirmations into free money. Callback URL injection turns every "we'll call your URL" feature into SSRF. Notification fanout leaks data through channels that bypass page-level authorization. The highest bounties come from payment signature smuggling ($7,500 Steam/Smart2Pay) and cloud credential exfil via webhook SSRF ($1,500-$2,500).

## Discovery Signals

| Signal | Where to Find | What It Means |
|---|---|---|
| `webhook`, `callback_url`, `endpoint_url` in settings UI | Admin/integration panels | Server-side URL fetch surface (SSRF candidate) |
| `Hash`, `X-Hub-Signature`, `X-Shopify-Hmac-SHA256` in requests | Proxy traffic, docs | Signed payload -- test canonicalization and replay |
| "Test webhook" / "Send test event" button | Integration config pages | On-demand SSRF trigger with response reflection |
| `notification_url`, `ipn_url`, `return_url` params | Payment flows | Payment callback -- signature bypass = value theft |
| Sequential/guessable event IDs | Webhook payloads, logs | Event replay and enumeration surface |
| `secret`, `signing_key` in API responses or docs | API docs, GraphQL schema | Key material for forging signatures |
| Integration create/update mutations sharing fields | GraphQL introspection | Mutable callback URL + stored credential = exfil primitive |
| WhatsApp/SMS/Slack/email subscription endpoints | Notification settings | Channel-binding IDOR (subscribe attacker to victim's events) |
| `X-Accel-Redirect` in proxy responses | Response headers | Reverse-proxy internal route access via controlled upstream |
| `retry_count`, `delivery_status` in webhook logs | Admin panels, API | Replay surface -- retries re-send signed payloads |
| Webhook topics as enum values (GraphQL) | Schema introspection | Per-topic authorization gaps (register for privileged topics) |
| `timestamp`, `nonce` fields in signature headers | Proxy traffic | Replay window -- missing or wide timestamp tolerance |

## Attack Surface

**Webhook URL Configuration (SSRF)**
- Custom integration endpoints, webhook URLs, callback URLs, IPN URLs
- "Test" buttons that trigger immediate server-side fetch
- SAML/OIDC metadata import, RSS/Atom feed URLs, OEmbed endpoints
- Health-check URLs, domain verification fetchers, link preview generators

**Signed Payload Delivery (Signature Bypass)**
- HMAC-SHA256 over concatenated fields (no delimiters = smuggling)
- Timestamp + nonce validation (replay window, missing checks)
- Payment processor callbacks (Stripe, PayPal IPN, Smart2Pay)
- Event type verification (forge `payment.succeeded` from `payment.created`)

**Notification Channels (Data Leakage)**
- Push notification fanout, email digests, Slack/Discord webhooks
- WhatsApp/SMS subscription endpoints, in-app activity feeds
- Webhook topic subscriptions with insufficient per-topic authorization

## High-Value Targets

**Payment Processor Callbacks**
- Stripe checkout webhooks, PayPal IPN, Smart2Pay, Adyen notifications, Braintree webhooks
- Amount/currency/status fields in signed payloads -- signature bypass = arbitrary credit
- Return URLs and success callbacks that grant access before server-side verification

**SaaS Integration Webhooks**
- GitHub/GitLab CI triggers, Jira/Phabricator escalation callbacks, Slack event subscriptions
- Integration settings storing both callback URL and API token/secret
- GraphQL mutations for webhook management (topic enum fuzzing, create vs update field sets)

**Notification Delivery Pipelines**
- Email notification templates with user-controlled interpolation points
- SMS/WhatsApp subscription bindings with enumerable resource IDs
- Push notification fanout logic (who receives, what data is included in cleartext)

**Webhook Infrastructure**
- Webhook delivery worker queues (Sidekiq, Celery, BullMQ) -- DoS via response manipulation
- Retry logic with re-resolution (DNS rebinding on retry), stale URL delivery
- Webhook log/debug endpoints exposing payload history or signing secrets

## Webhook Signature Bypass Matrix

| Signature Scheme | Bypass Technique | Impact | Real Example |
|---|---|---|---|
| Concatenated name+value (no delimiters) | Parameter smuggling via attacker-controlled field (email, description) | Forge arbitrary field values while preserving hash | Steam/Smart2Pay $7,500 -- email field smuggles `amount` |
| HMAC-SHA256 with static secret | Key leakage from client-side code, env vars, error messages | Full signature forgery on all events | GitHub/Shopify apps with hardcoded secrets |
| Timestamp + HMAC | Replay captured payload within tolerance window (typically 5min) | Re-deliver past events (duplicate payments, re-grant access) | Stripe default 300s tolerance |
| Algorithm in header (`alg` field) | Algorithm confusion: switch HMAC to `none` or RSA to HMAC | Bypass verification entirely | JWT-adjacent -- same `alg` confusion class |
| Symmetric key in webhook config | Steal key via IDOR on integration settings endpoint | Forge any webhook event | Integration API returning `signing_secret` in GET |
| Base64-encoded signature | Encoding mismatch (standard vs URL-safe base64, padding) | Validator accepts malformed signature | Parser-dependent base64 decoding |
| Signature covers subset of body | Modify unsigned fields (metadata, custom fields, headers) | Tamper with business logic fields outside signed scope | IPN callbacks signing only `amount` not `item_id` |
| Missing verification entirely | Send arbitrary POST with event JSON | Full event forgery | Exposed webhook endpoint with no signature check |
| HMAC with newline injection | Inject `\n` into signed content to shift field boundaries | Same class as HTTP request smuggling | Header injection in signed content |
| Sorted key-value canonicalization | Duplicate keys, encoding differences (`+` vs `%20`), key order | Produce collision in canonical form | OAuth1 signature base string attacks |

## Callback URL Injection (SSRF)

| Technique | Payload | What It Bypasses |
|---|---|---|
| Direct internal IP | `http://169.254.169.254/latest/meta-data/` | No URL validation (Helium $500, Dynatrace $1,500) |
| IPv6 embedded IPv4 | `http://[::ffff:169.254.169.254]/` | IPv4-only blocklist (HackerOne $2,500) |
| DNS rebinding | `A.178.62.122.208.1time.127.0.0.1.1time.repeat.rebind.network` | Validate-then-fetch with separate DNS lookups (Coinbase) |
| Redirect chain | `http://attacker.com/302?to=http://169.254.169.254/` | Pre-redirect-only URL validation |
| Userinfo confusion | `http://allowed.com@169.254.169.254/` | Host extraction via substring before `:` |
| Decimal IP | `http://2852039166/` (169.254.169.254) | String-prefix IP filters |
| URL-encoded host | `http://169.254.169.254%2f..%2f/` | Path-based allowlists |
| Mutable stored URL | Change `base_url` on existing integration, trigger outbound call | Credential follows stored URL to attacker (HackerOne Phabricator) |
| Octal/hex IP encoding | `http://0251.0376.0251.0376/` or `http://0xa9fea9fe/` | Regex-based IP filters expecting decimal dotted-quad |
| X-Accel-Redirect via app proxy | Controlled upstream returns `X-Accel-Redirect: /internal-path` header | NGINX internal locations exposed via trusted-upstream assumption (Shopify) |

## Event Injection & Replay

| Attack | Mechanism | Precondition | Impact |
|---|---|---|---|
| Event type forgery | POST `{"type":"payment.succeeded"}` to exposed endpoint | No signature verification or weak validation | Grant access/credit without payment |
| Payload replay | Capture signed webhook, re-send within timestamp window | Timestamp tolerance > 0, no nonce/idempotency | Duplicate delivery (double-credit, duplicate order) |
| Event ID enumeration | Increment sequential event IDs in replay requests | Predictable event IDs, no per-delivery token | Access historical event payloads |
| Cross-tenant event injection | Send event with victim's `merchant_id` to shared endpoint | Endpoint routes by body field, not authenticated source | Trigger actions on victim's account |
| Webhook topic privilege escalation | Register webhook for `BULK_OPERATIONS_FINISH` via GraphQL | Per-topic auth check missing (Shopify staff escalation) | Receive privileged data via notification channel |
| Stale callback exploitation | Event delivered to old/rotated callback URL still in retry queue | No callback URL re-validation on retry | Data delivered to decommissioned/compromised endpoint |
| Webhook response body injection | Craft event payload so target echoes attacker content in response | Webhook logs/UI displays response body | XSS in webhook log viewer, SSTI in response template |
| Idempotency key collision | Reuse idempotency key from different event type | Key scoped to endpoint not event type | Execute action meant for different event type |

## Notification Channel Attacks

| Channel | Attack | Signal | Impact |
|---|---|---|---|
| Email notifications | Template injection via user-controlled fields (name, subject) | `{{`, `${`, `<%= %>` in notification text | Phishing from trusted sender domain, data exfil |
| SMS/WhatsApp subscriptions | Channel-binding IDOR (subscribe to victim's events) | Sequential order/resource IDs, no ownership check | PII leakage via delivery updates (Zomato $300) |
| Slack/Discord webhooks | Webhook URL exposed or guessable | Integration logs, `.env` files, public repos | Post arbitrary messages as trusted integration |
| Push notifications | Fanout to unauthorized recipients | Private program/resource data in notification text | Information disclosure bypassing page-level auth (H1 $500) |
| Notification metadata | Staging/internal environment leak in sender domain or links | `+staging@`, reversed hostnames, internal URLs in footers | Infrastructure enumeration (HackerOne staging $1,000) |
| Activity feeds | Feed includes resources user cannot access directly | Items visible in feed but 403 on click-through | Existence confirmation oracle for private resources |

## Platform-Specific Webhook Patterns

| Platform | Signature Method | Known Weakness |
|---|---|---|
| Stripe | `Stripe-Signature: t=timestamp,v1=HMAC-SHA256` | 300s default tolerance window enables replay; test with `t=` far in past |
| GitHub | `X-Hub-Signature-256: sha256=HMAC` | Secret in app settings; leaked secret = full forgery; no timestamp |
| Shopify | `X-Shopify-Hmac-SHA256: base64(HMAC-SHA256)` | Per-topic auth gaps; staff verb-asymmetry on webhook CRUD |
| Twilio | `X-Twilio-Signature: base64(HMAC-SHA1)` | SHA1 collision potential; signature over URL+params, not body |
| Slack | `X-Slack-Signature: v0=HMAC-SHA256(timestamp:body)` | Timestamp tolerance 5min; webhook URLs in public repos |
| PayPal IPN | POST-back verification to `ipn.paypal.com` | Verify endpoint reachable = confirm; race between verify and process |
| SendGrid | `X-Twilio-Email-Event-Webhook-Signature` (ECDSA P-256) | Public key in settings; implementation errors in ECDSA verification |
| AWS SNS | JSON body with `SigningCertURL` + RSA signature | Cert URL must be validated (SSRF if fetched blindly); message type confusion |

## Defense-Bypass Pairs

| Defense | Bypass Technique | Why It Fails |
|---|---|---|
| IP blocklist on webhook URL | IPv6 embedded IPv4 (`::ffff:127.0.0.1`) | Blocklist covers IPv4 ranges only |
| DNS resolution at validation time | DNS rebinding (TTL=0, `rebind.network`) | TOCTOU -- fetch re-resolves to internal IP |
| HMAC signature on concatenated values | Parameter smuggling via attacker-controlled field | Concatenation without delimiters is not injective |
| "Test webhook" restricted to admins | Staff role with Settings permission can edit existing webhooks | Verb-asymmetric auth (create blocked, update allowed) |
| Webhook secret hidden in read API | Update mutation accepts `base_url` change, keeps secret | Credential follows mutable destination to attacker |
| Timestamp validation on signatures | Replay within tolerance window, or clock skew exploitation | 5-minute windows are common; system clock drift widens them |
| Rate limiting on webhook delivery | ReDoS via malicious response headers from attacker server | Single delivery pins worker CPU indefinitely (GitLab Sidekiq) |
| Per-function auth on webhook mutations | Per-enum-value (topic) auth missing | Registration allowed, topic carries privileged data |

## Chain Patterns

| Chain | Steps | Bounty Signal |
|---|---|---|
| Webhook URL SSRF -> cloud metadata -> IAM credential theft | Set callback to `169.254.169.254`, harvest IAM creds, pivot to S3/RDS | $1,500-$5,000 (Dynatrace, Helium, HackerOne) |
| Signature bypass -> payment amount tampering | Smuggle `amount=100` via email field, pay $1 get $20 credit | $7,500 (Steam/Smart2Pay) |
| Mutable callback URL -> credential exfiltration | Change integration `base_url`, trigger outbound call carrying stored API token | High (HackerOne Phabricator token leak) |
| Webhook topic escalation -> bulk data exfil | Register for `BULK_OPERATIONS_FINISH`, receive export download URLs | High (Shopify staff privilege escalation) |
| DNS rebinding -> internal service discovery -> proxy management plane | Flip DNS after validation, reach proxy loopback, enumerate services | $100-$500 (Coinbase via Proximo proxy) |
| Notification IDOR -> PII harvesting at scale | Subscribe attacker channel to sequential victim order IDs | $300+ (Zomato WhatsApp delivery updates) |
| ReDoS via webhook response -> queue starvation -> platform DoS | Malicious response header pins Sidekiq worker CPU for days | High (GitLab -- year-long stuck job) |
| Webhook verb-asymmetry -> data exfil redirect | Edit existing webhook URL to attacker domain, receive order data | $500 (Shopify staff Settings-only permission) |

## Testing Methodology

**Phase 1: Enumerate webhook/callback surfaces**
1. Map every feature accepting a URL the server fetches (webhooks, integrations, import, test buttons, notification endpoints)
2. Capture all outbound signed requests in proxy (filter for `signature`, `hmac`, `hash`, `token` headers/params)
3. Introspect GraphQL schema for webhook/notification mutations and enum types
4. Check API docs for webhook registration endpoints and signing key management

**Phase 2: Signature analysis**
1. Identify canonicalization method -- read docs or reverse from behavior (concatenated, sorted KV, JSON, XML)
2. For concatenation without delimiters: find attacker-controlled fields in canonical form (email, name, description, URL)
3. Test smuggling: embed target field name+value in controlled field, verify hash unchanged
4. Check timestamp/nonce: replay captured payload with original timestamp; widen window
5. Test `alg` confusion if algorithm is specified in header
6. Verify signature covers all business-logic fields (amount, item, recipient, status)

**Phase 3: SSRF via callback URLs**
1. Point callback URL at OOB listener (interactsh, Burp Collaborator) -- confirm server-initiated fetch
2. Test internal targets: `127.0.0.1`, `169.254.169.254`, `[::1]`, `[::ffff:169.254.169.254]`
3. If blocked: DNS rebinding via `rebind.network`, redirect chain via attacker 302, IP encoding variants
4. Check response reflection -- is webhook delivery response shown in UI, logs, or error messages?
5. For stored integrations: can you update callback URL independently of credentials?

**Phase 4: Authorization and injection**
1. Test verb-asymmetric auth: if webhook create is restricted, try update/delete/clone with lower-privilege role
2. Test per-topic authorization: register for every webhook topic enum value with minimal permissions
3. Test channel-binding: subscribe attacker's phone/email/Slack to victim's resource notifications
4. Test notification content for private data leakage (resource names, IDs, metadata in notification text)

**Phase 5: Webhook response manipulation (attacker as receiver)**
1. Host a malicious webhook receiver that returns pathological headers (9.5M spaces in header value = ReDoS)
2. Test slow-trickle responses (1 byte/sec) to exhaust connection pools and timeout bypass
3. Return oversized response bodies to trigger OOM in webhook delivery workers
4. Return crafted Content-Type and body to test for SSRF-like behavior if response is proxied or rendered
5. Test whether failed deliveries trigger retries to a now-changed callback URL

## Validation

| Claim | Proof Required |
|---|---|
| Signature bypass | Forge a valid-signature request with modified business field (amount, status, recipient) |
| SSRF via webhook URL | OOB interaction from target IP + response content or DNS resolution proof |
| Payment amount tampering | Two transactions: legitimate amount vs tampered amount, both accepted by processor |
| Event replay | Re-send captured event, show duplicate side effect (double credit, double notification) |
| Webhook topic escalation | Register for privileged topic, receive data the role cannot access directly |
| Notification IDOR | Subscribe to victim's resource, receive their notification on attacker's channel |
| Credential exfiltration via mutable URL | Collaborator log showing credential/token in outbound request to attacker domain |

## False Positives

| Looks Like a Bug | Why It Is Not |
|---|---|
| Webhook URL accepts any domain | Intended behavior -- webhooks are designed to call external URLs; SSRF requires reaching internal hosts |
| Replay accepted but idempotent | Server de-duped by event ID; no duplicate side effect occurred |
| Signature validation "missing" on test endpoint | Test endpoints intentionally skip validation for developer convenience; production endpoint may differ |
| Notification sent to non-member | Notification is for a public resource; no private data leaked |
| Webhook retries after failure | Retry is expected behavior; only exploitable if retry delivers to changed/compromised URL |
| Event contains sequential IDs | Sequential IDs alone are not a vulnerability; need enumeration + data access or action trigger |
| Webhook delivery to HTTP (not HTTPS) | Some programs intentionally allow HTTP for development; check if production enforces TLS |
| Integration stores both URL and secret | Storing both is normal architecture; the bug is when URL is mutable independently post-creation |

## Impact

| Scenario | Severity | Evidence Needed |
|---|---|---|
| Cloud credential theft via webhook SSRF | Critical | IAM credentials or metadata response body |
| Payment amount manipulation via signature bypass | Critical | Two accepted transactions with different amounts, same signature |
| Stored credential exfiltration via mutable callback URL | High | Token/secret in collaborator log from outbound request |
| Privileged data access via webhook topic escalation | High | Received data (export URL, customer records) not accessible via normal API |
| Mass PII harvesting via notification IDOR | Medium-High | Attacker-channel receiving victim's notifications at scale |
| Platform DoS via webhook response ReDoS | High | Worker pinned at 100% CPU; queue starvation demonstrated |
| Private resource existence disclosure via notifications | Low-Medium | Notification text reveals private resource name/ID |
| Webhook delivery queue starvation (DoS) | Medium-High | Worker pool exhausted; legitimate webhooks delayed/dropped |
| Event type confusion leading to unintended actions | Medium | Wrong handler invoked; state change that should not occur |

## Pro Tips

1. **Email fields are smuggling goldmines.** Email addresses accept `@`, `.`, `&`, `=`, `+` -- enough to embed key=value pairs. If the signature canonicalizes by concatenation, pre-stage the magic substring in your account email before triggering the payment flow.

2. **"Test webhook" buttons are SSRF-on-demand.** They trigger an immediate server-side fetch with response visibility. Always test internal IPs first, then escalate to IPv6, DNS rebinding, and redirect chains.

3. **Mutable destination + stored credential = credential exfil.** When an integration stores both a URL and a secret/token, and the URL is independently editable, changing the URL redirects the credential to you. Check every integration's update mutation for fields the UI hides.

4. **Webhook topics inherit the operation's privilege, not the registrant's.** A low-privilege user who registers a webhook for a high-privilege topic receives data from the high-privilege operation. Enumerate all topic enum values and test each with minimal permissions.

5. **DNS rebinding defeats validate-then-fetch.** Count DNS resolutions: use a custom authoritative DNS with per-query counters. The `rebind.network` service automates this with URL-encoded flip patterns.

6. **Verify the side effect, not the response.** A "400 Bad Request" or "error" response does not mean the subscription was not created. Wait for the event to fire and check whether your channel receives it anyway (Zomato's WhatsApp bot returned "error" but subscribed the attacker).

7. **Webhook response attacks target the sender, not the receiver.** A malicious webhook receiver can return pathological response headers (ReDoS patterns, huge bodies, slow-trickle) to DoS the sender's worker queue. Test by hosting a malicious receiver that returns crafted responses.

8. **Signature verification that covers only a subset of fields is broken by design.** Identify which fields are signed (intercept, modify each field, check if signature invalidates). Unsigned fields in the same payload are freely tampered.

9. **GraphQL update mutations often accept fields the UI hides.** Compare create and update mutation input types via introspection. If `base_url`, `callback_url`, or `api_token` appear in the update input but not in the UI form, send them directly -- the server may accept the hidden field.

10. **Webhook log viewers are XSS/SSTI surfaces.** If the target displays webhook request/response content in a dashboard, craft payloads in your webhook response body. The rendering context (HTML, template engine) determines whether you get stored XSS, SSTI, or nothing.

11. **404 vs 403 on webhook-linked resources is an oracle.** When notifications reference private resources, click through. A 404 means "does not exist." A 403 means "exists but you cannot access." The notification already confirmed existence; the response code confirms the authorization model.
