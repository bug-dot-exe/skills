# Attack Surface Reference

Organized by what you're attacking, not by vulnerability class.

**bbrecon output** — When using bbrecon, start from `ACTIVE/JUICY/juicy.focus.live.txt` and `ACTIVE/API/*.txt` for prioritized targets. See [bbrecon-integration.md](bbrecon-integration.md).

## Web Applications

The bread and butter. Where most bounty money is.

### Authentication
- Login bypass, password reset flows, 2FA bypass, session management
- OAuth/OIDC misconfigurations (redirect_uri, state, scope) — see OAuth section below
- JWT attacks (alg:none, key confusion, claim manipulation)
- Magic link / passwordless login token predictability
- Account enumeration via timing or error message differences

### Authorization
- IDOR / BOLA (object-level), BFLA (function-level)
- Privilege escalation (horizontal + vertical)
- Role-based access control bypass
- Tenant isolation failures in multi-tenant apps
- API endpoint auth vs UI auth inconsistency (UI hides button, API still allows)

### Injection
- SQLi (union, blind, error-based, ORM bypass)
- XSS (reflected, stored, DOM-based)
- SSTI, command injection, LDAP injection, header injection
- Host header injection (password reset poisoning, cache poisoning)

### SSRF
- Cloud metadata access, internal service discovery
- Protocol smuggling, DNS rebinding
- Blind SSRF via webhook/callback features
- PDF/image generators fetching user-controlled URLs

### Business Logic
- Workflow bypass, state manipulation, race conditions
- Price manipulation, coupon abuse, referral abuse
- Multi-step process skipping
- Negative quantity/amount in transactions
- Feature flag bypass

### Client-Side Vulnerabilities
- **PostMessage** — `window.addEventListener("message", handler)` without origin validation → DOM XSS, data theft
- **CSPT** — client-side path traversal in `fetch()`, `import()`, or routing with user-controlled path segments
- **Prototype pollution** — `__proto__`, `constructor.prototype` via deep merge or query params → XSS/RCE via gadgets
- **DOM clobbering** — named HTML elements overwriting JS globals used in security checks
- **Source map exposure** — `.map` files accessible → full original source code
- **Service worker abuse** — registering malicious SW for persistent XSS/data interception

### Infrastructure
- Subdomain takeover, misconfigured CORS, missing security headers
- Exposed admin panels, debug endpoints, default credentials
- `.git`, `.env`, `.DS_Store`, backup files exposed
- **CRLF/header injection** — parameter reflected in response headers → cache poisoning, session fixation
- **Host header injection** — password reset poisoning, cache poisoning, SSRF via virtual host routing

## OAuth / OIDC

Deserves its own section — consistently high-value and underexplored.

### Authorization Server Flaws
- Open dynamic client registration (`/register` without auth) — RFC 7591
- `token_endpoint_auth_method: "none"` accepted — token exchange without secret
- Arbitrary scope acceptance (server doesn't validate requested scopes)
- Weak redirect_uri validation (regex bypass, subdomain matching, path traversal)
- Authorization code replay (code usable more than once)
- Missing or weak PKCE enforcement
- State parameter not validated → CSRF on OAuth flow

### Token Flaws
- Access token in URL fragment (leaked via Referer header)
- Long-lived access tokens without rotation
- Refresh token not bound to client
- Token scope not enforced by resource server (token says `read`, server allows `write`)
- JWT-based tokens with `alg:none` or HMAC/RSA confusion

### Discovery
- `/.well-known/oauth-authorization-server` — lists supported flows, auth methods, scopes
- `/.well-known/openid-configuration` — OIDC discovery document
- `/register` — test if open (no auth required)
- Check `token_endpoint_auth_methods_supported` for `none`
- Check `scopes_supported` vs what server actually enforces

### Testing Pattern
1. Enumerate OAuth metadata endpoints
2. Test dynamic client registration (if available)
3. Register client with `none` auth + broad scopes
4. Walk the full authorize → callback → token flow
5. Test redirect_uri bypass patterns
6. Check if granted scopes match requested scopes
7. Test token at resource endpoints — does scope enforcement hold?

## SSO / SAML

### SAML
- XML signature wrapping (move signed element, inject unsigned)
- Comment injection in NameID (`user@target.com<!---->.evil.com`)
- Signature exclusion (remove signature, see if SP still accepts)
- Response replay (no `InResponseTo` or expiry check)
- XXE in SAML response XML parsing

### SSO Bypass
- Direct access to endpoints behind SSO (they trust `X-Forwarded-*` headers)
- SSO session vs application session mismatch (SSO session revoked, app session lives)
- IdP impersonation if discovery is misconfigured

## APIs

### REST
- IDOR via predictable resource IDs
- Mass assignment (extra fields in POST/PUT)
- Rate limiting bypass, pagination abuse
- Verb tampering (GET vs POST vs PUT)
- Content-type confusion (`application/json` vs `application/x-www-form-urlencoded`)
- API versioning — old versions (`/v1/`) lack newer security controls

### GraphQL
- Introspection enabled (`{__schema{types{name}}}`)
- Nested query DoS, batching attacks
- Authorization bypass per resolver
- Field suggestion exploitation
- Mutation without auth on admin operations
- Alias-based rate limit bypass

### WebSocket
- Missing origin validation, CSWSH (Cross-Site WebSocket Hijacking)
- Message injection/manipulation
- Auth token in handshake (replayable)
- No message-level authorization
- JWT/Bearer tokens transmitted in WS messages (extractable credentials)
- Privileged state mutations over WS (admin actions, role changes, payments)
- SQL statements or command execution keywords in WS messages
- Internal URLs (localhost, 10.x, 127.x) leaked in WS traffic
- Debug mode flags (`debug: true`) active in production WS channels
- WS connections are a blind spot — HTTP passive workflows don't see WS messages. Monitor separately via Caido's WS stream API or manual inspection.

### gRPC
- Reflection enabled (similar to GraphQL introspection)
- Missing auth on service methods
- Protobuf deserialization issues
- gRPC-web gateway exposing internal services

## MCP / AI Tool Servers

Emerging attack surface. Model Context Protocol servers bridge AI agents to external tools.

### Key Targets
- MCP server endpoints (`/register`, `/authorize`, `/token`, `/tools`)
- Dynamic client registration without authentication
- Tool execution without proper authorization checks
- Prompt injection via tool responses (tool returns malicious content that manipulates the AI)
- Scope/permission escalation through tool registration

### Testing Pattern
1. Discover MCP endpoints (often OAuth-based)
2. Test client registration — open? Auth required?
3. Register client with broad scopes / `none` auth method
4. Enumerate available tools and their permissions
5. Test tool execution authorization (can low-priv client call admin tools?)
6. Test input validation on tool parameters (injection into backend systems)

## Cloud

### AWS
- S3 bucket misconfiguration (public read/write/list)
- IAM privilege escalation
- Lambda function abuse (event injection, environment variable leaks)
- Metadata endpoint (169.254.169.254)
- Cognito misconfig (self-signup with admin attributes), STS assume-role abuse
- SQS/SNS public access

### Azure
- Blob storage public access
- Managed identity exploitation
- Function app misconfig (function keys exposed)
- Metadata endpoint with `Metadata: true` header
- Azure AD misconfigurations (app registration, consent flows)

### GCP
- Cloud Storage bucket exposure
- Service account key leakage
- Cloud Function invocation (unauthenticated)
- Metadata with `Metadata-Flavor: Google` header
- Firebase misconfig (see below)

### Serverless Specific
- Environment variable leaks (secrets in Lambda/Function config)
- Cold start timing attacks
- Shared execution environment risks
- Event injection (crafted S3 events, API Gateway payloads)
- Overpermissioned execution roles

## Mobile

### Android
- Decompile APK: `apktool`, `jadx`
- Hardcoded secrets, API keys, internal endpoints
- Insecure data storage (SharedPreferences, SQLite, external storage)
- Deep link hijacking, intent interception, exported components
- Certificate pinning bypass: `frida`, `objection`
- WebView JavaScript interface abuse

### iOS
- Binary analysis: `class-dump`, `Hopper`, `Ghidra`
- Keychain storage issues
- URL scheme hijacking
- Transport security exceptions (ATS)
- Pasteboard data leakage

### Mobile API Surface
The mobile API is often different from the web API — different endpoints, different auth, sometimes weaker validation. Always proxy mobile app traffic and compare with web.

## CI/CD Pipelines

- GitHub Actions: workflow injection via PR titles/labels/branch names, `pull_request_target` abuse
- GitLab CI: shared runner escape, secret extraction, pipeline variable injection
- Jenkins: unauthenticated console, script console RCE, credential enumeration
- Supply chain: malicious dependencies, typosquatting
- Build artifact exposure, secret leaking in logs
- Self-hosted runner compromise → lateral movement

## Email-Based Vectors

### When in scope
- SPF/DKIM/DMARC misconfiguration → email spoofing from target domain
- Email header injection via contact forms or user-controlled email fields
- HTML email rendering → XSS in email clients
- Password reset link manipulation via Host header injection
- Email verification bypass (race condition, parameter tampering)

## Technology-Specific Targets

When you fingerprint the tech stack (via `httpx --tech-detect`, response headers, or JS analysis), check for technology-specific misconfigurations:

| Technology | Critical Targets | What to test |
|-----------|-----------------|--------------|
| **Spring Boot** | `/actuator/*` (env, mappings, health, configprops, heapdump) | Credential exposure, internal topology, heap dump analysis |
| **Django** | DEBUG=True error pages, `/admin/` | Settings dump, SQL queries, admin panel |
| **Laravel** | Whoops error pages, `APP_DEBUG=true`, `.env` | APP_KEY leak (→ RCE via deserialization), DB creds |
| **WordPress** | `/wp-json/wp/v2/users`, `xmlrpc.php`, `wp-config.php` backups | User enum, brute force, credential exposure |
| **AEM** | `/crx/de`, `/crx/explorer`, `/system/console`, `/bin/querybuilder.json` | Admin console, content repo traversal, query injection |
| **Tomcat** | `/manager/html`, `/host-manager`, default error pages | Default creds → WAR deploy → RCE, version disclosure |
| **PHP** | `phpinfo()`, `php.ini` exposure, type juggling in auth | Config disclosure, loose comparison bypass |
| **Express/Node** | Stack traces with `node_modules/`, `__proto__` pollution | Path disclosure, prototype pollution to RCE |
| **Next.js** | `/_next/data/`, Server Actions, RSC payload manipulation | Data leak via getServerSideProps, action parameter tampering |
| **Ruby/Rails** | `ActionController::RoutingError`, mass assignment, `secret_key_base` | Route dump, attribute injection, session forgery |
| **GraphQL** | Introspection, GraphiQL UI, batching, field suggestions | Schema dump, auth bypass per resolver, DoS via nesting |

For automated detection via Caido passive workflows, see the technology-aware templates in [caido-integration.md](caido-integration.md).

## Focus Strategy

Don't spread thin. Pick 1-2 surfaces and go deep:
- **Starting out** → Web Applications (largest number of programs, most docs)
- **Differentiating** → Cloud, CI/CD, Mobile, OAuth/OIDC, MCP (fewer hunters, better ratio)
- **Highest bounties** → Cloud infra + SSRF chains, OAuth/auth bypass, RCE chains

## Source
https://bugbounty.info/Attack-Surface/
