# Crown Jewels by Domain

Reference for identifying high-value targets during the Summon workflow. Use this to guide the
crown jewels assessment in Step 5. Not exhaustive — adapt to the specific project.

## Smart Contracts / DeFi

**Assets:**
- Protocol-held funds (liquidity pools, vaults, treasuries, staking contracts)
- Governance tokens and voting power
- Oracle price feeds and data integrity
- Protocol invariants (e.g., total supply, collateralization ratio, exchange rate monotonicity)
- Privileged roles (owner, admin, guardian, pauser)

**Common attack vectors:**
- Reentrancy on state-changing external calls
- Price manipulation via flash loans or oracle staleness
- Rounding / precision loss in token accounting (especially on conversions)
- Access control bypass on privileged functions
- Front-running / sandwich attacks on user transactions
- Cross-chain message spoofing (bridges)
- Storage collision in upgradeable proxy patterns

**What exploitation looks like:**
- Attacker extracts more tokens than deposited
- Governance takeover via flash-loan voting
- Protocol enters irrecoverable state (bricked funds)
- Incorrect liquidation thresholds trigger mass liquidations

## Web Applications

**Assets:**
- User accounts and authentication credentials
- Session tokens and auth cookies
- Personally identifiable information (PII)
- Payment data (credit cards, bank accounts)
- Admin / superuser access
- File uploads and user-generated content

**Common attack vectors:**
- SQL injection in search, filter, or lookup endpoints
- XSS (stored, reflected, DOM-based) in user-controlled content
- CSRF on state-changing operations
- IDOR on resource access (sequential IDs, predictable paths)
- Authentication bypass (JWT manipulation, session fixation, OAuth misconfiguration)
- SSRF via URL parameters, webhooks, or import features
- Deserialization of untrusted data

**What exploitation looks like:**
- Account takeover (ATO) of arbitrary users
- Mass data exfiltration of PII
- Persistent XSS affecting all users viewing a page
- Admin panel access by unprivileged user

## APIs and Microservices

**Assets:**
- Inter-service authentication (mTLS certs, API keys, service tokens)
- Rate limiting and quota enforcement
- Data exposed through API responses (over-fetching)
- Webhook endpoints and callback URLs
- GraphQL introspection and query depth

**Common attack vectors:**
- Broken object-level authorization (BOLA) on REST resources
- Mass assignment via unfiltered request bodies
- GraphQL batching attacks and nested query DoS
- API key leakage in client-side code or logs
- Race conditions on non-idempotent operations
- Insufficient rate limiting on auth endpoints

**What exploitation looks like:**
- Access to other users' data via ID manipulation
- Privilege escalation through mass assignment of role fields
- API key extraction enabling unauthenticated access
- Brute force of credentials via unthrottled login endpoint

## Infrastructure and Cloud

**Assets:**
- Cloud credentials (IAM roles, service accounts, access keys)
- Secrets in environment variables, config files, or secret managers
- Container images and orchestration configs (K8s manifests)
- CI/CD pipelines and deployment credentials
- Network segmentation and internal services

**Common attack vectors:**
- SSRF to cloud metadata endpoints (169.254.169.254)
- Container escape via misconfigured privileges or kernel exploits
- CI/CD pipeline injection (command injection in build scripts)
- Over-permissioned IAM roles / service accounts
- Exposed internal services (databases, caches, admin panels) via network misconfiguration
- Supply chain attacks through dependency confusion or compromised packages

**What exploitation looks like:**
- RCE on production hosts
- Lateral movement from compromised service to secrets manager
- Full cloud account takeover via leaked root credentials
- Deployment of backdoored code through CI/CD compromise

## Cryptography and Authentication

**Assets:**
- Encryption keys (at rest and in transit)
- Key derivation functions and password hashing
- TLS/mTLS configuration
- Token signing keys (JWT secrets, HMAC keys)
- Random number generation for security-critical operations

**Common attack vectors:**
- Weak or predictable randomness (Math.random, unseeded PRNGs)
- ECB mode or other insecure cipher configurations
- Padding oracle attacks on CBC without HMAC
- JWT algorithm confusion (none, HS256 vs RS256)
- Timing attacks on comparison operations
- Hardcoded keys or secrets in source code

**What exploitation looks like:**
- Forging authentication tokens
- Decrypting stored secrets or communications
- Predicting session tokens or password reset codes
- Downgrade attacks on TLS

## Mobile Applications

**Assets:**
- Local storage (keychain, keystore, shared preferences)
- Certificate pinning implementation
- Deep links and intent handlers
- Biometric authentication integration
- API tokens stored on device

**Common attack vectors:**
- Insecure local storage of credentials
- Missing or bypassable certificate pinning
- Deep link hijacking for auth token theft
- Exported activities / content providers exposing internal data
- Weak biometric fallback mechanisms

**What exploitation looks like:**
- Credential extraction from rooted/jailbroken device
- Man-in-the-middle via pinning bypass
- Account takeover via deep link interception
- Data leakage through exported components
