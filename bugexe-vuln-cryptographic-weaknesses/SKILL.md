---
name: cryptographic-weaknesses
description: Cryptographic weakness testing for weak randomness, timing side-channels, insecure key management, and broken crypto primitives
depends_on: []
---

# Cryptographic Weaknesses

Testing for exploitable cryptographic failures in web applications: weak PRNG, timing side-channels, hardcoded/leaked secrets, broken primitives, and hash extension attacks. Scope excludes JWT-specific attacks (see `authentication_jwt`) and application-layer token guessing (see `predictable_token_enumeration`); this skill targets the underlying crypto weakness.

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|---|---|---|
| `Math.random()` / `random.random()` / `rand()` | JS bundles, Python source, PHP source | Non-CSPRNG; output is predictable given seed or prior outputs |
| UUID v1 in tokens/URLs | API responses, cookies, database IDs | Contains timestamp + MAC address; ordering and origin leak |
| `md5(` / `sha1(` in auth paths | Password hashing, HMAC construction, signature verification | Collision-prone; fast to brute-force; no salt built in |
| `==` / `strcmp` for secret comparison | Token verification, HMAC check, API key validation | Early-exit string comparison leaks secret length and prefix via timing |
| `BEGIN RSA PRIVATE KEY` / `.pem` / `.key` | Git history, S3 buckets, JS bundles, config files, Docker layers | Exposed private key enables impersonation, forgery, or decryption |
| `SECRET_KEY` / `JWT_SECRET` / `CRYPTO_SECRET` in source | `.env`, `config.js`, `application.properties`, Docker images | Hardcoded secret allows token forgery and session hijacking |
| `AES-ECB` / `DES` / `RC4` in code or headers | Encryption routines, TLS config, cookie encryption | ECB leaks patterns; DES/RC4 are broken; chosen-plaintext attacks |
| `PBKDF2` with < 100k iterations / `bcrypt` cost < 10 | Password storage, key derivation | Weak iterations make offline brute-force feasible with commodity GPUs |
| `secret + message` hashed (not HMAC) | MAC/signature construction in custom auth | Vulnerable to hash length extension (MD5/SHA1/SHA256) |
| Same key across dev/staging/prod | Deployment configs, environment variables | Dev key compromise gives production access |
| Base64-encoded structured tokens | Reset URLs, invitation links, API keys | Often encode timestamp+userID with no signature; forgeable |
| TLS downgrade / cleartext fallback | Protocol negotiation, STARTTLS, `--krb` | Security-elevated mode fails open to plaintext |

## Attack Surface

**Token Generation** -- Reset tokens, API keys, session IDs, invitation codes, email verification links, OTP seeds, CSRF tokens. Any value whose secrecy depends on unpredictability.

**Secret Storage** -- Hardcoded keys in source, unrotated secrets in git history, shared keys across environments, private keys in public artifacts (S3, Docker registry, firmware, mobile APK).

**Cryptographic Verification** -- HMAC/signature comparison, password hash verification, certificate validation, token signature checks. Any code path where timing or error differences leak information.

**Primitive Selection** -- MD5/SHA1 for security, ECB mode, weak KDF iterations, custom/homebrew crypto, short key lengths, insecure cipher modes.

**Protocol Negotiation** -- TLS version fallback, STARTTLS stripping, Kerberos-to-plaintext downgrade, algorithm negotiation confusion.

## Reconnaissance

**Secret Scanning Tools**
```bash
# Git history (all branches, all commits)
truffleHog git file://./target-repo --entropy=True --regex
gitleaks detect --source ./target-repo --verbose

# JS bundles
curl -s https://target.com/main.js | grep -oiE '(secret|key|token|password|api.?key)\s*[:=]\s*["\x27][^"\x27]{8,}["\x27]'

# Docker image layers
docker save TARGET_IMAGE | tar -xf - && grep -rl 'BEGIN.*PRIVATE\|SECRET_KEY\|API_KEY' .

# GitHub org-wide search (via gh CLI or API)
gh search code "JWT_SECRET org:TARGET_ORG" --json path,repository
```

**Crypto Primitive Detection**
```bash
# Identify hash/cipher usage in source
grep -rn 'md5\|sha1\|DES\|RC4\|ECB\|AES-128-ECB' --include='*.py' --include='*.js' --include='*.java' --include='*.php' .
# Identify non-CSPRNG usage
grep -rn 'Math\.random\|random\.random\|mt_rand\|java\.util\.Random\|math/rand' --include='*.py' --include='*.js' --include='*.java' --include='*.go' .
```

**TLS/Protocol Analysis**
```bash
# Check TLS configuration and cipher suites
testssl.sh --severity HIGH --vulnerable https://target.com
nmap --script ssl-enum-ciphers -p 443 target.com
```

## High-Value Targets

- Password reset tokens (predict or forge = ATO)
- API keys and webhook secrets (forge = full API access)
- Session ID generation (predict = session hijack)
- OAuth state/nonce parameters (predict = CSRF in OAuth flow)
- HMAC/signature verification endpoints (timing = forge signatures)
- `.env` files and git history (hardcoded secrets = everything)
- Mobile app bundles and firmware (embedded private keys)
- Docker images and CI/CD artifacts (build-time secrets in layers)

## Key Vulnerabilities

### Weak Randomness / Predictable Values

**Non-CSPRNG Usage by Language**

| Language | Insecure | Secure |
|---|---|---|
| JavaScript | `Math.random()` | `crypto.randomBytes()` / `crypto.getRandomValues()` |
| Python | `random.random()` / `random.randint()` | `secrets.token_hex()` / `os.urandom()` |
| PHP | `rand()` / `mt_rand()` / `uniqid()` | `random_bytes()` / `random_int()` (PHP 7+) |
| Java | `java.util.Random` | `java.security.SecureRandom` |
| Ruby | `rand()` | `SecureRandom.hex()` |
| Go | `math/rand` | `crypto/rand` |

**Token Structure Analysis**
1. Collect 20+ tokens from the same endpoint (registration, reset, invite)
2. Decode (base64, hex) and look for structure: timestamps, sequential counters, user IDs
3. Check entropy: `echo -n "TOKEN" | ent` -- good tokens show > 3.5 bits/byte
4. Diff sequential tokens: if only 1-2 bytes change, the random portion is small
5. UUID v1: bytes 0-7 are timestamp (100ns since 1582), bytes 10-15 are MAC address. Decode with `python3 -c "import uuid; u=uuid.UUID('TOKEN'); print(u.time, u.node)"`

**Seed Recovery** -- Java `Random` uses a 48-bit seed with LCG. Given one output, recover the seed with `java.util.Random` reversers (e.g., `untwist`). PHP `mt_rand()` uses Mersenne Twister; 624 outputs fully recover internal state. Python `random` also uses MT19937.

### Timing Side-Channels

**Where Timing Leaks Occur**
- String comparison of secrets: `if (token == stored_token)` exits on first mismatch
- HMAC verification: `if (hmac == expected)` instead of `hmac.compare_digest()`
- Database lookup by username: user-exists returns faster than user-not-found (or vice versa)
- Password hash verification: bcrypt on valid user vs early return on invalid user

**Practical Measurement**
```
# Measure timing for known-correct first byte vs known-wrong
for i in $(seq 1 1000); do
  curl -o /dev/null -s -w '%{time_total}\n' \
    -H "X-API-Key: AXXXXXX" https://target.com/api/verify
done > correct_prefix.txt

for i in $(seq 1 1000); do
  curl -o /dev/null -s -w '%{time_total}\n' \
    -H "X-API-Key: ZXXXXXX" https://target.com/api/verify
done > wrong_prefix.txt
```
- N >= 1000 requests per candidate to overcome network jitter
- Use percentile analysis (p50, p95), not averages -- averages are dominated by outlier latency
- Statistical test: Mann-Whitney U or Welch's t-test on the two distributions
- Signal threshold: > 1ms median difference is exploitable over internet; > 100us over LAN
- Byte-by-byte recovery: once first byte is confirmed, fix it and time the second byte

**User Enumeration via Timing** -- Login endpoints that hash the password only when the user exists. Measure `POST /login` with valid-username-wrong-password vs invalid-username. If valid user takes > 100ms longer (bcrypt), username existence is confirmed.

### Insecure Key Management

**Hardcoded Secret Discovery**
1. **Source code**: grep for `SECRET`, `KEY`, `PRIVATE`, `PASSWORD`, `CREDENTIAL`, `API_KEY` in all config files
2. **Git history**: `truffleHog` or `gitleaks` on full repo history -- secrets removed at HEAD persist in prior commits
3. **JS bundles**: search for base64 blobs > 32 chars, `AKIA` (AWS), `ghp_` (GitHub), `sk-` (Stripe/OpenAI)
4. **Docker images**: `docker save IMAGE | tar -x` then grep layers; `dive` reveals per-layer filesystem
5. **Mobile APKs**: `jadx` decompile, grep for key patterns in `strings.xml`, `BuildConfig`, `SharedPreferences`
6. **S3/GCS buckets**: enumerate `COMPANY-secrets`, `COMPANY-keys`, `COMPANY-backup` bucket names

**Key Rotation Failures** -- Secret leaked and removed but NOT rotated at source. The git-history copy is still valid. Verify every discovered key by attempting to use it against the service.

**Cross-Environment Key Reuse** -- Same `JWT_SECRET` or `COOKIE_SECRET` in dev and production. Compromised dev instance (often less protected) yields production token forgery.

### Broken Crypto Primitives

| Primitive | Problem | Exploit |
|---|---|---|
| MD5 for password hashing | No salt, ~10B hashes/sec on GPU | Rainbow tables, hashcat brute-force |
| SHA1 for signatures | Collision attacks practical (SHAttered) | Forge documents with same hash |
| ECB mode encryption | Identical plaintext blocks = identical ciphertext | Detect patterns, swap blocks, decrypt structured data |
| DES / 3DES / RC4 | Short key / biased output | Brute-force, statistical attacks |
| PBKDF2 < 100k iters | Too fast for offline attack | GPU-accelerated cracking |
| RSA < 2048 bits | Factorable with modern compute | Key recovery |
| Custom/homebrew crypto | Untested, unreviewed | Usually broken on first analysis |

**ECB Detection**: Encrypt a message with repeated blocks (`AAAAAAAAAAAAAAAA` x 4). If ciphertext contains repeated 16-byte blocks, the cipher is ECB mode.

**CBC Padding Oracle**: If the server returns different errors for "bad padding" vs "bad MAC" (or different timing), you can decrypt any ciphertext block-by-block. Test by flipping the last byte of a ciphertext block and observing the error type.

### Hash Length Extension

**When Vulnerable**: Application uses `hash(secret || message)` for MAC (not HMAC). Applies to MD5, SHA1, SHA256, SHA512 -- all Merkle-Damgard hashes.

**How It Works**: Given `hash(secret || message)` and `len(secret)`, compute `hash(secret || message || padding || attacker_data)` WITHOUT knowing the secret. The hash output IS the internal state needed to continue hashing.

**Tools**: `HashPump`, `hash_extender`, `hlextend` (Python)

```bash
# Forge extended signature
hashpump -s ORIGINAL_SIG -d "original_data" -a "&admin=true" -k SECRET_LENGTH
```

**When NOT Vulnerable**: HMAC (`hash(key XOR opad || hash(key XOR ipad || message))`), SHA-3/BLAKE2/BLAKE3 (sponge construction), any MAC using a proper construction.

### Signature Bypass Patterns

| Bypass | Technique | Impact |
|---|---|---|
| Algorithm confusion | Change JWT `alg` RS256 to HS256; server uses public key as HMAC secret | Token forgery (see `authentication_jwt` for JWT-specific detail) |
| Null/empty signature | Send token with `alg: none` or empty signature field | Auth bypass |
| Signature stripping | Remove signature entirely; some parsers accept unsigned data | Auth bypass |
| Return value ignored | `verify()` returns boolean but caller doesn't check it | Arbitrary forgery |
| Wrong key type | Server accepts any key that parses, not the intended signing key | Token forgery |
| Weak RSA exponent | Public exponent e=3 with unpadded RSA | Cube-root signature forgery |

## Bypass Techniques

- **Timing amplification**: if single-request timing is too noisy, find an endpoint that verifies the secret N times per request (batch API, array parameter) -- timing difference scales by N
- **Cache-based timing**: use server-side cache hit/miss as a boolean oracle for whether a value was recently verified
- **Error message differentiation**: "invalid signature" vs "expired token" vs "malformed token" reveals which check failed
- **Downgrade forcing**: strip STARTTLS from SMTP, force HTTP on HTTPS-capable endpoint, manipulate TLS ClientHello to force weak ciphers
- **Encoding tricks**: base64url vs base64, hex upper vs lower case, URL-encoded vs raw -- different decoders may accept different signatures
- **Version-keyed crypto oracle**: when an application uses per-version hardcoded encryption keys (e.g., Telerik RadAsyncUpload), try each known version key against the endpoint -- successful decryption/upload reveals the exact version (confirmed exploitation pattern from H1 #913695)
- **Extension manifest pivoting**: Chrome extension `manifest.json` files on GitHub declare `matches` for target URLs; pivot to the extension author's companion backend repos to find `.env` files with `JWT_SECRET`, `API_KEY`, `CRYPTO_SECRET` (confirmed from H1 #1298809)
- **Fail-open downgrade**: when a security-elevated protocol (Kerberos, STARTTLS, MFA) fails, trace the failure path -- if it silently falls back to cleartext/password-only, the downgrade IS the exploit (confirmed from curl KRB-FTP H1 #1590102)

## Testing Methodology

1. **Inventory crypto surfaces**: list all tokens, keys, hashes, signatures, encrypted values in scope
2. **Collect token samples**: 20+ tokens per endpoint; decode and analyze structure/entropy
3. **Identify PRNG**: grep source/bundles for non-CSPRNG functions per language table above
4. **Test timing**: measure secret-comparison endpoints with N=1000 requests, compare distributions
5. **Scan for hardcoded secrets**: run `truffleHog`/`gitleaks` on git history; grep JS bundles and Docker images
6. **Check primitives**: identify hash algorithms, cipher modes, KDF parameters in use
7. **Test hash extension**: if custom MAC uses `hash(secret||data)`, attempt extension with `hashpump`
8. **Test signature bypass**: try `alg:none`, empty signature, algorithm confusion on any signed token
9. **Verify key rotation**: for any discovered secret, test if it is still valid against the service
10. **Check protocol downgrade**: test failure paths of security-elevated modes (TLS, Kerberos, MFA)

## Validation

- Weak PRNG: predict the next token value and use it to authenticate or reset a password
- Timing leak: demonstrate statistical significance (p < 0.05) across N=1000+ requests showing byte-by-byte recovery
- Hardcoded secret: use discovered key to forge a valid token/session and access another user's data
- Broken primitive: demonstrate practical exploitation (crack a hash, detect ECB patterns, exploit padding oracle)
- Hash extension: forge a valid MAC for an extended message without knowing the secret
- Key rotation failure: demonstrate a secret removed from HEAD is still valid against the live service

## False Positives

- `Math.random()` used for non-security purposes (UI animation, shuffle display order)
- MD5/SHA1 used for non-security checksums (file dedup, cache keys, ETags)
- Timing differences < 0.1ms over internet with N < 500 (noise, not signal)
- Hardcoded keys that are explicitly test/development values with no production access
- ECB mode used for single-block encryption (no repeated-block pattern possible)
- Self-signed certificates in development environments with no production exposure
- Joke/honeypot credentials (e.g., Reddit's `/etc%2fpasswd` easter egg) -- verify discovered secrets are real before reporting
- Keys in git history that have already been rotated at the service (verify by attempting to use them)

## Impact

- **Account takeover**: predict reset tokens, forge sessions, recover passwords from weak hashes
- **Data breach**: decrypt data protected by broken ciphers, read traffic via leaked private keys
- **Impersonation**: forge signatures, mint valid tokens with hardcoded secrets
- **Lateral movement**: dev key reuse gives production access; leaked cloud keys give infrastructure control
- **Regulatory/compliance**: weak crypto violates PCI-DSS, HIPAA, SOC2, GDPR encryption requirements

## Chain Patterns

| Chain | Steps | Combined Severity |
|---|---|---|
| Weak PRNG -> token prediction -> ATO | Identify `Math.random()` in reset flow -> predict next token -> reset victim password | Critical |
| Timing leak -> user enumeration -> credential stuffing | Time login endpoint -> build valid username list -> stuff with breach corpus | High |
| Hardcoded JWT secret -> forge admin token -> full access | Find `JWT_SECRET` in git history/JS bundle -> sign admin JWT -> access admin API | Critical |
| ECB detection -> block manipulation -> privilege escalation | Identify ECB-encrypted cookie -> swap role block from admin response -> replay | High |
| Hash extension -> parameter injection -> auth bypass | Extend `hash(secret\|\|data)` MAC with `&admin=true` -> bypass authorization check | Critical |
| Leaked private key -> MITM/impersonation -> data theft | Find `.pem` in S3/git -> impersonate TLS server or sign forged tokens -> intercept traffic | Critical |
| Weak PBKDF -> offline crack -> credential reuse -> ATO | Exfiltrate hashes (SQLi/backup) -> crack with hashcat -> reuse on other services | High |
| UUID v1 -> timestamp/MAC leak -> session prediction | Decode UUID v1 tokens -> derive generation time and server MAC -> narrow prediction window | Medium |
| Padding oracle -> decrypt cookie -> session hijack | Flip ciphertext bytes -> classify server error type -> recover plaintext block-by-block -> forge session | Critical |
| Protocol downgrade -> credential theft -> lateral movement | Force Kerberos/TLS failure -> capture plaintext password -> reuse across internal services | High |

## Pro Tips

1. Collect tokens from the SAME endpoint at known intervals -- timestamp correlation is the fastest way to confirm time-based token generation
2. For timing attacks, use TCP connection reuse (`curl --keepalive`) and run from the same datacenter region as the target to minimize jitter
3. `truffleHog` on git history catches secrets that `grep` on HEAD misses -- always scan full history, all branches, all tags
4. When you find one hardcoded secret, search the same author's other repos and the organization's other repos -- key reuse is epidemic
5. PHP `mt_rand()` state recovery needs only 624 consecutive outputs; if an endpoint leaks sequential mt_rand values (e.g., CAPTCHA IDs), the entire PRNG is broken
6. ECB mode is instantly detectable on any endpoint that encrypts attacker-controlled input -- send 32 identical bytes and check for repeated ciphertext blocks
7. Padding oracle attacks work even through WAFs if you send requests slowly enough -- the oracle is in the error TYPE, not the error MESSAGE
8. Hash length extension requires knowing the secret length; try lengths 8 through 64 -- most secrets are 16, 32, or 64 bytes
9. The strongest signal for weak crypto is custom implementation -- any code that builds its own MAC, KDF, or cipher instead of using a library is almost certainly broken
10. Always verify discovered secrets are still active before reporting -- rotated secrets are not vulnerabilities, just historical hygiene issues
11. Grep every `pom.xml`, `build.gradle`, `package.json`, `Pipfile`, `Cargo.toml` for `http://` repository URLs -- build-time dependency MITM is a supply-chain Critical ($1K PortSwigger -- H1 #506161)
12. For HTTP clients (curl, requests, undici), audit redirect handlers against the full origin tuple (scheme+host+port) -- same-host HTTPS-to-HTTP downgrade leaks `Authorization`/cookies to cleartext (curl CVE-2022-27776 -- H1 #1551591)
13. Test HSTS enforcement with trailing-dot hostnames (`target.com.`) -- trailing-dot canonicalization bypasses HSTS, cookies, and CORS allow-lists across curl, browsers, and language HTTP clients (curl CVE-2022-30115 -- H1 #1565622)
14. For any config option combining allowlist + denylist, test the empty-list state -- `--proto -all,+https` with a typo leaving the denylist empty may silently re-enable disabled protocols (curl CVE-2024-2004 -- H1 #2437131)
15. Audit credential-propagation on indirect transfers (redirects, metalink mirrors, referrals) -- curl sent `Authorization` to metalink secondary hosts because the redirect-strip check didn't cover metalink peer URLs (CVE-2021-22923 -- H1 #1213181)
16. For ECDH endpoints accepting JWE/JOSE payloads, send an invalid-curve point (not on P-256) -- if the server computes ECDH without rejecting, you can recover the private key bit-by-bit via small-subgroup oracle ($1K+ bounties across node-jose, jose2go, Nimbus -- H1 #213437)
17. Cross-language vulnerability porting: when a STARTTLS stripping bug is found in Python smtplib, immediately check Ruby `net/imap`, Go `net/smtp`, Java `javax.mail` -- the same silent-fallback flaw recurs across languages ($500-$1K per language -- H1 #144782, #1178562)
18. For any "is this valid?" crypto check, ask "valid for WHAT?" -- OCSP responses checked for signature but not bound to the cert serial number bypass revocation entirely (curl CVE-2020-8286 -- H1 #1048457)
19. Test security-config boolean options with all falsy values (`false`, `0`, `null`, `undefined`, `""`). Node.js `rejectUnauthorized: undefined` disabled TLS verification for every `global-agent` user (H1 #1278254)
20. Audit every plaintext-to-encrypted transition for buffer-state carryover -- if the pre-TLS read buffer is not flushed before handshake, an MITM can inject fake "encrypted" responses (curl STARTTLS injection CVE-2021-22947 -- H1 #1334763)
21. For multi-client E2EE products, diff the key-verification flow across iOS/Android/Desktop -- the platform that implements less is the vulnerability. Nextcloud Desktop/Android skipped public-key binding verification that iOS did ($1.5K -- H1 #1189162)

## TLS/Certificate Attack Patterns

| Attack Pattern | Test Method | Signal | Corpus Reference |
|---|---|---|---|
| STARTTLS stripping (fail-open) | MITM proxy returns non-OK to STARTTLS; check if client sends credentials in cleartext | Client continues without TLS after rejected upgrade | Python smtplib $1K, Ruby net/imap $500 |
| Missing cert validation in stdlib wrappers | Call `IMAP4_SSL(host)` / `smtp.starttls()` without explicit `ssl_context`; connect via MITM with wrong-hostname cert | Connection succeeds despite hostname mismatch | Google oauth2.py $10.1K |
| OCSP response substitution | Present revoked cert + stapled OCSP response from a different same-issuer cert | Client accepts revoked cert because serial number not cross-checked | curl CVE-2020-8286 |
| Proxy CONNECT cert mismatch | Route HTTPS through HTTP proxy; proxy presents own cert instead of origin's | Client validates proxy cert, not origin cert (missing `servername` propagation) | Undici ProxyAgent $1K |
| Tri-state return value mishandling | Trigger X509_verify_cert internal error (missing SAN + name constraints); check if app treats unknown error as success | `SSL_ERROR_WANT_RETRY_VERIFY` returned to unprepared app | OpenSSL CVE-2021-4044 $1.2K |
| Pre-TLS buffer injection | Pipeline extra data after STARTTLS-OK response; check if client reads it as post-TLS authenticated data | Injected cleartext treated as encrypted response | curl CVE-2021-22947 |
| Falsy-coercion cert bypass | Set `rejectUnauthorized` to `undefined`/`0`/`null`/`""`; connect to self-signed server | Connection succeeds because parser treats non-false falsy as disabled | Node.js $150 (high real-world impact) |
| Build-time dependency MITM | Grep `pom.xml`/`build.gradle`/`package.json` for `http://` repository URLs | JAR/package fetched over cleartext, replaceable in transit | PortSwigger $1K |

## Defense-Bypass Pairs

| Defense | Bypass | How to Test |
|---|---|---|
| OCSP stapling (revocation check) | Substitute OCSP response from different same-issuer cert (serial not bound) | Present revoked cert + valid sibling's OCSP response |
| SSH host-key pinning (`CURLOPT_SSH_HOST_PUBLIC_KEY_MD5`) | Supply fingerprint string != 32 chars; validator fails open | Set fingerprint to 31 or 33 chars, connect to different host |
| STARTTLS upgrade (cleartext-to-encrypted) | Inject error response to STARTTLS command; client falls back silently | MITM proxy returns `454 TLS not available`; watch for cleartext auth |
| E2EE public-key binding | Substitute public key during device onboarding on platforms missing verification | Replace server-stored public key; add new device; check if client encrypts to attacker key |
| `rejectUnauthorized` TLS validation | Pass `undefined` instead of `true` via env-var-driven config construction | Trace library option-building from env vars; test with unset var |
| ECDH point-on-curve validation | Send invalid-curve ephemeral public key in JWE; server computes ECDH on wrong subgroup | Craft small-order twist point; observe MAC-based oracle for shared secret |
| Certificate hostname verification | Route through proxy that shares TLS context between proxy and origin socket | Test HTTPS-over-CONNECT with mismatched origin hostname |
| Cryptographic MAC (hash-based) | Extend `hash(secret\|\|data)` without knowing secret (Merkle-Damgard construction) | Use `hashpump` with guessed secret lengths 8-64 |
| TOTP/HOTP shared secret strength | Measure base32 secret length; if < 32 chars (160 bits), entropy below RFC 4226 minimum | Count displayed TOTP secret characters x 5 bits/char |
| Build integrity (signed releases) | MITM dependency fetch over HTTP before signing | Grep build configs for `http://` repo URLs; intercept during build |

## Cryptographic Weakness Matrix

| Weakness Class | Discovery Signal | Test Technique | Common Finding |
|---|---|---|---|
| Non-crypto PRNG in security context | `math/rand`, `Math.random()`, `mt_rand()`, `java.util.Random` in source | Collect 20+ outputs; check entropy; attempt state recovery | Token/ISN/port prediction ($750K gVisor) |
| Non-crypto hash key for identifiers | Jenkins/FNV/Murmur with static key in ID generation | Observe outputs across connection tuples; solve for key algebraically | Network identifier prediction, device tracking |
| Spec-silent crypto precondition | ECDH/RSA/DH accepting attacker-controlled key material | Send malformed key (invalid curve point, small-order group element) | Private key recovery via oracle ($1K+ JWE) |
| Validator fail-open on malformed input | Length/format check gates security comparison | Supply wrong-length/wrong-format input to pinning/fingerprint APIs | Silent bypass of host-key/cert pinning |
| Protocol upgrade buffer carryover | Same TCP stream transitions plaintext-to-TLS | Pipeline data after upgrade-OK; check if read as authenticated | Response injection in IMAP/POP3/FTP/SMTP |
| Cross-client crypto inconsistency | Multi-platform E2EE product (iOS/Android/Desktop/Web) | Diff key-verification flow across all clients | Missing verification on subset of platforms ($1.5K) |
| Documentation-implementation drift | Security boolean option with `=== false` vs `!value` check | Test with all falsy values per language (`null`, `undefined`, `0`, `""`) | TLS verification silently disabled |
| Opportunistic TLS fail-open | STARTTLS/AUTH TLS/STLS in protocol negotiation | MITM returns error to upgrade command; observe client behavior | Cleartext credential transmission ($500-$1K) |
| Insufficient key/secret entropy | TOTP secret < 32 base32 chars, HMAC key < 128 bits | Count key length; multiply by bits-per-encoding-char | Below RFC minimum ($300) |
| Insecure default in stdlib wrapper | TLS API constructor with optional `ssl_context` parameter | Call without context; connect through MITM with wrong cert | MitM of all downstream consumers ($10.1K) |
| Signed-object-to-instance unbinding | OCSP/JWT/SAML/SCT validates signature but not target binding | Substitute signed object from different-but-same-issuer instance | Revocation/authN bypass |
| Copy-paste primitive drift | New feature duplicated from existing with changed algorithm/encoding | Diff original vs copy; check every primitive for consistency | Encode/decode mismatch, wrong hash algorithm |

## Summary

Cryptographic weaknesses in web applications cluster around predictable randomness, timing side-channels in secret comparison, hardcoded/leaked key material, and misuse of broken primitives. Each produces a distinct exploitation path: PRNG prediction enables token forgery, timing leaks enable byte-by-byte secret recovery, hardcoded keys enable direct impersonation, and broken primitives enable offline attacks against captured data.
