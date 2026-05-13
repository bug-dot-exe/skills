# Transport Security — Non-Obvious Patterns

## TLS Version Floor

Minimum: TLS 1.2. TLS 1.0 and 1.1 are deprecated (RFC 8996) and disabled by most
clients. TLS 1.3 preferred where available — it removes all weak cipher suites by
design. Never configure `MinVersion` below `TLS12`.

## Cipher Suites to Avoid

Weak suites still appear in defaults on older runtimes:

- **RC4** — statistical bias; broken
- **3DES / DES** — SWEET32 birthday attack; 64-bit block size
- **MD5 / SHA-1 MAC** — collision attacks
- **CBC mode suites** — BEAST, LUCKY13, POODLE
- **Export-grade ciphers** — intentionally weakened (FREAK, Logjam)
- **NULL ciphers** — no encryption

Safe choices: ECDHE + AES-256-GCM, ECDHE + ChaCha20-Poly1305.
ECDHE provides forward secrecy — compromise of the long-term key doesn't expose past sessions.

## Certificate Verification

Disabling certificate verification is indistinguishable from no TLS at all — a
MITM can present any certificate and intercept all traffic. Common dangerous patterns:

- Python: `ssl.CERT_NONE`, `requests.get(url, verify=False)`, `urllib3.disable_warnings()`
- Go: `tls.Config{InsecureSkipVerify: true}`
- Node: `NODE_TLS_REJECT_UNAUTHORIZED=0`
- curl: `-k` / `--insecure`

These are sometimes added to "fix" a dev/staging issue and then shipped to production.
Search the codebase for all of them.

## HSTS

`Strict-Transport-Security: max-age=31536000; includeSubDomains`

Tells browsers to never attempt plain HTTP connections. Without it, an attacker
on the network can intercept the first HTTP request before the redirect fires
(SSL stripping). `includeSubDomains` prevents attacks via a subdomain.

Preload at https://hstspreload.org for maximum protection (hardcodes the domain
in browser binaries — requires `preload` directive and careful rollout).

## HTTP-to-HTTPS Redirect

Application-level redirect is not sufficient on its own — the initial request
travels over plain HTTP. The correct defense is HSTS (so the browser never
makes the plain-HTTP request) plus the redirect (for first-time visitors and
non-browser clients).

## Server Timeouts (Slowloris / Resource Exhaustion)

A server with no read/write timeouts lets a slow client hold connections open
indefinitely. An attacker sends partial HTTP requests very slowly, exhausting
the connection pool without triggering any rate limiter.

Configure read timeout, write timeout, and idle timeout on the HTTP server.
