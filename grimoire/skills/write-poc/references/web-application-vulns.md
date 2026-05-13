# Web Application Vulnerabilities

Format templates for web application proof-of-concept output.

## SQL Injection

**Preferred format:** Standalone Python script or curl commands

**Template structure:**
```python
#!/usr/bin/env python3
"""
SQL Injection PoC - [Target Component]
CWE-89: Improper Neutralization of Special Elements used in an SQL Command

Demonstrates: [data exfiltration / auth bypass / etc.]
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

# Step 1: Send crafted input to vulnerable parameter
# The [parameter] field is concatenated into a SQL query without sanitization
payload = {"param": "' OR 1=1--"}
resp = requests.post(f"{TARGET}/endpoint", data=payload)

# Step 2: Verify injection succeeded
if "expected_indicator" in resp.text:
    print("[+] SQL injection confirmed: query logic was altered")
    print(f"    Response contained {len(resp.json())} records (expected 1)")
else:
    print("[-] Injection did not succeed — target may be patched")
```

**For time-based blind injection**, use `sleep()` payloads and measure response time
differences. Print the timing delta as evidence.

## Cross-Site Scripting (XSS)

**Preferred format:** curl command + browser reproduction steps

**Reflected XSS:**
```bash
# Inject a benign payload into the vulnerable parameter
# The value is reflected in the response without encoding
curl -s "http://localhost:8080/search?q=<img+src=x+onerror=alert(1)>" | grep -o '<img[^>]*>'
```

**Stored XSS:** Use a multi-step format — one request to store, one to retrieve and
demonstrate reflection.

**DOM-based XSS:** Provide a JavaScript snippet showing the vulnerable sink and a URL
that triggers it. Include the exact DOM API call that introduces the payload.

## Server-Side Request Forgery (SSRF)

**Preferred format:** Standalone script with out-of-band verification

```python
# Step 1: Start a listener to confirm the server makes the request
# In terminal 1: nc -lvp 8888
# Step 2: Send the SSRF payload
payload = {"url": "http://127.0.0.1:8888/ssrf-probe"}
resp = requests.post(f"{TARGET}/fetch", json=payload)
# Step 3: Check listener — if connection received, SSRF confirmed
```

For blind SSRF, use DNS-based out-of-band techniques with a controlled domain or
a webhook service.

## Authentication / Authorization Bypass

**Preferred format:** Multi-step request sequence

Document the exact sequence of requests showing:
1. Normal authenticated flow (baseline)
2. Modified flow that bypasses the check
3. Evidence of unauthorized access

Use numbered steps with curl commands or a script that performs both flows
and compares results.

## Insecure Direct Object Reference (IDOR)

**Preferred format:** curl commands showing two user contexts

```bash
# As User A (owns resource 1)
curl -H "Authorization: Bearer TOKEN_A" http://localhost:8080/api/resource/1
# Returns: User A's data (expected)

# As User B (should NOT access resource 1)
curl -H "Authorization: Bearer TOKEN_B" http://localhost:8080/api/resource/1
# Returns: User A's data (VULNERABILITY — no authorization check)
```
