# Transport Security — Python Patterns

## TLS Certificate Verification

```python
import ssl

ctx = ssl.create_default_context()   # Safe — TLS 1.2+, cert verification on
ctx.check_hostname = False           # DANGEROUS
ctx.verify_mode = ssl.CERT_NONE      # DANGEROUS — MITM possible

import requests
requests.get(url, verify=False)      # DANGEROUS
requests.get(url)                    # Safe — verify=True by default
```

Suppressing the `InsecureRequestWarning` is a red flag that someone added
`verify=False` and then silenced the warning instead of fixing the root cause:

```python
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # DANGEROUS
```

## Minimum TLS Version (stdlib ssl)

```python
import ssl

ctx = ssl.create_default_context()
ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # Explicit floor; default is usually fine

# Never set:
ctx.minimum_version = ssl.TLSVersion.SSLv3    # DANGEROUS
ctx.minimum_version = ssl.TLSVersion.TLSv1    # DANGEROUS
```

`ssl.create_default_context()` already enforces a safe minimum in CPython 3.10+.
Older versions may need the explicit floor.
