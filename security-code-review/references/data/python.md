# Data Exposure — Python Patterns

## Logging Format String Attack

```python
import logging
logger = logging.getLogger(__name__)

# DANGEROUS — user input as the format string itself
logger.info(user_input)  # %(name)s, %(filename)s in input leaks LogRecord fields

# Safe — user data as arguments
logger.info("User action: %s", user_input)
```

When `user_input` is the format string, attackers can trigger exceptions or
extract data from the `LogRecord` via `%(name)s`, `%(filename)s`, etc.

## __repr__ / __str__ Leaking Sensitive Data

```python
class User:
    def __init__(self, name, email, ssn):
        self.name = name
        self.email = email
        self.ssn = ssn
    # DANGEROUS — default repr exposes all attributes in logs/tracebacks

    def __repr__(self):  # Safe — explicit repr excludes sensitive fields
        return f"User(name={self.name!r}, email={self.email!r})"
```

## Response Filtering

```python
from dataclasses import dataclass, asdict

@dataclass
class UserRecord:
    id: str
    email: str
    name: str
    password_hash: str  # Never expose in API responses
    stripe_id: str

PUBLIC_FIELDS = {"id", "email", "name"}
user_response = lambda u: {k: v for k, v in asdict(u).items() if k in PUBLIC_FIELDS}
```

## Safe Error Responses

```python
# Safe
logger.exception("Unhandled error")
return {"error": "An unexpected error occurred"}, 500

# DANGEROUS — leaks internals
return {"error": str(exc)}, 500               # SQL queries, file paths
return {"error": traceback.format_exc()}, 500  # Full stack trace
```

## Secure Temporary Files

```python
import tempfile

open("/tmp/myapp_data.txt", "w")  # DANGEROUS — predictable name, symlink attack

# Safe — unpredictable name, 0o600 permissions, auto-cleanup
with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as f:
    f.write(sensitive_data)
```

