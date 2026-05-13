# Input Validation — Python Patterns

## os.path.join Absolute Path Bypass

```python
os.path.join("/app/uploads", "/etc/passwd")  # Returns "/etc/passwd"!
```

If the second argument starts with `/`, it replaces the base entirely.

**Safe pattern:**

```python
from pathlib import Path
UPLOAD_DIR = Path("/app/uploads").resolve()

def safe_path(user_filename: str) -> Path:
    clean_name = Path(user_filename).name  # basename only
    if not clean_name or clean_name == ".":
        raise ValueError("Invalid filename")
    target = (UPLOAD_DIR / clean_name).resolve()
    if not target.is_relative_to(UPLOAD_DIR):
        raise ValueError("Path traversal attempt")
    return target
```

## assert Is Removed with -O

```python
assert amount > 0           # GONE with python -O!
assert amount <= balance    # GONE with python -O!

# Safe — explicit checks survive optimization
if amount <= 0:
    raise ValueError("Amount must be positive")
```

Never use `assert` for input validation or security checks.

## re.fullmatch vs re.match

```python
re.match(PAT, "ok@ex.com\n<script>")     # Matches! (no end anchor)
re.fullmatch(PAT, "ok@ex.com\n<script>")  # None (anchors both ends)
```

`match()` only anchors the start. Use `fullmatch()` for input validation.

## File Upload: python-magic for MIME Detection

```python
import magic  # python-magic — detects from content bytes, not headers

detected_mime = magic.from_buffer(content, mime=True)
if detected_mime not in ALLOWED_MIME:
    raise ValueError("Invalid file type")
```

Never trust the user-supplied `Content-Type` header.

## Pydantic Request Validation (FastAPI)

```python
from pydantic import BaseModel, EmailStr, Field, field_validator

class CreateUserRequest(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=100)
    age: int = Field(ge=0, le=150)

    @field_validator("name")
    @classmethod
    def sanitize_name(cls, v: str) -> str:
        return "".join(c for c in v if c.isprintable())
```

FastAPI auto-validates and returns 422 without reaching your handler.

## secrets vs random

```python
import secrets
token = secrets.token_urlsafe(32)   # Cryptographically secure

import random
token = random.getrandbits(128)     # DANGEROUS — Mersenne Twister PRNG
# Predictable after observing 624 outputs
```

`random` is for simulations. `secrets` is for anything security-relevant.
