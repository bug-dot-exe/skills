# Auth — Python (stdlib) Patterns

## Password Hashing: passlib CryptContext

```python
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

hashed = pwd_context.hash(password)
pwd_context.verify(plain, hashed)  # Returns bool
```

Or direct bcrypt:

```python
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
bcrypt.checkpw(password.encode(), hashed.encode())
```

## Timing-Safe Comparison

```python
import hmac
# DANGEROUS — == short-circuits (timing side-channel)
provided == expected

# Safe — constant-time
hmac.compare_digest(provided.encode(), expected.encode())
```

Use for tokens, API keys, CSRF tokens, webhook signatures.

## HMAC Message Signing

```python
import hmac, hashlib

def sign(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def verify(key: bytes, message: bytes, signature: str) -> bool:
    return hmac.compare_digest(
        hmac.new(key, message, hashlib.sha256).hexdigest(), signature)
```
