# Secrets Management — Python / FastAPI Patterns

## Startup Validation with pydantic-settings

```python
from pydantic_settings import BaseSettings
from pydantic import AnyUrl

class Settings(BaseSettings):
    database_url: AnyUrl
    secret_key: str
    jwt_secret: str
    model_config = {"env_file": ".env"}

settings = Settings()  # Raises ValidationError at startup if any field is missing
```

Instantiating `Settings()` at module level (not inside a request handler)
ensures the process fails before accepting any traffic when secrets are absent.

For FastAPI, use `lifespan` or a module-level singleton — do not instantiate
inside a dependency that runs lazily per request.

## Checking for Accidental Exposure

```bash
# Search committed files for common secret patterns
git log -p | grep -E "(api_key|secret_key|password)\s*=\s*['\"][^'\"]{8,}"
# If found: rotate the secret — removing from history is not sufficient
```
