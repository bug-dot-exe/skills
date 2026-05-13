# Data Exposure — FastAPI Patterns

## Pydantic Response Models (Only Return What's Needed)

```python
from pydantic import BaseModel

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    # Intentionally omit: password_hash, stripe_id, is_admin, internal_flags

    model_config = {"from_attributes": True}

@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: str, user: User = Depends(get_current_user)):
    # Even if the DB model has 20 fields, only 3 are returned
    return await db.get_user(user_id)
```

FastAPI enforces the `response_model` at serialization — extra fields are
automatically excluded even if the DB object has them.

## Global Exception Handler

```python
from fastapi import Request
from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error", path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "An unexpected error occurred. Please try again."},
    )
```

## Safe Logging

```python
import structlog
logger = structlog.get_logger()

# DANGEROUS — credentials and PII in logs
logger.info("login attempt", email=email, password=password)
logger.error("payment failed", card_number=card_number)

# Safe — redact sensitive fields
logger.info("login attempt", email=email, user_id=user_id)
logger.error("payment failed", last_four=card[-4:], user_id=user_id)
```
