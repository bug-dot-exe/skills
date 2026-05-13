# Web Hardening — FastAPI Patterns

## slowapi Rate Limiting

```python
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request
from fastapi.responses import JSONResponse

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse({"error": "Too many requests"}, status_code=429,
                        headers={"Retry-After": "60"})

@app.post("/login")
@limiter.limit("5/minute")  # Strict for auth endpoints
async def login(request: Request): ...

@app.get("/search")
@limiter.limit("30/minute")
async def search(request: Request): ...
```

## Rate Limiting by User ID (Not Just IP)

```python
def get_rate_limit_key(request: Request) -> str:
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
            return payload["sub"]  # Rate limit by user ID when authenticated
        except jwt.InvalidTokenError:
            pass
    return get_remote_address(request)  # Fall back to IP for unauthenticated

limiter = Limiter(key_func=get_rate_limit_key)
```

## Security Headers Middleware

```python
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "0"  # Disabled — use CSP instead
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; "
        "connect-src 'self' https://api.example.com"
    )
    return response
```

## CORS Configuration

```python
from fastapi.middleware.cors import CORSMiddleware

# DANGEROUS — allows everything
app.add_middleware(CORSMiddleware, allow_origins=["*"])

# Safe — explicit origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://myapp.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

## HTML Sanitization: bleach

```python
import bleach

ALLOWED_TAGS = ["b", "i", "em", "strong", "p", "br", "ul", "ol", "li"]
ALLOWED_ATTRS = {}  # No attributes — prevents onclick, onerror, href injection

clean = bleach.clean(user_html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)
```

**FastAPI's Jinja2Templates auto-escapes `.html` files.** Never use
`{{ content | safe }}` or `Markup()` without sanitizing first.
