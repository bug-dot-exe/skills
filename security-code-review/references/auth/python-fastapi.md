# Auth — FastAPI Patterns

## Password Hashing with passlib

```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)
```

## JWT in httpOnly Cookies

```python
from datetime import datetime, timedelta, timezone
import jwt

def create_access_token(user_id: str, expires_minutes: int = 60) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_minutes),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")

@app.post("/login")
async def login(credentials: LoginRequest):
    user = await authenticate(credentials.email, credentials.password)
    if not user:
        raise HTTPException(401, "Invalid credentials")  # Don't reveal which field was wrong
    token = create_access_token(user.id)
    response = JSONResponse({"message": "Logged in"})
    response.set_cookie(
        key="access_token", value=token,
        httponly=True, secure=True, samesite="strict", max_age=3600,
    )
    return response
```

## Dependency-Based Auth and Authorization

```python
from fastapi import Cookie, Depends, HTTPException

async def get_current_user(access_token: str = Cookie(None)) -> User:
    if not access_token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(access_token, settings.secret_key, algorithms=["HS256"])
        user = await db.get_user(payload["sub"])
        if not user:
            raise HTTPException(401, "User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

async def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return user

@app.delete("/users/{user_id}")
async def delete_user(user_id: str, admin: User = Depends(require_admin)): ...
```

## IDOR Prevention

```python
@app.get("/documents/{doc_id}")
async def get_document(doc_id: str, user: User = Depends(get_current_user)):
    doc = await db.get_document(doc_id)
    if not doc or (doc.owner_id != user.id and user.role != "admin"):
        raise HTTPException(404, "Not found")  # 404, not 403 — don't confirm existence
    return doc
```

## Postgres Row-Level Security (Defense in Depth)

```sql
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_own_documents" ON documents
    FOR ALL USING (owner_id = current_setting('app.current_user_id')::uuid);
-- Set per request: SET LOCAL app.current_user_id = '<uuid>';
```

RLS is defense in depth — application-level `Depends` checks are still needed.
