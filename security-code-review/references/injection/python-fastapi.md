# Injection Prevention — FastAPI / SQLAlchemy Patterns

## SQLAlchemy ORM (Parameterized Automatically)

```python
from sqlalchemy import select
from sqlalchemy.orm import Session

# Safe — ORM parameterizes all values
stmt = select(User).where(User.email == user_email)
result = session.execute(stmt).scalar_one_or_none()
```

## Raw SQL with Bind Parameters

```python
from sqlalchemy import text

# DANGEROUS — string formatting in SQL
query = f"SELECT * FROM users WHERE email = '{user_email}'"

# Safe — named bind parameters
result = session.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": user_email}
)
```

## Dynamic Column Names: Allowlist Required

```python
ALLOWED_SORT_COLUMNS = {"name", "created_at", "email"}

def get_users(sort_by: str):
    if sort_by not in ALLOWED_SORT_COLUMNS:
        raise HTTPException(400, "Invalid sort column")
    # Safe — sort_by is from a known set, not user-controlled
    return session.execute(text(f"SELECT * FROM users ORDER BY {sort_by}"))
```

Bind parameters only work for values, not identifiers (column/table names).

## Mass Assignment Prevention with Pydantic

```python
class UpdateProfileRequest(BaseModel):
    name: str = Field(max_length=100)
    bio: str = Field(max_length=500)
    # Intentionally omit: role, is_admin, email, password_hash

@app.put("/profile")
async def update_profile(
    req: UpdateProfileRequest,
    user: User = Depends(get_current_user)
):
    # Only update fields explicitly defined in the request model
    user.name = req.name
    user.bio = req.bio
```

Pydantic models act as an allowlist — fields not in the model are ignored.
