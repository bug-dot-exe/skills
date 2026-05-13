# Input Validation — FastAPI Patterns

## Pydantic Request Models (Auto-Validated)

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
This eliminates the need for manual `if not email:` checks.

## File Upload: python-magic for MIME Detection

```python
import magic
import uuid
from pathlib import Path

ALLOWED_MIME = {"image/jpeg", "image/png", "image/gif", "image/webp"}
MAX_SIZE = 10 * 1024 * 1024  # 10 MB

@app.post("/upload")
async def upload_file(file: UploadFile):
    content = await file.read(MAX_SIZE + 1)
    if len(content) > MAX_SIZE:
        raise HTTPException(413, "File too large")

    # Check actual content bytes — never trust the user-supplied Content-Type
    detected_mime = magic.from_buffer(content, mime=True)
    if detected_mime not in ALLOWED_MIME:
        raise HTTPException(400, "Invalid file type")

    ext = Path(file.filename).suffix.lower()
    if ext not in {".jpg", ".jpeg", ".png", ".gif", ".webp"}:
        raise HTTPException(400, "Invalid file extension")

    safe_name = f"{uuid.uuid4()}{ext}"  # Never use the user-provided filename
    return {"filename": safe_name}
```

## Path Traversal Prevention

```python
from pathlib import Path

UPLOAD_DIR = Path("/app/uploads").resolve()

def safe_path(user_filename: str) -> Path:
    clean_name = Path(user_filename).name  # basename only — strips any ../ components
    if not clean_name or clean_name == ".":
        raise HTTPException(400, "Invalid filename")
    target = (UPLOAD_DIR / clean_name).resolve()
    if not target.is_relative_to(UPLOAD_DIR):
        raise HTTPException(400, "Path traversal attempt")
    return target
```
