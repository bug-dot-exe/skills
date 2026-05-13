# Input Validation — Go Patterns

## http.DetectContentType for MIME Detection

```go
buf := make([]byte, 512)
n, _ := file.Read(buf)
detected := http.DetectContentType(buf[:n])
if !allowedMIME[detected] {
    http.Error(w, "Invalid file type", http.StatusBadRequest)
    return
}
```

Use `http.DetectContentType` on actual bytes, not the user-supplied
`Content-Type` header.

## filepath.EvalSymlinks for Path Traversal

```go
clean := filepath.Base(userFilename)  // basename only
target := filepath.Join(uploadDir, clean)
resolved, err := filepath.EvalSymlinks(filepath.Dir(target))
absUpload, _ := filepath.Abs(uploadDir)
if !strings.HasPrefix(resolved, absUpload) {
    return "", fmt.Errorf("path traversal attempt")
}
```

`filepath.Base` strips directory components. `EvalSymlinks` resolves
symlinks before the prefix check.

## http.MaxBytesReader for Upload Size

```go
r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
```

Enforce size limits before parsing — prevents memory exhaustion from
oversized uploads.

## Struct Validation: go-playground/validator

```go
var validate = validator.New()

type CreateUserRequest struct {
    Email string `json:"email" validate:"required,email"`
    Name  string `json:"name" validate:"required,min=1,max=100"`
    Age   int    `json:"age" validate:"gte=0,lte=150"`
}

if err := validate.Struct(req); err != nil {
    http.Error(w, "Validation failed", http.StatusBadRequest)
    return
}
```

## DisallowUnknownFields for Mass Assignment Prevention

```go
dec := json.NewDecoder(r.Body)
dec.DisallowUnknownFields()  // Rejects unexpected fields
if err := dec.Decode(&req); err != nil {
    http.Error(w, "Invalid JSON", http.StatusBadRequest)
    return
}
```

Without this, extra fields like `"role": "admin"` silently pass through
if they don't match struct tags.
