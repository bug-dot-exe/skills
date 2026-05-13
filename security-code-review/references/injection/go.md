# Injection Prevention — Go Patterns

## database/sql Placeholders

```go
// Postgres: $1, $2, ...
db.QueryRow("SELECT id, email FROM users WHERE email = $1", userEmail)

// MySQL/SQLite: ?
db.QueryRow("SELECT id, email FROM users WHERE email = ?", userEmail)

// DANGEROUS — string concatenation
query := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", userEmail)
```

## GORM: Safe vs Dangerous

```go
// Safe — GORM parameterizes Where arguments
db.Where("email = ?", userEmail).First(&user)

// Safe — struct-based queries
db.Where(&User{Email: userEmail}).First(&user)

// DANGEROUS — raw string in Where
db.Where(fmt.Sprintf("email = '%s'", userEmail)).First(&user)

// DANGEROUS — Raw without placeholders
db.Raw(fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", userEmail))

// Safe — Raw with placeholders
db.Raw("SELECT * FROM users WHERE email = ?", userEmail).Scan(&user)
```

## sqlx Named Parameters

```go
var user User
db.Get(&user, "SELECT * FROM users WHERE email = $1", userEmail)

// Named struct binding
query := "INSERT INTO users (email, name) VALUES (:email, :name)"
db.NamedExec(query, user)
```

## Command Injection: os/exec

```go
// Safe — exec.Command passes args directly to process, no shell
cmd := exec.Command("convert", userFilename, "output.png")

// DANGEROUS — shell invocation with user input
cmd := exec.Command("bash", "-c", "convert "+userFilename+" output.png")
```

**Gotcha:** `os/exec` does NOT invoke a shell by default. Each argument is
passed directly. Never use `bash -c` or `sh -c` with user input.

## Template Injection: html/template vs text/template

```go
import "html/template"  // Safe — auto-escapes in HTML, JS, URI, CSS contexts
import "text/template"  // DANGEROUS — no escaping at all!
```

Always use `html/template` for anything rendered in a browser.

`template.HTML(userContent)` marks content as safe, skipping escaping — only
use with explicitly sanitized content.

## Dynamic Column Allowlist

```go
var allowedSortColumns = map[string]bool{
    "name": true, "created_at": true, "email": true,
}
if !allowedSortColumns[sortBy] {
    return nil, fmt.Errorf("invalid sort column")
}
query := fmt.Sprintf("SELECT * FROM users ORDER BY %s", sortBy)
```
