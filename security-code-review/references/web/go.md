# Web Hardening — Go Patterns

## html/template vs text/template

```go
import "html/template"  // Auto-escapes in HTML, JS, URI, CSS contexts
import "text/template"  // NO escaping — XSS if used for browser output
```

Always use `html/template` for anything rendered in a browser.

## template.HTML Bypass

```go
// DANGEROUS — marks content as safe, skipping escaping
data := map[string]interface{}{
    "Content": template.HTML(userContent),  // XSS if unsanitized!
}
```

Only use `template.HTML` with explicitly sanitized content.

## HTML Sanitization: bluemonday

```go
import "github.com/microcosm-cc/bluemonday"

p := bluemonday.StrictPolicy()    // Strip all HTML
p := bluemonday.UGCPolicy()       // User-generated content defaults
p := bluemonday.NewPolicy()       // Custom:
p.AllowElements("b", "i", "em", "strong", "p", "br")
clean := p.Sanitize(userHTML)
```

## gorilla/csrf Middleware

```go
csrfMiddleware := csrf.Protect(
    []byte(cfg.CSRFKey),
    csrf.Secure(true),
    csrf.SameSite(csrf.SameSiteStrictMode),
)
r.Use(csrfMiddleware)

// In handler — pass token to template:
data["CSRFToken"] = csrf.Token(r)
// In template: <input type="hidden" name="gorilla.csrf.Token" value="{{.CSRFToken}}">
```

## Origin Header Validation

```go
func ValidateOrigin(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet && r.Method != http.MethodHead {
            origin := r.Header.Get("Origin")
            if origin != "" && origin != cfg.AllowedOrigin {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }
        }
        next.ServeHTTP(w, r)
    })
}
```

## Rate Limiting: x/time/rate

```go
import "golang.org/x/time/rate"

// Per-IP rate limiting
type IPRateLimiter struct {
    mu       sync.Mutex
    limiters map[string]*rate.Limiter
    rate     rate.Limit
    burst    int
}

func (l *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
    l.mu.Lock()
    defer l.mu.Unlock()
    limiter, exists := l.limiters[ip]
    if !exists {
        limiter = rate.NewLimiter(l.rate, l.burst)
        l.limiters[ip] = limiter
    }
    return limiter
}

// Different limits for auth vs general
var generalLimiter = NewIPRateLimiter(rate.Every(time.Second), 100)
var authLimiter    = NewIPRateLimiter(rate.Every(12*time.Second), 5)
```

For multi-instance deployments, use Redis instead of in-memory limiters.

## CORS: rs/cors

```go
// DANGEROUS
c := cors.AllowAll()

// Safe — explicit origins
c := cors.New(cors.Options{
    AllowedOrigins:   []string{"https://myapp.com"},
    AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
    AllowedHeaders:   []string{"Authorization", "Content-Type"},
    AllowCredentials: true,
    MaxAge:           86400,
})
```

## Security Headers Middleware

```go
func SecurityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-XSS-Protection", "0")
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
        next.ServeHTTP(w, r)
    })
}
```

