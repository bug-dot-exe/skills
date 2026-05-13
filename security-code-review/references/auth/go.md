# Auth — Go Patterns

## Password Hashing: x/crypto/bcrypt

```go
import "golang.org/x/crypto/bcrypt"

bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
```

## JWT in httpOnly Cookies: golang-jwt

```go
import "github.com/golang-jwt/jwt/v5"

claims := jwt.MapClaims{
    "sub": userID,
    "exp": time.Now().Add(time.Hour).Unix(),
    "iat": time.Now().Unix(),
}
token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
signed, _ := token.SignedString(jwtKey)

http.SetCookie(w, &http.Cookie{
    Name: "access_token", Value: signed,
    HttpOnly: true, Secure: true,
    SameSite: http.SameSiteStrictMode, MaxAge: 3600, Path: "/",
})
```

## User from Context Pattern

```go
type contextKey string
const userContextKey contextKey = "user"

// AuthMiddleware parses JWT and injects user into context
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("access_token")
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        token, err := jwt.Parse(cookie.Value, func(t *jwt.Token) (interface{}, error) {
            if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method")
            }
            return jwtKey, nil
        })
        if err != nil || !token.Valid {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        claims, _ := token.Claims.(jwt.MapClaims)
        userID, _ := claims["sub"].(string)
        user, _ := getUserByID(userID)
        ctx := context.WithValue(r.Context(), userContextKey, user)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func UserFromContext(ctx context.Context) *User {
    user, _ := ctx.Value(userContextKey).(*User)
    return user
}
```

**Gotcha:** Always validate the signing method in the parse callback. Without it,
an attacker can switch to `alg: none` and bypass signature verification.

## Middleware-Based Role Checks (Chi)

```go
func RequireRole(roles ...string) func(http.Handler) http.Handler {
    allowed := make(map[string]bool)
    for _, r := range roles { allowed[r] = true }
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := UserFromContext(r.Context())
            if user == nil || !allowed[user.Role] {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

r.Route("/admin", func(r chi.Router) {
    r.Use(RequireRole("admin"))
    r.Get("/users", AdminListUsersHandler)
})
```

