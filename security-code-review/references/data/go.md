# Data Exposure — Go Patterns

## Response Structs: Explicit Field Control

```go
// DB model — has everything
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	PasswordHash string `json:"-"`  // Never serialized
	StripeID     string `json:"-"`  // Never serialized
	IsAdmin      bool   `json:"-"`  // Never serialized
}

// Preferred: separate response struct for explicit control
type UserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func toUserResponse(u *User) UserResponse {
	return UserResponse{ID: u.ID, Email: u.Email, Name: u.Name}
}
```

`json:"-"` is defense in depth. The primary control is a separate response
type that only includes fields you intend to expose.

## Safe Logging with log/slog

```go
import "log/slog"

// DANGEROUS — credentials and PII in logs
slog.Info("login attempt", "email", email, "password", password)
slog.Error("payment failed", "card_number", cardNumber)

// Safe — redact sensitive fields
slog.Info("login attempt", "email", email, "user_id", userID)
slog.Error("payment failed", "last_four", card[len(card)-4:], "user_id", userID)
```

## Safe Error Handling

```go
func GetItemHandler(w http.ResponseWriter, r *http.Request) {
	item, err := db.GetItem(chi.URLParam(r, "id"))
	if err != nil {
		slog.Error("failed to get item", "error", err, "path", r.URL.Path)
		http.Error(w, "An unexpected error occurred", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(item)
}
```

Never return `err.Error()` to clients — it may contain SQL queries, file
paths, internal hostnames, or stack traces.

