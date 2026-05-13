# Secrets Management — Go Patterns

## Startup Validation with envconfig

```go
import "github.com/kelseyhightower/envconfig"

type Config struct {
    DatabaseURL string `envconfig:"DATABASE_URL" required:"true"`
    SecretKey   string `envconfig:"SECRET_KEY"   required:"true"`
    JWTSecret   string `envconfig:"JWT_SECRET"   required:"true"`
}

func MustLoad() Config {
    var cfg Config
    if err := envconfig.Process("", &cfg); err != nil {
        panic(err) // fail fast — don't start with missing secrets
    }
    return cfg
}

var cfg = MustLoad() // package-level init — fails before serving any requests
```

`required:"true"` causes `envconfig.Process` to return an error if the
variable is absent or empty. The `panic` ensures the process exits immediately
rather than starting in a broken state.
