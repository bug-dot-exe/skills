# Transport Security — Go Patterns

## TLS Configuration

```go
srv := &http.Server{
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
        },
    },
}
```

`CipherSuites` only applies to TLS 1.2. TLS 1.3 cipher suites are fixed by the
spec and cannot be configured — which is a feature, not a limitation.

## http.Server Timeouts (Slowloris Prevention)

```go
srv := &http.Server{
    Addr:         ":8080",
    Handler:      router,
    ReadTimeout:  5 * time.Second,
    WriteTimeout: 10 * time.Second,
    IdleTimeout:  120 * time.Second,
}
```

**Gotcha:** A bare `http.ListenAndServe` has NO timeouts — a slow client
can hold connections open indefinitely (Slowloris).

## Dangerous: InsecureSkipVerify

```go
// DANGEROUS — disables certificate verification entirely
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    },
}
```

Search the codebase for `InsecureSkipVerify` — it is sometimes left in from
development and never removed.
