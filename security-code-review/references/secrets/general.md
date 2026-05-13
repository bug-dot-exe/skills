# Secrets Management — Non-Obvious Patterns

## Validate at Startup, Fail Fast

Don't discover a missing secret on the first request that needs it. Validate
all required environment variables at application startup and refuse to boot
if any are missing. This catches misconfigurations at deploy time rather than
creating silent runtime failures or intermittent errors in production.

## Secrets Survive in Artifacts After Removal from Source

Removing a secret from the current HEAD commit is not enough — it may still
exist in:

- **Git history** — `git log -p` reveals it; any clone has the full history
- **Client-side bundles** — search minified JS for key patterns
- **Docker image layers** — each `RUN`, `COPY`, and `ADD` creates a layer;
  a secret in an intermediate layer is still extractable with `docker history`
  and layer inspection tools
- **CI/CD build logs** — `echo $SECRET` in a build step exposes it in logs
- **Error messages and log files** — if a value was ever logged

**The only safe response to an exposed secret is rotation.** Remove from
source _and_ rotate the value.

## Docker Layers: Safe Secret Injection

```dockerfile
# DANGEROUS — SECRET_KEY baked into image layer
RUN pip install ... && echo $SECRET_KEY > /app/config

# Safe — use build secrets (Docker BuildKit)
RUN --mount=type=secret,id=mytoken \
    cat /run/secrets/mytoken | pip install ...

# Or: inject via runtime env vars, not build args
ENV SECRET_KEY=""  # placeholder; set actual value at container start
```

Never use `ARG` for secrets — build args are visible in `docker history`.

## Least-Privilege API Keys

API keys and database credentials should have the minimum permissions required:
read-only database user for reporting queries, scoped API keys for specific
resources. A leaked read-only DB credential is significantly less damaging than
a leaked admin credential.
