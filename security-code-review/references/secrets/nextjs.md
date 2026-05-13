# Secrets Management — Next.js / TypeScript Patterns

## Startup Validation with Zod

```typescript
import { z } from 'zod'

const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  NEXTAUTH_SECRET: z.string().min(32),
  STRIPE_SECRET_KEY: z.string().startsWith('sk_'),
})

export const env = envSchema.parse(process.env)
// Throws ZodError at startup if any variable is missing or invalid
```

Import `env` from this module wherever environment variables are needed.
The parse happens at module load time, so the server fails before handling
any requests if secrets are absent.

## NEXT_PUBLIC_ Prefix Danger

Variables prefixed `NEXT_PUBLIC_` are inlined into the client-side bundle at
build time and shipped to every browser. Never use this prefix for:

- API keys or secrets
- Database connection strings
- Internal service URLs
- Feature flags that gate privileged behavior

```bash
# Check for accidentally exposed secrets in the bundle
grep -r "NEXT_PUBLIC_" .env* next.config.js
```

Only `NEXT_PUBLIC_` variables that are genuinely safe to be public should
use this prefix (e.g., public API base URL, analytics tracking IDs with
no write access).
