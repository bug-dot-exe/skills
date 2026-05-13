# Web Hardening — Next.js / TypeScript Patterns

## React XSS: dangerouslySetInnerHTML

React escapes JSX values automatically. The risk is explicit bypass:

```typescript
// Safe — React escapes this
return <div>{userContent}</div>

// DANGEROUS — bypasses escaping
return <div dangerouslySetInnerHTML={{ __html: userContent }} />

// Safe — sanitize first
import DOMPurify from 'isomorphic-dompurify'
const clean = DOMPurify.sanitize(userContent, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
  ALLOWED_ATTR: [],
})
return <div dangerouslySetInnerHTML={{ __html: clean }} />
```

## CSP in next.config.js

```typescript
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "connect-src 'self' https://api.example.com",
    ].join('; ')
  },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
]

module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }]
  }
}
```

## Upstash Rate Limiting (Serverless-Friendly)

```typescript
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(100, '15 m'),
})

const authRatelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, '1 m'),  // Strict for auth
})

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for') ?? '127.0.0.1'
  const { success } = await authRatelimit.limit(ip)
  if (!success) {
    return NextResponse.json(
      { error: 'Too many requests' },
      { status: 429, headers: { 'Retry-After': '60' } }
    )
  }
}
```

## SameSite Cookies + Origin Validation

```typescript
// If auth uses httpOnly + SameSite=Strict, most CSRF is mitigated.
// Additional defense:
export async function POST(request: Request) {
  const origin = request.headers.get('origin')
  if (origin !== env.NEXT_PUBLIC_APP_URL) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
}
```

## CSRF Tokens for Forms

```typescript
import { randomBytes } from 'crypto'
const csrfToken = randomBytes(32).toString('hex')
// Include as hidden field, validate on submission
```

## CORS in Route Handlers

```typescript
return NextResponse.json(data, {
  headers: {
    'Access-Control-Allow-Origin': env.NEXT_PUBLIC_APP_URL,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  }
})
```
