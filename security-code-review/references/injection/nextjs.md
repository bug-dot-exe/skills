# Injection Prevention — Next.js / TypeScript Patterns

## Prisma: Safe vs Dangerous

```typescript
// Safe — Prisma parameterizes automatically
const user = await prisma.user.findUnique({ where: { email: userEmail } })

// DANGEROUS — raw SQL with interpolation
await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`)

// Safe — tagged template (Prisma parameterizes these)
await prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`
```

**Gotcha:** `$queryRawUnsafe` does exactly what the name says. `$queryRaw`
with tagged templates is safe because Prisma extracts interpolated values
as parameters.

## Supabase (Safe by Default)

```typescript
const { data } = await supabase
  .from('users')
  .select('*')
  .eq('email', userEmail)  // parameterized automatically
```

## Raw SQL with pg/pool

```typescript
// DANGEROUS — string concatenation
const query = `SELECT * FROM users WHERE email = '${userEmail}'`

// Safe — bind parameters ($1, $2, ...)
const { rows } = await pool.query(
  'SELECT * FROM users WHERE email = $1',
  [userEmail]
)
```
