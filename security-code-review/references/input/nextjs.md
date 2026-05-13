# Input Validation — Next.js / TypeScript Patterns

## NEXT_PUBLIC_ Exposes to Every Browser

Any environment variable prefixed with `NEXT_PUBLIC_` is bundled into
client-side JavaScript. If a secret appears in a `NEXT_PUBLIC_` variable,
it's exposed to every browser that loads your app.

## Zod Schemas for Request Validation

```typescript
import { z } from 'zod'

const CreateUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100).trim(),
  age: z.number().int().min(0).max(150),
})

export async function POST(request: Request) {
  const result = CreateUserSchema.safeParse(await request.json())
  if (!result.success) {
    return NextResponse.json(
      { error: "Invalid input", details: result.error.flatten() },
      { status: 400 }
    )
  }
  // result.data is typed and validated
}
```

## File Upload: Consider file-type Package

```typescript
const allowedTypes = ['image/jpeg', 'image/png', 'image/gif']
if (!allowedTypes.includes(file.type)) {
  throw new Error('Invalid file type')
}
```

`file.type` is browser-reported and can be spoofed. For server-side
validation, consider the `file-type` package which detects MIME from
actual content bytes.
