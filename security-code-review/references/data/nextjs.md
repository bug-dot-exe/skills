# Data Exposure — Next.js / TypeScript Patterns

## Response Shaping

```typescript
// Define what the API returns — not the full DB model
interface UserResponse {
  id: string
  email: string
  name: string
  // Omit: passwordHash, internalFlags, stripeCustomerId
}

function toUserResponse(user: DbUser): UserResponse {
  return { id: user.id, email: user.email, name: user.name }
}
```

## Safe Error Handling

```typescript
// DANGEROUS — leaking internals
catch (error) {
  return NextResponse.json(
    { error: error.message, stack: error.stack },
    { status: 500 }
  )
}

// Safe — generic message to client, full details in server logs
catch (error) {
  console.error('Internal error:', error)
  return NextResponse.json(
    { error: 'An error occurred. Please try again.' },
    { status: 500 }
  )
}
```

## Safe Logging

```typescript
// DANGEROUS
console.log('Login:', { email, password })
console.log('Payment:', { cardNumber, cvv })

// Safe
console.log('Login:', { email, userId })
console.log('Payment:', { last4: card.last4, userId })
```

