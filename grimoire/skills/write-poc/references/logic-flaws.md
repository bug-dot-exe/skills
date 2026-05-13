# Logic / Business Logic Flaws

**Preferred format:** Step-by-step reproduction with explanation

Logic bugs often require narrative context. Use a numbered reproduction format:

```markdown
## Reproduction Steps

1. Create account with role "user"
2. Navigate to /admin/settings (should return 403)
3. Modify request: change `role` cookie value from "user" to "admin"
4. Resend request — server returns 200 with admin panel

## Why This Works

The server checks the role from the client-supplied cookie (line 142 in
auth_middleware.js) rather than from the server-side session. An attacker
can escalate privileges by modifying the cookie value.
```
