# Injection Prevention — Non-Obvious Patterns

Beyond "use parameterized queries" — the patterns that actually get exploited.

## Dynamic Identifiers Can't Be Parameterized

Bind parameters only work for **values**, not column names, table names, or
`ORDER BY` targets. Dynamic identifiers must use an allowlist:

```
ALLOWED = {"name", "created_at", "email"}
if sort_by not in ALLOWED: reject
query = f"SELECT * FROM users ORDER BY {sort_by}"  # safe — from known set
```

Never parameterize identifiers — most drivers silently quote them as string
literals, breaking the query without preventing injection.

## SQL Injection Hides in Filters, Not Login Forms

Login forms get tested by everyone. Injection actually lives in:
- Sort/order parameters
- Search with LIKE clauses
- Bulk operations and CSV import
- Reporting/export endpoints (often raw SQL for performance)
- JSON/JSONB field queries
- GraphQL resolvers

## Second-Order Injection

Input is safely stored in the database, then later read and used in a new query
without parameterization. The insert was safe; the subsequent use is the
vulnerability. Always parameterize at the point of use, not just at the point
of storage.

## Deserialization = Arbitrary Code Execution

Formats that reconstruct arbitrary objects (pickle, Java ObjectInputStream,
PHP unserialize, Ruby Marshal, YAML with object tags) execute code on load.
Never deserialize untrusted data with these formats. Use JSON, protobuf, or
safe-load variants.

## Template Injection (SSTI)

If user input is the **template itself** (not a variable in a template), the
template engine evaluates it. Test: if `{{7*7}}` renders as `49`, it's injectable.
Full RCE is typically one step away. User input should be passed as template
**variables**, never as template **source**.

## Mass Assignment via Unexpected Fields

If the API binds all request fields directly to a model, an attacker can add
`"role": "admin"` or `"is_admin": true` to a profile update request. Explicitly
define which fields are writable from user input — reject or ignore unexpected ones.
