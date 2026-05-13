# Data & Logging — Non-Obvious Patterns

Response shaping, error handling, logging, and secrets management patterns that
leak information in subtle ways.

## Response Shaping: Explicit Field Allowlists

Never serialize full database objects into API responses. Define a response type
with only the fields the client needs. Even `json:"-"` or similar annotations
are defense in depth — the primary control is a separate response type that
explicitly includes only safe fields.

## Error Messages: Generic to Client, Detailed Server-Side

Return "An unexpected error occurred" to clients. Log the full error (with
stack trace, query details, file paths) server-side only. Attackers use
verbose error messages to discover database schemas, internal paths, and
technology stacks.

## Logging: Never Log Secrets or PII

Passwords, tokens, API keys, credit card numbers, SSNs — never in logs. Logs
often have weaker access controls than the application database. Redact
sensitive fields before logging, and use structured logging to make redaction
systematic rather than ad-hoc.

