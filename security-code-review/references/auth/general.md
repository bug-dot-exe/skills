# Auth & Authorization — Non-Obvious Patterns

Patterns that are easy to miss in security reviews. Claude already knows the basics
(use bcrypt, use JWTs, check permissions) — this covers what gets overlooked.

## IDOR: Return 404, Not 403

When a user tries to access a resource they don't own, return 404 — not 403.
A 403 confirms the resource exists, enabling enumeration. The ownership check
and the not-found check should be indistinguishable to the caller.

## Session Fixation After Privilege Change

Regenerate session tokens after any privilege change: login, role change, password
reset, email change. If the session ID stays the same, an attacker who set or
captured the pre-auth session ID hijacks the authenticated session.

## Timing-Safe Token Comparison

String `==` short-circuits on the first differing byte — an attacker can
recover a token byte-by-byte via timing analysis. Use constant-time comparison
for all token/key/CSRF comparisons.

## Auth Bypass via HTTP Method Switching

If a route checks auth only on POST but the framework also routes GET to the
same handler, attackers switch methods. Ensure auth middleware applies regardless
of HTTP method, or explicitly reject unexpected methods.

## OAuth State Parameter

The `state` parameter in OAuth flows prevents CSRF — without it, an attacker
can initiate an OAuth flow and have the victim complete it, linking the
attacker's external account to the victim's local account.

## Password Reset Token Requirements

- Cryptographically random (not derived from user data or timestamps)
- Single-use (invalidated after first use OR after a new one is generated)
- Time-limited (15-30 minutes max)
- Doesn't reveal whether the account exists ("If this email is registered, you'll receive a reset link")

## Don't Reveal Auth Failure Reason

"Invalid credentials" — not "User not found" or "Incorrect password." Distinct
messages feed credential stuffing by confirming which emails are registered.

## Token Storage: httpOnly Cookies, Not localStorage

localStorage is readable by any JS on the page — one XSS and tokens are
exfiltrated. httpOnly cookies can't be read by JavaScript at all.
