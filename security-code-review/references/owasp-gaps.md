# OWASP Checklist Gaps

The universal checklist covers A01/A02/A03/A05/A06/A07/A10 adequately through
standard controls. Three categories are underweighted and need explicit attention
during design review and offensive pass:

---

## A04 — Insecure Design (CWE-362, CWE-501, CWE-656)

These are design flaws, not implementation bugs. The checklist won't surface them.

- **Client-side trust:** Are pricing, quantity, role, or discount values ever derived
  from client input? The server must calculate totals and enforce limits; never trust
  amounts or permissions the client sends.

- **Race conditions (TOCTOU):** Are read-then-write sequences atomic? Voucher
  redemption, balance transfers, and uniqueness checks need transactions or atomic ops.

  ```
  // UNSAFE: window between check and update allows double-redemption
  if voucher.used: return error()
  apply_discount(); voucher.used = true; db.save(voucher)

  // SAFE: atomic conditional update — fails if already used
  result = db.atomic_update({code: code, used: false}, {used: true})
  if result.matched == 0: return error("invalid or already redeemed")
  ```

- **Skippable workflow steps:** Can a user call step 3 of a checkout or approval
  flow without completing step 2? Enforce sequencing server-side, not just in the UI.

---

## A08 — Software & Data Integrity Failures (CWE-345, CWE-494, CWE-502)

Not covered by the checklist at all.

- **Insecure deserialization:** `pickle.loads`, `yaml.load` (without SafeLoader),
  Java `ObjectInputStream`, PHP `unserialize` on any user-controlled input → RCE.
  Use `json.loads` or a schema-validated safe parser for untrusted data.
  *(Deserialization is in the Injection checklist; this extends it to integrity context.)*

- **Missing Subresource Integrity (SRI):** CDN `<script>` and `<link>` tags without
  `integrity` attributes mean a compromised CDN injects into every user's browser.
  Add `integrity="sha384-..."` and `crossorigin="anonymous"` to all CDN-hosted assets.

- **CI/CD pipeline poisoning:** `pull_request_target` workflows that check out and
  execute untrusted PR code with access to repo secrets are a common supply chain
  attack vector. Scope runners tightly; don't combine `pull_request_target` with
  `actions/checkout` of the PR branch without explicit trust gates.

---

## A09 — Security Logging & Monitoring Failures (CWE-117, CWE-778)

Section 8 of the checklist covers *what not to log* (secrets, PII). This covers
*what you must log* — gaps here make attacks invisible and forensics impossible.

- **Missing security event logging:** Auth failures, authorization denials, and admin
  actions must produce log entries. No log on failed login = brute force is
  undetectable. No log on authorization denial = IDOR attempts leave no trace.

- **Log injection:** User input written to logs without sanitization allows newline
  injection to forge entries or corrupt log parsers. Use structured logging with
  explicit fields (`{"event": "login_failure", "user": sanitize(username)}`), never
  string concatenation into log messages.

- **Secrets in logs:** Full request-body logging captures passwords, tokens, and PII.
  Redact `password`, `token`, `authorization`, `secret`, and `ssn` fields before
  any log statement that includes request data.
