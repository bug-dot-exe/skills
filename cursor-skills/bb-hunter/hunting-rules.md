# Hunting Rules (from claude-bug-bounty)

Always active. Breaking them wastes time and reduces payout rate.

Source: [claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)

---

## 1. READ FULL SCOPE FIRST

Before a single request: read in-scope, out-of-scope, excluded bug classes, safe harbor.
One out-of-scope request = potential ban.

## 2. NEVER HUNT THEORETICAL BUGS

> "Can an attacker do this RIGHT NOW, against a real user, causing real harm?"
> If NO — STOP. Move on.

NOT a bug: "Could theoretically allow...", "Wrong but no practical impact", "3+ preconditions", dead code, SSRF with DNS callback only.

## 3. KILL WEAK FINDINGS FAST

Run the 7-Question Gate BEFORE spending time. Kill at Q1 if needed.

## 4. CHECK SCOPE EXPLICITLY FOR EVERY ASSET

Verify it's on the scope list. Third-party service = out of scope.

## 5. 5-MINUTE RULE

If a surface shows nothing interesting after 5 minutes → move on.

Kill signals: all hosts 403/static, no API with IDs, no interesting JS, nuclei 0 medium/high.

## 6. AUTOMATION = RECON ONLY

Manual testing finds unique bugs. Scanners find duplicates.
Automation: subfinder, httpx, katana, nuclei. Manual: IDOR, auth bypass, business logic, race.

## 7. IMPACT-FIRST HUNTING

"What's the worst thing if auth was broken here?"
Nothing valuable → skip. Admin access, PII, fund theft → hunt there.

## 8. HUNT LESS-SATURATED BUG CLASSES

High competition (skip unless target-specific): XSS, SSRF basics, open redirect alone.
Low competition: Cache poisoning, race conditions, business logic, HTTP smuggling, CI/CD.

## 9. DEPTH OVER BREADTH

One target deeply understood > ten shallowly tested.
Read 5+ disclosed reports. Understand business domain. Map crown jewels.

## 10. THE SIBLING RULE

> "Check EVERY sibling endpoint. If `/api/user/123/orders` has auth,
> check `/api/user/123/export`, `/api/user/123/delete`, `/api/user/123/share`."

Explains 30% of paid IDOR/auth bugs.

## 11. A→B SIGNAL METHOD

When you confirm bug A → hunt for B and C before writing.
A confirmed bug = signal the developer made the mistake elsewhere.
Time-box: 20 minutes on B. If not confirmed → submit A and move on.

## 12. NEW == UNREVIEWED

Features < 30 days old have lowest security maturity. Hunt new features first.

## 13. FOLLOW THE MONEY

Billing/credits/refunds/wallet = most shortcuts. Price manipulation, race on payment, quota bypass = high ROI.

## 14. 20-MINUTE ROTATION RULE

Every 20 min: "Am I making progress?" No → rotate to next endpoint, subdomain, or vuln class.

## 15. BUSINESS IMPACT > VULN CLASS

Clickjacking usually $0 but MetaMask paid $120K. Ask "What's the business impact?" first.

## 16. VALIDATE BEFORE WRITING

Run validation gates before starting a report. Gate 0 is 30 seconds.
30 seconds to kill a bad lead. 30 minutes to write a report.

## 17. CREDENTIAL LEAKS NEED EXPLOITATION PROOF

Finding an API key = Informational.
Proving what the key accesses (S3, DB, admin panel) = Medium/High.
Always call the API as the leaked key. Enumerate permissions.
