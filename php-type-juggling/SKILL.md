---
name: php-type-juggling
category: vulnerabilities
description: PHP type juggling attacks for loose comparison bypass, magic hashes, strcmp bypass, json_decode coercion, and authentication bypass
depends_on: []
---

# PHP Type Juggling

Exploiting PHP's loose comparison operators and automatic type coercion to bypass authentication, authorization, and validation checks. PHP's `==` operator performs type juggling that creates exploitable equivalences.

## Discovery Signals

| # | Signal | Where to Check | Implication |
|---|--------|---------------|-------------|
| 1 | `X-Powered-By: PHP/X.X` or `.php` in URLs | Response headers, URL paths | Confirms PHP backend; all juggling vectors apply |
| 2 | JSON body accepted on login/auth endpoints | `Content-Type: application/json` test | `json_decode` feeds typed values into loose comparisons |
| 3 | `strcmp`, `==`, `switch` in error/stack traces | Error pages, debug output, source repos | Direct evidence of loose comparison in auth path |
| 4 | Array-to-string Warning in 500 responses | Send `param[]=val` on any field | PHP confirms it passed an array where string expected |
| 5 | OTP/2FA endpoint with numeric codes | Password reset, MFA verify | `0 == "any_string"` bypasses OTP on PHP <8.0 |
| 6 | Token/hash comparison in URL params | `?token=xxx`, `?hash=xxx` | Likely `==` comparison; send `true`, `0`, or magic hash |
| 7 | `password_verify` or `md5`/`sha1` in source | GitHub org search, leaked source | Hash comparison surface for magic hash or array attack |
| 8 | `in_array` or `array_search` without strict | Source code, open-source dependencies | Missing third `true` param enables type-juggled membership |
| 9 | PHP framework (Laravel, CodeIgniter, WordPress) | `X-Powered-By`, generator meta, cookies | Framework-specific auth may use loose comparison internally |
| 10 | `filter_var` in validation chain | Source review | `filter_var(array, FILTER_VALIDATE_EMAIL)` returns false silently |
| 11 | Cookie-based role/hash checks | Intercept cookie values | Cookie value fed to `==` comparison; send `true` via JSON |
| 12 | API accepts both form-encoded and JSON | Toggle `Content-Type` header | JSON lets you send `true`/`0`/`null`/`[]` as typed values |

## PHP Comparison Matrix

| Input A | Operator | Input B | Result | Why |
|---------|----------|---------|--------|-----|
| `"0"` | `==` | `false` | TRUE | String "0" is falsy |
| `""` | `==` | `false` | TRUE | Empty string is falsy |
| `"0"` | `==` | `null` | TRUE | Null coerces to empty/zero |
| `0` | `==` | `"any_string"` | TRUE (PHP <8) | String coerced to int 0 |
| `"0e12345"` | `==` | `"0e67890"` | TRUE | Both parse as 0 in scientific notation |
| `true` | `==` | `"anything"` | TRUE | Non-empty string is truthy |
| `[]` | `==` | `false` | TRUE | Empty array is falsy |
| `NULL` | `==` | `false` | TRUE | Null is falsy |
| `"1abc"` | `==` | `1` | TRUE (PHP <8) | PHP casts string to leading int |
| `"php"` | `==` | `0` | TRUE (PHP <8) | Non-numeric string casts to 0 |
| `strcmp([], "x")` | `==` | `0` | TRUE | strcmp returns NULL on array; NULL == 0 |
| `"0x1A"` | `==` | `26` | TRUE (PHP 5) | Hex string auto-converted to int |

## Magic Hash Corpus

| Hash Type | Magic String | Hash Output (0e...) | Usage |
|-----------|-------------|---------------------|-------|
| MD5 | `240610708` | `0e462097431906509019562988736854` | Most common; password comparison bypass |
| MD5 | `QNKCDZO` | `0e830400451993494058024219903391` | Alpha-only; bypasses numeric-input filters |
| MD5 | `aabg7XSs` | `0e087386482136013740957780965295` | Mixed-case alternative |
| MD5 | `aabC9RqS` | `0e041022518165728065344349536299` | Mixed-case alternative |
| MD5 | `0e215962017` | `0e291242476940776845150308577824` | Numeric-only; self-referential 0e input |
| SHA1 | `10932435112` | `0e07766915004133176347055865026311692244` | SHA1 magic hash; rarer but works |
| SHA1 | `aaroZmOk` | `0e17475571305855834424832553469632939624` | Alpha-only SHA1 variant |
| SHA256 | `34250003024812` | `0e46289032038065916139621039085883773413...` | SHA256; extremely rare, high value |

**Usage**: if `md5($input) == $stored_hash` and stored hash is also `0e[digits]`, both evaluate to `0 == 0 = TRUE`.

## Attack Surface

**Loose Comparisons**
- `==` operator with mixed types (string vs int, string vs bool)
- `switch` statements (use loose comparison by default)
- `in_array()` without strict flag
- `array_search()` without strict flag

**Function-Level Coercion**
- `strcmp()` with non-string input returns NULL (which `==` treats as 0)
- `json_decode()` creating unexpected types from JSON input
- `intval()` and `floatval()` truncation
- `is_numeric()` accepts hex strings in PHP 5, scientific notation in all versions

## Key Vulnerabilities

### Loose Comparison Bypass

```php
// Pattern 1: Direct comparison
if ($token == $stored_token) { /* grant access */ }
// Attack: send boolean true as JSON: {"token": true}

// Pattern 2: Hash comparison
if (md5($input) == $stored_hash) { /* grant access */ }
// Attack: find magic hash input, or send 0/true via JSON

// Pattern 3: strcmp
if (strcmp($password, $db_password) == 0) { /* grant access */ }
// Attack: send password as array: password[]=x

// Pattern 4: switch statement
switch ($role) { case 0: /* admin */ break; }
// Attack: send role as "0abc" (coerces to int 0)
```

### strcmp Bypass with Arrays

`strcmp()` returns NULL when given a non-string argument. NULL loosely equals 0:

```
POST /login
password[]=anything    # Send array instead of string
```

This bypasses: `if (strcmp($input, $password) == 0)` -- Confirmed paid in H1 #792895 (Revive Adserver).

### json_decode Type Coercion

```json
{"password": true}     // true == "secret123" is TRUE
{"password": 0}        // 0 == "secret123" is TRUE (PHP <8)
{"password": []}       // May bypass isset() + empty() checks
{"password": null}     // null == "" may bypass empty password checks
```

### in_array and array_search Without Strict Mode

```php
in_array("0", ["a", "b", "c"])  // TRUE in PHP <8 (0 == "a")
in_array(0, ["a", "b", "c"])    // TRUE (0 == "a")
in_array(true, ["a", "b"])      // TRUE (true == "a")
```

## Defense-Bypass Pairs

| Defense | Bypass | Technique |
|---------|--------|-----------|
| `==` comparison on password hash | Send `true` via JSON | Boolean `true == "any_hash"` is TRUE |
| `strcmp($input, $secret) == 0` | Send `param[]=x` | Array makes strcmp return NULL; `NULL == 0` is TRUE |
| `md5($input) == $stored_hash` | Magic hash input (`240610708`) | Both hashes start with `0e`; `0 == 0` is TRUE |
| `in_array($input, $whitelist)` | Send integer `0` | `0 == "admin"` is TRUE in PHP <8 |
| `is_numeric()` guard before comparison | Send `0e1` or `0x1A` | Passes `is_numeric()` but juggling still applies |
| `filter_var($email, FILTER_VALIDATE_EMAIL)` | Send array | Returns FALSE on array, may be interpreted as "passed" |
| PHP 8 strict `==` for strings vs int | Send `true` via JSON | Boolean juggling still works in PHP 8 |
| `!empty($password)` check | Send `"0"` | `"0"` is truthy for `!empty()` but `"0" == false` |
| `password_verify($hash, $input)` | Send array for `$input` | Warning + false in PHP 7; TypeError in PHP 8 but may expose path |
| `htmlspecialchars` on output | Type juggle on input comparison | Output encoding does not fix input comparison logic |

## Chain Patterns

| First Bug | Second Bug | Combined Impact | Example |
|-----------|-----------|----------------|---------|
| Type juggling auth bypass | Admin panel access | Full account takeover | H1 #792895: array param bypasses password check then changes email |
| JSON type coercion (`true`) | HMAC/hash validation skip | Cookie forgery, session hijack | H1 #894170: `hash:0` bypasses HMAC check in JSON cookie |
| strcmp array bypass | OTP/2FA skip | Authentication bypass | `otp[]=x` bypasses `strcmp($otp, $stored) == 0` |
| Magic hash collision | Password reset token bypass | Account takeover | Reset token hash starts with `0e`; send magic-hash input |
| `in_array` without strict | Role/permission whitelist bypass | Privilege escalation | `in_array(0, ["admin", "editor"])` returns TRUE |
| Array param → 500 error | Full path disclosure | Information leak for LFI chain | H1 #115422: PasswordLock leaks path on array input |
| Type juggling on `switch` | Admin role assignment | Privilege escalation | `switch($role)` with `case 0:` matches any non-numeric string |
| `is_numeric` + loose compare | WAF bypass + auth bypass | Bypasses both validation and comparison | `0e1` passes `is_numeric()` and `== 0` |

## PHP Version Considerations

| Attack | PHP 5.x | PHP 7.x | PHP 8.0+ |
|--------|---------|---------|----------|
| `0 == "string"` = TRUE | Yes | Yes | **No** (fixed) |
| `"0e..." == "0e..."` = TRUE | Yes | Yes | Yes (still works) |
| `strcmp([], "str")` = NULL | Yes | Yes | **Warning + false** |
| `true == "string"` = TRUE | Yes | Yes | Yes |
| `json_decode` type juggling | Yes | Yes | Yes |
| `"0x1A" == 26` | Yes | No | No |

## Methodology

1. **Identify PHP**: confirm target runs PHP (headers, file extensions, error messages)
2. **Map comparison points**: find login, token validation, role checks, OTP verification
3. **Test JSON type coercion**: toggle `Content-Type` to `application/json`, send `true`, `0`, `""`, `null`, `[]`
4. **Test array parameter**: send `param[]=value` where strings expected on every auth-related field
5. **Test magic hashes**: if hash comparison suspected, try known magic hash inputs
6. **Test in_array**: if whitelist checking suspected, send type-juggled values
7. **PHP version check**: PHP 8.0+ fixed `0 == "string"` but magic hashes and boolean juggling still work

## Pro Tips

1. Always toggle `Content-Type` to `application/json` on PHP endpoints -- this unlocks typed values (`true`, `0`, `null`, `[]`) that form-encoded cannot express
2. The `param[]=x` array trick is a 2-second test per field; run it on every auth parameter before deeper analysis
3. Magic hashes work even on PHP 8.0+ because `"0e..." == "0e..."` was NOT fixed -- only `0 == "string"` was
4. When a 500 error mentions `strcmp`, `strlen`, `substr`, or `preg_match` on array input, the function is confirmed as a loose-comparison sink
5. `switch` statements in PHP use `==` by default -- a frequently overlooked loose-comparison surface
6. `is_numeric("0e1")` returns TRUE, so `is_numeric` guards do not prevent magic hash attacks
7. H1 #894170 (CTF writeup) documents the most methodical approach: "first thing I do with JSON parameters is change the data type and see what happens"
8. On PHP 7, `0 == "admin"` is TRUE -- test with integer `0` on any role/permission field
9. `password_verify()` with array input produces a Warning in PHP 7 (potential path disclosure) and TypeError in PHP 8 (potential error-based info leak)
10. Chain type juggling DoS (H1 #961997) with path disclosure for LFI reconnaissance -- the 500 error itself leaks filesystem paths

## Validation Requirements

- Authentication bypass: demonstrate login without valid credentials using type juggling
- Magic hash: show two different inputs producing hashes that compare as equal
- strcmp bypass: demonstrate access using array parameter instead of string
- Token validation bypass: access protected resource with juggled token value
