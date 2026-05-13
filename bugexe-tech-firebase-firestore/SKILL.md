---
name: firebase-firestore
description: Firebase/Firestore security testing covering security rules, Cloud Functions, and client-side trust issues
depends_on: []
---

# Firebase / Firestore

Security testing for Firebase applications. Focus on Firestore/Realtime Database rules, Cloud Storage exposure, callable/onRequest Functions trusting client input, and incorrect ID token validation.

## Attack Surface

**Data Stores**
- Firestore (documents/collections, rules, REST/SDK)
- Realtime Database (JSON tree, rules)
- Cloud Storage (rules, signed URLs)

**Authentication**
- Auth ID tokens, custom claims, anonymous/sign-in providers
- App Check attestation (and its limits)

**Server-Side**
- Cloud Functions (onCall/onRequest, triggers)
- Admin SDK (bypasses rules)

**Infrastructure**
- Hosting rewrites, CDN/caching, CORS

## Architecture

**Endpoints**
- Firestore REST: `https://firestore.googleapis.com/v1/projects/<project>/databases/(default)/documents/<path>`
- Realtime DB: `https://<project>.firebaseio.com/.json`
- Storage REST: `https://storage.googleapis.com/storage/v1/b/<bucket>`

**Auth**
- Google-signed ID tokens (iss: `accounts.google.com` or `securetoken.google.com/<project>`)
- Audience: `<project>` or `<app-id>`, identity in `sub`/`uid`
- Rules engines: separate for Firestore, Realtime DB, and Storage
- Functions bypass rules when using Admin SDK

## High-Value Targets

- Firestore collections with sensitive data (users, orders, payments)
- Realtime Database root and high-level nodes
- Cloud Storage buckets with private files
- Cloud Functions (especially triggers that grant roles or issue signed URLs)
- Admin/staff routes and privilege-granting endpoints
- Export/report functions that generate signed outputs

## Reconnaissance

**Extract Project Config**

From client bundle:
```javascript
// apiKey, authDomain, projectId, appId, storageBucket, messagingSenderId
firebase.apps[0].options
```

Firebase init endpoint (works on any Firebase-hosted target):
```bash
# Fetch project config without decompiling anything
curl -s "https://target.com/__/firebase/init.js"
# Returns: firebase.initializeApp({apiKey: "...", projectId: "...", ...})
# Record: apiKey, projectId, storageBucket, databaseURL, messagingSenderId, appId
```

APK/IPA extraction (mobile targets):
```bash
# Decompile APK and grep for Firebase config
apktool d target.apk -o decompiled/
grep -rn "firebaseio.com\|firebase.*apiKey\|google-services.json" decompiled/
# Also check: google-services.json, GoogleService-Info.plist
# Look for: Cloudinary URLs, AWS keys (AKIA*), Stripe keys, other hardcoded creds
```

**Obtain Principals**
- Unauthenticated
- Anonymous (if enabled)
- Basic user A, user B
- Staff/admin (if available)

Capture ID tokens for each.

## Key Vulnerabilities

### Firestore Rules

Rules are not filters—a query must include constraints that make the rule true for all returned documents.

**Common Gaps**
- `allow read: if request.auth != null` — any authenticated user reads all data
- `allow write: if request.auth != null` — mass write access
- Missing per-field validation (allows adding `isAdmin`/`role`/`tenantId` fields)
- Using client-supplied `ownerId`/`orgId` instead of `resource.data.ownerId == request.auth.uid`
- Over-broad list rules on root collections (per-doc checks exist but list still leaks)

**Secure Patterns**
```javascript
// Restrict write fields
request.resource.data.keys().hasOnly(['field1', 'field2', 'field3'])

// Enforce ownership
resource.data.ownerId == request.auth.uid &&
request.resource.data.ownerId == request.auth.uid

// Org membership check
exists(/databases/(default)/documents/orgs/$(org)/members/$(request.auth.uid))
```

**Tests**
- Compare results for users A/B on identical queries; diff counts and IDs
- Cross-tenant reads: `where orgId == otherOrg`; try queries without org filter
- Write-path: set/patch with foreign `ownerId`/`orgId`; attempt to flip privilege flags

### Firestore Queries

- Use REST to avoid SDK client-side constraints
- Probe composite index requirements (UI-driven queries may hide missing rule coverage)
- Explore `collectionGroup` queries that may bypass per-collection rules
- Use `startAt`/`endAt`/`in`/`array-contains` to probe rule edges and pagination cursors

### Realtime Database

- Misconfigured rules frequently expose entire JSON trees
- Probe `https://<project>.firebaseio.com/.json` with and without auth
- Confirm rules use `auth.uid` and granular path checks
- Avoid `.read/.write: true` or `auth != null` at high-level nodes
- Attempt to write privilege-bearing nodes (roles, org membership)

### Cloud Storage

**Common Issues**
- Public reads on sensitive buckets/paths
- Signed URLs with long TTL, no content-disposition controls, replayable across tenants
- List operations exposed: `/o?prefix=` enumerates object keys

**Tests**
- GET gs:// paths via HTTPS without auth; verify Content-Type and `Content-Disposition: attachment`
- Generate and reuse signed URLs across accounts and paths; try case/URL-encoding variants
- Upload HTML/SVG and verify `X-Content-Type-Options: nosniff`; check for script execution

### Cloud Functions

`onCall` provides `context.auth` automatically; `onRequest` must verify ID tokens explicitly. Admin SDK bypasses rules—all ownership/tenant checks must be in code.

**Common Gaps**
- Trusting client `uid`/`orgId` from request body instead of `context.auth`
- Missing `aud`/`iss` verification when manually parsing tokens
- Over-broad CORS allowing credentialed cross-origin requests
- Triggers (onCreate/onWrite) granting roles based on document content controlled by client

**Tests**
- Call both onCall and onRequest endpoints with varied tokens; expect identical decisions
- Create crafted docs to trigger privilege-granting functions
- Attempt SSRF via Functions to project/metadata endpoints

### Auth & Token Issues

**Verification Requirements**
- Issuer, audience (project), signature (Google JWKS), expiration
- Optionally App Check binding when used

**Pitfalls**
- Accepting any JWT with valid signature but wrong audience/project
- Trusting `uid`/account IDs from request body instead of `context.auth.uid`
- Mixing session cookies and ID tokens without verifying both paths equivalently
- Custom claims copied into docs then trusted by app code

**Tests**
- Replay tokens across environments/projects; expect strict `aud`/`iss` rejection
- Call Functions with and without Authorization; verify identical checks

### App Check

App Check is not a substitute for authorization.

**Bypasses**
- REST calls directly to googleapis endpoints with ID token succeed regardless of App Check
- Mobile reverse engineering: hook client and reuse ID token flows without attestation

**Tests**
- Compare SDK vs REST behavior with/without App Check headers
- Confirm no elevated authorization via App Check alone

### Tenant Isolation

Apps often implement multi-tenant data models (`orgs/<orgId>/...`). Bind tenant from server context (membership doc or custom claim), not client payload.

**Tests**
- Vary org header/subdomain/query while keeping token fixed; verify server denies cross-tenant access
- Export/report Functions: ensure queries execute under caller scope

## Bypass Techniques

- Content-type switching: JSON vs form vs multipart to hit alternate code paths in onRequest
- Parameter/field pollution: duplicate JSON keys (last-one-wins in many parsers); sneak privilege fields
- Caching/CDN: Hosting rewrites keying responses without Authorization or tenant headers
- Race windows: write then read before background enforcements complete

## Blind Enumeration

- Firestore: use error shape, document count, ETag/length to infer existence
- Storage: length/timing differences on signed URL attempts leak validity
- Functions: constant-time comparisons vs variable messages reveal authorization branches

## XSS via Identity Fields

A high-paying pattern ($313K corpus max): set your display name or profile fields to a polyglot XSS payload, then find where that identity data renders unescaped across the platform.

1. Set display name to: `<img src=x onerror=alert(document.domain)>` or `"><svg onload=alert(1)>`
2. Trigger every flow that renders your identity: comments, shared documents, team member lists, activity feeds, email notifications, PDF exports
3. Check each rendering context: HTML body, HTML attribute, JavaScript string, email template

This works because Firebase Auth stores display name as a raw string, and consuming applications often trust it as "validated by Firebase." The payload travels through Firebase Auth into every downstream consumer.

## Realtime DB Protocol Fingerprinting

Identify Firebase Realtime Database connections in WebSocket traffic:
- Frame signature `{"t":"d","d":{...}}` indicates Firebase Realtime DB
- Frame signature `{"event":..., "data":...}` indicates a different real-time framework (Supabase, Hasura)
- Use this fingerprint to route your testing methodology correctly

## Serverless Access Control Audit

For any BaaS application (Firebase, Supabase, AWS Amplify):
1. Extract the backend configuration and API keys from the client bundle
2. Identify all data collections/tables and their access rules
3. Test each CRUD operation as each principal (unauth, user A, user B, admin)
4. Verify that the API key alone does not grant data access -- the key is an identifier, not an authorization credential
5. Check if any Cloud Functions trust client-supplied UIDs from request body instead of extracting from the verified token

## Testing Methodology

1. **Extract config** - Get project config from client bundle AND `/__/firebase/init.js`
2. **Obtain principals** - Collect tokens for unauth, anonymous, user A/B, admin
3. **Build matrix** - Resource x Action x Principal across Firestore/Realtime/Storage/Functions
4. **SDK vs REST** - Exercise every action via both to detect parity gaps
5. **Seed IDs** - Start from list/query paths to gather document IDs
6. **Cross-principal** - Swap document paths, tenants, and user IDs across principals
7. **APK/IPA audit** - Grep mobile binaries for hardcoded Firebase config, additional API keys, internal endpoints

## Defense-Bypass Pairs

| Defense | Bypass | Evidence |
|---------|--------|----------|
| API key restriction by referrer | Mobile app traffic has no referrer; use curl without Referer header | Key is identifier, not secret |
| App Check attestation | REST calls to googleapis with ID token bypass App Check entirely | App Check is device attestation, not authz |
| Firestore rules `auth != null` | Anonymous auth enabled = any user passes `auth != null` check | Anonymous sign-in counts as authenticated |
| Cloud Function `onCall` auth | Switch to raw `onRequest` endpoint with forged Authorization header | onRequest must manually verify tokens |
| CSP blocks inline scripts | Firebase Hosting, *.firebaseapp.com, *.web.app on CSP allowlist | Shared hosting domain in CSP |
| Firestore per-document rules | `collectionGroup` queries may bypass per-collection rules | Group queries cross collection boundaries |

## Chain Patterns

| Base Finding | Chain With | Combined Impact |
|-------------|-----------|----------------|
| Firebase API key exposed | No auth on Realtime DB rules | Full database read/write via REST |
| Anonymous auth enabled | Firestore `auth != null` rules | Any visitor reads all "authenticated" data |
| Cloud Function trusts client UID | IDOR on document paths | Cross-user data access via Functions |
| Storage bucket public list | Signed URL with long TTL | Persistent access to private files |
| XSS payload in display name | Firebase Auth renders in downstream apps | Stored XSS across all consumers |

## Tooling

- SDK + REST: httpie/curl + jq for REST; Firebase emulator and Rules Playground for rapid iteration
- Rules analysis: script probes for common patterns (`auth != null`, missing field validation)
- Functions: fuzz onRequest with varied content-types and missing/forged Authorization
- Storage: enumerate prefixes; test signed URL generation and reuse patterns
- `/__/firebase/init.js`: fastest way to extract project config on any Firebase-hosted site

## Validation Requirements

- Owner vs non-owner Firestore queries showing unauthorized access or metadata leak
- Cloud Storage read/write beyond intended scope (public object, signed URL reuse, list exposure)
- Function accepting forged/foreign identity (wrong `aud`/`iss`) or trusting client `uid`/`orgId`
- Minimal reproducible requests with roles/tokens used and observed deltas
