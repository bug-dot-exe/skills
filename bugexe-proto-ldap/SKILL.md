---
name: ldap
description: LDAP security testing covering injection attacks, anonymous bind, credential exposure, and attribute enumeration
depends_on: []
---

# LDAP

Security testing for LDAP (Lightweight Directory Access Protocol) integrations. Focus on LDAP injection for authentication bypass and data extraction, anonymous bind access, clear-text credential transmission, and attribute enumeration via search operations.

## Attack Surface

**LDAP Integration Points**
- Authentication: user login via LDAP bind (simple bind, SASL)
- Authorization: group membership queries, role lookups
- User management: create, modify, delete entries via LDAP
- Directory search: user lookup, address book, auto-complete features
- Service accounts: applications binding to LDAP for backend queries

**Protocols**
- LDAP (port 389): plaintext or STARTTLS upgrade
- LDAPS (port 636): LDAP over TLS
- Global Catalog (ports 3268/3269): Active Directory multi-domain queries

**Directory Implementations**
- Microsoft Active Directory
- OpenLDAP
- Oracle Internet Directory
- FreeIPA / 389 Directory Server
- Apache Directory Server

**Common Integration Patterns**
- Web application login forms binding user credentials against LDAP
- Single Sign-On (SSO) with LDAP as identity store
- Self-service password change/reset via LDAP modify
- User/group synchronization between LDAP and applications
- API authentication via LDAP backend

## High-Value Targets

- Login forms backed by LDAP authentication
- User search/lookup features (employee directory, contact search, auto-complete)
- Self-service portals (password change, profile update)
- Admin interfaces managing LDAP entries
- Service account credentials in application configuration
- LDAP URLs in application responses or error messages

## Reconnaissance

**LDAP Service Detection**
```
nmap -sV -p 389,636,3268,3269 target
```
- Port 389: LDAP
- Port 636: LDAPS
- Port 3268: AD Global Catalog
- Port 3269: AD Global Catalog over TLS

**RootDSE Query (Anonymous)**
```
ldapsearch -x -H ldap://target -s base -b "" "(objectClass=*)" "*" +
```
Returns: naming contexts (base DNs), supported LDAP versions, supported controls, supported SASL mechanisms, server type and version.

**Naming Context Discovery**
```
ldapsearch -x -H ldap://target -s base -b "" namingContexts
```
Reveals the directory base DNs (e.g., `dc=corp,dc=example,dc=com`).

**Application-Side Detection**
- Login error messages mentioning "LDAP", "directory", "bind failed", "invalid DN"
- User attributes in profiles matching LDAP attribute names (cn, sn, givenName, mail, sAMAccountName)
- HTTP headers or cookies containing LDAP-related identifiers

## Key Vulnerabilities

### LDAP Injection

**Authentication Bypass**
```
# Vulnerable code pattern:
# filter = "(&(uid=" + username + ")(userPassword=" + password + "))"

# Attacker input:
username: admin)(|(uid=*
password: anything

# Resulting filter:
(&(uid=admin)(|(uid=*)(userPassword=anything))
# Always matches if uid=admin exists (OR condition always true)
```

**Tautology Injection**
```
username: *)(uid=*))(|(uid=*
username: admin)(&)
username: *()|&'
```

**Blind LDAP Injection**
```
# Extract attribute values character by character:
username: admin)(userPassword=a*     # If login succeeds: password starts with 'a'
username: admin)(userPassword=b*     # If login fails: password does not start with 'b'
```
- Boolean inference: response difference (success vs failure, timing, error message)
- Extract: passwords, group memberships, email addresses, custom attributes

**Search Filter Injection**
```
# Vulnerable: search = "(cn=" + input + ")"

# Attacker input to dump all entries:
input: *)(objectClass=*

# Resulting filter:
(cn=*)(objectClass=*)
# Returns all entries

# Attacker input for targeted extraction:
input: *)(mail=admin*
# Returns entries where mail starts with "admin"
```

**AND/OR Injection**
```
# Injecting OR conditions into AND filters:
(&(uid=INPUT)(objectClass=user))

# Input: admin)(|(objectClass=*
# Result: (&(uid=admin)(|(objectClass=*)(objectClass=user)))
# OR makes the filter always match
```

### Anonymous Bind

**Access Without Credentials**
```
# Test anonymous bind
ldapsearch -x -H ldap://target -b "dc=corp,dc=example,dc=com" "(objectClass=*)"

# If successful: enumerate entire directory
ldapsearch -x -H ldap://target -b "dc=corp,dc=example,dc=com" "(objectClass=user)" cn mail sAMAccountName
```

**Information Available via Anonymous Bind**
- User names, email addresses, phone numbers, titles, department
- Group memberships and organizational structure
- Computer accounts and service principals
- Custom attributes containing sensitive data
- Password policy information (lockout threshold, complexity requirements)

**Active Directory Specific**
- Default: anonymous bind allowed for rootDSE only (pre-Windows Server 2003 allowed full)
- `dsHeuristics` attribute may enable legacy anonymous access
- LDAP signing not required: MITM attacks on bind operations

### Clear-Text Credentials

**Simple Bind Without TLS**
- LDAP simple bind sends username and password in plaintext
- Network capture reveals credentials: `tcpdump -i eth0 port 389 -X`
- Service account passwords exposed in transit

**STARTTLS Stripping**
- Downgrade attack: MITM strips STARTTLS upgrade, forcing plaintext bind
- Application configured to try TLS but fall back to plaintext on failure

**Configuration Exposure**
- Service account bind DN and password in application config files
- Connection strings: `LDAP://dc.corp.com/CN=svc_app,OU=ServiceAccounts,DC=corp,DC=com`
- Spring/Java: `application.properties` with `spring.ldap.password`
- .NET: `web.config` with `connectionString` containing bind credentials

### Attribute Enumeration

**User Attribute Extraction**
```
# Enumerate specific attributes
ldapsearch -x -H ldap://target -D "cn=user,dc=corp,dc=com" -w pass \
  -b "dc=corp,dc=com" "(objectClass=user)" \
  cn sAMAccountName mail userPrincipalName memberOf description

# Wildcard attribute retrieval
ldapsearch -x -H ldap://target -D "bind_dn" -w pass \
  -b "dc=corp,dc=com" "(sAMAccountName=admin)" "*" +
```

**Sensitive Attributes**
- `userPassword` / `unicodePwd`: password hashes (if readable)
- `memberOf`: group memberships revealing access levels
- `description`: often contains temporary passwords or notes
- `sAMAccountName` / `uid`: login usernames
- `servicePrincipalName`: Kerberoasting targets (AD)
- `msDS-AllowedToDelegateTo`: delegation targets (AD)
- `adminCount`: identifies admin accounts (AD)

**Enumeration via Application**
- Search features returning different result counts for valid vs invalid filters
- Auto-complete leaking existence of entries
- Error messages revealing DN structure or attribute names
- Response timing differences for existing vs non-existing entries

### LDAP Password Spraying

**Via Application**
- Login form backed by LDAP: spray passwords against enumerated usernames
- Lockout policies may differ between direct LDAP and application-mediated auth
- Application may not surface LDAP account lockout errors

**Direct LDAP**
```
# Test credentials
ldapwhoami -x -H ldap://target -D "cn=user,dc=corp,dc=com" -w "password"
```

### Referral Exploitation

**LDAP Referral Injection**
- If the application follows LDAP referrals: redirect queries to attacker-controlled LDAP server
- Attacker server returns crafted entries with malicious attribute values
- Credentials may be sent to the referral server

### DN/Filter Metacharacter Escape Failures

**Distinguished Name Injection**
```
# DN special characters: , + " \ < > ; = / (space at start/end) # (at start)
# If user input is used in DN construction:
input: admin,cn=Admins,dc=corp
# May modify the target DN
```

**Filter Special Characters**
```
# Filter special characters: * ( ) \ NUL
# Must be hex-escaped in filters: \2a \28 \29 \5c \00
# Application failing to escape these enables injection
```

## Bypass Techniques

- Unicode normalization: LDAP implementations may normalize Unicode differently than the application
- Null byte injection: `\00` in filter strings may truncate the filter in some implementations
- Wildcard in attribute values: `*` matches any value when not escaped
- Case insensitivity: LDAP comparisons are often case-insensitive; exploit for filter bypass
- Base DN manipulation: if user controls search base, redirect to different OU/subtree
- `extensibleMatch` filter: `(cn:=admin)` bypasses some WAF rules filtering standard filter syntax

## Testing Methodology

1. **Service identification** - Detect LDAP ports, query rootDSE, discover naming contexts
2. **Anonymous bind** - Test unauthenticated access to directory data
3. **Injection testing** - Test login and search inputs for LDAP filter injection (AND/OR/blind)
4. **Credential security** - Verify TLS enforcement, check for plaintext bind operations
5. **Attribute enumeration** - Extract user attributes, group memberships, sensitive fields via authenticated queries
6. **Configuration audit** - Search for exposed service account credentials in application configs
7. **Referral testing** - Check if application follows LDAP referrals to external servers
8. **Password policy** - Test lockout thresholds, password complexity via application-mediated LDAP

## Validation

1. LDAP injection: authentication bypass or data extraction via manipulated filter
2. Anonymous bind: directory data retrieved without credentials (user list, attributes)
3. Blind injection: attribute value extracted character-by-character via boolean inference
4. Credential exposure: service account password retrieved from configuration or network capture
5. Attribute enumeration: sensitive attributes (passwords, memberships, SPNs) retrieved via search
6. Referral exploitation: application following referral to attacker-controlled server

## False Positives

- LDAP injection characters rejected or properly escaped by input validation
- Anonymous bind returns only rootDSE (no directory enumeration)
- LDAPS enforced with no plaintext fallback
- Application parameterizes LDAP queries (bind DN and filter escaped)
- Read access restricted per-attribute via ACLs

## Impact

- Authentication bypass: login as any user including administrators
- Data extraction: bulk enumeration of directory users, groups, and attributes
- Credential theft: service account passwords or user password hashes
- Privilege discovery: group memberships and delegation paths for lateral movement
- Network credential exposure: plaintext bind credentials captured on the network

## Pro Tips

1. LDAP injection is syntactically different from SQL injection; test with `*`, `)(`, `|(`, not `'` or `--`
2. Always test anonymous bind first; it is surprisingly common in internal applications
3. Active Directory has specific attributes (sAMAccountName, memberOf, servicePrincipalName) that are high-value targets
4. Blind LDAP injection is slower but more reliable than error-based; automate character extraction
5. Service account credentials in configuration are a common finding; check every config file format
6. LDAP over port 389 without STARTTLS is an automatic finding in any validation run
7. Check if the application uses LDAP for authorization (group checks) in addition to authentication; injection in group queries can escalate privileges
8. Test with ldapsearch, Python ldap3 library, or Burp with LDAP-specific extensions

## Summary

LDAP security depends on proper input escaping in filter construction, enforcing authenticated bind for all queries, encrypting all communications with TLS, and restricting attribute-level read access. Each gap enables distinct attacks from authentication bypass to full directory enumeration.
