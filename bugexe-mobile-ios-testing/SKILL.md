---
name: ios-testing
category: mobile
description: iOS security testing covering IPA analysis, Keychain access, plist inspection, URL scheme testing, and ATS configuration review
depends_on: []
---

# iOS Security Testing

Security testing for iOS applications. Focus on IPA binary analysis, Keychain data access, plist inspection, URL scheme testing, and App Transport Security configuration review.

## When to Use

- iOS IPA is in scope for security testing
- Mobile application communicates with a target API
- Client-side security controls need validation (pinning, jailbreak detection, data protection)
- Sensitive data storage on device needs assessment
- Custom URL schemes or universal links need testing

## Methodology

### 1. Static Analysis (IPA)

**IPA Extraction and Inspection**
```bash
# From jailbroken device
scp root@{device}:/var/containers/Bundle/Application/{uuid}/{app}.app/Info.plist .

# Using ipatool or frida-ios-dump
frida-ios-dump -l        # List apps
frida-ios-dump {bundle}  # Dump decrypted IPA

# Unzip IPA
unzip target.ipa -d target_extracted
```

**Binary Analysis**
```bash
# Check for PIE, ARC, stack canaries
otool -hv Payload/{app}.app/{binary}    # Architecture and flags
otool -Iv Payload/{app}.app/{binary}    # Imported symbols

# Check for encryption (App Store binaries are encrypted)
otool -l {binary} | grep crypt

# Strings extraction
strings {binary} | grep -iE "api[_-]?key|secret|token|password|https?://"

# Class dump for Objective-C
class-dump {binary} > classes.h
```

**Info.plist Analysis**
- URL schemes: `CFBundleURLSchemes` entries for custom scheme handlers
- Universal links: `com.apple.developer.associated-domains` entitlement
- ATS exceptions: `NSAppTransportSecurity` dictionary
- Exported UTIs and document types
- Background modes and capabilities
- Minimum OS version (affects available security features)

**Code Review Targets**
- Hardcoded credentials, API keys, certificates in binary or bundled resources
- Insecure data storage: NSUserDefaults for sensitive data, unprotected Core Data/SQLite
- Insecure crypto: CommonCrypto with ECB, static IVs, hardcoded keys
- WebView: WKWebView JavaScript bridges, message handlers accepting untrusted input
- Pasteboard usage: UIPasteboard for sensitive data (accessible by other apps pre-iOS 16)

### 2. Keychain Access

**Inspection (jailbroken device)**
```bash
# Using keychain-dumper
keychain-dumper -a      # Dump all keychain items

# Using objection
objection -g {bundle} explore
# Then: ios keychain dump
# Then: ios keychain dump --json
```

**Common Issues**
- Keychain items stored with `kSecAttrAccessibleAlways` (accessible even when locked)
- Tokens stored with `kSecAttrAccessibleAfterFirstUnlock` instead of `kSecAttrAccessibleWhenUnlocked`
- Missing `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` for high-value secrets
- Keychain sharing between apps via access groups (check entitlements)
- Keychain items surviving app uninstall (data persistence)

**Data Protection Levels**
| Level | Security | Use Case |
|-------|----------|----------|
| WhenUnlocked | Best | Active session tokens |
| AfterFirstUnlock | Moderate | Background refresh tokens |
| Always | Weakest | Avoid for sensitive data |
| WhenPasscodeSetThisDeviceOnly | Best + device-bound | Crypto keys, biometric secrets |

### 3. Plist and Local Storage Inspection

```bash
# Application data directory (jailbroken)
ls /var/mobile/Containers/Data/Application/{uuid}/

# NSUserDefaults (plist)
cat /var/mobile/Containers/Data/Application/{uuid}/Library/Preferences/{bundle}.plist
plutil -convert xml1 {plist_file}

# SQLite databases
find /var/mobile/Containers/Data/Application/{uuid}/ -name "*.sqlite*"
sqlite3 {database} ".tables"
sqlite3 {database} "SELECT * FROM {table};"

# Cookies and web storage
cat /var/mobile/Containers/Data/Application/{uuid}/Library/Cookies/Cookies.binarycookies

# Cache and snapshots
ls /var/mobile/Containers/Data/Application/{uuid}/Library/Caches/
ls /var/mobile/Containers/Data/Application/{uuid}/Library/SplashBoard/Snapshots/
```

**Common Issues**
- Credentials, tokens, or PII stored in NSUserDefaults (plaintext plist)
- Unencrypted SQLite databases with sensitive records
- Application snapshots containing sensitive screen content
- Keyboard cache containing sensitive input (disable autocorrect for sensitive fields)
- HTTP response cache containing sensitive API responses

### 4. URL Scheme Testing

**Discovery**
```bash
# From Info.plist
/usr/libexec/PlistBuddy -c "Print :CFBundleURLTypes" Info.plist

# Test scheme handling
# On device: open URL in Safari or use "open" command
# Via objection: ios hooking generate scheme {scheme}
```

**Testing**
- Trigger URL scheme from Safari or other app: `{scheme}://action?param=value`
- Test for injection in URL scheme parameters (path traversal, command injection)
- Check for authentication bypass: does the scheme handler skip auth checks?
- Test for sensitive data in scheme responses (oauth tokens, session data)
- Universal link vs custom scheme precedence and hijacking

**Common Vulnerabilities**
- URL scheme hijacking: another app registers the same scheme
- Missing input validation on scheme parameters leading to injection
- Scheme handlers performing privileged actions without re-authentication
- OAuth callback via custom scheme susceptible to interception (use universal links instead)

### 5. ATS Configuration Review

**Check NSAppTransportSecurity in Info.plist**
```xml
<!-- Weak: allows all cleartext -->
<key>NSAllowsArbitraryLoads</key>
<true/>

<!-- Per-domain exceptions -->
<key>NSExceptionDomains</key>
<dict>
  <key>example.com</key>
  <dict>
    <key>NSExceptionAllowsInsecureHTTPLoads</key>
    <true/>
    <key>NSExceptionMinimumTLSVersion</key>
    <string>TLSv1.0</string>
  </dict>
</dict>
```

**Issues to Flag**
- `NSAllowsArbitraryLoads: true` disabling ATS globally
- Exceptions for first-party domains (should use HTTPS)
- `NSExceptionMinimumTLSVersion` set below TLSv1.2
- `NSAllowsArbitraryLoadsInWebContent` enabling cleartext in WebViews
- Missing certificate pinning for sensitive API connections

### 6. Certificate Pinning Bypass

```bash
# Objection
objection -g {bundle} explore
# Then: ios sslpinning disable

# Frida script
frida -U -l ios_pinning_bypass.js -f {bundle}

# SSL Kill Switch 2 (jailbroken)
# Install via Cydia/Sileo, toggle in Settings
```

## Key Commands

```bash
# Device interaction
ideviceinstaller -l                    # List installed apps
idevice_id -l                          # List connected devices
iproxy 2222 22                         # SSH port forwarding
ssh root@localhost -p 2222             # SSH to device

# Objection (non-jailbroken via repackaging, or jailbroken)
objection -g {bundle} explore
ios keychain dump
ios plist cat {path}
ios hooking list classes
ios hooking watch method "{class} {method}"

# Frida
frida-ps -Ua                           # List running apps
frida -U -l script.js {bundle}         # Run hook script
```

## Corpus-Derived Attack Patterns

### Mobile OAuth Redirect Mechanism Audit
For every OAuth flow in the iOS app: (1) identify the redirect mechanism: custom URL scheme (insecure -- any app can register the same scheme), Universal Link (better -- domain-verified), or in-app browser tab (best). If custom URL scheme is used for the OAuth callback, an attacker's app can register the same scheme and intercept the authorization code. Test scheme precedence and hijacking on the target device.

### Native-Mobile-Browser Bridge Attacks (3-Layer Audit)
For mobile browsers and WebView-based apps, audit the native-to-JS bridge in three layers, then compose: (1) JS bridge surface (page to native): enumerate every native function exposed via `webkit.messageHandlers`, `WKScriptMessageHandler`, or `JSContext` bridges, (2) Native handler surface: check what each handler can access (filesystem, keychain, network, other apps), (3) Composition: find any way to get attacker-controlled content into a context that can call bridge functions (XSS on a trusted origin, universal link to attacker page in privileged WebView, `javascript:` URI in deep link).

### Mobile Bundle Credential Audit
Systematically extract and search the IPA bundle for embedded credentials: (1) `Payload/<App>.app/Podfile` and `Podfile.lock` for private repo credentials, (2) `Payload/<App>.app/*.plist` for API keys and tokens, (3) embedded frameworks in `Payload/<App>.app/Frameworks/`, (4) `Assets.car` for embedded configuration, (5) binary strings for OAuth client secrets, Firebase configs, and cloud provider keys. Private git repo credentials in Podfile are a direct source code access vector.

### Mobile S3/Cloud Storage Upload Audit
For every upload flow in the app: (1) capture the upload destination URL (S3, GCS, Azure Blob), (2) test the bucket/container for public listing and read access, (3) test whether the pre-signed URL or upload policy can be manipulated to write to other paths or other users' directories, (4) check if uploaded files are served from a domain that shares cookies with the main application (stored XSS via file upload).

### Universal Link vs Custom Scheme Precedence Hijacking
If the app uses both Universal Links and custom URL schemes for the same flow: test what happens when Universal Link association fails (missing apple-app-site-association, domain unreachable). The OS falls back to the custom scheme, which may be hijackable. Also test whether a malicious app can claim the same Universal Link domain via an expired or misconfigured association file.

### Identity-Reuse Audit After Account Deletion
Test whether deleting an account and recreating one with the same identifier (email, phone, username) inherits any state from the deleted account: session tokens, push notification registrations, shared keychain items, cached data, or backend associations. If the identifier is reused but the internal user ID changes, orphaned references may grant the new account access to the old account's resources.

### Cross-Client Crypto Consistency Audit
For any multi-client E2EE product: enumerate all clients (desktop, web, mobile-iOS, mobile-Android). For each client pair, verify: (1) key exchange produces identical shared secrets, (2) public key verification (safety numbers, QR codes) uses the same derivation, (3) key rotation is synchronized across clients. If one client skips verification steps or trusts unverified keys, an attacker can MITM the E2EE session from that client.

### Real-Time API Participation Audit
For any synchronous communication feature (voice, video, chat rooms, screen share, collaborative editing): enumerate the join/subscribe mechanism and test whether an unauthorized party can join or eavesdrop by: (1) guessing or enumerating room/call IDs, (2) replaying a captured join token after session expiry, (3) calling the join API without the required invitation token but with a valid session.

### Sandbox/Privilege Classifier URL Scheme Confusion
For every sandbox or privilege classifier in the iOS app or browser: enumerate all URL schemes and origin types the classifier handles explicitly, then test schemes it does NOT handle. If an unrecognized scheme (e.g., `file:`, `blob:`, `data:`, custom app scheme) is treated as unprivileged by default, but the resource it loads runs in a privileged context, the classifier can be bypassed.

## Validation

- Demonstrate sensitive data extracted from Keychain, plists, or SQLite databases
- Show URL scheme abuse leading to unauthorized actions or data leakage
- Prove ATS bypass or certificate pinning bypass enables traffic interception
- Confirm insecure data protection levels on stored credentials
- Document exact commands, device state (jailbroken/non-jailbroken), and observed results
